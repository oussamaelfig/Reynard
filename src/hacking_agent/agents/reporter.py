"""
=============================================================================
Reynard — Reporter Specialist
=============================================================================
Synthesises a professional penetration-test report from the knowledge graph
and evidence store.

HARD RULE:  A finding appears under "Verified Vulnerabilities" ONLY if
            `evidence.is_verified(vuln_id)` returns True. Everything else
            is "Informational / Unverified."

The reporter does NOT call any tools. It reads memory + evidence, calls the
LLM once for free-form markdown (call_text), and returns the report as
`AgentResult.artifact`.

Reports are also written to `logs/report_<timestamp>.md`.
=============================================================================
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from datetime import datetime

from rich.console import Console

from hacking_agent.agents.base import BaseAgent
from hacking_agent.core.paths import LOG_DIR, ensure_runtime_dirs
from hacking_agent.core.schemas import AgentResult, AgentTask, PoC, Vulnerability

console = Console()


# =============================================================================
# CVSS v3.1 base-score helper (pure functions)
# =============================================================================
# A faithful implementation of the CVSS v3.1 base-score equations
# (https://www.first.org/cvss/v3.1/specification-document, section 7.1). Pure
# and side-effect free so it can be unit-tested offline and reused anywhere.

_CVSS_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    # PR depends on Scope; handled explicitly below.
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _cvss_roundup(value: float) -> float:
    """Round up to one decimal place per the CVSS v3.1 spec (Appendix A)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_cvss_vector(vector: str) -> dict[str, str]:
    """Parse a ``CVSS:3.1/AV:N/...`` vector string into a metric->value map."""
    metrics: dict[str, str] = {}
    for token in (vector or "").strip().split("/"):
        if ":" not in token:
            continue
        key, _, val = token.partition(":")
        key = key.strip().upper()
        if key in ("CVSS",):
            continue
        metrics[key] = val.strip().upper()
    return metrics


def cvss_v31_base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score from a vector string.

    Returns 0.0 if the vector is missing a required base metric (so callers can
    treat an unparseable/`N/A` vector as informational).
    """
    m = parse_cvss_vector(vector)
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in m for k in required):
        return 0.0
    try:
        scope_changed = m["S"] == "C"
        av = _CVSS_WEIGHTS["AV"][m["AV"]]
        ac = _CVSS_WEIGHTS["AC"][m["AC"]]
        ui = _CVSS_WEIGHTS["UI"][m["UI"]]
        pr = _CVSS_WEIGHTS["PR_C" if scope_changed else "PR_U"][m["PR"]]
        c = _CVSS_WEIGHTS["C"][m["C"]]
        i = _CVSS_WEIGHTS["I"][m["I"]]
        a = _CVSS_WEIGHTS["A"][m["A"]]
    except KeyError:
        return 0.0

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return _cvss_roundup(base)


def severity_from_score(score: float) -> str:
    """Map a CVSS base score to the qualitative severity rating."""
    if score <= 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# Representative CVSS v3.1 vectors per qualitative severity, used when a finding
# only carries a severity label and no measured vector.
CVSS_VECTOR_BY_SEVERITY: dict[str, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "low": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info": "N/A",
}


def cvss_for_severity(severity: str) -> tuple[str, float]:
    """Return a representative (vector, base_score) for a qualitative severity."""
    sev = (severity or "medium").strip().lower()
    vector = CVSS_VECTOR_BY_SEVERITY.get(sev, CVSS_VECTOR_BY_SEVERITY["medium"])
    if vector == "N/A":
        return vector, 0.0
    return vector, cvss_v31_base_score(vector)


# =============================================================================
# CWE mapping
# =============================================================================
# Keyword -> CWE, scanned in order against the vulnerability type/title. First
# match wins, so more specific phrases come first.

_CWE_BY_KEYWORD: list[tuple[str, str]] = [
    ("prototype pollution", "CWE-1321"),
    ("request smuggling", "CWE-444"),
    ("cache poisoning", "CWE-349"),
    ("cache deception", "CWE-525"),
    ("host header", "CWE-644"),
    ("path traversal", "CWE-22"),
    ("directory traversal", "CWE-22"),
    ("command injection", "CWE-78"),
    ("os command", "CWE-78"),
    ("deserial", "CWE-502"),
    ("open redirect", "CWE-601"),
    ("ssrf", "CWE-918"),
    ("server-side request forgery", "CWE-918"),
    ("ssti", "CWE-1336"),
    ("template injection", "CWE-1336"),
    ("xxe", "CWE-611"),
    ("xml external", "CWE-611"),
    ("sqli", "CWE-89"),
    ("sql injection", "CWE-89"),
    ("nosql", "CWE-943"),
    ("stored xss", "CWE-79"),
    ("reflected xss", "CWE-79"),
    ("dom xss", "CWE-79"),
    ("dom-based", "CWE-79"),
    ("xss", "CWE-79"),
    ("cross-site scripting", "CWE-79"),
    ("csrf", "CWE-352"),
    ("cross-site request forgery", "CWE-352"),
    ("cors", "CWE-942"),
    ("clickjack", "CWE-1021"),
    ("jwt", "CWE-347"),
    ("oauth", "CWE-287"),
    ("authentication", "CWE-287"),
    ("idor", "CWE-639"),
    ("access control", "CWE-284"),
    ("authorization", "CWE-285"),
    ("business logic", "CWE-840"),
    ("information disclosure", "CWE-200"),
    ("file upload", "CWE-434"),
    ("graphql", "CWE-200"),
    ("websocket", "CWE-346"),
    ("llm", "CWE-1427"),
    ("race condition", "CWE-362"),
]


def cwe_for(vuln_type: str) -> str:
    """Best-effort CWE identifier for a vulnerability type/title string."""
    text = (vuln_type or "").lower()
    for keyword, cwe in _CWE_BY_KEYWORD:
        if keyword in text:
            return cwe
    return "CWE-Other"


# =============================================================================
# Assessment findings + professional report template
# =============================================================================

@dataclass
class Finding:
    """A single client-report finding with scoring + remediation metadata."""
    title: str
    vuln_type: str = ""
    severity: str = "medium"
    endpoint: str = ""
    parameter: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    verified: bool = False
    evidence: list[dict] = field(default_factory=list)

    def ensure_scored(self) -> None:
        """Fill CWE / CVSS vector / CVSS score from severity when unset."""
        if not self.cwe:
            self.cwe = cwe_for(self.vuln_type or self.title)
        if not self.cvss_vector:
            vector, score = cvss_for_severity(self.severity)
            self.cvss_vector = vector
            if not self.cvss_score:
                self.cvss_score = score
        elif not self.cvss_score:
            self.cvss_score = cvss_v31_base_score(self.cvss_vector)


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_DEFAULT_REMEDIATION: list[tuple[str, str]] = [
    ("xss", "Context-encode all user-controlled output and apply a strict "
            "Content-Security-Policy; prefer framework auto-escaping."),
    ("sql", "Use parameterized queries / prepared statements and least-"
            "privilege database accounts; never build SQL from user input."),
    ("ssrf", "Enforce an allowlist of permitted egress hosts, block internal "
             "IP ranges and link-local metadata, and disable unused URL schemes."),
    ("idor", "Enforce server-side object-level authorization on every request "
             "using the authenticated identity, not client-supplied IDs."),
    ("access control", "Apply deny-by-default authorization checks on every "
                       "sensitive endpoint and verify roles server-side."),
    ("csrf", "Require unpredictable per-request anti-CSRF tokens and set "
             "SameSite cookies on state-changing endpoints."),
    ("deserial", "Avoid deserializing untrusted data; use data-only formats "
                 "and integrity checks / allowlisted types."),
    ("ssti", "Never render user input as a template; use a logic-less sandboxed "
             "template engine and context-encode output."),
    ("xxe", "Disable external entity and DTD processing in the XML parser."),
    ("path traversal", "Canonicalize and validate file paths against an "
                       "allowlist; reject traversal sequences."),
]


def _default_remediation(vuln_type: str) -> str:
    text = (vuln_type or "").lower()
    for keyword, advice in _DEFAULT_REMEDIATION:
        if keyword in text:
            return advice
    return ("Validate and sanitize all untrusted input, enforce least "
            "privilege, and add regression tests covering this vector.")


def _poc_to_evidence(poc: PoC) -> dict:
    return {
        "verdict": poc.verdict,
        "payload": poc.payload,
        "request": poc.request_summary,
        "response": poc.response_excerpt,
        "agent": poc.agent_name,
        "timestamp": poc.timestamp,
    }


def extract_findings(memory, evidence) -> list[Finding]:
    """Build scored ``Finding`` objects from a run's memory + evidence store.

    A finding is marked verified ONLY when ``evidence.is_verified`` returns
    True for the vulnerability id — the same evidence gate the lab reporter
    uses. Everything else is carried as unverified/informational.
    """
    findings: list[Finding] = []
    for entity in memory.query("Vulnerability"):
        vuln_id = entity.id
        attrs = entity.attrs
        status = attrs.get("status", "theoretical")
        if status == "false_positive":
            continue
        verified = bool(evidence.is_verified(vuln_id))
        vuln_type = str(attrs.get("vuln_type") or attrs.get("type") or "finding")
        parameter = attrs.get("parameter") or ""
        endpoint = (
            attrs.get("endpoint")
            or attrs.get("url")
            or getattr(memory, "target_url", "")
            or ""
        )
        severity = str(attrs.get("severity") or "medium").lower()
        pocs = evidence.get_by_vuln(vuln_id)
        title = f"{vuln_type}" + (f" via `{parameter}`" if parameter else "")
        finding = Finding(
            title=title.strip() or vuln_type,
            vuln_type=vuln_type,
            severity=severity,
            endpoint=endpoint,
            parameter=parameter,
            description=str(attrs.get("hypothesis") or attrs.get("notes") or ""),
            impact=str(attrs.get("impact") or ""),
            remediation=str(attrs.get("remediation") or _default_remediation(vuln_type)),
            cvss_vector=str(attrs.get("cvss_vector") or ""),
            verified=verified,
            evidence=[_poc_to_evidence(p) for p in pocs],
        )
        finding.ensure_scored()
        findings.append(finding)
    findings.sort(
        key=lambda f: (0 if f.verified else 1,
                       _SEVERITY_ORDER.get(f.severity, 5),
                       -f.cvss_score)
    )
    return findings


def _reproduction_steps(finding: Finding) -> list[str]:
    """Derive concrete reproduction steps from a finding's evidence."""
    steps: list[str] = []
    if finding.endpoint:
        steps.append(f"Send a request to `{finding.endpoint}`"
                     + (f" targeting the `{finding.parameter}` parameter." if finding.parameter else "."))
    for ev in finding.evidence:
        payload = (ev.get("payload") or "").strip()
        request = (ev.get("request") or "").strip()
        if request:
            steps.append(f"Deliver: {request[:200]}")
        elif payload:
            steps.append(f"Deliver payload: {payload[:200]}")
    if not steps:
        steps.append("Reproduction steps unavailable — see evidence below.")
    return steps


def render_finding_section(finding: Finding, index: int) -> str:
    """Render one finding as a professional per-finding markdown section."""
    finding.ensure_scored()
    lines = [
        f"### {index}. {finding.title}",
        "",
        f"- **Severity:** {finding.severity.capitalize()}",
        f"- **CVSS v3.1:** {finding.cvss_score} "
        f"(`{finding.cvss_vector}`)",
        f"- **CWE:** {finding.cwe}",
        f"- **Affected endpoint:** {finding.endpoint or 'N/A'}"
        + (f" (parameter `{finding.parameter}`)" if finding.parameter else ""),
        f"- **Status:** {'VERIFIED (evidence-gated)' if finding.verified else 'Unverified / informational'}",
        "",
        "**Description**",
        "",
        finding.description or "No description provided.",
        "",
        "**Impact**",
        "",
        finding.impact or "See severity and CVSS rating above.",
        "",
        "**Reproduction steps**",
        "",
    ]
    for i, step in enumerate(_reproduction_steps(finding), 1):
        lines.append(f"{i}. {step}")
    lines += ["", "**Evidence**", ""]
    if finding.evidence:
        for ev in finding.evidence:
            lines.append(
                f"- [{str(ev.get('verdict', '')).upper()}] "
                f"payload: `{(ev.get('payload') or '')[:160]}`"
            )
            if ev.get("response"):
                lines.append("")
                lines.append("```")
                lines.append(str(ev.get("response"))[:400])
                lines.append("```")
    else:
        lines.append("- No proof-of-concept artifacts were recorded.")
    lines += [
        "",
        "**Remediation**",
        "",
        finding.remediation or _default_remediation(finding.vuln_type),
        "",
    ]
    return "\n".join(lines)


def _severity_tally(findings: list[Finding]) -> dict[str, int]:
    tally = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        tally[f.severity] = tally.get(f.severity, 0) + 1
    return tally


def render_assessment_report(
    meta: dict,
    findings: list[Finding],
    recon_summary: str = "",
) -> str:
    """Render a client-grade assessment report in Markdown.

    ``meta`` carries the engagement header (engagement_name, client, tester,
    targets, scope, testing_window, generated_at). ``findings`` are the scored
    findings (verified first). This is deterministic and LLM-free so it can be
    produced offline and unit-tested.
    """
    generated_at = meta.get("generated_at") or datetime.utcnow().isoformat()
    verified = [f for f in findings if f.verified]
    unverified = [f for f in findings if not f.verified]
    tally = _severity_tally(findings)

    lines = [
        f"# Security Assessment Report — {meta.get('engagement_name', 'Engagement')}",
        "",
        f"- **Client:** {meta.get('client', 'N/A')}",
        f"- **Tester:** {meta.get('tester', 'N/A')}",
        f"- **Generated:** {generated_at}",
        f"- **Targets:** {', '.join(meta.get('targets', [])) or 'N/A'}",
    ]
    if meta.get("testing_window"):
        lines.append(f"- **Testing window:** {meta['testing_window']}")
    lines += [
        "",
        "## 1. Executive Summary",
        "",
        (
            f"This report documents an authorized security assessment of "
            f"{', '.join(meta.get('targets', [])) or 'the in-scope assets'}. "
            f"Testing identified {len(findings)} finding(s), of which "
            f"{len(verified)} were evidence-verified. Severity distribution: "
            f"{tally['critical']} critical, {tally['high']} high, "
            f"{tally['medium']} medium, {tally['low']} low, {tally['info']} "
            f"informational."
        ),
        "",
        "## 2. Scope",
        "",
        f"- **Authorized domains:** {', '.join(meta.get('authorized_domains', [])) or 'N/A'}",
        f"- **Authorized CIDRs:** {', '.join(meta.get('authorized_cidrs', [])) or 'N/A'}",
        f"- **Out of scope:** {', '.join(meta.get('out_of_scope', [])) or 'None declared'}",
        "",
        "## 3. Methodology",
        "",
        (
            "The assessment followed a scoped recon → enumerate → test → report "
            "workflow driven by Reynard's multi-agent orchestrator (recon, "
            "analysis, exploitation, and skeptical validation). All activity was "
            "constrained by the engagement's rules of engagement (authorized "
            "scope, out-of-scope denylist, request rate limit, and destructive-"
            "action policy). Only findings backed by a reproducible proof of "
            "concept are reported as verified."
        ),
        "",
        "## 4. Findings Summary",
        "",
        "| # | Finding | Severity | CVSS | CWE | Verified |",
        "| ---: | --- | --- | ---: | --- | :---: |",
    ]
    for i, f in enumerate(findings, 1):
        f.ensure_scored()
        lines.append(
            f"| {i} | {f.title.replace('|', chr(92) + '|')} | "
            f"{f.severity.capitalize()} | {f.cvss_score} | {f.cwe} | "
            f"{'yes' if f.verified else 'no'} |"
        )
    if not findings:
        lines.append("| — | No findings recorded | — | — | — | — |")

    lines += ["", "## 5. Verified Vulnerabilities", ""]
    if verified:
        for i, f in enumerate(verified, 1):
            lines.append(render_finding_section(f, i))
    else:
        lines.append("No findings passed the evidence gate.")

    lines += ["", "## 6. Informational / Unverified Findings", ""]
    if unverified:
        for i, f in enumerate(unverified, 1):
            lines.append(render_finding_section(f, i))
    else:
        lines.append("None.")

    lines += [
        "",
        "## 7. Reconnaissance Summary",
        "",
        recon_summary or "No reconnaissance summary was recorded.",
        "",
    ]
    return "\n".join(lines)

REPORTER_SYSTEM = """You are the REPORTING specialist for an autonomous penetration-testing system.

# YOUR MISSION
Produce a professional penetration-test report in Markdown. The report is
for a technical audience (security engineers, developers).

# STRUCTURE (follow this order)
1. **Executive Summary** — 2-3 sentences: target, scope, key result.
2. **Methodology** — Briefly describe the multi-agent pipeline: recon →
   analysis → exploitation → verification.
3. **Verified Vulnerabilities** — One subsection per finding with:
     - **Title** (e.g. "Reflected XSS via `search` parameter")
     - **Severity** (Critical / High / Medium / Low / Info)
     - **Endpoint & Parameter**
     - **Description** — What the vulnerability is and why it matters
     - **Proof of Concept** — The exact request/payload and the response
       excerpt proving exploitation (provided to you as PoC data)
     - **Remediation** — Concrete fix recommendation
4. **Informational Findings** — Theoretical or partial findings that could
   not be conclusively verified. Same subsection format minus the PoC.
5. **Reconnaissance Summary** — Technologies, endpoints, and parameters
   discovered.
6. **Appendix** — Session statistics (iterations, tool calls, agent
   dispatches).

# RULES
- NEVER invent a PoC that wasn't provided to you.
- NEVER upgrade an INFORMATIONAL finding to VERIFIED — only the evidence
  store controls that classification.
- Use Markdown code blocks for PoC payloads and responses.
- Be concise but thorough.

# OUTPUT
A single Markdown document (no JSON wrapper). Start with `# Penetration Test Report`.
"""


class ReporterAgent(BaseAgent):
    name = "reporter"
    role = "reporter"

    def execute(self, task: AgentTask) -> AgentResult:
        # Assessment mode: produce the deterministic, client-grade professional
        # report (CVSS/CWE/remediation) with no LLM call. The default lab path
        # (no assessment_mode flag) is unchanged.
        if task.context.get("assessment_mode"):
            return self._execute_assessment(task)
        prompt = self._build_prompt(task)
        try:
            report_md = self.call_text(REPORTER_SYSTEM, prompt)
        except Exception as e:
            return AgentResult(
                success=False, summary=f"Reporter LLM failure: {e}"
            )

        # ---- persist to disk ----
        report_path = self._save_report(report_md)
        console.print(f"[green bold]📄 Report saved → {report_path}[/]")

        # ---- build summary JSON ----
        verified, informational = self._classify_vulns()
        summary_json = {
            "generated_at": datetime.utcnow().isoformat(),
            "target": task.context.get("target_url", "unknown"),
            "verified_count": len(verified),
            "informational_count": len(informational),
            "total_pocs": len(self.evidence.all_pocs()),
            "report_path": report_path,
        }
        json_path = report_path.replace(".md", ".json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary_json, f, indent=2)
        console.print(f"[green]   📊 Summary JSON → {json_path}[/]")

        return AgentResult(
            success=True,
            summary=(
                f"Report generated: {len(verified)} verified, "
                f"{len(informational)} informational."
            ),
            artifact=report_md,
        )

    # ---- assessment mode ------------------------------------------------

    def build_assessment_report(self, task: AgentTask) -> str:
        """Build the professional assessment report markdown from this agent's
        memory + evidence store. LLM-free and reusable by the assess CLI."""
        findings = extract_findings(self.memory, self.evidence)
        meta = dict(task.context.get("engagement_meta") or {})
        meta.setdefault("targets", [self.memory.target_url] if self.memory.target_url else [])
        recon_summary = task.context.get("recon_summary") or self.kg_summary()
        return render_assessment_report(meta, findings, recon_summary)

    def _execute_assessment(self, task: AgentTask) -> AgentResult:
        try:
            report_md = self.build_assessment_report(task)
        except Exception as e:  # noqa: BLE001 - surfaced in result
            return AgentResult(
                success=False, summary=f"Assessment report failure: {e}"
            )
        report_path = self._save_report(report_md)
        console.print(f"[green bold]📄 Assessment report saved → {report_path}[/]")
        verified, informational = self._classify_vulns()
        return AgentResult(
            success=True,
            summary=(
                f"Assessment report generated: {len(verified)} verified, "
                f"{len(informational)} informational."
            ),
            artifact=report_md,
        )

    # ---- helpers --------------------------------------------------------

    def _classify_vulns(self) -> tuple[list[dict], list[dict]]:
        """Split KG Vulnerability entities into verified vs informational."""
        verified: list[dict] = []
        informational: list[dict] = []
        for entity in self.memory.query("Vulnerability"):
            vuln_id = entity.id
            if self.evidence.is_verified(vuln_id):
                verified.append({"id": vuln_id, **entity.attrs})
            else:
                status = entity.attrs.get("status", "theoretical")
                if status != "false_positive":
                    informational.append({"id": vuln_id, **entity.attrs})
        return verified, informational

    def _build_prompt(self, task: AgentTask) -> str:
        target_url = task.context.get("target_url", "unknown")
        verified, informational = self._classify_vulns()
        all_pocs = self.evidence.all_pocs()

        sections: list[str] = [
            f"# TARGET\n{target_url}",
            f"\n{self.kg_summary()}",
            f"\n{self.state_summary()}",
        ]

        # ---- verified findings + PoCs ----
        if verified:
            sections.append("\n# VERIFIED VULNERABILITIES (evidence-gated)")
            for v in verified:
                vid = v["id"]
                pocs = self.evidence.get_by_vuln(vid)
                poc_text = "\n".join(self._format_poc(p) for p in pocs)
                sections.append(
                    f"\n## {v.get('vuln_type', '?')} — {v.get('parameter', 'N/A')}\n"
                    f"  Severity: {v.get('severity', 'medium')}\n"
                    f"  Hypothesis: {v.get('hypothesis', '')}\n"
                    f"  Status: VERIFIED\n"
                    f"  PoCs:\n{poc_text}"
                )
        else:
            sections.append(
                "\n# VERIFIED VULNERABILITIES\n  (none — no finding passed "
                "the evidence gate)"
            )

        # ---- informational ----
        if informational:
            sections.append("\n# INFORMATIONAL / UNVERIFIED FINDINGS")
            for v in informational:
                sections.append(
                    f"\n## {v.get('vuln_type', '?')} — {v.get('parameter', 'N/A')}\n"
                    f"  Severity: {v.get('severity', 'medium')}\n"
                    f"  Hypothesis: {v.get('hypothesis', '')}\n"
                    f"  Status: {v.get('status', 'theoretical')}"
                )

        sections.append(
            "\n# YOUR TASK\n"
            "Write the full Markdown report following the structure in your "
            "system prompt. Use the data above as your sole source of truth."
        )
        return "\n".join(sections)

    def _format_poc(self, poc: PoC) -> str:
        return (
            f"    - [{poc.verdict.upper()}] payload: {poc.payload[:200]}\n"
            f"      request: {poc.request_summary[:200]}\n"
            f"      response: {poc.response_excerpt[:300]}\n"
            f"      agent: {poc.agent_name} @ {poc.timestamp}"
        )

    def _save_report(self, content: str) -> str:
        ensure_runtime_dirs()
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(str(LOG_DIR), f"report_{ts}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path
