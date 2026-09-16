"""
=============================================================================
Reynard — Reporter Specialist
=============================================================================
Synthesises a professional penetration-test report from the knowledge graph
and evidence store.

HARD RULE: A customer finding appears only when the centralized
``finding_validation.is_reportable`` policy accepts its complete, independently
validated EvidenceBundle. Suppressed candidates are counted, never described.

The reporter does not call tools or an LLM. It deterministically renders
customer output from evidence accepted by the report gate.

Reports are also written to `logs/report_<timestamp>.md`.
=============================================================================
"""
from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from rich.console import Console

from hacking_agent.agents.base import BaseAgent
from hacking_agent.core.evidence_bundle import (
    V_REFUTED,
    V_UNVERIFIED,
    V_VERIFIED,
    build_bundle_from_pocs,
    sanitize_text,
)
from hacking_agent.core.finding_validation import (
    emit_suppression,
    evaluate_reportability,
    is_reportable,
    partition_reportable,
)
from hacking_agent.core.paths import LOG_DIR, ensure_runtime_dirs
from hacking_agent.core.schemas import AgentResult, AgentTask

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
    """A candidate plus the sealed evidence needed to cross the report gate."""
    title: str
    finding_id: str = ""
    vuln_id: str = ""
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
    # Compatibility mirror only.  Customer boundaries call ``is_reportable``;
    # assigning this boolean cannot promote a candidate.
    verified: bool = False
    evidence: list[dict] = field(default_factory=list)
    verification_status: str = ""
    evidence_bundle: dict = field(default_factory=dict)
    suppression_reason_code: str = ""
    suppression_rationale: str = ""

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

    @property
    def is_reportable(self) -> bool:
        return is_reportable(self)


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


def _bundle_evidence(bundle: Any) -> list[dict]:
    """Project already-sanitized bundle exchanges into report evidence rows."""
    rows: list[dict] = []
    if bundle is None:
        return rows
    for exchange in getattr(bundle, "test_exchanges", []) or []:
        rows.append({
            "verdict": "success",
            "payload": "",
            "request": sanitize_text(str(exchange.request or "")),
            "response": sanitize_text(str(exchange.response or "")),
            "agent": "validator",
            "timestamp": str(exchange.timestamp or ""),
            "label": str(exchange.label or "replay"),
        })
    for control in getattr(bundle, "control_tests", []) or []:
        exchange = getattr(control, "exchange", None)
        rows.append({
            "verdict": "control",
            "payload": "",
            "request": sanitize_text(str(getattr(exchange, "request", "") or "")),
            "response": sanitize_text(str(getattr(exchange, "response", "") or "")),
            "agent": "validator",
            "timestamp": str(getattr(exchange, "timestamp", "") or ""),
            "label": "control",
        })
    return rows


def extract_findings(memory, evidence, evidence_bundles=None) -> list[Finding]:
    """Build internal candidate objects and evaluate the strict report gate.

    Candidates are retained with structured suppression diagnostics.  The
    returned list is not itself a customer export; every renderer/exporter
    partitions it through the same central predicate.
    """
    findings: list[Finding] = []
    for entity in memory.query("Vulnerability"):
        vuln_id = entity.id
        attrs = entity.attrs
        status = attrs.get("status", "theoretical")
        if status == "false_positive":
            continue
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
        bundle = None
        if evidence_bundles is not None:
            try:
                candidates = evidence_bundles.by_vuln(vuln_id)
                bundle = candidates[-1] if candidates else None
            except Exception:
                bundle = None
        if bundle is None:
            state = evidence.verification_state(vuln_id)
            bundle = build_bundle_from_pocs(
                vuln_id,
                pocs,
                verification_status={
                    "verified": V_VERIFIED,
                    "refuted": V_REFUTED,
                }.get(state, V_UNVERIFIED),
                vuln_type=vuln_type,
                title=vuln_type,
                severity=severity,
                target=str(getattr(memory, "target_url", "") or endpoint),
                endpoint=str(endpoint),
                identity="anonymous",
            )
            # Give fallback bundles a stable local id and evidence seal.  They
            # remain suppressed unless the full Validator transcript exists.
            bundle.id = f"bundle:{vuln_id}"
            bundle.finding_id = vuln_id
            bundle.seal()
        title = f"{vuln_type}" + (f" via `{parameter}`" if parameter else "")
        finding = Finding(
            title=title.strip() or vuln_type,
            finding_id=vuln_id,
            vuln_id=vuln_id,
            vuln_type=vuln_type,
            severity=severity,
            endpoint=sanitize_text(str(endpoint)),
            parameter=parameter,
            description=sanitize_text(
                str(attrs.get("hypothesis") or attrs.get("notes") or "")
            ),
            impact=sanitize_text(str(attrs.get("impact") or "")),
            remediation=sanitize_text(
                str(attrs.get("remediation") or _default_remediation(vuln_type))
            ),
            cvss_vector=str(attrs.get("cvss_vector") or ""),
            evidence=_bundle_evidence(bundle),
            verification_status=str(bundle.verification_status or ""),
            evidence_bundle=bundle.to_dict(),
        )
        decision = evaluate_reportability(finding)
        finding.verified = decision.reportable
        if not decision.reportable:
            finding.suppression_reason_code = decision.reason_code
            finding.suppression_rationale = decision.rationale
            emit_suppression(finding, decision)
        finding.ensure_scored()
        findings.append(finding)
    findings.sort(
        key=lambda f: (0 if f.verified else 1,
                       _SEVERITY_ORDER.get(f.severity, 5),
                       -f.cvss_score)
    )
    return findings


def finding_to_report_dict(finding: Finding) -> dict[str, Any]:
    """Serialize one confirmed finding; reject all attempted bypasses."""
    decision = evaluate_reportability(finding)
    if not decision.reportable:
        raise ValueError(
            f"candidate is not reportable: {decision.reason_code}"
        )
    finding.ensure_scored()
    return {
        "finding_id": finding.finding_id,
        "vuln_id": finding.vuln_id,
        "title": finding.title,
        "vuln_type": finding.vuln_type,
        "severity": finding.severity,
        "cwe": finding.cwe,
        "cvss_vector": finding.cvss_vector,
        "cvss_score": finding.cvss_score,
        "endpoint": finding.endpoint,
        "parameter": finding.parameter,
        "verification_status": "verified",
        "verified": True,  # compatibility mirror; never trusted by the gate
        "description": finding.description,
        "impact": finding.impact,
        "remediation": finding.remediation,
        "evidence": list(finding.evidence),
        "evidence_bundle": dict(finding.evidence_bundle),
    }


def _reproduction_steps(finding: Finding) -> list[str]:
    """Derive concrete reproduction steps from a finding's evidence."""
    bundle_steps = (
        finding.evidence_bundle.get("reproduction_steps", [])
        if isinstance(finding.evidence_bundle, dict) else []
    )
    if bundle_steps:
        return [str(step) for step in bundle_steps]
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
    if not is_reportable(finding):
        return ""
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
        "- **Status:** CONFIRMED (independently replayed and evidence-gated)",
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

    ``findings`` may include internal candidates, but only entries accepted by
    the centralized reportability predicate are rendered.  Suppressed details
    never cross this customer-facing boundary.
    """
    generated_at = meta.get("generated_at") or datetime.utcnow().isoformat()
    verified, suppressed = partition_reportable(findings)
    tally = _severity_tally(verified)
    external_suppressed = int(meta.get("external_suppressed_count", 0) or 0)
    suppressed_total = len(suppressed) + external_suppressed
    reason_counts: dict[str, int] = {}
    for finding, decision in suppressed:
        reason_counts[decision.reason_code] = (
            reason_counts.get(decision.reason_code, 0) + 1
        )
        emit_suppression(finding, decision)
    for reason, count in dict(
        meta.get("external_suppression_reasons") or {}
    ).items():
        if isinstance(count, int) and count > 0:
            reason_counts[str(reason)] = reason_counts.get(str(reason), 0) + count

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
            f"Testing found {len(verified)} independently validated "
            f"vulnerability/vulnerabilities. Severity distribution for confirmed "
            f"findings only: "
            f"{tally['critical']} critical, {tally['high']} high, "
            f"{tally['medium']} medium, {tally['low']} low, {tally['info']} "
            f"informational. {suppressed_total} candidate observation(s) were "
            "suppressed by the validation gate and are not findings in this report."
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
            "action policy). Only independently replayed findings with matched "
            "controls, complete sealed evidence, and vulnerability-specific "
            "behavioural proof are reported."
        ),
        "",
        "## 4. Findings Summary",
        "",
        "| # | Finding | Severity | CVSS | CWE | Verified |",
        "| ---: | --- | --- | ---: | --- | :---: |",
    ]
    for i, f in enumerate(verified, 1):
        f.ensure_scored()
        lines.append(
            f"| {i} | {f.title.replace('|', chr(92) + '|')} | "
            f"{f.severity.capitalize()} | {f.cvss_score} | {f.cwe} | "
            "yes |"
        )
    if not verified:
        lines.append(
            "| — | No independently validated vulnerabilities found | "
            "— | — | — | — |"
        )

    lines += ["", "## 5. Confirmed Vulnerabilities", ""]
    if verified:
        for i, f in enumerate(verified, 1):
            lines.append(render_finding_section(f, i))
    else:
        lines.append(
            "No independently validated vulnerabilities were found. Scanner, "
            "model, and other candidate observations that did not pass the "
            "strict evidence gate are intentionally excluded."
        )

    lines += ["", "## 6. Validation Gate Summary", ""]
    if suppressed_total:
        lines.append(
            f"{suppressed_total} internal candidate observation(s) were "
            "suppressed and are not reportable findings."
        )
        if reason_counts:
            lines.append("")
            lines.append("| Suppression reason | Count |")
            lines.append("| --- | ---: |")
            for reason, count in sorted(reason_counts.items()):
                lines.append(f"| `{reason}` | {count} |")
    else:
        lines.append("No candidate observations were suppressed.")

    lines += [
        "",
        "## 7. Reconnaissance Summary",
        "",
        recon_summary or "No reconnaissance summary was recorded.",
        "",
    ]
    return "\n".join(lines)

class ReporterAgent(BaseAgent):
    name = "reporter"
    role = "reporter"

    def execute(self, task: AgentTask) -> AgentResult:
        # Reports are deterministic and evidence-derived.  An LLM is never
        # allowed to synthesize or promote customer-facing findings.
        return self._execute_assessment(task)

    # ---- assessment mode ------------------------------------------------

    def build_assessment_report(self, task: AgentTask) -> str:
        """Build the professional assessment report markdown from this agent's
        memory + evidence store. LLM-free and reusable by the assess CLI."""
        findings = extract_findings(
            self.memory, self.evidence, self.evidence_bundles,
        )
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
        report_md = self._append_evidence_appendix(report_md, task)
        report_path = self._save_report(report_md)
        console.print(f"[green bold]📄 Assessment report saved → {report_path}[/]")
        verified, informational = self._classify_vulns()
        return AgentResult(
            success=True,
            summary=(
                f"Assessment report generated: {len(verified)} confirmed, "
                f"{len(informational)} suppressed."
            ),
            artifact=report_md,
        )

    # ---- helpers --------------------------------------------------------

    def _classify_vulns(self) -> tuple[list[dict], list[dict]]:
        """Split internal candidates with the same centralized predicate."""
        candidates = extract_findings(
            self.memory, self.evidence, self.evidence_bundles,
        )
        confirmed, suppressed = partition_reportable(candidates)
        return (
            [
                {"id": finding.finding_id, "title": finding.title}
                for finding in confirmed
            ],
            [
                {
                    "id": finding.finding_id,
                    "reason_code": decision.reason_code,
                }
                for finding, decision in suppressed
            ],
        )

    def _append_evidence_appendix(self, report_md: str, task: AgentTask) -> str:
        """Append the machine-generated EvidenceBundle appendix verbatim.

        This is the reproducible, evidence-derived portion of the report (control
        tests, sanitized exchanges, reproduction steps) — not LLM narration."""
        appendix = ""
        if self.evidence_bundles is not None:
            try:
                appendix = self.evidence_bundles.render_markdown(
                    verified_only=True,
                )
            except Exception:
                appendix = ""
        if not appendix or not appendix.strip():
            return report_md
        return (
            f"{report_md}\n\n---\n\n"
            "# Evidence Appendix (machine-generated, verbatim)\n\n"
            "The following reproducible evidence bundles back the verified "
            "findings above. Secrets are redacted; each bundle includes the "
            "test exchange, control comparison, and reproduction steps.\n\n"
            f"{appendix}\n"
        )

    def _save_report(self, content: str) -> str:
        ensure_runtime_dirs()
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(str(LOG_DIR), f"report_{ts}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path
