"""Turn a finding into a copy-paste, bug-bounty-ready submission (Markdown).

Reuses the reporter's finding model + CVSS/CWE helpers so the harness produces
the same evidence-gated writeup a client report would, formatted with the
sections bug-bounty programs ask for (asset, weakness, CVSS, summary, steps,
PoC, impact, remediation, references). Pure + offline-testable — it never calls
an LLM and never widens scope.
"""
from __future__ import annotations

from typing import Any, Optional

from hacking_agent.agents.reporter import (
    Finding,
    _default_remediation,
    _reproduction_steps,
    cvss_for_severity,
    cvss_v31_base_score,
    cwe_for,
)

# A few high-signal references by CWE (extend as needed).
_OWASP_BY_KEYWORD: list[tuple[str, str]] = [
    ("sql", "https://owasp.org/www-community/attacks/SQL_Injection"),
    ("xss", "https://owasp.org/www-community/attacks/xss/"),
    ("ssrf", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"),
    ("idor", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    ("authorization", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    ("access control", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    ("authentication", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    ("csrf", "https://owasp.org/www-community/attacks/csrf"),
    ("cors", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"),
    ("ssti", "https://owasp.org/www-community/attacks/Server-Side_Template_Injection"),
    ("xxe", "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"),
    ("command", "https://owasp.org/www-community/attacks/Command_Injection"),
    ("information disclosure", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    ("graphql", "https://owasp.org/www-project-web-security-testing-guide/"),
]


def finding_from_dict(d: dict[str, Any]) -> Finding:
    f = Finding(
        title=str(d.get("title") or d.get("vuln_type") or "Security finding"),
        vuln_type=str(d.get("vuln_type") or ""),
        severity=str(d.get("severity") or "medium").lower(),
        endpoint=str(d.get("endpoint") or d.get("target") or ""),
        parameter=str(d.get("parameter") or ""),
        description=str(d.get("description") or ""),
        impact=str(d.get("impact") or ""),
        remediation=str(d.get("remediation") or ""),
        cwe=str(d.get("cwe") or ""),
        cvss_vector=str(d.get("cvss_vector") or ""),
        cvss_score=float(d.get("cvss_score") or 0.0),
        verified=bool(d.get("verified")),
        evidence=list(d.get("evidence") or []),
    )
    f.ensure_scored()
    return f


def _cwe_url(cwe: str) -> str:
    num = "".join(ch for ch in str(cwe) if ch.isdigit())
    return f"https://cwe.mitre.org/data/definitions/{num}.html" if num else ""


def _owasp_url(vuln_type: str, title: str) -> str:
    text = f"{vuln_type} {title}".lower()
    for kw, url in _OWASP_BY_KEYWORD:
        if kw in text:
            return url
    return ""


def _poc_block(finding: Finding) -> list[str]:
    lines: list[str] = []
    if not finding.evidence:
        lines.append("_No proof-of-concept artifact was captured for this finding. "
                     "Reproduce the steps above to collect a request/response pair._")
        return lines
    for ev in finding.evidence:
        verdict = str(ev.get("verdict", "")).upper()
        payload = (ev.get("payload") or "").strip()
        request = (ev.get("request") or "").strip()
        response = (ev.get("response") or "").strip()
        if verdict or payload:
            lines.append(f"- **{verdict or 'PoC'}**"
                         + (f" — payload: `{payload[:200]}`" if payload else ""))
        if request:
            lines += ["", "_Request:_", "```http", request[:600], "```"]
        if response:
            lines += ["", "_Response (excerpt):_", "```http", response[:1200], "```"]
        lines.append("")
    return lines


def build_submission_markdown(finding: dict[str, Any],
                              meta: Optional[dict[str, Any]] = None) -> str:
    """Render one finding as a complete, copy-paste bug-bounty submission."""
    meta = meta or {}
    f = finding_from_dict(finding)
    target = str(finding.get("target") or meta.get("target") or "").strip()
    asset = f.endpoint or target or "the in-scope asset"
    program = str(meta.get("engagement_name") or meta.get("program") or "").strip()
    severity = f.severity.capitalize()
    cvss = "N/A" if (not f.cvss_score or f.cvss_vector == "N/A") else \
        f"{f.cvss_score} (`{f.cvss_vector}`)"
    weakness = f.cwe or cwe_for(f.vuln_type or f.title)
    cwe_url = _cwe_url(weakness)
    owasp = _owasp_url(f.vuln_type, f.title)
    status = "Verified (reproduced, evidence-gated)" if f.verified \
        else "Unverified — requires manual confirmation"

    lines: list[str] = [f"# {f.title}", ""]
    meta_rows = [
        f"- **Asset (in scope):** {asset}",
        (f"- **Endpoint / parameter:** `{f.endpoint}`"
         + (f" · `{f.parameter}`" if f.parameter else "")) if f.endpoint else "",
        f"- **Severity:** {severity}",
        f"- **CVSS v3.1:** {cvss}",
        f"- **Weakness:** {weakness}" + (f" — {cwe_url}" if cwe_url else ""),
        f"- **Status:** {status}",
    ]
    if program:
        meta_rows.insert(0, f"- **Program:** {program}")
    lines += [r for r in meta_rows if r]

    lines += ["", "## Summary", "",
              f.description or (f"A {f.vuln_type or 'security'} issue was identified "
                               f"on {asset}.")]

    lines += ["", "## Steps to Reproduce", ""]
    for i, step in enumerate(_reproduction_steps(f), 1):
        lines.append(f"{i}. {step}")

    lines += ["", "## Proof of Concept", ""]
    lines += _poc_block(f)

    lines += ["", "## Impact", "",
              f.impact or ("An attacker could abuse this weakness against "
                           f"{asset}; see the CVSS rating for scored severity.")]

    lines += ["", "## Remediation", "",
              f.remediation or _default_remediation(f.vuln_type)]

    refs = []
    if cwe_url:
        refs.append(f"- {weakness}: {cwe_url}")
    if owasp:
        refs.append(f"- OWASP: {owasp}")
    if refs:
        lines += ["", "## References", ""] + refs

    lines += ["", "---",
              "_Prepared with Reynard. Reproduce strictly within the program's "
              "rules of engagement._"]
    return "\n".join(lines)


def iter_report_findings(report_json: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a report.json into per-finding dicts annotated with their target."""
    out: list[dict[str, Any]] = []
    for t in report_json.get("targets_assessed", []) or []:
        target = t.get("target", "")
        for f in t.get("findings", []) or []:
            out.append({**f, "target": target})
    return out


def report_meta(report_json: dict[str, Any]) -> dict[str, Any]:
    keys = ("engagement_name", "client", "tester", "targets",
            "authorized_domains", "authorized_cidrs", "out_of_scope",
            "generated_at")
    return {k: report_json.get(k) for k in keys if k in report_json}
