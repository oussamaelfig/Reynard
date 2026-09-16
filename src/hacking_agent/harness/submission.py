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
    _bundle_evidence,
    _default_remediation,
    _reproduction_steps,
    cvss_for_severity,
    cvss_v31_base_score,
    cwe_for,
    finding_to_report_dict,
    render_assessment_report,
)
from hacking_agent.core.evidence_bundle import sanitize_text
from hacking_agent.core.finding_validation import (
    evaluate_reportability,
    partition_reportable,
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


class UnreportableFindingError(ValueError):
    """Raised when code attempts to export an internal candidate."""


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return max(0, default)


def finding_from_dict(d: dict[str, Any]) -> Finding:
    raw_bundle = d.get("evidence_bundle")
    bundle = dict(raw_bundle) if isinstance(raw_bundle, dict) else {}
    f = Finding(
        title=sanitize_text(
            str(d.get("title") or d.get("vuln_type") or "Security finding")
        ),
        finding_id=str(d.get("finding_id") or ""),
        vuln_id=str(d.get("vuln_id") or d.get("finding_id") or ""),
        vuln_type=sanitize_text(str(d.get("vuln_type") or "")),
        severity=str(d.get("severity") or "medium").lower(),
        endpoint=sanitize_text(str(d.get("endpoint") or d.get("target") or "")),
        parameter=sanitize_text(str(d.get("parameter") or "")),
        description=sanitize_text(str(d.get("description") or "")),
        impact=sanitize_text(str(d.get("impact") or "")),
        remediation=sanitize_text(str(d.get("remediation") or "")),
        cwe=str(d.get("cwe") or ""),
        cvss_vector=str(d.get("cvss_vector") or ""),
        cvss_score=float(d.get("cvss_score") or 0.0),
        verified=bool(d.get("verified")),
        # The top-level evidence field is an unsealed compatibility projection.
        # Always regenerate it from the integrity-checked bundle.
        evidence=_bundle_evidence(bundle),
        verification_status=str(d.get("verification_status") or ""),
        evidence_bundle=bundle,
        suppression_reason_code=str(d.get("suppression_reason_code") or ""),
        suppression_rationale=str(d.get("suppression_rationale") or ""),
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
    decision = evaluate_reportability(f)
    if not decision.reportable:
        raise UnreportableFindingError(
            f"submission suppressed: {decision.reason_code}"
        )
    target = sanitize_text(
        str(finding.get("target") or meta.get("target") or "")
    ).strip()
    asset = f.endpoint or target or "the in-scope asset"
    program = sanitize_text(
        str(meta.get("engagement_name") or meta.get("program") or "")
    ).strip()
    severity = f.severity.capitalize()
    cvss = "N/A" if (not f.cvss_score or f.cvss_vector == "N/A") else \
        f"{f.cvss_score} (`{f.cvss_vector}`)"
    weakness = f.cwe or cwe_for(f.vuln_type or f.title)
    cwe_url = _cwe_url(weakness)
    owasp = _owasp_url(f.vuln_type, f.title)
    status = "Confirmed (independently replayed, evidence-gated)"

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
    """Flatten only centrally reportable findings from a report document."""
    out: list[dict[str, Any]] = []
    for t in report_json.get("targets_assessed", []) or []:
        if not isinstance(t, dict):
            continue
        target = t.get("target", "")
        for f in t.get("findings", []) or []:
            if not isinstance(f, dict):
                continue
            try:
                finding = finding_from_dict(f)
                if evaluate_reportability(finding).reportable:
                    out.append({
                        **finding_to_report_dict(finding),
                        "target": sanitize_text(str(target or "")),
                    })
            except (TypeError, ValueError):
                continue
    return out


def report_meta(report_json: dict[str, Any]) -> dict[str, Any]:
    keys = ("engagement_name", "client", "tester", "targets",
            "authorized_domains", "authorized_cidrs", "out_of_scope",
            "generated_at", "testing_window")
    return {k: report_json.get(k) for k in keys if k in report_json}


def sanitize_report_json(report_json: dict[str, Any]) -> dict[str, Any]:
    """Re-gate a stored report and return a customer-safe strict document."""
    source = report_json if isinstance(report_json, dict) else {}
    safe: dict[str, Any] = report_meta(source)
    safe["reportability_policy_version"] = 1
    safe["target_count"] = _safe_int(source.get("target_count", 0))

    declared_suppressed = _safe_int(source.get("suppressed_count", 0))
    raw_reasons = source.get("suppression_reasons") or {}
    reasons = {
        str(key): value
        for key, value in (
            raw_reasons.items() if isinstance(raw_reasons, dict) else []
        )
        if isinstance(value, int) and value >= 0
    }
    rejected_here = 0
    targets: list[dict[str, Any]] = []
    for target_row in source.get("targets_assessed", []) or []:
        if not isinstance(target_row, dict):
            rejected_here += 1
            continue
        candidates: list[Finding] = []
        malformed = 0
        for item in target_row.get("findings", []) or []:
            if not isinstance(item, dict):
                malformed += 1
                continue
            try:
                candidates.append(finding_from_dict(item))
            except (TypeError, ValueError):
                malformed += 1
        confirmed, suppressed = partition_reportable(candidates)
        rejected_here += malformed
        if malformed:
            key = "malformed_evidence"
            reasons[key] = reasons.get(key, 0) + malformed
        for _finding, decision in suppressed:
            rejected_here += 1
            reasons[decision.reason_code] = reasons.get(decision.reason_code, 0) + 1
        serialized = [finding_to_report_dict(finding) for finding in confirmed]
        targets.append({
            "target": sanitize_text(str(target_row.get("target") or "")),
            "verdict": sanitize_text(str(target_row.get("verdict") or "")),
            "wall_clock_seconds": target_row.get("wall_clock_seconds", 0),
            "findings": serialized,
            "confirmed_count": len(serialized),
            "suppressed_count": (
                _safe_int(target_row.get("suppressed_count", 0))
                + len(suppressed)
                + malformed
            ),
        })

    confirmed_count = sum(len(row["findings"]) for row in targets)
    safe["targets_assessed"] = targets
    safe["target_count"] = len(targets) or safe["target_count"]
    safe["finding_count"] = confirmed_count
    safe["verified_count"] = confirmed_count
    safe["confirmed_count"] = confirmed_count
    safe["suppressed_count"] = declared_suppressed + rejected_here
    safe["suppression_reasons"] = reasons
    return safe


def render_stored_report_markdown(report_json: dict[str, Any]) -> str:
    """Render stored JSON after re-gating; never trust stored Markdown."""
    safe = sanitize_report_json(report_json)
    findings = [
        finding_from_dict(item)
        for row in safe.get("targets_assessed", [])
        for item in row.get("findings", [])
    ]
    meta = report_meta(safe)
    target_lines = [
        f"- `{row.get('target', '')}`: {row.get('verdict', '')} "
        f"({row.get('confirmed_count', 0)} confirmed finding(s), "
        f"{row.get('suppressed_count', 0)} suppressed candidate(s))"
        for row in safe.get("targets_assessed", [])
    ]
    # Preserve the aggregate suppression count in the deterministic renderer
    # without exposing candidate titles/details.
    meta["external_suppressed_count"] = safe.get("suppressed_count", 0)
    meta["external_suppression_reasons"] = safe.get("suppression_reasons", {})
    meta["_trusted_aggregate_recon_summary"] = True
    return render_assessment_report(
        meta,
        findings,
        "\n".join(target_lines) or "No targets assessed.",
    )
