"""Bug-bounty submission generator (copy-paste report per finding)."""
from __future__ import annotations

from hacking_agent.harness.submission import (
    build_submission_markdown,
    finding_from_dict,
    iter_report_findings,
    report_meta,
)

RICH = {
    "title": "SQL injection via `id`",
    "vuln_type": "sql injection",
    "severity": "high",
    "endpoint": "https://app.example.com/api/users",
    "parameter": "id",
    "description": "The id parameter is concatenated into a SQL query.",
    "impact": "An attacker can read arbitrary rows from the database.",
    "remediation": "Use parameterized queries.",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cvss_score": 7.5,
    "verified": True,
    "target": "https://app.example.com/",
    "evidence": [{"verdict": "success", "payload": "id=1' OR '1'='1",
                  "request": "GET /api/users?id=1'%20OR%20'1'='1",
                  "response": "HTTP/1.1 200 OK\n{\"users\":[...]}"}],
}

REQUIRED_SECTIONS = [
    "## Summary", "## Steps to Reproduce", "## Proof of Concept",
    "## Impact", "## Remediation",
]


def test_submission_has_all_bugbounty_sections():
    md = build_submission_markdown(RICH, {"engagement_name": "Acme BBP"})
    assert md.startswith("# SQL injection via `id`")
    for sec in REQUIRED_SECTIONS:
        assert sec in md, f"missing section {sec}"
    assert "**Severity:** High" in md
    assert "CVSS v3.1:** 7.5" in md
    assert "CWE-89" in md                      # mapped weakness
    assert "cwe.mitre.org" in md               # reference link
    assert "Program:** Acme BBP" in md
    assert "app.example.com/api/users" in md
    assert "OR '1'='1" in md                   # PoC payload included
    assert "```http" in md                     # request/response fences


def test_submission_sparse_finding_fills_defaults():
    md = build_submission_markdown({"title": "Reflected XSS", "severity": "medium",
                                    "vuln_type": "xss"})
    for sec in REQUIRED_SECTIONS:
        assert sec in md
    assert "CWE-79" in md                       # inferred CWE
    assert "CVSS v3.1:**" in md                 # scored from severity
    # No evidence -> explicit PoC placeholder, not a crash.
    assert "No proof-of-concept" in md


def test_finding_from_dict_scores_when_missing():
    f = finding_from_dict({"title": "SSRF", "vuln_type": "ssrf", "severity": "high"})
    assert f.cwe == "CWE-918"
    assert f.cvss_score > 0


def test_iter_report_findings_annotates_target():
    rj = {"targets_assessed": [
        {"target": "https://a/", "findings": [{"title": "A"}]},
        {"target": "https://b/", "findings": [{"title": "B"}, {"title": "C"}]},
    ]}
    items = iter_report_findings(rj)
    assert [i["title"] for i in items] == ["A", "B", "C"]
    assert items[0]["target"] == "https://a/" and items[2]["target"] == "https://b/"


def test_report_meta_extracts_header():
    meta = report_meta({"engagement_name": "X", "targets": ["t"], "junk": 1})
    assert meta["engagement_name"] == "X" and meta["targets"] == ["t"]
    assert "junk" not in meta
