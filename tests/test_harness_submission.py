"""Bug-bounty submission generator (copy-paste report per finding)."""
from __future__ import annotations

import pytest

from hacking_agent.agents.reporter import finding_to_report_dict
from hacking_agent.harness.submission import (
    UnreportableFindingError,
    build_submission_markdown,
    finding_from_dict,
    iter_report_findings,
    report_meta,
)
from test_finding_validation import finding_for, valid_bundle

RICH = finding_to_report_dict(
    finding_for(valid_bundle(), title="SQL injection via `id`")
)
RICH["target"] = "https://app.example.test/"

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
    assert "app.example.test/items" in md
    assert "OR%201=1" in md                    # validated request included
    assert "```http" in md                     # request/response fences


def test_submission_sparse_finding_fills_defaults():
    with pytest.raises(UnreportableFindingError):
        build_submission_markdown({
            "title": "Reflected XSS",
            "severity": "medium",
            "vuln_type": "xss",
            "verified": True,
        })


def test_finding_from_dict_scores_when_missing():
    f = finding_from_dict({"title": "SSRF", "vuln_type": "ssrf", "severity": "high"})
    assert f.cwe == "CWE-918"
    assert f.cvss_score > 0


def test_iter_report_findings_annotates_target():
    rj = {"targets_assessed": [
        {"target": "https://a/", "findings": [RICH]},
        {"target": "https://b/", "findings": [{"title": "suppressed"}]},
    ]}
    items = iter_report_findings(rj)
    assert [i["title"] for i in items] == ["SQL injection via `id`"]
    assert items[0]["target"] == "https://a/"


def test_report_meta_extracts_header():
    meta = report_meta({"engagement_name": "X", "targets": ["t"], "junk": 1})
    assert meta["engagement_name"] == "X" and meta["targets"] == ["t"]
    assert "junk" not in meta
