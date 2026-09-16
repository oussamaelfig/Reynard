"""Regression tests (engagement) - split from test_core_regressions.py."""
from __future__ import annotations

from regression_common import *  # noqa: F401,F403


class EngagementLoadTests(unittest.TestCase):
    def test_engagement_from_dict_parses_scope_and_roe(self):
        eng = engagement_from_dict({
            "engagement_name": "Acme",
            "client": "Acme Corp",
            "tester": "Reynard",
            "authorized_domains": ["example.com", "staging.example.net"],
            "authorized_cidrs": ["10.0.0.0/24"],
            "out_of_scope": ["payments.example.com"],
            "max_requests_per_second": 5,
            "max_total_requests": 1000,
            "allow_destructive": False,
            "testing_window": {"start": "2026-01-01", "end": "2026-12-31"},
        })
        self.assertEqual(eng.engagement_name, "Acme")
        self.assertIn("example.com", eng.authorized_domains)
        self.assertEqual(eng.out_of_scope, ["payments.example.com"])
        self.assertEqual(eng.max_requests_per_second, 5.0)
        self.assertEqual(eng.max_total_requests, 1000)
        self.assertFalse(eng.allow_destructive)
        self.assertTrue(eng.has_authorized_scope())

    def test_engagement_aliases_and_string_lists(self):
        eng = engagement_from_dict({
            "name": "Alias",
            "domains": "a.com, b.com",
            "deny": ["x.a.com"],
            "rate_limit_rps": 2,
        })
        self.assertEqual(eng.engagement_name, "Alias")
        self.assertEqual(eng.authorized_domains, ["a.com", "b.com"])
        self.assertEqual(eng.out_of_scope, ["x.a.com"])
        self.assertEqual(eng.max_requests_per_second, 2.0)

    def test_empty_scope_is_not_authorized(self):
        self.assertFalse(Engagement().has_authorized_scope())

    def test_testing_window_bounds(self):
        from datetime import datetime
        eng = Engagement(
            authorized_domains=["a.com"],
            testing_window_start="2026-01-01T00:00:00",
            testing_window_end="2026-12-31T23:59:59",
        )
        self.assertTrue(eng.is_within_window(datetime(2026, 6, 1)))
        self.assertFalse(eng.is_within_window(datetime(2025, 6, 1)))
        self.assertFalse(eng.is_within_window(datetime(2027, 6, 1)))
        # no window => always within
        self.assertTrue(Engagement(authorized_domains=["a.com"]).is_within_window())

    def test_load_engagement_sample_yaml(self):
        from hacking_agent.core.paths import PROJECT_ROOT
        path = PROJECT_ROOT / "eval" / "engagement.sample.yaml"
        eng = load_engagement(str(path))
        self.assertTrue(eng.has_authorized_scope())
        self.assertIn("example.com", eng.authorized_domains)
        self.assertIn("payments.example.com", eng.out_of_scope)
        self.assertFalse(eng.allow_destructive)


class EngagementScopeGuardTests(unittest.TestCase):
    def _engagement(self, **overrides):
        base = dict(
            engagement_name="E1",
            authorized_domains=["example.com"],
            authorized_cidrs=["10.0.0.0/24"],
            out_of_scope=["payments.example.com"],
            allow_destructive=False,
        )
        base.update(overrides)
        return Engagement(**base)

    def test_default_lab_guard_unchanged_no_destructive_block(self):
        # Without an engagement attached, destructive shell + rate limits are
        # inert, preserving lab behaviour.
        guard = ScopeGuard.from_target_url("https://lab.example.com")
        guard.validate("run_shell", {"command": "rm -rf /tmp/loot"})
        self.assertFalse(guard.block_destructive)
        self.assertEqual(guard.max_total_requests, 0)

    def test_in_scope_allowed_out_of_scope_denied(self):
        guard = ScopeGuard.from_engagement(self._engagement())
        guard.validate("http_request", {"url": "https://app.example.com/x"})
        with self.assertRaises(ScopeViolation):
            guard.validate("http_request", {"url": "https://payments.example.com/"})

    def test_out_of_scope_overrides_authorized_domain(self):
        # payments.example.com is a subdomain of the authorized example.com but
        # is on the denylist, so it must still be blocked.
        guard = ScopeGuard.from_engagement(self._engagement())
        self.assertFalse(guard.is_in_scope("https://payments.example.com/"))
        self.assertTrue(guard.is_in_scope("https://api.example.com/"))

    def test_unauthorized_domain_denied(self):
        guard = ScopeGuard.from_engagement(self._engagement())
        with self.assertRaises(ScopeViolation):
            guard.validate("http_request", {"url": "https://evil.net/"})

    def test_max_total_requests_hard_cap(self):
        guard = ScopeGuard.from_engagement(
            self._engagement(max_total_requests=2)
        )
        guard.validate("http_request", {"url": "https://example.com/1"})
        guard.validate("http_request", {"url": "https://example.com/2"})
        with self.assertRaises(RateLimitExceeded):
            guard.validate("http_request", {"url": "https://example.com/3"})
        self.assertEqual(guard.requests_made(), 2)

    def test_scope_probe_does_not_consume_request_budget(self):
        guard = ScopeGuard.from_engagement(
            self._engagement(max_total_requests=2)
        )
        for _ in range(10):
            guard.is_in_scope("https://example.com/probe")
        self.assertEqual(guard.requests_made(), 0)

    def test_rate_limit_min_interval_sleeps(self):
        guard = ScopeGuard.from_engagement(
            self._engagement(max_requests_per_second=10)
        )
        clock = [0.0]
        slept: list[float] = []
        guard._now = lambda: clock[0]
        guard._sleep = lambda s: (slept.append(s), clock.__setitem__(0, clock[0] + s))
        for i in range(4):
            guard.validate("http_request", {"url": f"https://example.com/{i}"})
        self.assertEqual(len(slept), 3)
        for wait in slept:
            self.assertAlmostEqual(wait, 0.1, places=6)

    def test_destructive_block_toggle(self):
        blocked = ScopeGuard.from_engagement(
            self._engagement(allow_destructive=False)
        )
        for cmd in ("rm -rf /", "DROP TABLE users", "shutdown -h now"):
            with self.assertRaises(ScopeViolation):
                blocked.validate("run_shell", {"command": cmd})
        # SQL destructive in an http body is also caught.
        with self.assertRaises(ScopeViolation):
            blocked.validate("http_request", {
                "url": "https://example.com/q",
                "data": "q=1; DROP TABLE accounts",
            })
        # Toggle on: destructive allowed.
        allowed = ScopeGuard.from_engagement(
            self._engagement(allow_destructive=True)
        )
        allowed.validate("run_shell", {"command": "rm -rf /var/www/old"})

    def test_delete_carlos_lab_pattern_allowed_even_when_blocking(self):
        # The classic "delete carlos" lab win condition must not be treated as
        # a destructive action against a real client asset.
        guard = ScopeGuard.from_engagement(
            self._engagement(allow_destructive=False)
        )
        guard.validate("http_request", {
            "url": "https://example.com/admin/delete",
            "data": "username=carlos",
        })


class CvssHelperTests(unittest.TestCase):
    def test_known_vectors(self):
        from hacking_agent.agents.reporter import cvss_v31_base_score
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N": 0.0,
        }
        for vector, expected in cases.items():
            self.assertEqual(cvss_v31_base_score(vector), expected, vector)

    def test_invalid_vector_scores_zero(self):
        from hacking_agent.agents.reporter import cvss_v31_base_score
        self.assertEqual(cvss_v31_base_score("N/A"), 0.0)
        self.assertEqual(cvss_v31_base_score("garbage"), 0.0)

    def test_severity_from_score_and_severity_vectors(self):
        from hacking_agent.agents.reporter import (
            cvss_for_severity,
            severity_from_score,
        )
        self.assertEqual(severity_from_score(0.0), "info")
        self.assertEqual(severity_from_score(3.9), "low")
        self.assertEqual(severity_from_score(5.0), "medium")
        self.assertEqual(severity_from_score(7.5), "high")
        self.assertEqual(severity_from_score(9.9), "critical")
        vector, score = cvss_for_severity("critical")
        self.assertEqual(score, 9.8)
        self.assertEqual(severity_from_score(score), "critical")

    def test_cwe_mapping(self):
        from hacking_agent.agents.reporter import cwe_for
        self.assertEqual(cwe_for("Reflected XSS via search"), "CWE-79")
        self.assertEqual(cwe_for("SQL injection in login"), "CWE-89")
        self.assertEqual(cwe_for("SSRF"), "CWE-918")
        self.assertEqual(cwe_for("Insecure deserialization"), "CWE-502")
        self.assertEqual(cwe_for("something novel"), "CWE-Other")


class AssessmentReportTests(unittest.TestCase):
    def _memory_with_finding(self, verified=True):
        mem = AgentMemory(target_url="https://example.com")
        ev = EvidenceStore()
        vuln = mem.add_entity("Vulnerability", {
            "vuln_type": "Reflected XSS",
            "severity": "high",
            "parameter": "search",
            "endpoint": "https://example.com/search",
            "hypothesis": "search reflects unencoded input into HTML",
        })
        if verified:
            ev.record(PoC(
                vuln_id=vuln.id,
                payload="<script>alert(1)</script>",
                request_summary="GET /search?q=<script>alert(1)</script>",
                response_excerpt="<h1><script>alert(1)</script></h1>",
                verdict="success",
                agent_name="exploitation",
            ))
        return mem, ev

    def test_exploitation_success_alone_does_not_pass_report_gate(self):
        from hacking_agent.agents.reporter import extract_findings
        mem, ev = self._memory_with_finding(verified=True)
        findings = extract_findings(mem, ev)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertFalse(f.verified)
        self.assertEqual(
            f.suppression_reason_code, "legacy_or_missing_status"
        )
        self.assertEqual(f.cwe, "CWE-79")
        self.assertGreater(f.cvss_score, 0.0)
        self.assertEqual(f.parameter, "search")

    def test_unverified_finding_not_gated_as_verified(self):
        from hacking_agent.agents.reporter import extract_findings
        mem, ev = self._memory_with_finding(verified=False)
        findings = extract_findings(mem, ev)
        self.assertEqual(len(findings), 1)
        self.assertFalse(findings[0].verified)

    def test_report_suppresses_unvalidated_candidate_details(self):
        from hacking_agent.agents.reporter import (
            extract_findings,
            render_assessment_report,
        )
        mem, ev = self._memory_with_finding(verified=True)
        findings = extract_findings(mem, ev)
        meta = {
            "engagement_name": "Acme",
            "client": "Acme Corp",
            "tester": "Reynard",
            "targets": ["https://example.com"],
            "authorized_domains": ["example.com"],
            "out_of_scope": ["payments.example.com"],
        }
        md = render_assessment_report(meta, findings, "recon notes")
        for section in (
            "Executive Summary", "Scope", "Methodology",
            "Confirmed Vulnerabilities", "Validation Gate Summary", "Acme Corp",
        ):
            self.assertIn(section, md, section)
        self.assertNotIn("search reflects unencoded input", md)
        self.assertIn("No independently validated vulnerabilities", md)


class AssessCliTests(unittest.TestCase):
    def test_refuses_empty_scope(self):
        from hacking_agent.cli import assess
        with self.assertRaises(EngagementError):
            assess.authorized_targets(Engagement())

    def test_derives_https_targets_from_domains(self):
        from hacking_agent.cli import assess
        eng = Engagement(authorized_domains=["example.com", "b.example.net"])
        self.assertEqual(
            assess.authorized_targets(eng),
            ["https://example.com/", "https://b.example.net/"],
        )

    def test_explicit_target_out_of_scope_skipped(self):
        from hacking_agent.cli import assess
        eng = Engagement(
            authorized_domains=["example.com"],
            out_of_scope=["payments.example.com"],
        )
        targets = assess.authorized_targets(
            eng,
            explicit=["https://app.example.com/", "https://payments.example.com/"],
        )
        self.assertEqual(targets, ["https://app.example.com/"])

    def test_build_consolidated_report_offline(self):
        from hacking_agent.cli import assess
        from hacking_agent.agents.reporter import Finding
        eng = Engagement(
            engagement_name="Acme",
            authorized_domains=["example.com"],
        )
        finding = Finding(
            title="Reflected XSS",
            vuln_type="Reflected XSS",
            severity="high",
            endpoint="https://example.com/search",
            verified=True,
        )
        finding.ensure_scored()
        rows = [{
            "target": "https://example.com/",
            "verdict": "assessed",
            "wall_clock_seconds": 1.0,
            "findings": [finding],
        }]
        md, js = assess.build_consolidated_report(
            eng, ["https://example.com/"], rows
        )
        self.assertIn("Executive Summary", md)
        # A caller cannot bypass the policy by assigning verified=True.
        self.assertEqual(js["finding_count"], 0)
        self.assertEqual(js["verified_count"], 0)
        self.assertEqual(js["suppressed_count"], 1)
        self.assertNotIn("Reflected XSS", md)


if __name__ == "__main__":
    unittest.main()
