"""Tests for EvidenceBundle (core/evidence_bundle.py)."""
from __future__ import annotations

import sqlite3
import unittest

from hacking_agent.core import evidence_bundle as eb
from hacking_agent.core.evidence_bundle import (
    ControlTest, EvidenceBundle, EvidenceBundleStore, SanitizedExchange,
    build_bundle_from_pocs, sanitize_text,
)
from hacking_agent.core.durable import DurableStore
from hacking_agent.core.schemas import PoC


class SanitizationTests(unittest.TestCase):
    def test_redacts_sensitive_headers(self):
        raw = "GET / HTTP/1.1\nHost: x.com\nCookie: session=abc123\nAuthorization: Bearer tok"
        out = sanitize_text(raw)
        self.assertNotIn("abc123", out)
        self.assertNotIn("Bearer tok", out)
        self.assertIn("Host: x.com", out)
        self.assertIn(eb.REDACTED, out)

    def test_redacts_kv_and_json_secrets(self):
        self.assertIn(eb.REDACTED, sanitize_text("user=bob&password=hunter2"))
        self.assertNotIn("hunter2", sanitize_text("user=bob&password=hunter2"))
        self.assertNotIn("s3cr3t", sanitize_text('{"api_key": "s3cr3t"}'))

    def test_redacts_explicit_secret_values(self):
        out = sanitize_text("token appears here: LIVECOOKIEVALUE123",
                            extra_secrets=("LIVECOOKIEVALUE123",))
        self.assertNotIn("LIVECOOKIEVALUE123", out)


class BundleTests(unittest.TestCase):
    def test_build_and_render(self):
        b = EvidenceBundle(id="bundle:1", title="IDOR", vuln_type="IDOR",
                           severity="high", endpoint="GET /api/users/2",
                           identity="userA")
        b.add_test(SanitizedExchange.build(
            label="test", identity="userA",
            request="GET /api/users/2\nCookie: session=abc",
            response="200 OK {\"ssn\": \"...\"}", status_code=200))
        b.add_control(ControlTest(description="userB cannot access userA record",
                                  result="403 Forbidden"))
        b.set_verification(eb.V_VERIFIED, verified_by="validator",
                           causal_signal="userA reads userB record cross-identity")
        md = b.render_markdown()
        self.assertIn("IDOR", md)
        self.assertIn("Control", md)
        self.assertNotIn("session=abc", md)  # sanitized
        self.assertTrue(b.is_verified)
        self.assertTrue(b.has_concrete_evidence())

    def test_roundtrip(self):
        b = EvidenceBundle(id="bundle:1", vuln_type="SQLi", severity="critical")
        b.add_test(SanitizedExchange.build(request="GET /a?id=1'"))
        b.add_oob("DNS interaction from 1.2.3.4")
        d = b.to_dict()
        b2 = EvidenceBundle.from_dict(d)
        self.assertEqual(b2.vuln_type, "SQLi")
        self.assertEqual(len(b2.test_exchanges), 1)
        self.assertEqual(b2.oob_interactions, ["DNS interaction from 1.2.3.4"])

    def test_needs_concrete_evidence(self):
        b = EvidenceBundle(id="bundle:1", vuln_type="XSS")
        self.assertFalse(b.has_concrete_evidence())
        b.add_screenshot("/tmp/proof.png")
        self.assertTrue(b.has_concrete_evidence())


class StoreTests(unittest.TestCase):
    def test_create_get_by_vuln(self):
        store = EvidenceBundleStore()
        b = store.create(vuln_id="vuln:1", vuln_type="SSRF", severity="high")
        self.assertEqual(store.get(b.id).vuln_type, "SSRF")
        self.assertEqual(len(store.by_vuln("vuln:1")), 1)

    def test_persistence_roundtrip(self):
        conn = sqlite3.connect(":memory:")
        store = DurableStore(conn, path=None)  # type: ignore[arg-type]
        bundles = EvidenceBundleStore()
        b = bundles.create(vuln_id="vuln:1", vuln_type="XXE")
        b.set_verification(eb.V_VERIFIED)
        self.assertTrue(bundles.persist(store, "x.com", "x.com"))
        loaded = EvidenceBundleStore()
        self.assertEqual(loaded.load(store, "x.com", "x.com"), 1)
        self.assertEqual(len(loaded.verified()), 1)


class BuildFromPocsTests(unittest.TestCase):
    def test_success_and_control_from_pocs(self):
        pocs = [
            PoC(payload="' OR 1=1-- ", request_summary="GET /a?id=1' OR 1=1-- ",
                response_excerpt="all rows returned", verdict="success",
                agent_name="exploitation", vuln_id="vuln:1"),
            PoC(payload="' OR 1=2-- ",
                request_summary="COUNTER: GET /a?id=1' OR 1=2-- ",
                response_excerpt="no rows", verdict="failure",
                agent_name="validator", vuln_id="vuln:1"),
        ]
        bundle = build_bundle_from_pocs(
            "vuln:1", pocs, verification_status=eb.V_VERIFIED, vuln_type="SQLi",
            endpoint="GET /a", identity="anonymous")
        self.assertEqual(len(bundle.test_exchanges), 1)
        self.assertEqual(len(bundle.control_tests), 1)
        self.assertTrue(bundle.reproduction_steps)
        self.assertTrue(bundle.is_verified)

    def test_sanitizes_live_cookie_in_pocs(self):
        pocs = [PoC(payload="x", request_summary="GET /a\nCookie: session=LIVEVAL999",
                    response_excerpt="ok", verdict="success",
                    agent_name="exploitation", vuln_id="vuln:1")]
        bundle = build_bundle_from_pocs("vuln:1", pocs,
                                        extra_secrets=("LIVEVAL999",))
        self.assertNotIn("LIVEVAL999", bundle.test_exchanges[0].request)


class OrchestratorEvidenceTests(unittest.TestCase):
    def _orch(self):
        import os
        from unittest.mock import patch
        from hacking_agent.cli.orchestrator import Orchestrator
        env = {"DEEPSEEK_API_KEY": "test-key", "REYNARD_DURABLE_MEMORY": "0",
               "REYNARD_EMBEDDINGS": "lexical"}
        with patch.dict(os.environ, env, clear=False):
            return Orchestrator(target_url="https://app.example.com/",
                                objective="test", subagents_enabled=False,
                                max_iterations=5, mission_mode="production")

    def test_assemble_bundles_from_pocs_records_surface_finding(self):
        orch = self._orch()
        try:
            vuln = orch.memory.add_entity("Vulnerability", {
                "vuln_type": "SQLi", "severity": "high", "parameter": "id",
                "status": "theoretical"})
            orch.evidence.record(PoC(
                vuln_id=vuln.id, payload="' OR 1=1-- ",
                request_summary="GET /a?id=1' OR 1=1-- ",
                response_excerpt="all rows returned", verdict="success",
                agent_name="exploitation"))
            orch._assemble_evidence_bundles()
            bundles = orch.bundles.by_vuln(vuln.id)
            self.assertEqual(len(bundles), 1)
            self.assertTrue(bundles[0].is_verified)
            # A finding is recorded on the attack surface, evidence-linked.
            findings = orch.surface.findings()
            self.assertTrue(any(f.evidence_bundle_id == bundles[0].id
                                and f.status == "verified" for f in findings))
        finally:
            orch.logger.close()


if __name__ == "__main__":
    unittest.main()
