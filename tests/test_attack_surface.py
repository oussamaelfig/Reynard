"""Regression tests for the Attack Surface model (core/attack_surface.py)."""
from __future__ import annotations

import sqlite3
import unittest

from hacking_agent.core import attack_surface as asm
from hacking_agent.core.attack_surface import AttackSurface
from hacking_agent.core.durable import DurableStore
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.scope import ScopeGuard


class NormalizationTests(unittest.TestCase):
    def test_normalize_url_strips_query_and_fragment(self):
        self.assertEqual(
            asm.normalize_url("HTTPS://Example.com/Path?a=1#frag"),
            "https://example.com/Path",
        )

    def test_normalize_url_keeps_query_when_requested(self):
        self.assertEqual(
            asm.normalize_url("http://x.com/a?b=2", keep_query=True),
            "http://x.com/a?b=2",
        )

    def test_endpoint_key_is_method_plus_normalized_url(self):
        self.assertEqual(
            asm.endpoint_key("post", "http://x.com/login?next=/a"),
            "POST http://x.com/login",
        )

    def test_query_param_names(self):
        self.assertEqual(
            asm.query_param_names("http://x.com/s?q=1&page=2"), ["q", "page"]
        )


class AssetMergeTests(unittest.TestCase):
    def test_rediscovery_accrues_provenance_and_upgrades_confidence(self):
        s = AttackSurface(target="http://x.com")
        s.add(asm.KIND_SUBDOMAIN, "a.x.com", source="subfinder",
              confidence="suspected")
        a = s.add(asm.KIND_SUBDOMAIN, "a.x.com", source="crtsh",
                  confidence="confirmed")
        self.assertEqual(sorted(a.sources), ["crtsh", "subfinder"])
        self.assertEqual(a.confidence, "confirmed")

    def test_list_attrs_union_on_merge(self):
        s = AttackSurface()
        s.add_endpoint("http://x.com/a", method="GET", source="katana", status_code=200)
        a = s.add_endpoint("http://x.com/a", method="GET", source="httpx", status_code=403)
        self.assertEqual(a.attrs["status_codes"], [200, 403])

    def test_endpoint_auto_derives_query_parameters(self):
        s = AttackSurface()
        s.add_endpoint("http://x.com/search?q=1&cat=books", source="wayback")
        params = s.query(asm.KIND_PARAMETER)
        names = sorted(p.attrs["name"] for p in params)
        self.assertEqual(names, ["cat", "q"])

    def test_empty_identifier_rejected(self):
        s = AttackSurface()
        with self.assertRaises(ValueError):
            s.add(asm.KIND_HOST, "")


class ScopeAnnotationTests(unittest.TestCase):
    def test_scope_status_annotated_readonly(self):
        guard = ScopeGuard(allowed_domains=["x.com"])
        s = AttackSurface(target="http://x.com", scope_evaluator=guard.classify)
        in_scope = s.add_host("api.x.com", source="subfinder")
        out_scope = s.add_host("evil.com", source="subfinder")
        self.assertEqual(in_scope.scope_status, asm.SCOPE_IN)
        self.assertEqual(out_scope.scope_status, asm.SCOPE_OUT)

    def test_attach_evaluator_reannotates_existing(self):
        s = AttackSurface(target="http://x.com")
        s.add_host("api.x.com", source="subfinder")
        self.assertEqual(s.query(asm.KIND_SUBDOMAIN)[0].scope_status, asm.SCOPE_UNKNOWN)
        guard = ScopeGuard(allowed_domains=["x.com"])
        s.attach_scope_evaluator(guard.classify)
        self.assertEqual(s.query(asm.KIND_SUBDOMAIN)[0].scope_status, asm.SCOPE_IN)

    def test_out_of_scope_denylist_wins(self):
        guard = ScopeGuard(allowed_domains=["x.com"], out_of_scope=["secret.x.com"])
        self.assertEqual(guard.classify("secret.x.com"), asm.SCOPE_OUT)
        self.assertEqual(guard.classify("ok.x.com"), asm.SCOPE_IN)


class ObservationsFindingsTests(unittest.TestCase):
    def test_observe_and_find(self):
        s = AttackSurface()
        ep = s.add_endpoint("http://x.com/api/users", source="katana", is_api=True)
        s.observe("reflection", "q reflected unencoded", source="analyzer",
                  asset_keys=[ep.key])
        f = s.record_finding("IDOR on /api/users", "IDOR", severity="high",
                             asset_keys=[ep.key])
        self.assertEqual(len(s.observations()), 1)
        self.assertEqual(len(s.findings()), 1)
        self.assertEqual(f.status, "theoretical")

    def test_finding_inherits_scope_from_asset(self):
        guard = ScopeGuard(allowed_domains=["x.com"])
        s = AttackSurface(target="http://x.com", scope_evaluator=guard.classify)
        ep = s.add_endpoint("http://x.com/a", source="katana")
        f = s.record_finding("t", "XSS", asset_keys=[ep.key])
        self.assertEqual(f.scope_status, asm.SCOPE_IN)


class DeltaHuntingTests(unittest.TestCase):
    def test_diff_detects_new_assets(self):
        prev = AttackSurface(target="http://x.com")
        prev.add_host("a.x.com", source="subfinder")
        cur = AttackSurface(target="http://x.com")
        cur.add_host("a.x.com", source="subfinder")
        cur.add_host("new.x.com", source="subfinder")
        delta = cur.diff(prev)
        new_ids = [a.identifier for a in delta.new_assets]
        self.assertIn("new.x.com", new_ids)
        self.assertNotIn("a.x.com", new_ids)

    def test_prioritized_leads_boosts_new_and_admin(self):
        guard = ScopeGuard(allowed_domains=["x.com"])
        prev = AttackSurface(target="http://x.com", scope_evaluator=guard.classify)
        prev.add_host("www.x.com", source="subfinder")
        cur = AttackSurface(target="http://x.com", scope_evaluator=guard.classify)
        cur.add_host("www.x.com", source="subfinder")
        cur.add_host("admin.x.com", source="subfinder")
        leads = cur.prioritized_leads(previous=prev, limit=5)
        self.assertEqual(leads[0].identifier, "admin.x.com")

    def test_out_of_scope_excluded_from_leads(self):
        guard = ScopeGuard(allowed_domains=["x.com"])
        s = AttackSurface(target="http://x.com", scope_evaluator=guard.classify)
        s.add_host("evil.com", source="subfinder")
        self.assertEqual(s.prioritized_leads(), [])


class SerializationTests(unittest.TestCase):
    def test_roundtrip(self):
        s = AttackSurface(target="http://x.com", scope_key="x.com")
        s.add_endpoint("http://x.com/a?id=1", source="katana", status_code=200)
        s.observe("timing", "slow on /a", source="probe")
        s.record_finding("t", "SQLi", severity="critical")
        d = s.to_dict()
        s2 = AttackSurface.from_dict(d)
        self.assertEqual(s2.stats()["total_assets"], s.stats()["total_assets"])
        self.assertEqual(len(s2.findings()), 1)
        self.assertEqual(len(s2.observations()), 1)

    def test_persistence_roundtrip_via_durable_store(self):
        conn = sqlite3.connect(":memory:")
        store = DurableStore(conn, path=None)  # type: ignore[arg-type]
        s = AttackSurface(target="http://x.com", scope_key="x.com")
        s.add_host("a.x.com", source="subfinder")
        s.add_endpoint("http://x.com/login", method="POST", source="katana")
        self.assertTrue(s.persist(store))
        # A fresh surface for the same scope inherits the prior surface.
        s2 = AttackSurface(target="http://x.com", scope_key="x.com")
        loaded = s2.load(store)
        self.assertGreaterEqual(loaded, 2)
        self.assertIsNotNone(s2.get(asm.KIND_SUBDOMAIN, "a.x.com"))


class MemoryBridgeTests(unittest.TestCase):
    def test_ingest_memory_kg(self):
        mem = AgentMemory(target_url="http://x.com")
        t = mem.add_entity("Target", {"url": "http://x.com"})
        ep = mem.add_entity("Endpoint", {"url": "http://x.com/a", "method": "GET"})
        mem.add_relationship(t.id, "HAS_ENDPOINT", ep.id)
        tech = mem.add_entity("Technology", {"name": "nginx"})
        mem.add_relationship(t.id, "USES_TECHNOLOGY", tech.id)
        s = AttackSurface(target="http://x.com")
        n = s.ingest_memory_kg(mem)
        self.assertGreaterEqual(n, 2)
        self.assertTrue(s.query(asm.KIND_ENDPOINT))
        self.assertTrue(s.query(asm.KIND_TECHNOLOGY))

    def test_project_to_memory(self):
        guard = ScopeGuard(allowed_domains=["x.com"])
        s = AttackSurface(target="http://x.com", scope_evaluator=guard.classify)
        s.add_endpoint("http://x.com/a", source="katana")
        s.add_technology("nginx", source="httpx")
        mem = AgentMemory(target_url="http://x.com")
        n = s.project_to_memory(mem)
        self.assertGreaterEqual(n, 2)
        self.assertTrue(mem.query("Endpoint"))
        self.assertTrue(mem.query("Technology"))


if __name__ == "__main__":
    unittest.main()
