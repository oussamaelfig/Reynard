"""Tests for structured recon wrappers (core/recon_wrappers.py)."""
from __future__ import annotations

import json
import unittest

from hacking_agent.core import attack_surface as asm
from hacking_agent.core import recon_wrappers as rw
from hacking_agent.core.attack_surface import AttackSurface
from hacking_agent.core.scope import ScopeGuard


class ParserTests(unittest.TestCase):
    def test_parse_subfinder_plain_and_json(self):
        out = "a.x.com\nb.x.com\n" + json.dumps({"host": "c.x.com"})
        recs = rw.parse_subfinder(out)
        ids = sorted(r.identifier for r in recs)
        self.assertEqual(ids, ["a.x.com", "b.x.com", "c.x.com"])
        self.assertTrue(all(r.kind == asm.KIND_SUBDOMAIN for r in recs))

    def test_parse_httpx_extracts_endpoint_tech_ip(self):
        line = json.dumps({
            "url": "https://x.com/", "status_code": 200, "title": "Home",
            "tech": ["nginx", "PHP"], "webserver": "nginx", "a": ["1.2.3.4"],
            "content_type": "text/html",
        })
        recs = rw.parse_httpx(line)
        kinds = [r.kind for r in recs]
        self.assertIn(asm.KIND_ENDPOINT, kinds)
        self.assertIn(asm.KIND_TECHNOLOGY, kinds)
        self.assertIn(asm.KIND_IP, kinds)
        ep = next(r for r in recs if r.kind == asm.KIND_ENDPOINT)
        self.assertEqual(ep.attrs["status_code"], 200)

    def test_parse_naabu(self):
        out = "\n".join(json.dumps(o) for o in [
            {"host": "x.com", "ip": "1.2.3.4", "port": 443},
            {"host": "x.com", "ip": "1.2.3.4", "port": 8080},
        ])
        recs = rw.parse_naabu(out)
        self.assertEqual([r.identifier for r in recs], ["x.com:443", "x.com:8080"])

    def test_parse_katana_new_and_old_and_js(self):
        out = "\n".join([
            json.dumps({"request": {"endpoint": "https://x.com/a", "method": "POST"},
                        "response": {"status_code": 200}}),
            json.dumps({"endpoint": "https://x.com/app.js"}),
        ])
        recs = rw.parse_katana(out)
        kinds = {r.identifier: r.kind for r in recs}
        self.assertEqual(kinds["https://x.com/a"], asm.KIND_ENDPOINT)
        self.assertEqual(kinds["https://x.com/app.js"], asm.KIND_JS)

    def test_parse_waybackurls(self):
        out = "https://x.com/a\nhttps://x.com/main.js\nnot-a-url\n"
        recs = rw.parse_waybackurls(out)
        kinds = {r.identifier: r.kind for r in recs}
        self.assertEqual(kinds["https://x.com/main.js"], asm.KIND_JS)
        self.assertEqual(kinds["https://x.com/a"], asm.KIND_ENDPOINT)
        self.assertNotIn("not-a-url", kinds)

    def test_parse_crtsh(self):
        text = json.dumps([
            {"name_value": "a.x.com\n*.x.com", "common_name": "x.com"},
            {"name_value": "b.x.com"},
        ])
        recs = rw.parse_crtsh(text)
        ids = sorted(r.identifier for r in recs)
        self.assertEqual(ids, ["a.x.com", "b.x.com", "x.com"])

    def test_parse_urlscan(self):
        text = json.dumps({"results": [
            {"page": {"domain": "a.x.com", "url": "https://a.x.com/p"},
             "task": {"url": "https://a.x.com/t"}},
        ]})
        recs = rw.parse_urlscan(text)
        subs = [r.identifier for r in recs if r.kind == asm.KIND_SUBDOMAIN]
        urls = [r.identifier for r in recs if r.kind == asm.KIND_URL]
        self.assertIn("a.x.com", subs)
        self.assertIn("https://a.x.com/p", urls)

    def test_parse_dnsx(self):
        out = json.dumps({"host": "x.com", "a": ["1.2.3.4"], "cname": ["cdn.example.net"]})
        recs = rw.parse_dnsx(out)
        kinds = {r.kind for r in recs}
        self.assertIn(asm.KIND_IP, kinds)
        self.assertIn(asm.KIND_SUBDOMAIN, kinds)


class RunnerDegradationTests(unittest.TestCase):
    def test_missing_tool_is_graceful_noop(self):
        def fake_runner(cmd, timeout):
            return {"stdout": "", "stderr": "", "exit_code": 1}  # command -v fails
        res = rw.run_subfinder("x.com", runner=fake_runner)
        self.assertFalse(res.available)
        self.assertFalse(res.ok)
        self.assertEqual(res.records, [])

    def test_present_tool_parses_output(self):
        def fake_runner(cmd, timeout):
            if cmd.startswith("command -v"):
                return {"stdout": "/usr/bin/subfinder", "exit_code": 0}
            return {"stdout": "a.x.com\nb.x.com\n", "exit_code": 0}
        res = rw.run_subfinder("x.com", runner=fake_runner)
        self.assertTrue(res.available)
        self.assertEqual(len(res.records), 2)

    def test_http_runner_with_injected_fetch(self):
        payload = json.dumps([{"name_value": "a.x.com"}])
        res = rw.run_crtsh("x.com", fetch=lambda url, headers=None: (200, payload))
        self.assertTrue(res.ok)
        self.assertEqual(res.records[0].identifier, "a.x.com")

    def test_http_runner_handles_failure(self):
        res = rw.run_crtsh("x.com", fetch=lambda url, headers=None: (0, ""))
        self.assertFalse(res.ok)


class IngestTests(unittest.TestCase):
    def test_ingest_into_surface_with_provenance_and_scope(self):
        guard = ScopeGuard(allowed_domains=["x.com"])
        surface = AttackSurface(target="http://x.com", scope_evaluator=guard.classify)
        res = rw.ReconResult(tool="subfinder", records=[
            rw.ReconRecord(kind=asm.KIND_SUBDOMAIN, identifier="api.x.com"),
            rw.ReconRecord(kind=asm.KIND_SUBDOMAIN, identifier="evil.com"),
        ])
        n = rw.ingest_recon_result(surface, res)
        self.assertEqual(n, 2)

        def _find(ident):
            return next(a for a in surface.assets() if a.identifier == ident)
        api = _find("api.x.com")
        evil = _find("evil.com")
        self.assertEqual(api.scope_status, asm.SCOPE_IN)
        self.assertEqual(evil.scope_status, asm.SCOPE_OUT)
        self.assertIn("subfinder", api.sources)

    def test_ingest_endpoints_and_tech(self):
        surface = AttackSurface(target="http://x.com")
        line = json.dumps({"url": "https://x.com/a", "status_code": 200,
                           "tech": ["nginx"]})
        res = rw.ReconResult(tool="httpx", records=rw.parse_httpx(line))
        rw.ingest_recon_result(surface, res)
        self.assertTrue(surface.query(asm.KIND_ENDPOINT))
        self.assertTrue(surface.query(asm.KIND_TECHNOLOGY))

    def test_result_to_json_summary(self):
        res = rw.ReconResult(tool="subfinder", records=[
            rw.ReconRecord(kind=asm.KIND_SUBDOMAIN, identifier="a.x.com"),
        ])
        d = json.loads(res.to_json())
        self.assertEqual(d["tool"], "subfinder")
        self.assertEqual(d["count"], 1)

    def test_result_from_json_roundtrip(self):
        original = rw.ReconResult(tool="katana", records=[
            rw.ReconRecord(kind=asm.KIND_ENDPOINT, identifier="https://x.com/a",
                           attrs={"method": "GET"}),
        ])
        restored = rw.result_from_json(original.to_json())
        self.assertIsNotNone(restored)
        self.assertEqual(restored.tool, "katana")
        self.assertEqual(restored.records[0].identifier, "https://x.com/a")


class ExecutorIngestionTests(unittest.TestCase):
    def test_executor_auto_ingests_recon_tool_into_surface(self):
        from hacking_agent.agents.base import BudgetedToolExecutor
        from hacking_agent.core.memory import AgentMemory
        from hacking_agent.core.state_machine import StateMachine, StateMachineConfig

        guard = ScopeGuard(allowed_domains=["x.com"])
        surface = AttackSurface(target="http://x.com", scope_evaluator=guard.classify)
        mem = AgentMemory(target_url="http://x.com")
        sm = StateMachine(StateMachineConfig(max_iterations=5))
        ex = BudgetedToolExecutor(mem, sm, scope_guard=guard, surface=surface)

        result_json = rw.ReconResult(tool="subfinder_scan", records=[
            rw.ReconRecord(kind=asm.KIND_SUBDOMAIN, identifier="api.x.com"),
        ]).to_json()
        ex._ingest_recon_surface("subfinder_scan", result_json, "recon")
        self.assertTrue(any(a.identifier == "api.x.com" for a in surface.assets()))

    def test_executor_without_surface_is_noop(self):
        from hacking_agent.agents.base import BudgetedToolExecutor
        from hacking_agent.core.memory import AgentMemory
        from hacking_agent.core.state_machine import StateMachine, StateMachineConfig

        mem = AgentMemory(target_url="http://x.com")
        sm = StateMachine(StateMachineConfig(max_iterations=5))
        ex = BudgetedToolExecutor(mem, sm, scope_guard=None, surface=None)
        # Should not raise when no surface is attached.
        ex._ingest_recon_surface("subfinder_scan", "{}", "recon")


if __name__ == "__main__":
    unittest.main()
