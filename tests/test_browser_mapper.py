"""Tests for the Playwright application mapper -> attack surface (WS4).

The browser itself needs Docker/Chromium, so these tests cover the pure
network->records conversion and the surface ingestion path (hermetic)."""
from __future__ import annotations

import json
import unittest

from hacking_agent.core import attack_surface as asm
from hacking_agent.core import recon_wrappers as rw
from hacking_agent.core.attack_surface import AttackSurface
from hacking_agent.core.scope import ScopeGuard


NETWORK = {
    "requests": [
        {"url": "https://app.x.com/", "method": "GET", "resource_type": "document"},
        {"url": "https://app.x.com/static/main.js", "method": "GET", "resource_type": "script"},
        {"url": "https://app.x.com/api/v1/users?page=1", "method": "GET", "resource_type": "xhr"},
        {"url": "https://app.x.com/graphql", "method": "POST", "resource_type": "fetch"},
    ],
    "responses": [
        {"url": "https://app.x.com/static/main.js", "status": 200,
         "content_type": "application/javascript",
         "sourcemap_header": "https://app.x.com/static/main.js.map"},
        {"url": "https://app.x.com/api/v1/users?page=1", "status": 200,
         "content_type": "application/json"},
    ],
    "websockets": ["wss://app.x.com/socket"],
    "links": ["https://app.x.com/account", "https://evil.com/tracker"],
    "forms": [
        {"action": "https://app.x.com/login", "method": "POST",
         "inputs": ["username", "password", "csrf"]},
    ],
}


class ConversionTests(unittest.TestCase):
    def test_records_cover_all_traffic_kinds(self):
        recs = rw.records_from_browser_network(NETWORK, base_url="https://app.x.com/")
        by_kind = {}
        for r in recs:
            by_kind.setdefault(r.kind, []).append(r.identifier)
        self.assertIn(asm.KIND_JS, by_kind)
        self.assertIn(asm.KIND_WEBSOCKET, by_kind)
        self.assertIn(asm.KIND_ENDPOINT, by_kind)
        self.assertIn(asm.KIND_SOURCEMAP, by_kind)
        self.assertIn(asm.KIND_PARAMETER, by_kind)
        # source map captured from response header
        self.assertIn("https://app.x.com/static/main.js.map", by_kind[asm.KIND_SOURCEMAP])

    def test_api_endpoints_flagged(self):
        recs = rw.records_from_browser_network(NETWORK, base_url="https://app.x.com/")
        api = [r for r in recs if r.kind == asm.KIND_ENDPOINT and r.attrs.get("is_api")]
        api_urls = {r.identifier for r in api}
        self.assertIn("https://app.x.com/api/v1/users?page=1", api_urls)
        self.assertIn("https://app.x.com/graphql", api_urls)

    def test_form_inputs_become_parameters(self):
        recs = rw.records_from_browser_network(NETWORK, base_url="https://app.x.com/")
        params = [r for r in recs if r.kind == asm.KIND_PARAMETER]
        names = {r.attrs.get("name") for r in params}
        self.assertTrue({"username", "password", "csrf"} <= names)

    def test_js_source_map_flagged(self):
        recs = rw.records_from_browser_network(NETWORK, base_url="https://app.x.com/")
        js = next(r for r in recs if r.kind == asm.KIND_JS)
        self.assertTrue(js.attrs.get("has_source_map"))


class IngestTests(unittest.TestCase):
    def test_browser_map_result_ingests_into_surface(self):
        guard = ScopeGuard(allowed_domains=["x.com"])
        surface = AttackSurface(target="https://app.x.com", scope_evaluator=guard.classify)
        res = rw.browser_map_result(NETWORK, base_url="https://app.x.com/")
        self.assertEqual(res.tool, "browser_map")
        n = rw.ingest_recon_result(surface, res)
        self.assertGreater(n, 0)
        # API endpoint present and in scope; websocket present
        self.assertTrue(surface.query(asm.KIND_WEBSOCKET))
        endpoints = surface.query(asm.KIND_ENDPOINT)
        self.assertTrue(any(e.attrs.get("is_api") for e in endpoints))
        # third-party link is annotated out-of-scope (x.com scope)
        evil = next((a for a in surface.assets() if "evil.com" in a.identifier), None)
        if evil is not None:
            self.assertEqual(evil.scope_status, asm.SCOPE_OUT)

    def test_browser_map_is_a_recon_wrapper_tool(self):
        self.assertIn("browser_map", rw.RECON_WRAPPER_TOOLS)

    def test_executor_auto_ingests_browser_map(self):
        from hacking_agent.agents.base import BudgetedToolExecutor
        from hacking_agent.core.memory import AgentMemory
        from hacking_agent.core.state_machine import StateMachine, StateMachineConfig

        guard = ScopeGuard(allowed_domains=["x.com"])
        surface = AttackSurface(target="https://app.x.com", scope_evaluator=guard.classify)
        mem = AgentMemory(target_url="https://app.x.com")
        sm = StateMachine(StateMachineConfig(max_iterations=5))
        ex = BudgetedToolExecutor(mem, sm, scope_guard=guard, surface=surface)
        result_json = rw.browser_map_result(NETWORK, base_url="https://app.x.com/").to_json()
        ex._ingest_recon_surface("browser_map", result_json, "recon")
        self.assertTrue(surface.query(asm.KIND_ENDPOINT))


if __name__ == "__main__":
    unittest.main()
