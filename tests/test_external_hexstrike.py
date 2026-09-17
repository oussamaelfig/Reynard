"""Tests for the HexStrike capability broker (broker discipline + scope + degradation)."""
from __future__ import annotations

import unittest
from unittest.mock import Mock

import pytest

from hacking_agent.core.scope import ScopeGuard
from hacking_agent.integrations.external import hexstrike as hx


@pytest.fixture(autouse=True)
def explicit_hexstrike_environment(monkeypatch):
    # Availability is checked on every broker operation, not just construction.
    monkeypatch.setenv("HEXSTRIKE_ENABLED", "1")


class _FakeClient:
    base_url = "http://fake:8888"

    def __init__(self, tools_status=None, run_result=None):
        self._ts = tools_status or {
            "arjun": True, "x8": True, "paramspider": False, "dalfox": True,
            "sqlmap": True, "nuclei": True, "wpscan": True, "prowler": True,
            "graphql-cop": True,
        }
        self._run_result = run_result or {"success": True,
                                          "parameters_found": ["debug", "admin"]}

    def is_available(self, force_check=False):
        return True

    def health(self):
        return {"version": "6.0.0", "tools_status": self._ts}

    def run_tool(self, tool, params):
        return dict(self._run_result, tool=tool, params=params)


def _broker(**kw):
    return hx.HexStrikeCapabilityBroker(client=_FakeClient(**kw))


class DegradationTests(unittest.TestCase):
    def test_server_down_is_graceful(self):
        client = Mock(spec=hx.HexStrikeClient)
        client.base_url = "http://unavailable.fixture.invalid"
        client.is_available.return_value = False
        b = hx.HexStrikeCapabilityBroker(client=client)
        self.assertFalse(b.available())
        self.assertEqual(b.search_capability("xss"), [])
        cap = b.execute_capability("dalfox", "https://x.com/")
        self.assertFalse(cap.available)
        self.assertTrue(cap.errors)
        client.health.assert_not_called()
        client.run_tool.assert_not_called()


class BrokerDisciplineTests(unittest.TestCase):
    def test_search_returns_small_subset(self):
        b = _broker()
        res = b.search_capability("hidden parameter discovery", limit=5)
        self.assertLessEqual(len(res), 5)
        self.assertTrue(res)  # arjun/x8 available

    def test_search_is_gap_first_and_flags_native(self):
        b = _broker()
        res = b.search_capability("sql injection")
        # sqlmap is native -> flagged native_equivalent with a prefer-native note.
        sqlmap = next((r for r in res if r["capability"] == "sqlmap"), None)
        self.assertIsNotNone(sqlmap)
        self.assertTrue(sqlmap["native_equivalent"])
        self.assertIn("native", sqlmap["note"].lower())

    def test_search_excludes_unavailable_tools(self):
        b = _broker()
        res = b.search_capability("parameter")
        names = [r["capability"] for r in res]
        self.assertNotIn("paramspider", names)  # marked unavailable in fake status

    def test_full_catalogue_never_returned_by_search(self):
        # search is bounded; list_capabilities (diagnostics) is not exposed as a tool.
        b = _broker()
        self.assertLessEqual(len(b.search_capability("xss", limit=5)), 5)


class ScopeAndExecutionTests(unittest.TestCase):
    def test_execute_blocks_out_of_scope_target(self):
        b = _broker()
        guard = ScopeGuard(allowed_domains=["x.com"])
        cap = b.execute_capability("arjun", "https://evil.com/", scope_guard=guard)
        self.assertTrue(any("out of scope" in e for e in cap.errors))

    def test_execute_in_scope_returns_observations_no_findings(self):
        b = _broker()
        guard = ScopeGuard(allowed_domains=["x.com"])
        cap = b.execute_capability("arjun", "https://x.com/search", scope_guard=guard)
        self.assertTrue(cap.structured_observations)
        self.assertNotIn("findings", cap.to_dict())
        self.assertTrue(cap.raw_result_reference)  # raw spilled to file, not inlined

    def test_execute_unknown_capability_rejected(self):
        b = _broker()
        cap = b.execute_capability("definitely-not-a-tool", "https://x.com/")
        self.assertTrue(any("unknown/unavailable" in e for e in cap.errors))


class ToolSurfaceTests(unittest.TestCase):
    def test_only_three_external_tools_reach_the_model(self):
        from hacking_agent.core.tools import TOOL_SCHEMAS
        names = {t["function"]["name"] for t in TOOL_SCHEMAS}
        external = {n for n in names if n.startswith("hexstrike_") or n == "browser_use_explore"}
        self.assertEqual(external,
                         {"browser_use_explore", "hexstrike_search_capability",
                          "hexstrike_run_capability"})


if __name__ == "__main__":
    unittest.main()
