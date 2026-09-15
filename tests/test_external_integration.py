"""Integration tests: external tools flow through the untrusted boundary.

Covers scope gating at the BudgetedToolExecutor chokepoint, surface ingestion of
external results (observations, never findings), the active-scope-guard handoff,
and that external-origin leads still require Reynard's own validation."""
from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from hacking_agent.agents.base import BudgetedToolExecutor
from hacking_agent.core import attack_surface as asm
from hacking_agent.core.attack_surface import AttackSurface
from hacking_agent.core.evidence import EvidenceStore
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.schemas import ToolDecision
from hacking_agent.core.state_machine import StateMachine, StateMachineConfig


class _FakeClient:
    base_url = "http://fake:8888"

    def is_available(self, force_check=False):
        return True

    def health(self):
        return {"version": "6.0.0",
                "tools_status": {"arjun": True, "dalfox": True, "nuclei": True}}

    def run_tool(self, tool, params):
        return {"success": True, "parameters_found": ["debug", "admin"],
                "endpoints": ["https://x.com/api/secret"], "tool": tool}


def _executor():
    from hacking_agent.core.scope import ScopeGuard
    guard = ScopeGuard(allowed_domains=["x.com"])
    surface = AttackSurface(target="https://x.com/", scope_evaluator=guard.classify)
    memory = AgentMemory(target_url="https://x.com/")
    sm = StateMachine(StateMachineConfig(max_iterations=10))
    ex = BudgetedToolExecutor(memory, sm, scope_guard=guard, surface=surface)
    return ex, surface, memory, guard


def _decision(tool, args):
    return ToolDecision(tool=tool, args=args, reasoning="test",
                        expected_signal="test")


class ScopeGatingTests(unittest.TestCase):
    def test_hexstrike_out_of_scope_target_blocked_by_executor(self):
        ex, *_ = _executor()
        out = ex.call(_decision("hexstrike_run_capability",
                                {"capability": "arjun", "target": "https://evil.com/"}),
                      agent_name="t", phase="exploit", iteration=1)
        self.assertTrue(out["blocked"])
        self.assertIn("SCOPE VIOLATION", out["blocked_reason"])

    def test_browser_use_out_of_scope_url_blocked_by_executor(self):
        ex, *_ = _executor()
        out = ex.call(_decision("browser_use_explore", {"url": "https://evil.com/"}),
                      agent_name="t", phase="recon", iteration=1)
        self.assertTrue(out["blocked"])

    def test_hexstrike_run_extracts_params_urls_for_scope(self):
        from hacking_agent.core.scope import ScopeGuard
        guard = ScopeGuard(allowed_domains=["x.com"])
        # An out-of-scope URL hidden in parameters must also be caught.
        targets = guard._extract_targets(
            "hexstrike_run_capability",
            {"capability": "arjun", "target": "https://x.com/",
             "parameters": {"url": "https://evil.com/x"}})
        self.assertIn("https://evil.com/x", targets)


class IngestionTests(unittest.TestCase):
    def test_hexstrike_result_ingested_as_observations_not_findings(self):
        ex, surface, memory, guard = _executor()
        broker = __import__(
            "hacking_agent.integrations.external.hexstrike",
            fromlist=["HexStrikeCapabilityBroker"]).HexStrikeCapabilityBroker(
                client=_FakeClient())
        with patch.dict(os.environ, {"HEXSTRIKE_ENABLED": "1"}, clear=False), \
             patch("hacking_agent.integrations.external.hexstrike.get_broker",
                   return_value=broker):
            out = ex.call(_decision("hexstrike_run_capability",
                                    {"capability": "arjun",
                                     "target": "https://x.com/search"}),
                          agent_name="exploitation", phase="exploit", iteration=1)
        self.assertFalse(out["blocked"])
        # Observations entered the surface; NO findings were created.
        self.assertTrue(surface.observations())
        self.assertEqual(len(surface.findings()), 0)

    def test_active_scope_guard_published_before_dispatch(self):
        # browser_use_explore is an EXTERNAL_TOOL, so the executor publishes its
        # ScopeGuard to the adapters right before dispatch (even when the provider
        # is unavailable and the call degrades).
        ex, surface, memory, guard = _executor()
        ex.call(_decision("browser_use_explore", {"url": "https://x.com/"}),
                agent_name="t", phase="recon", iteration=1)
        from hacking_agent.integrations.external.base import get_active_scope_guard
        self.assertIs(get_active_scope_guard(), guard)

    def test_browser_use_unavailable_degrades_through_executor(self):
        ex, surface, memory, guard = _executor()
        out = ex.call(_decision("browser_use_explore", {"url": "https://x.com/"}),
                      agent_name="external/browser_use", phase="recon", iteration=1)
        self.assertFalse(out["blocked"])
        data = json.loads(out["result"])
        self.assertFalse(data["available"])          # graceful degradation
        self.assertEqual(len(surface.findings()), 0)  # still no findings


class ValidationRequiredTests(unittest.TestCase):
    def test_external_leads_require_reynard_validation(self):
        # External ingestion never marks a vuln verified; only an evidence-backed
        # PoC does. Simulate: ingest external obs, then check the evidence gate.
        ex, surface, memory, guard = _executor()
        broker = __import__(
            "hacking_agent.integrations.external.hexstrike",
            fromlist=["HexStrikeCapabilityBroker"]).HexStrikeCapabilityBroker(
                client=_FakeClient())
        evidence = EvidenceStore()
        with patch.dict(os.environ, {"HEXSTRIKE_ENABLED": "1"}, clear=False), \
             patch("hacking_agent.integrations.external.hexstrike.get_broker",
                   return_value=broker):
            ex.call(_decision("hexstrike_run_capability",
                              {"capability": "arjun", "target": "https://x.com/x"}),
                    agent_name="exploitation", phase="exploit", iteration=1)
        # A hypothetical vuln id has no verified evidence from the external run.
        self.assertFalse(evidence.is_verified("vuln:external"))
        self.assertEqual(len(surface.findings()), 0)


class _FakeProvider:
    def available(self):
        return True


def _offline_orch(target, mission_mode):
    from hacking_agent.cli.orchestrator import Orchestrator
    env = {"DEEPSEEK_API_KEY": "test-key", "REYNARD_DURABLE_MEMORY": "0",
           "REYNARD_EMBEDDINGS": "lexical", "REYNARD_EXTERNAL_ENABLED": "1"}
    with patch.dict(os.environ, env, clear=False):
        return Orchestrator(target_url=target, objective="test",
                            subagents_enabled=False, max_iterations=8,
                            mission_mode=mission_mode)


class OrchestratorTriggerTests(unittest.TestCase):
    def test_browser_use_triggered_in_production_when_signals_warrant(self):
        orch = _offline_orch("https://app.example.com/", "production")
        try:
            # Signals: SPA (tech) + auth (identity on surface) -> gain 0.7 >= 0.5.
            orch.memory.add_fact("technology_stack", "React")
            orch.surface.add_identity("admin", role_hint="admin",
                                      authenticated=True, source="test")
            orch._external_providers = lambda: (_FakeProvider(), _FakeProvider())
            calls = []
            orch.tool_executor.call = lambda decision, **kw: (
                calls.append(decision.tool) or {"result": "{}", "blocked": False})
            orch._maybe_invoke_external()
            self.assertIn("browser_use_explore", calls)
            self.assertTrue(orch._external_ran.get("browser_use"))
        finally:
            orch.logger.close()

    def test_no_external_trigger_in_benchmark_mode(self):
        orch = _offline_orch("https://0abc.web-security-academy.net/", "benchmark")
        try:
            orch.memory.add_fact("technology_stack", "React")
            orch._external_providers = lambda: (_FakeProvider(), _FakeProvider())
            calls = []
            orch.tool_executor.call = lambda decision, **kw: (
                calls.append(decision.tool) or {"result": "{}", "blocked": False})
            orch._maybe_invoke_external()
            self.assertEqual(calls, [])  # inert in benchmark mode
        finally:
            orch.logger.close()

    def test_hexstrike_hint_injected_for_gap_hypothesis(self):
        orch = _offline_orch("https://app.example.com/", "production")
        try:
            from hacking_agent.core.schemas import Hypothesis
            orch.active_hypothesis = Hypothesis(
                text="test graphql introspection", vuln_type="graphql",
                vector="graphql", phase="injection")
            orch._external_providers = lambda: (_FakeProvider(), _FakeProvider())
            # browser_use already ran so only hexstrike can fire.
            orch._external_ran["browser_use"] = True
            calls = []
            orch.tool_executor.call = lambda decision, **kw: (
                calls.append(decision.tool) or {"result": "{}", "blocked": False})
            orch._maybe_invoke_external()
            # HexStrike is a hint (Reynard chooses the capability), not an auto-run.
            self.assertEqual(calls, [])
            self.assertTrue(orch.memory.get_fact("external_capability_hint"))
        finally:
            orch.logger.close()


class ToolNameTests(unittest.TestCase):
    def test_external_tools_in_toolname_literal(self):
        from typing import get_args
        from hacking_agent.core.schemas import ToolName
        names = set(get_args(ToolName))
        for t in ("browser_use_explore", "hexstrike_search_capability",
                  "hexstrike_run_capability"):
            self.assertIn(t, names)


if __name__ == "__main__":
    unittest.main()
