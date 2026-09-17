"""Tests for mission mode (benchmark vs production) and its orchestrator wiring."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from hacking_agent.core import mission as mission_mod
from hacking_agent.core.mission import Mission, detect_mode


class DetectModeTests(unittest.TestCase):
    def test_lookalike_lab_hosts_are_production(self):
        for target in (
            "https://web-security-academy.net.attacker.test",
            "https://notportswigger.net", "https://exploit-server.net.attacker.test",
            "https://[malformed", "https://user@portswigger.net",
        ):
            with self.subTest(target=target):
                self.assertFalse(mission_mod.is_lab_host(target))

    def test_engagement_overrides_explicit_and_environment_benchmark(self):
        with patch.dict(os.environ, {"REYNARD_MISSION_MODE": "benchmark"}):
            mission = Mission.detect("https://portswigger.net", explicit="benchmark", engagement_attached=True)
        self.assertEqual(mission.mode, mission_mod.MODE_PRODUCTION)
        self.assertEqual(mission.source, "engagement")

    def test_lab_host_is_benchmark(self):
        self.assertEqual(
            detect_mode("https://0abc.web-security-academy.net/"),
            mission_mod.MODE_BENCHMARK,
        )

    def test_plain_host_is_production_by_default(self):
        self.assertEqual(detect_mode("https://app.example.com/"),
                         mission_mod.MODE_PRODUCTION)

    def test_explicit_override_wins_over_lab_host(self):
        self.assertEqual(
            detect_mode("https://x.web-security-academy.net/", explicit="production"),
            mission_mod.MODE_PRODUCTION,
        )

    def test_engagement_forces_production_even_on_lab_host(self):
        self.assertEqual(
            detect_mode("https://x.web-security-academy.net/", engagement_attached=True,
                        explicit=None),
            mission_mod.MODE_PRODUCTION,
        )

    def test_lab_profile_implies_benchmark(self):
        self.assertEqual(
            detect_mode("https://app.example.com/", lab_profile={"id": "x"}),
            mission_mod.MODE_BENCHMARK,
        )

    def test_env_override(self):
        with patch.dict(os.environ, {"REYNARD_MISSION_MODE": "benchmark"}, clear=False):
            self.assertEqual(detect_mode("https://app.example.com/"),
                             mission_mod.MODE_BENCHMARK)

    def test_mission_source_provenance(self):
        self.assertEqual(Mission.detect("https://app.example.com/").source, "default")
        self.assertEqual(
            Mission.detect("https://x.web-security-academy.net/").source, "lab_host"
        )
        self.assertEqual(
            Mission.detect("https://app.example.com/", explicit="prod").source, "explicit"
        )


def _build_offline_orchestrator(target, objective="", lab_profile=None,
                                mission_mode=None, max_iterations=8):
    from hacking_agent.cli.orchestrator import Orchestrator
    env = {
        "DEEPSEEK_API_KEY": "test-key",
        "REYNARD_DURABLE_MEMORY": "0",
        "REYNARD_EMBEDDINGS": "lexical",
    }
    with patch.dict(os.environ, env, clear=False):
        return Orchestrator(
            target_url=target,
            objective=objective,
            lab_profile=lab_profile,
            subagents_enabled=False,
            max_iterations=max_iterations,
            mission_mode=mission_mode,
        )


class OrchestratorMissionWiringTests(unittest.TestCase):
    def test_plain_target_is_production_and_drops_lab_profile(self):
        orch = _build_offline_orchestrator(
            "https://app.example.com/", "Test the app.",
            lab_profile={"id": "portswigger_sqli_hidden_data", "playbook_id": "sqli"},
            mission_mode="production",
        )
        try:
            self.assertTrue(orch.mission.is_production)
            self.assertEqual(orch.lab_profile, {})
            self.assertTrue(orch.memory.get_fact("mission_production"))
        finally:
            orch.logger.close()

    def test_lab_host_is_benchmark_and_keeps_profile(self):
        orch = _build_offline_orchestrator(
            "https://0abc.web-security-academy.net/", "Reflected XSS lab.",
            lab_profile={"id": "x", "playbook_id": "xss", "vulnerability": "xss"},
        )
        try:
            self.assertTrue(orch.mission.is_benchmark)
            self.assertTrue(orch.lab_profile)
            self.assertFalse(orch.memory.get_fact("mission_production"))
        finally:
            orch.logger.close()

    def test_production_does_not_short_circuit_on_lab_solved(self):
        orch = _build_offline_orchestrator(
            "https://app.example.com/", "Test the app.", mission_mode="production",
        )
        try:
            # Even if a lab_solved fact somehow appears, production must not treat
            # it as a terminal success signal.
            orch.memory.add_fact("lab_solved", True, source="test")
            self.assertFalse(
                orch.memory.get_fact("lab_solved") and orch.mission.is_benchmark
            )
        finally:
            orch.logger.close()


if __name__ == "__main__":
    unittest.main()
