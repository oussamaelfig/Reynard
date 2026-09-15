"""Regression tests (orchestrator) - split from test_core_regressions.py."""
from __future__ import annotations

from regression_common import *  # noqa: F401,F403


class SubagentSchedulerTests(unittest.TestCase):
    def test_runs_safe_subagents_in_parallel(self):
        scheduler = BoundedSubagentScheduler(SubagentPolicy(max_parallel=2))

        def sleeper(name: str):
            def run():
                time.sleep(0.2)
                return AgentResult(success=True, summary=f"{name} done")
            return run

        started = time.monotonic()
        runs = scheduler.run([
            SubagentSpec(name="a", lane="readiness", run=sleeper("a")),
            SubagentSpec(name="b", lane="analysis", run=sleeper("b")),
        ])
        elapsed = time.monotonic() - started

        self.assertEqual(len(runs), 2)
        self.assertTrue(all(run.success for run in runs))
        self.assertTrue(all(run.parallel for run in runs))
        self.assertLess(elapsed, 0.35)

    def test_state_mutating_subagents_are_serial_by_default(self):
        scheduler = BoundedSubagentScheduler(SubagentPolicy(max_parallel=2))
        order: list[str] = []

        def mutating(name: str):
            def run():
                order.append(name)
                return AgentResult(success=True, summary=f"{name} done")
            return run

        runs = scheduler.run([
            SubagentSpec(
                name="exploit-a",
                lane="exploitation",
                run=mutating("a"),
                mutates_target=True,
            ),
            SubagentSpec(
                name="exploit-b",
                lane="exploitation",
                run=mutating("b"),
                mutates_target=True,
            ),
        ])

        self.assertEqual(order, ["a", "b"])
        self.assertTrue(all(not run.parallel for run in runs))

    def test_race_condition_can_opt_into_parallel_stateful_lanes(self):
        scheduler = BoundedSubagentScheduler(SubagentPolicy(
            max_parallel=2,
            allow_stateful_parallel=True,
        ))
        runs = scheduler.run([
            SubagentSpec(
                name="race-a",
                lane="exploitation",
                run=lambda: AgentResult(success=True, summary="a"),
                mutates_target=True,
            ),
            SubagentSpec(
                name="race-b",
                lane="exploitation",
                run=lambda: AgentResult(success=True, summary="b"),
                mutates_target=True,
            ),
        ], lab_profile={"playbook_id": "race_condition"})

        self.assertTrue(all(run.parallel for run in runs))


class StateMachineConcurrencyTests(unittest.TestCase):
    def test_tool_call_recording_is_thread_safe(self):
        sm = StateMachine()

        def record_many():
            for _ in range(100):
                sm.record_tool_call("http_request")

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: record_many(), range(8)))

        self.assertEqual(sm.tool_calls["http_request"], 800)

    def test_tool_budget_reservation_is_atomic(self):
        sm = StateMachine()

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(lambda _: sm.try_record_tool_call("nuclei_scan"), range(50)))

        self.assertEqual(sum(1 for item in results if item), 5)
        self.assertEqual(sm.tool_calls["nuclei_scan"], 5)


class AnalystProfileFallbackTests(unittest.TestCase):
    def test_profile_driven_analyst_creates_focused_finding(self):
        memory = AgentMemory(target_url="https://0abc.web-security-academy.net/")
        memory.add_entity("Target", {"url": "https://0abc.web-security-academy.net/"})
        profile = detect_lab_profile(
            "HTTP request smuggling CL.TE lab. Target: https://0abc.web-security-academy.net/",
            "https://0abc.web-security-academy.net/",
        )
        analyst = AnalystAgent(
            provider=None,
            memory=memory,
            state_machine=StateMachine(),
            evidence=EvidenceStore(),
        )
        output = analyst.execute(
            AgentTask(
                task_description="Analyze detected lab profile.",
                context={
                    "target_url": "https://0abc.web-security-academy.net/",
                    "lab_profile": profile,
                },
            )
        )
        self.assertTrue(output.success)
        self.assertEqual(len(output.vulnerabilities_found), 1)
        self.assertIn("request smuggling", output.vulnerabilities_found[0].vuln_type.lower())


class OrchestratorDryRunTests(unittest.TestCase):
    def test_offline_integration_drive(self):
        target = "https://0abc.web-security-academy.net/"
        profile = detect_lab_profile("Reflected XSS lab. Target: " + target, target)
        orch = _build_offline_orchestrator(target, "Reflected XSS lab.",
                                           lab_profile=profile, max_iterations=12)
        try:
            with patch("hacking_agent.cli.orchestrator.load_methodology",
                       return_value=""), \
                    patch("hacking_agent.cli.orchestrator.console"):
                orch.sm.transition(Event.START, "test")
                orch._seed_hypotheses()

                # (1) hypotheses get seeded from the lab profile.
                self.assertTrue(orch.agenda.all())
                primary = next(h for h in orch.agenda.all()
                               if h.notes == "seed:lab_profile")
                self.assertEqual(primary.phase, "recon")

                # A cooler alternative so demotion can backtrack to it.
                alt = orch.agenda.add(
                    text="Alternative vector", vuln_type="sqli", vector="category",
                    phase="recon", heat=0.4, notes="test:alt",
                )

                orch.coordinator = _ScriptedCoordinator()
                spec = _ScriptedSpecialist([True, False, False, False])
                orch.specialists = {k: spec for k in orch.specialists}
                orch.registry.get = lambda role: _FakeProvider()

                # (2)+(3) coordinator step selects the hottest OPEN hypothesis
                # and a success advances its StrategyEngine phase.
                orch._step()
                self.assertIs(orch.active_hypothesis, primary)
                self.assertEqual(primary.phase, "injection")

                # (4) repeated failure demotes the vector and backtracks.
                for _ in range(3):
                    orch._step()
                self.assertEqual(primary.status, "demoted")
                self.assertIs(orch._select_active_hypothesis(), alt)

                # (5) report gating prevents premature done while alt untried.
                gated = orch._intercept_done(
                    CoordinatorDecision(done=True, reasoning="premature")
                )
                self.assertFalse(gated.done)
                self.assertIsNotNone(gated.next_agent)
        finally:
            orch.logger.close()


class StallDetectorTests(unittest.TestCase):
    def test_stall_fires_after_patience_no_progress_steps(self):
        from hacking_agent.core.strategy import StallDetector

        det = StallDetector(patience=3)
        # First observation never stalls (nothing to compare against).
        self.assertFalse(det.record(
            agent="recon", phase="recon", hypothesis_id="h1",
            kg_count=0, evidence_count=0,
        ))
        # Three consecutive no-progress steps -> stall on the third.
        self.assertFalse(det.record(
            agent="recon", phase="recon", hypothesis_id="h1",
            kg_count=0, evidence_count=0,
        ))
        self.assertFalse(det.record(
            agent="recon", phase="recon", hypothesis_id="h1",
            kg_count=0, evidence_count=0,
        ))
        self.assertTrue(det.record(
            agent="recon", phase="recon", hypothesis_id="h1",
            kg_count=0, evidence_count=0,
        ))

    def test_progress_resets_stall_counter(self):
        from hacking_agent.core.strategy import StallDetector

        det = StallDetector(patience=2)
        det.record(agent="recon", phase="recon", hypothesis_id="h1",
                   kg_count=0, evidence_count=0)
        det.record(agent="recon", phase="recon", hypothesis_id="h1",
                   kg_count=0, evidence_count=0)
        # New KG entity = progress, resets the counter.
        self.assertFalse(det.record(
            agent="recon", phase="recon", hypothesis_id="h1",
            kg_count=5, evidence_count=0,
        ))
        self.assertEqual(det.stall_count, 0)
        # A later phase also counts as progress.
        self.assertFalse(det.record(
            agent="exploitation", phase="injection", hypothesis_id="h1",
            kg_count=5, evidence_count=0,
        ))

    def test_orchestrator_stall_forces_backtrack_and_pivot(self):
        from hacking_agent.core.strategy import StallDetector

        target = "https://0abc.web-security-academy.net/"
        profile = detect_lab_profile("Reflected XSS lab. Target: " + target, target)
        orch = _build_offline_orchestrator(target, "Reflected XSS lab.",
                                           lab_profile=profile)
        try:
            with patch("hacking_agent.cli.orchestrator.console"):
                orch._seed_hypotheses()
                h = orch._select_active_hypothesis()
                self.assertIsNotNone(h)
                orch.stall_detector = StallDetector(patience=1)
                # First step registers a baseline (no stall yet).
                orch._check_stall("recon")
                self.assertFalse(orch._needs_pivot)
                # Second step with no new KG/evidence/phase -> stall -> backtrack.
                orch._check_stall("recon")
                self.assertTrue(orch._needs_pivot)
                self.assertEqual(h.status, "demoted")
                self.assertGreaterEqual(orch._stall_forced_pivots, 1)
        finally:
            orch.logger.close()


class ReconGuardTests(unittest.TestCase):
    def test_redundant_recon_advances_phase_and_reroutes(self):
        target = "https://0abc.web-security-academy.net/"
        profile = detect_lab_profile("Reflected XSS lab. Target: " + target, target)
        orch = _build_offline_orchestrator(target, "Reflected XSS lab.",
                                           lab_profile=profile)
        try:
            with patch("hacking_agent.cli.orchestrator.console"):
                orch._seed_hypotheses()
                h = orch._select_active_hypothesis()
                self.assertEqual(h.phase, "recon")
                # Materialize the recon surface for this vector.
                orch.memory.add_entity("Endpoint", {"url": target + "search"})
                orch._recon_materialized.add(orch._recon_signature(h))

                task = AgentTask(task_description="Re-run recon on target.",
                                 context={})
                self.assertTrue(orch._recon_is_redundant(task))
                routed, new_task = orch._advance_past_recon(task)
                self.assertNotEqual(routed, "recon")
                self.assertNotEqual(h.phase, "recon")
                self.assertIn("recon-guard", new_task.task_description)
        finally:
            orch.logger.close()

    def test_recon_not_redundant_without_materialized_surface(self):
        target = "https://0abc.web-security-academy.net/"
        profile = detect_lab_profile("Reflected XSS lab. Target: " + target, target)
        orch = _build_offline_orchestrator(target, "Reflected XSS lab.",
                                           lab_profile=profile)
        try:
            with patch("hacking_agent.cli.orchestrator.console"):
                orch._seed_hypotheses()
                orch._select_active_hypothesis()
                task = AgentTask(task_description="Initial recon.", context={})
                self.assertFalse(orch._recon_is_redundant(task))
        finally:
            orch.logger.close()


class CategoryAgendaSeedingTests(unittest.TestCase):
    def test_category_playbooks_cover_non_web_categories(self):
        self.assertEqual(
            set(category_playbooks("network")), {"network_pentest", "metasploit"}
        )
        self.assertEqual(
            set(category_playbooks("binary")),
            {"binary_pwn", "reverse_engineering"},
        )
        self.assertEqual(category_playbooks("web"), ["essential_skills"])

    def test_network_ip_target_seeds_category_agenda(self):
        orch = _build_offline_orchestrator(
            "10.10.10.10", "Enumerate services on the authorized box."
        )
        try:
            self.assertEqual(orch.target_category, "network")
            orch._seed_hypotheses()
            agenda = orch.agenda.all()
            self.assertTrue(agenda, "non-web target produced an empty agenda")
            seeded = {h.vector for h in agenda
                      if h.notes == "seed:category_playbook"}
            self.assertTrue({"network_pentest", "metasploit"} <= seeded)
            for h in agenda:
                if h.notes == "seed:category_playbook":
                    self.assertEqual(h.vuln_type, "network")
        finally:
            orch.logger.close()

    def test_binary_bin_target_seeds_pwn_playbooks(self):
        self.assertEqual(detect_target_category("challenge.bin", "ELF pwn"), "binary")
        orch = _build_offline_orchestrator(
            "challenge.bin", "Reverse engineer this ELF binary and pop a shell."
        )
        try:
            self.assertEqual(orch.target_category, "binary")
            orch._seed_hypotheses()
            seeded = {h.vector for h in orch.agenda.all()
                      if h.notes == "seed:category_playbook"}
            self.assertTrue({"binary_pwn", "reverse_engineering"} <= seeded)
        finally:
            orch.logger.close()

    def test_web_target_seeding_stays_backward_compatible(self):
        target = "https://0abc.web-security-academy.net/"
        profile = detect_lab_profile("Reflected XSS lab. Target: " + target, target)
        orch = _build_offline_orchestrator(target, "Reflected XSS lab.",
                                           lab_profile=profile)
        try:
            self.assertEqual(orch.target_category, "web")
            orch._seed_hypotheses()
            notes = {h.notes for h in orch.agenda.all()}
            self.assertNotIn("seed:category_playbook", notes)
            self.assertTrue(any(h.vuln_type == "xss" for h in orch.agenda.all()))
        finally:
            orch.logger.close()


class StrongTierRoutingTests(unittest.TestCase):
    def test_strong_tier_falls_back_to_pivot_then_default(self):
        with patch.dict(os.environ, {
            "LLM_DEFAULT_PROVIDER": "deepseek",
            "DEEPSEEK_API_KEY": "test",
            "LLM_PIVOT_MODEL": "pivot-model",
            "LLM_PIVOT_REASONING_EFFORT": "high",
        }, clear=True):
            registry = ProviderRegistry.from_env()
        strong = registry.config("strong")
        self.assertEqual(strong.model, "pivot-model")
        self.assertEqual(strong.reasoning_effort, "high")
        self.assertIn("strong", registry.describe())

    def test_strong_tier_prefers_explicit_strong_env(self):
        with patch.dict(os.environ, {
            "LLM_DEFAULT_PROVIDER": "deepseek",
            "DEEPSEEK_API_KEY": "test",
            "LLM_STRONG_MODEL": "strong-model",
            "LLM_PIVOT_MODEL": "pivot-model",
        }, clear=True):
            registry = ProviderRegistry.from_env()
        self.assertEqual(registry.config("strong").model, "strong-model")


if __name__ == "__main__":
    unittest.main()
