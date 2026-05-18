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
    detect_lab_profile,
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
from hacking_agent.core.schemas import ProviderConfig
from hacking_agent.core.scope import ScopeGuard, ScopeViolation
from hacking_agent.core.state_machine import StateMachine
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


if __name__ == "__main__":
    unittest.main()
