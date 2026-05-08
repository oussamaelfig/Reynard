import os
import unittest

from hacking_agent.agents.base import BudgetedToolExecutor
from hacking_agent.core.evidence import EvidenceStore
from hacking_agent.core.lab_intel import detect_lab_profile, normalize_target_input
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.paths import LOG_DIR
from hacking_agent.core.schemas import PoC, ToolDecision
from hacking_agent.core.scope import ScopeGuard, ScopeViolation
from hacking_agent.core.state_machine import StateMachine
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

        profile = detect_lab_profile(
            "SSRF via OpenID dynamic client registration. Target: " + target,
            target,
        )
        self.assertEqual(profile["id"], "portswigger_oidc_dynamic_client_registration_ssrf")


class ToolRegressionTests(unittest.TestCase):
    def test_tool_registry_and_schema_count_match_after_caido_local(self):
        self.assertEqual(len(TOOL_FUNCTIONS), len(TOOL_SCHEMAS))
        self.assertIn("caido_local_api", TOOL_FUNCTIONS)

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
