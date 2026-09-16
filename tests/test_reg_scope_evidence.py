"""Regression tests (scope_evidence) - split from test_core_regressions.py."""
from __future__ import annotations

from regression_common import *  # noqa: F401,F403


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
        self.assertFalse(store.is_verified("vuln:1"))
        self.assertEqual(store.verification_state("vuln:1"), "unverified")

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
            validation_metadata={"protocol_valid": True},
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


if __name__ == "__main__":
    unittest.main()
