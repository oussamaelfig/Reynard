"""Regression tests (tooling) - split from test_core_regressions.py."""
from __future__ import annotations

from regression_common import *  # noqa: F401,F403


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


class ToolParityTests(unittest.TestCase):
    def test_tool_registry_parity(self):
        # 62 base + 8 recon wrappers + 1 authz matrix + 1 browser_map + 3 external (browser_use +
        # hexstrike search/run) = 75.
        self.assertEqual(len(TOOL_FUNCTIONS), 75)
        self.assertEqual(len(TOOL_SCHEMAS), 75)


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
        self.assertEqual(len(names), 75)
        # A ToolDecision selecting a Phase-2 tool must now validate.
        decision = ToolDecision(
            tool="race_send",
            args={"url": "https://lab.example.com/", "mode": "single_packet"},
            reasoning="Fire a last-byte-synchronized batch for a desync probe.",
            expected_signal="Distinct status distribution vs. baseline.",
        )
        self.assertEqual(decision.tool, "race_send")


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
