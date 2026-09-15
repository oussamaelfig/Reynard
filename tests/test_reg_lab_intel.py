"""Regression tests (lab_intel) - split from test_core_regressions.py."""
from __future__ import annotations

from regression_common import *  # noqa: F401,F403


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


if __name__ == "__main__":
    unittest.main()
