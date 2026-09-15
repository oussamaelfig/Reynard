"""Regression tests (integrations) - split from test_core_regressions.py."""
from __future__ import annotations

from regression_common import *  # noqa: F401,F403


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


if __name__ == "__main__":
    unittest.main()
