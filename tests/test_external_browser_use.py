"""Tests for the Browser Use adapter (scope hard-restriction, parsing, degradation).

Browser Use itself is not installed in CI, so these cover the pure/guarded paths."""
from __future__ import annotations

import unittest

from hacking_agent.core.scope import ScopeGuard
from hacking_agent.integrations.external import browser_use as bu


class DegradationTests(unittest.TestCase):
    def test_available_false_without_install(self):
        self.assertFalse(bu.BrowserUseExplorer().available())

    def test_explore_degrades_gracefully(self):
        cap = bu.BrowserUseExplorer().explore(
            "map workflows", "https://app.x.com/",
            scope_guard=ScopeGuard(allowed_domains=["x.com"]))
        self.assertFalse(cap.available)
        self.assertTrue(cap.errors)
        self.assertEqual(cap.structured_observations, [])

    def test_entry_url_out_of_scope_is_rejected(self):
        # Even if it were installed, an out-of-scope entry URL must be refused.
        ex = bu.BrowserUseExplorer()
        # Force available() True to exercise the scope pre-check branch.
        ex.available = lambda: True  # type: ignore[method-assign]
        cap = ex.explore("x", "https://evil.com/",
                         scope_guard=ScopeGuard(allowed_domains=["x.com"]))
        self.assertTrue(any("out of scope" in e for e in cap.errors))


class ScopeRestrictionTests(unittest.TestCase):
    def test_allowed_domain_patterns_from_scope(self):
        guard = ScopeGuard(allowed_domains=["x.com"])
        pats = bu._allowed_domain_patterns(guard, "https://app.x.com/")
        self.assertIn("*.x.com", pats)
        self.assertIn("x.com", pats)
        self.assertIn("app.x.com", pats)
        self.assertNotIn("evil.com", pats)

    def test_in_scope_predicate(self):
        guard = ScopeGuard(allowed_domains=["x.com"])
        self.assertTrue(bu._in_scope(guard, "https://api.x.com/a"))
        self.assertFalse(bu._in_scope(guard, "https://evil.com/a"))


class ParsingTests(unittest.TestCase):
    def setUp(self):
        self.guard = ScopeGuard(allowed_domains=["x.com"])

    def test_structured_output_scope_checked(self):
        w = bu.WorkflowExploration(
            steps=[bu.WorkflowStep(page="/login", action="submit",
                                   navigation="https://app.x.com/dashboard"),
                   bu.WorkflowStep(page="/x", action="click",
                                   navigation="https://evil.com/leak")],
            network_requests=[
                bu.DiscoveredRequest(method="POST", url="https://app.x.com/api/invite", kind="xhr"),
                bu.DiscoveredRequest(method="GET", url="https://evil.com/track", kind="fetch")],
            auth_state="authenticated", workflow_states=["login", "invite"],
            observations=["invite changes member role"])
        obs = bu._observations_from_structured(w, self.guard)
        urls = [o.url for o in obs if o.url]
        self.assertIn("https://app.x.com/api/invite", urls)
        self.assertFalse(any("evil.com" in u for u in urls))  # redirects scope-checked
        self.assertTrue(any(o.category == "api" for o in obs))
        self.assertTrue(any(o.category == "auth_state" for o in obs))

    def test_har_parsing_scope_checked(self):
        import json, tempfile, os
        har = {"log": {"entries": [
            {"request": {"method": "GET", "url": "https://app.x.com/api/users"},
             "response": {"status": 200, "headers": [
                 {"name": "content-type", "value": "application/json"}]}},
            {"request": {"method": "GET", "url": "https://evil.com/x"},
             "response": {"status": 200, "headers": []}},
        ]}}
        d = tempfile.mkdtemp()
        p = os.path.join(d, "t.har")
        with open(p, "w") as fh:
            json.dump(har, fh)
        obs = bu._observations_from_har(p, self.guard)
        urls = [o.url for o in obs]
        self.assertIn("https://app.x.com/api/users", urls)
        self.assertNotIn("https://evil.com/x", urls)
        api = next(o for o in obs if o.url == "https://app.x.com/api/users")
        self.assertEqual(api.kind_hint, __import__(
            "hacking_agent.core.attack_surface", fromlist=["KIND_API"]).KIND_API)


if __name__ == "__main__":
    unittest.main()
