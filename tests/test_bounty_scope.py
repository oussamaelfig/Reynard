"""Tests for bug-bounty scope import (integrations/bounty.py)."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from hacking_agent.integrations import bounty
from hacking_agent.integrations.bounty import (
    BountyScopeError, HackerOneClient, build_engagement_from_source,
    import_scope_file, normalize_scope_host, parse_structured_scopes,
)
from hacking_agent.core.scope import ScopeGuard


class NormalizationTests(unittest.TestCase):
    def test_wildcard_and_url_reduce_to_host(self):
        self.assertEqual(normalize_scope_host("https://*.example.com/graphql"),
                         "example.com")
        self.assertEqual(normalize_scope_host("*.example.com"), "example.com")
        self.assertEqual(normalize_scope_host("app.example.com:443"),
                         "app.example.com")


class ParseStructuredScopesTests(unittest.TestCase):
    def test_eligibility_routes_allow_vs_deny(self):
        scopes = [
            {"asset_type": "URL", "asset_identifier": "app.example.com",
             "eligible_for_submission": True},
            {"asset_type": "WILDCARD", "asset_identifier": "*.example.com",
             "eligible_for_submission": True},
            {"asset_type": "URL", "asset_identifier": "blog.example.com",
             "eligible_for_submission": False},
            {"asset_type": "CIDR", "asset_identifier": "10.0.0.0/24",
             "eligible_for_submission": True},
        ]
        buckets = parse_structured_scopes(scopes)
        self.assertIn("app.example.com", buckets.authorized_domains)
        self.assertIn("example.com", buckets.authorized_domains)
        self.assertIn("blog.example.com", buckets.out_of_scope)
        self.assertIn("10.0.0.0/24", buckets.authorized_cidrs)


class FileImporterTests(unittest.TestCase):
    def _write(self, name, content):
        d = tempfile.mkdtemp()
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        return p

    def test_import_structured_scopes_json(self):
        p = self._write("scope.json", json.dumps({
            "handle": "acme",
            "scopes": [
                {"asset_type": "URL", "asset_identifier": "app.acme.com",
                 "eligible_for_submission": True},
                {"asset_type": "URL", "asset_identifier": "legacy.acme.com",
                 "eligible_for_submission": False},
            ],
        }))
        eng = import_scope_file(p)
        self.assertIn("app.acme.com", eng.authorized_domains)
        self.assertIn("legacy.acme.com", eng.out_of_scope)

    def test_import_in_scope_out_of_scope_lists(self):
        p = self._write("scope.json", json.dumps({
            "in_scope": ["*.acme.com", "https://api.acme.com/"],
            "out_of_scope": ["careers.acme.com"],
        }))
        eng = import_scope_file(p)
        self.assertIn("acme.com", eng.authorized_domains)
        self.assertIn("api.acme.com", eng.authorized_domains)
        self.assertIn("careers.acme.com", eng.out_of_scope)

    def test_import_engagement_format_delegates(self):
        p = self._write("eng.json", json.dumps({
            "engagement_name": "acme-pentest",
            "authorized_domains": ["acme.com"],
            "max_requests_per_second": 5,
        }))
        eng = import_scope_file(p)
        self.assertEqual(eng.engagement_name, "acme-pentest")
        self.assertEqual(eng.max_requests_per_second, 5.0)

    def test_feeds_scope_guard_readonly(self):
        p = self._write("scope.json", json.dumps({
            "in_scope": ["*.acme.com"], "out_of_scope": ["secret.acme.com"],
        }))
        eng = import_scope_file(p)
        guard = ScopeGuard.from_engagement(eng)
        self.assertTrue(guard.is_in_scope("api.acme.com"))
        self.assertFalse(guard.is_in_scope("secret.acme.com"))
        self.assertFalse(guard.is_in_scope("evil.com"))


class HackerOneConnectorTests(unittest.TestCase):
    def _transport(self, pages):
        calls = {"i": 0}

        def transport(method, url, headers=None):
            self.assertEqual(method, "GET")
            self.assertIn("Authorization", headers or {})
            self.assertTrue(headers["Authorization"].startswith("Basic "))
            i = calls["i"]
            calls["i"] += 1
            return 200, pages[min(i, len(pages) - 1)]
        return transport

    def test_fetch_and_build_engagement_paginated(self):
        page1 = {
            "data": [
                {"attributes": {"asset_type": "URL",
                                "asset_identifier": "app.acme.com",
                                "eligible_for_submission": True}},
            ],
            "links": {"next": "https://api.hackerone.com/v1/next"},
        }
        page2 = {
            "data": [
                {"attributes": {"asset_type": "URL",
                                "asset_identifier": "old.acme.com",
                                "eligible_for_submission": False}},
            ],
            "links": {},
        }
        client = HackerOneClient(username="u", token="t",
                                 transport=self._transport([page1, page2]))
        eng = client.build_engagement("acme")
        self.assertIn("app.acme.com", eng.authorized_domains)
        self.assertIn("old.acme.com", eng.out_of_scope)
        self.assertEqual(eng.engagement_name, "hackerone:acme")

    def test_rejected_credentials_raise(self):
        def transport(method, url, headers=None):
            return 401, {"errors": []}
        client = HackerOneClient(username="u", token="bad", transport=transport)
        with self.assertRaises(BountyScopeError):
            client.build_engagement("acme")

    def test_from_env_requires_both_credentials(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(HackerOneClient.from_env())
        with patch.dict(os.environ, {"HACKERONE_API_USERNAME": "u",
                                     "HACKERONE_API_TOKEN": "t"}, clear=True):
            self.assertIsNotNone(HackerOneClient.from_env())

    def test_build_from_source_hackerone_without_creds_errors(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(BountyScopeError):
                build_engagement_from_source("hackerone:acme")


if __name__ == "__main__":
    unittest.main()
