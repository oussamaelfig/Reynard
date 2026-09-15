"""Tests for the authorization matrix (core/authz_matrix.py)."""
from __future__ import annotations

import unittest

from hacking_agent.core import authz_matrix as az
from hacking_agent.core.authz_matrix import (
    AuthorizationMatrix, AuthzIdentity, AuthzResource, classify_response,
    identities_from_registry,
)


IDENTITIES = [
    AuthzIdentity(name="admin", role="admin", is_admin=True, authenticated=True),
    AuthzIdentity(name="user1", role="user", authenticated=True),
    AuthzIdentity(name="user2", role="user", authenticated=True),
    AuthzIdentity(name="anon", role="anonymous", authenticated=False),
]


def _requester(table):
    """table[(identity, url)] = dict(status, body, final_url)."""
    def req(identity, method, url):
        return table.get((identity, url), {"status": 403, "body": "Forbidden"})
    return req


class ClassifyTests(unittest.TestCase):
    def test_status_based(self):
        self.assertEqual(classify_response(403, "nope")[0], az.DENY)
        self.assertEqual(classify_response(404, "")[0], az.NOTFOUND)
        self.assertEqual(classify_response(200, "welcome user dashboard data")[0], az.ALLOW)

    def test_soft_deny_200_login_page(self):
        out, _ = classify_response(200, "Please log in to continue")
        self.assertEqual(out, az.DENY)

    def test_redirect_to_login_is_deny(self):
        out, _ = classify_response(302, "", final_url="https://x.com/login")
        self.assertEqual(out, az.DENY)

    def test_admin_markers_flag(self):
        _, admin = classify_response(200, "Manage Users / delete user")
        self.assertTrue(admin)


class VerticalAnomalyTests(unittest.TestCase):
    def test_bfla_authenticated_user_reaches_admin_function(self):
        url = "https://x.com/admin/users"
        table = {
            ("admin", url): {"status": 200, "body": "manage users dashboard delete user"},
            ("user1", url): {"status": 200, "body": "manage users dashboard delete user"},
            ("user2", url): {"status": 403, "body": "Forbidden"},
            ("anon", url): {"status": 302, "body": "", "final_url": "https://x.com/login"},
        }
        res = [AuthzResource.get(url, expected_min_role="admin")]
        m = AuthorizationMatrix(IDENTITIES, res).build(_requester(table))
        anomalies = m.analyze()
        kinds = {(a.kind, a.offending_identity) for a in anomalies}
        self.assertIn(("bfla", "user1"), kinds)
        # user2 was denied -> not flagged
        self.assertNotIn(("bfla", "user2"), kinds)

    def test_unauth_access_to_internal_path(self):
        url = "https://x.com/internal/config"
        table = {
            ("admin", url): {"status": 200, "body": "config admin panel"},
            ("user1", url): {"status": 403, "body": "Forbidden"},
            ("user2", url): {"status": 403, "body": "Forbidden"},
            ("anon", url): {"status": 200, "body": "SECRET_KEY=abc config values"},
        }
        m = AuthorizationMatrix(IDENTITIES, [AuthzResource.get(url)]).build(_requester(table))
        anomalies = m.analyze()
        self.assertTrue(any(a.kind == "unauth_access" and a.offending_identity == "anon"
                            for a in anomalies))

    def test_proper_access_control_yields_no_anomaly(self):
        url = "https://x.com/admin"
        table = {
            ("admin", url): {"status": 200, "body": "admin dashboard manage users"},
            ("user1", url): {"status": 403, "body": "Forbidden"},
            ("user2", url): {"status": 403, "body": "Forbidden"},
            ("anon", url): {"status": 302, "body": "", "final_url": "https://x.com/login"},
        }
        m = AuthorizationMatrix(IDENTITIES, [AuthzResource.get(url)]).build(_requester(table))
        self.assertEqual(m.analyze(), [])


class HorizontalAnomalyTests(unittest.TestCase):
    def test_bola_user_reads_another_users_object(self):
        url = "https://x.com/api/users/1001"
        owner_body = '{"id":1001,"ssn":"111-22-3333","email":"a@x.com"}'
        table = {
            ("user1", url): {"status": 200, "body": owner_body},  # owner
            ("user2", url): {"status": 200, "body": owner_body},  # break!
            ("anon", url): {"status": 403, "body": "Forbidden"},
            ("admin", url): {"status": 200, "body": owner_body},
        }
        res = [AuthzResource.get(url, owner_identity="user1", sensitive=True)]
        m = AuthorizationMatrix(IDENTITIES, res).build(_requester(table))
        anomalies = m.analyze()
        self.assertTrue(any(a.kind == "bola" and a.offending_identity == "user2"
                            and a.control_identity == "user1" for a in anomalies))

    def test_no_idor_when_content_differs(self):
        url = "https://x.com/account"
        table = {
            ("user1", url): {"status": 200, "body": "user1 private data " * 20},
            ("user2", url): {"status": 200, "body": "x"},  # own tiny page, different
            ("anon", url): {"status": 403, "body": "Forbidden"},
            ("admin", url): {"status": 200, "body": "admin"},
        }
        res = [AuthzResource.get(url, owner_identity="user1", sensitive=True)]
        m = AuthorizationMatrix(IDENTITIES, res).build(_requester(table))
        self.assertFalse(any(a.kind in ("idor", "bola") for a in m.analyze()))


class EvidenceAndRenderTests(unittest.TestCase):
    def test_to_evidence_bundles_has_control_and_test(self):
        url = "https://x.com/api/users/1001"
        owner_body = '{"id":1001,"ssn":"111-22-3333"}'
        table = {
            ("user1", url): {"status": 200, "body": owner_body},
            ("user2", url): {"status": 200, "body": owner_body},
            ("anon", url): {"status": 403, "body": "Forbidden"},
            ("admin", url): {"status": 200, "body": owner_body},
        }
        res = [AuthzResource.get(url, owner_identity="user1", sensitive=True)]
        m = AuthorizationMatrix(IDENTITIES, res).build(_requester(table))
        bundles = m.to_evidence_bundles(target="https://x.com")
        self.assertTrue(bundles)
        b = bundles[0]
        self.assertTrue(b.is_verified)
        self.assertTrue(b.test_exchanges)
        self.assertTrue(b.control_tests)
        self.assertTrue(b.reproduction_steps)

    def test_render_and_to_dict(self):
        url = "https://x.com/admin"
        table = {("admin", url): {"status": 200, "body": "admin manage users"}}
        m = AuthorizationMatrix(IDENTITIES, [AuthzResource.get(url)]).build(_requester(table))
        self.assertIn("AUTHORIZATION MATRIX", m.render())
        d = m.to_dict()
        self.assertIn("matrix", d)
        self.assertIn("anomalies", d)


class RegistryTests(unittest.TestCase):
    def test_identities_from_registry(self):
        class _Sess:
            def __init__(self, name, role, authed):
                self.name, self.role_hint, self.authenticated = name, role, authed

        class _Reg:
            def __init__(self):
                self._s = {"admin": _Sess("admin", "admin", True),
                           "u1": _Sess("u1", "user", True),
                           "anon": _Sess("anon", "unauth", False)}
            def names(self):
                return list(self._s)
            def get(self, name):
                return self._s[name]

        idents = identities_from_registry(_Reg())
        by_name = {i.name: i for i in idents}
        self.assertTrue(by_name["admin"].is_admin)
        self.assertEqual(by_name["anon"].role, "anonymous")
        self.assertFalse(by_name["anon"].authenticated)


class ToolAndIngestionTests(unittest.TestCase):
    def test_tool_requires_two_identities(self):
        # Fresh default registry has a single "default" session -> structured error.
        from hacking_agent.core.tools import execute_tool
        import json
        out = json.loads(execute_tool("authz_matrix_scan",
                                      {"urls": ["https://x.com/admin"]}))
        self.assertIn("error", out)

    def test_ingest_scan_into_surface_records_findings(self):
        from hacking_agent.core.attack_surface import AttackSurface
        scan = {
            "anomalies": [
                {"kind": "bola", "resource": "GET /api/users/1",
                 "offending_identity": "user2", "control_identity": "user1",
                 "severity": "high", "detail": "user2 read user1 object"},
            ]
        }
        surface = AttackSurface(target="http://x.com")
        n = az.ingest_scan_into_surface(surface, scan)
        self.assertEqual(n, 1)
        self.assertTrue(surface.findings())
        self.assertTrue(surface.observations())

    def test_executor_ingests_authz_scan(self):
        import json
        from hacking_agent.agents.base import BudgetedToolExecutor
        from hacking_agent.core.attack_surface import AttackSurface
        from hacking_agent.core.memory import AgentMemory
        from hacking_agent.core.state_machine import StateMachine, StateMachineConfig

        surface = AttackSurface(target="http://x.com")
        mem = AgentMemory(target_url="http://x.com")
        sm = StateMachine(StateMachineConfig(max_iterations=5))
        ex = BudgetedToolExecutor(mem, sm, scope_guard=None, surface=surface)
        scan = json.dumps({"anomalies": [
            {"kind": "bfla", "resource": "GET /admin", "offending_identity": "user1",
             "control_identity": "user2", "severity": "high", "detail": "bfla"}]})
        ex._ingest_authz_surface("authz_matrix_scan", scan, "exploitation")
        self.assertTrue(surface.findings())


if __name__ == "__main__":
    unittest.main()
