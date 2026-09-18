"""Read-only business contracts exercised with deterministic offline requesters."""
from __future__ import annotations

import json
import hashlib
from typing import Any

import pytest
from pydantic import ValidationError

from hacking_agent.core.business_logic import BusinessRuleSpec, evaluate_business_rules
from hacking_agent.core.sessions import AuthSession

URL = "https://app.test/api/invoices/fixture-a?key=private-query-token"
MARKER = "controlled-owner-private-marker"


def rule(**updates: Any) -> BusinessRuleSpec:
    values = {"name": "invoice owner contract", "url": URL, "owner_identity": "owner",
              "denied_identity": "peer", "json_path": "/invoice/owner_id", "expected_value": MARKER}
    return BusinessRuleSpec(**{**values, **updates})


def response(status: int = 200, *, marker: Any = MARKER, body: str | None = None,
             **updates: Any) -> dict:
    return {"status": status, "body": body if body is not None else json.dumps({"invoice": {"owner_id": marker}}),
            "final_url": URL, "headers": {"content-type": "application/json"}, "truncated": False,
            **updates}


class FixtureRunner:
    """No HTTP client, container, registry singleton or external process."""

    def __init__(self, handler=None):
        self.verified_identities = {"owner", "peer"}
        self.identity_fingerprints = {identity: hashlib.sha256(identity.encode()).hexdigest()
                                      for identity in self.verified_identities}
        self.sessions = {name: AuthSession(name) for name in ("owner", "peer", "anonymous")}
        self.sessions["owner"].static_headers = {"Authorization": "Bearer owner-secret"}
        self.sessions["peer"].static_headers = {"Authorization": "Bearer peer-secret"}
        self.calls: list[tuple[str, str, str, AuthSession]] = []
        self.handler = handler or self.disclosure

    def clone_session(self, name: str) -> AuthSession:
        return AuthSession.from_transfer_dict(self.sessions[name].to_transfer_dict())

    def verify_session(self, identity_name: str, *, session: AuthSession) -> bool:
        return session.name == identity_name and identity_name in self.verified_identities

    def request(self, identity_name: str, method: str, url: str, *, data=None,
                headers=None, session: AuthSession | None = None) -> dict:
        assert session is not None
        assert method == "GET" and data is None and headers is None
        self.calls.append((identity_name, method, url, session))
        return self.handler(identity_name, method, url, session)

    @staticmethod
    def disclosure(identity, _method, _url, _session):
        return response() if identity != "anonymous" else response(403, body="Forbidden")


def result(runner: FixtureRunner, spec: BusinessRuleSpec | None = None) -> dict:
    return evaluate_business_rules(runner, [spec or rule()])["results"][0]


def test_repeated_cross_user_marker_is_candidate_not_verified_or_reportable():
    runner = FixtureRunner()
    outcome = evaluate_business_rules(runner, [rule()])
    finding = outcome["results"][0]
    assert finding["classification"] == "candidate"
    assert finding["reason"] == "private_marker_reproduced"
    assert finding["verification_status"] == "unverified"
    assert finding["customer_reportable"] is False
    assert outcome["metrics"] == {
        "rules_total": 1, "passed_count": 0, "candidate_count": 1, "inconclusive_count": 0,
        "request_attempts": 6, "responses_received": 6, "identity_check_attempts": 8,
        "verified_count": 0, "reportable_count": 0,
    }
    assert [call[0] for call in runner.calls] == ["owner", "peer", "anonymous"] * 2
    assert all(call[1:3] == ("GET", URL) for call in runner.calls)
    assert len(finding["evidence"]) == 6
    assert all(len(item["request_sha256"]) == len(item["response_sha256"]) == 64
               for item in finding["evidence"])


@pytest.mark.parametrize("status", [401, 403, 404])
def test_proper_denial_passes_only_with_repeated_owner_baselines(status):
    runner = FixtureRunner(lambda identity, *_: response() if identity == "owner"
                           else response(status, body="denied"))
    observed = result(runner)
    assert observed["classification"] == "passed"
    assert observed["reason"] == "declared_access_denied"
    assert len(runner.calls) == 6


def test_explicit_anonymous_disclosure_has_authenticated_owner_control():
    runner = FixtureRunner(lambda *_: response())
    observed = result(runner, rule(denied_identity="anonymous"))
    assert observed["classification"] == "candidate"
    assert [call[0] for call in runner.calls] == ["owner", "anonymous"] * 2


def test_public_or_shared_marker_does_not_confirm_named_identity_contract():
    runner = FixtureRunner(lambda *_: response())
    observed = result(runner)
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "anonymous_control_not_denied"


@pytest.mark.parametrize("peer_response", [
    response(body="<html>Please log in</html>"),
    response(body="<html>A shared template with a public dashboard</html>"),
    response(marker="another-owner-private-marker"),
    response(body='{"invoice":{}}'),
    response(body='{"invoice":{"owner_id":"unrelated"},"other":"' + MARKER + '"}'),
    response(body='{"invoice":{"owner_id":"' + MARKER + '","owner_id":"unrelated"}}'),
    response(body='{"invoice":{"owner_id":"' + MARKER + '"},"invalid":NaN}'),
])
def test_soft_200_shared_templates_missing_or_ambiguous_markers_are_inconclusive(peer_response):
    runner = FixtureRunner(lambda identity, *_: response() if identity == "owner" else peer_response)
    observed = result(runner)
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "marker_missing_or_ambiguous"
    assert len(runner.calls) == 2


@pytest.mark.parametrize("owner_response", [response(401, body="expired session"),
                                            response(marker="wrong-controlled-owner"),
                                            response(body="<html>generic login page</html>")])
def test_expired_owner_or_missing_owner_marker_stops_before_cross_user_probes(owner_response):
    runner = FixtureRunner(lambda *_: owner_response)
    observed = result(runner)
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "owner_baseline_missing"
    assert len(runner.calls) == 1


@pytest.mark.parametrize("peer_response", [response(truncated=True), response(truncated=None),
                                          response(body="a" * 65537), response(body=None, truncated=True),
                                          response(body="\ud800")])
def test_truncated_or_unbounded_response_is_never_a_candidate(peer_response):
    runner = FixtureRunner(lambda identity, *_: response() if identity == "owner" else peer_response)
    observed = result(runner)
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "incomplete_response"


def test_replay_inconsistency_does_not_become_a_candidate():
    counts = {"owner": 0, "peer": 0, "anonymous": 0}

    def handler(identity, *_):
        counts[identity] += 1
        if identity == "owner" or (identity == "peer" and counts[identity] == 1):
            return response()
        return response(403, body="Forbidden")

    observed = result(FixtureRunner(handler))
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "replay_inconsistent"


@pytest.mark.parametrize("identity", ["owner", "peer"])
def test_unverified_identity_prevents_all_requests(identity):
    runner = FixtureRunner()
    runner.verified_identities.remove(identity)
    assert result(runner)["reason"] == "identity_not_verified"
    assert not runner.calls


@pytest.mark.parametrize("peer_fingerprint", ["", "not-a-fingerprint", None, "same"])
def test_missing_or_duplicate_account_identity_proof_prevents_requests(peer_fingerprint):
    runner = FixtureRunner()
    runner.identity_fingerprints["peer"] = (runner.identity_fingerprints["owner"]
                                            if peer_fingerprint == "same" else peer_fingerprint)
    observed = result(runner)
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "distinct_identities_not_proven"
    assert not runner.calls


def test_each_probe_uses_a_fresh_deep_snapshot_and_does_not_mutate_baseline():
    def handler(identity, _method, _url, session):
        assert "X-Fixture-Mutation" not in session.static_headers
        session.static_headers["X-Fixture-Mutation"] = "changed only within one attempt"
        return FixtureRunner.disclosure(identity, _method, _url, session)

    runner = FixtureRunner(handler)
    assert result(runner)["classification"] == "candidate"
    snapshots = [call[3] for call in runner.calls]
    assert len({id(session) for session in snapshots}) == 6
    assert len({id(session.http_cookies) for session in snapshots}) == 6
    assert all("X-Fixture-Mutation" not in session.static_headers for session in runner.sessions.values())


@pytest.mark.parametrize("alias", ["session", "cookies", "headers"])
def test_broken_shallow_clone_fails_closed(alias):
    runner = FixtureRunner()
    original_clone = runner.clone_session

    def broken_clone(name):
        clone = original_clone(name)
        if alias == "session":
            return runner.sessions[name]
        if alias == "cookies":
            clone.http_cookies = runner.sessions[name].http_cookies
        if alias == "headers":
            clone.static_headers = runner.sessions[name].static_headers
        return clone

    runner.clone_session = broken_clone
    assert result(runner)["reason"] == "request_blocked_or_failed"
    assert not runner.calls


def test_anonymous_clone_with_credentials_fails_closed():
    runner = FixtureRunner()
    runner.sessions["anonymous"].static_headers = {"Cookie": "private-secret"}
    observed = result(runner)
    assert observed["reason"] == "request_blocked_or_failed"
    assert [call[0] for call in runner.calls] == ["owner", "peer"]


@pytest.mark.parametrize("when", ["before", "after"])
def test_identity_expiring_around_resource_request_is_inconclusive(when):
    runner = FixtureRunner()
    checks = []

    def verify(identity_name, *, session):
        checks.append((identity_name, session))
        return when == "after" and len(checks) == 1

    runner.verify_session = verify
    observed = result(runner)
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "identity_verification_failed"
    assert len(runner.calls) == (1 if when == "after" else 0)


def test_runner_scope_budget_and_window_errors_propagate_as_safe_inconclusive_codes():
    def blocked(*_):
        raise ValueError(f"Scope or budget error: {URL} with {MARKER} Bearer raw-secret")

    runner = FixtureRunner(blocked)
    outcome = evaluate_business_rules(runner, [rule()])
    assert outcome["results"][0]["reason"] == "request_blocked_or_failed"
    assert outcome["metrics"]["request_attempts"] == 1
    assert outcome["metrics"]["responses_received"] == 0
    assert "raw-secret" not in json.dumps(outcome)


@pytest.mark.parametrize("final_url", ["https://app.test/login", "https://other.test/api/invoices/fixture-a",
                                        URL + "&changed=1", URL + "#fragment", ""])
def test_redirect_or_changed_resource_is_inconclusive(final_url):
    runner = FixtureRunner(lambda *_: response(final_url=final_url))
    assert result(runner)["classification"] == "inconclusive"
    assert len(runner.calls) == 1


def test_private_configuration_response_credentials_and_marker_are_never_returned():
    runner = FixtureRunner()
    spec = rule(name=MARKER)
    serialized = json.dumps(evaluate_business_rules(runner, [spec]))
    for private in (MARKER, URL, "private-query-token", "Bearer", "owner-secret", "peer-secret",
                    "/invoice/owner_id", "app.test"):
        assert private not in serialized


def test_model_repr_and_validation_error_text_hide_private_fields():
    representation = repr(rule())
    for private in (MARKER, URL, "/invoice/owner_id"):
        assert private not in representation
    with pytest.raises(ValidationError) as caught:
        rule(expected_value=MARKER + "\n")
    assert MARKER not in str(caught.value)


@pytest.mark.parametrize("marker", [True, 1.0, "1"])
def test_json_marker_comparison_does_not_coerce_types(marker):
    runner = FixtureRunner(lambda identity, *_: response(marker=1 if identity == "owner" else marker))
    assert result(runner, rule(expected_value=1))["classification"] == "inconclusive"


def test_json_pointer_supports_arrays_and_escaped_member_names_without_code_execution():
    body = json.dumps({"a/b": [{"~owner": MARKER}]})
    runner = FixtureRunner(lambda identity, *_: response(body=body) if identity != "anonymous"
                           else response(403, body="Forbidden"))
    assert result(runner, rule(json_path="/a~1b/0/~0owner"))["classification"] == "candidate"


@pytest.mark.parametrize("changes", [
    {"method": "POST"}, {"data": "price=0"}, {"url": "https://user:secret@app.test/x"},
    {"url": "https://app.test/x#fragment"}, {"url": "file:///tmp/data"},
    {"url": "app.test/x"}, {"url": "https://app.test/a/../private"},
    {"json_path": "$.invoice.owner"}, {"json_path": "/owner~2id"},
    {"json_path": "/owner\n"}, {"expected_value": True}, {"expected_value": None},
    {"expected_value": {}}, {"expected_value": 1.0}, {"expected_value": ""},
    {"expected_value": "a" * 513}, {"expected_value": "owner\nsecret"},
    {"expected_denied_statuses": [200]}, {"expected_denied_statuses": [401, 401]},
    {"expected_denied_statuses": [True]}, {"expected_denied_statuses": []},
    {"owner_identity": "anonymous"}, {"denied_identity": "owner"},
])
def test_operator_spec_rejects_ambiguous_unsafe_or_generic_contracts(changes):
    with pytest.raises(ValidationError):
        rule(**changes)


def test_rule_limit_duplicate_names_and_empty_rule_list():
    runner = FixtureRunner()
    with pytest.raises(ValueError, match="twenty"):
        evaluate_business_rules(runner, [rule(name=f"rule-{index}") for index in range(21)])
    with pytest.raises(ValueError, match="unique"):
        evaluate_business_rules(runner, [rule(), rule()])
    assert evaluate_business_rules(runner, [])["results"] == []
    assert not runner.calls


def test_status_subset_is_respected_and_spec_is_frozen():
    spec = rule(expected_denied_statuses=[403])
    assert spec.expected_denied_statuses == (403,)
    with pytest.raises(ValidationError):
        spec.denied_identity = "anonymous"
    runner = FixtureRunner(lambda identity, *_: response() if identity == "owner"
                           else response(401, body="Forbidden"))
    assert result(runner, spec)["classification"] == "inconclusive"
