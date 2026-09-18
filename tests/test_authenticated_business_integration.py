"""Business contracts through the real runner and transport, with no network I/O."""
from __future__ import annotations

import json

import httpx
import pytest

from hacking_agent.core import http_transport
from hacking_agent.core.authenticated_research import AuthenticatedResearchPlan, ResearchRunner
from hacking_agent.core.business_logic import BusinessRuleSpec, evaluate_business_rules
from hacking_agent.core.engagement import Engagement
from hacking_agent.core.scope import ScopeGuard

ORIGIN = "https://app.test"
RESOURCE = ORIGIN + "/safe/resource"
PRIVATE_MARKER = "fixture-private-owner-object"


@pytest.fixture
def application(monkeypatch):
    """All clients use this in-memory app; even a regression cannot reach DNS."""
    client_type = httpx.Client
    state = {"expired": set(), "expire_on_resource": "", "deny_peer": False,
             "soft_login_peer": False, "truncate_resource": False, "seen": []}

    def dispatch(request):
        state["seen"].append(request)
        identity = {"Bearer owner-fixture-key": "owner", "Bearer peer-fixture-key": "peer"}.get(
            request.headers.get("authorization"), "anonymous",
        )
        if request.url.path == "/me":
            if identity == "anonymous" or identity in state["expired"]:
                return httpx.Response(401, json={"error": "authentication required"})
            return httpx.Response(200, json={"id": "fixture-" + identity + "-account"})
        if request.url.path == "/safe/home":
            return httpx.Response(200, text="<html>Read-only fixture home</html>",
                                  headers={"Content-Type": "text/html"})
        if request.url.path == "/safe/resource":
            if state["expire_on_resource"] == identity:
                state["expired"].add(identity)
            if identity == "anonymous" or (identity == "peer" and state["deny_peer"]):
                return httpx.Response(403, json={"error": "forbidden"})
            if identity == "peer" and state["soft_login_peer"]:
                return httpx.Response(200, text="<html>Please log in again</html>")
            if state["truncate_resource"]:
                return httpx.Response(200, text="x" * (http_transport.MAX_RESPONSE_BYTES + 1))
            return httpx.Response(200, json={"invoice": {"owner_marker": PRIVATE_MARKER}},
                                  headers={"Set-Cookie": "resource_ctx=within-one-clone; Path=/; Secure"})
        raise AssertionError("Unexpected fixture request")

    monkeypatch.setattr(http_transport.httpx, "Client", lambda **kwargs: client_type(
        transport=httpx.MockTransport(dispatch), **kwargs,
    ))
    plan = AuthenticatedResearchPlan(
        origin=ORIGIN,
        identities=[
            {"name": identity, "headers": {"Authorization": f"Bearer {identity}-fixture-key"},
             "verification": {"url": ORIGIN + "/me", "json_path": "/id", "expected": f"fixture-{identity}-account"}}
            for identity in ("owner", "peer")
        ],
        read_prefixes=[ORIGIN + "/safe/"], start_urls=[ORIGIN + "/safe/home"],
        max_requests=100,
    )
    guard = ScopeGuard.from_engagement(Engagement(authorized_domains=["app.test"], max_total_requests=200))
    runner = ResearchRunner(plan, guard)
    assert runner.run()["status"] == "completed"
    assert runner.verified_identities == {"owner", "peer"}
    state["seen"].clear()
    return runner, guard, state


def spec(**changes):
    return BusinessRuleSpec(**{
        "name": "private invoice", "url": RESOURCE, "owner_identity": "owner",
        "denied_identity": "peer", "json_path": "/invoice/owner_marker",
        "expected_value": PRIVATE_MARKER, **changes,
    })


def evaluate(runner, **changes):
    return evaluate_business_rules(runner, [spec(**changes)])


def test_actual_runner_replays_with_fresh_auth_checks_and_shared_request_budget(application):
    runner, guard, state = application
    initial_budget = guard._request_count
    initial_runner_count = runner._requests
    outcome = evaluate(runner)
    assert outcome["results"][0]["classification"] == "candidate"
    assert outcome["results"][0]["customer_reportable"] is False
    assert outcome["metrics"]["identity_check_attempts"] == 8
    # Six resource reads and eight pre/post identity probes; every actual HTTP
    # request consumes exactly one shared engagement and runner budget unit.
    assert guard._request_count - initial_budget == 14
    assert runner._requests - initial_runner_count == 14
    assert len(state["seen"]) == 14
    assert all(request.method == "GET" and request.url.host == "app.test" for request in state["seen"])


def test_cookie_updates_stay_within_one_replay_clone(application):
    runner, _, state = application
    assert evaluate(runner)["results"][0]["classification"] == "candidate"
    resources = [request for request in state["seen"] if request.url.path == "/safe/resource"]
    identity_checks = [request for request in state["seen"] if request.url.path == "/me"]
    assert all("resource_ctx" not in request.headers.get("cookie", "") for request in resources)
    assert sum("resource_ctx=within-one-clone" in request.headers.get("cookie", "")
               for request in identity_checks) == 4
    assert all(not list(session.http_cookies) for session in runner.sessions.values())


@pytest.mark.parametrize("when", ["before", "after_owner_read", "after_peer_read"])
def test_expired_session_cannot_create_passed_or_candidate_result(application, when):
    runner, _, state = application
    if when == "before":
        state["expired"].add("owner")
    else:
        state["expire_on_resource"] = "owner" if when == "after_owner_read" else "peer"
    outcome = evaluate(runner)
    observed = outcome["results"][0]
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "identity_verification_failed"
    if when == "before":
        assert not any(request.url.path == "/safe/resource" for request in state["seen"])
    assert outcome["metrics"]["candidate_count"] == outcome["metrics"]["passed_count"] == 0


def test_real_scoped_transport_proper_denial_passes(application):
    runner, _, state = application
    state["deny_peer"] = True
    observed = evaluate(runner)["results"][0]
    assert observed["classification"] == "passed"
    assert observed["verification_status"] == "unverified"


def test_real_scoped_transport_soft_200_login_remains_inconclusive(application):
    runner, _, state = application
    state["soft_login_peer"] = True
    assert evaluate(runner)["results"][0]["classification"] == "inconclusive"


def test_real_scoped_transport_truncation_is_inconclusive(application):
    runner, _, state = application
    state["truncate_resource"] = True
    assert evaluate(runner)["results"][0]["classification"] == "inconclusive"


@pytest.mark.parametrize("url", ["https://other.test/safe/resource", ORIGIN + "/outside/resource"])
def test_new_endpoint_cannot_escape_origin_or_explicit_read_policy(application, url):
    runner, _, state = application
    observed = evaluate(runner, url=url)["results"][0]
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "request_blocked_or_failed"
    assert all(str(request.url) == ORIGIN + "/me" for request in state["seen"])


def test_engagement_budget_exhaustion_during_post_read_verification_fails_closed(application):
    runner, guard, state = application
    guard.max_total_requests = guard._request_count + 2
    observed = evaluate(runner)["results"][0]
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "request_blocked_or_failed"
    assert len(state["seen"]) == 2


def test_deadline_exhaustion_prevents_any_business_network_request(application):
    runner, _, state = application
    runner._started = -1e12
    observed = evaluate(runner)["results"][0]
    assert observed["classification"] == "inconclusive"
    assert observed["reason"] == "request_blocked_or_failed"
    assert not state["seen"]


def test_integrated_outputs_never_expose_private_auth_or_resource_values(application):
    runner, _, _ = application
    serialized = json.dumps(evaluate(runner))
    for secret in ("owner-fixture-key", "peer-fixture-key", PRIVATE_MARKER,
                   "within-one-clone", "fixture-owner-account", "fixture-peer-account"):
        assert secret not in serialized
