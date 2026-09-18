"""Deterministic account/login/crawl contracts using mocks and a loopback lab."""
from __future__ import annotations

import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import ValidationError

from hacking_agent.core import authenticated_research as ar, http_transport, sessions
from hacking_agent.core.engagement import Engagement
from hacking_agent.core.scope import ScopeGuard


ORIGIN = "https://fixture.test"


def configuration(origin=ORIGIN, setup=False):
    identity = {
        "name": "alice", "role_hint": "user", "cookie_header": "session=alice",
        "verification": {"url": origin + "/me", "json_path": "/user/id", "expected": "alice"},
    }
    plan = {"origin": origin, "identities": [identity], "read_prefixes": [origin + "/app"]}
    if setup:
        identity["cookie_header"] = ""
        identity["setup"] = [
            {"purpose": "register", "method": "GET", "url": origin + "/register"},
            {"purpose": "register", "method": "POST", "url": origin + "/register",
             "include_hidden_from": origin + "/register", "fields": {"username": "alice", "password": "fixture-password"}},
            {"purpose": "login", "method": "GET", "url": origin + "/login"},
            {"purpose": "login", "method": "POST", "url": origin + "/login",
             "include_hidden_from": origin + "/login", "fields": {"username": "alice", "password": "fixture-password"}},
        ]
        plan["allowed_mutations"] = [
            {"purpose": purpose, "method": "POST", "url": origin + "/" + purpose}
            for purpose in ("register", "login")
        ]
        plan["allow_account_creation"] = True
    return plan


def guard_for(origin=ORIGIN, **options):
    host = httpx.URL(origin).host
    return ScopeGuard.from_engagement(Engagement(authorized_domains=[host], **options))


@pytest.fixture(autouse=True)
def no_container(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Authenticated HTTP research must not use Docker or global session registry")
    monkeypatch.setattr(sessions, "_docker_exec", forbidden)
    monkeypatch.setattr(sessions, "get_registry", forbidden)


def install_http(monkeypatch, handler):
    real_client = httpx.Client
    monkeypatch.setattr(http_transport.httpx, "Client", lambda **kwargs: real_client(
        transport=httpx.MockTransport(handler), **kwargs))


def simple_application(request):
    cookie = request.headers.get("cookie", "")
    if request.url.path == "/me":
        return httpx.Response(200, json={"user": {"id": "alice"}}) if "session=alice" in cookie else httpx.Response(401)
    if request.url.path == "/app":
        return httpx.Response(200, text='<a href="/app/hidden">Hidden area</a><a href="/app/logout">Logout</a>'
                              '<a href="/app/search?token=private-query">Search</a><a href="https://outside.invalid/">External</a>'
                              '<form method="POST" action="/app/change"><input name="password" value="fixture-secret"></form>',
                              headers={"content-type": "text/html"})
    if request.url.path == "/app/hidden":
        assert "session=alice" in cookie
        return httpx.Response(200, text="Private page body that is never exported", headers={"content-type": "text/html"})
    raise AssertionError("Unexpected fixture request")


def runner_for(monkeypatch, config=None, handler=simple_application, guard=None):
    install_http(monkeypatch, handler)
    return ar.ResearchRunner(ar.AuthenticatedResearchPlan.model_validate(config or configuration()), guard or guard_for())


def test_authenticated_crawl_is_get_only_metadata_and_does_not_follow_actions(monkeypatch):
    calls = []
    def handler(request):
        calls.append((request.method, str(request.url)))
        return simple_application(request)
    runner = runner_for(monkeypatch, handler=handler)
    result = runner.run()
    assert result["status"] == "completed"
    assert result["page_count"] == 2 and result["form_count"] == 1
    assert result["blocked_link_count"] == 3
    assert runner.verified_identities == {"alice"}
    assert len(runner.identity_fingerprints["alice"]) == 64
    assert all(method == "GET" and "?" not in url and "outside" not in url for method, url in calls)
    assert not any("logout" in url or "/change" in url for _, url in calls)
    assert result["request_count"] == runner.request_count == 5
    serialized = json.dumps(result)
    for secret in ("fixture-password", "fixture-secret", "private-query", "Private page body", "session=alice"):
        assert secret not in serialized
    assert result["credential_scope"] == "private_to_authenticated_research"
    assert result["findings"] == []
    assert all(not item["submitted"] for item in result["observations"] if item["kind"] == "form")


@pytest.mark.parametrize("field,value", [("origin", "https://fixture.test/path"), ("origin", "https://fixture.test/?secret=x"),
                                        ("read_prefixes", []), ("max_requests", 0), ("max_pages", 101), ("max_depth", 7),
                                        ("deadline_seconds", float("inf")), ("deadline_seconds", float("nan")), ("extra", True)])
def test_plan_strict_bounds(field, value):
    config = configuration(); config[field] = value
    with pytest.raises(ValidationError):
        ar.AuthenticatedResearchPlan.model_validate(config)


@pytest.mark.parametrize("expected", [True, False, None, 1.5, "", "  "])
def test_verification_expected_value_must_identify_an_account(expected):
    config = configuration(); config["identities"][0]["verification"]["expected"] = expected
    with pytest.raises(ValidationError):
        ar.AuthenticatedResearchPlan.model_validate(config)


@pytest.mark.parametrize("pointer", ["user/id", "/bad~escape", "/bad~2"])
def test_json_pointer_validation(pointer):
    config = configuration(); config["identities"][0]["verification"]["json_path"] = pointer
    with pytest.raises(ValidationError):
        ar.AuthenticatedResearchPlan.model_validate(config)


@pytest.mark.parametrize("name", ["anonymous", "Anonymous", "default", "../x", "", "bad name"])
def test_identity_names_are_explicit_unique_and_not_reserved(name):
    config = configuration(); config["identities"][0]["name"] = name
    with pytest.raises(ValidationError):
        ar.AuthenticatedResearchPlan.model_validate(config)


def test_duplicate_identity_names_or_expected_markers_rejected():
    for field in ("name", "verification"):
        config = configuration()
        peer = copy.deepcopy(config["identities"][0]); peer["name"] = "bob"
        peer["verification"]["expected"] = "bob"
        peer[field] = config["identities"][0][field]
        config["identities"].append(peer)
        with pytest.raises(ValidationError):
            ar.AuthenticatedResearchPlan.model_validate(config)


@pytest.mark.parametrize("headers", [{"Host": "outside.invalid"}, {"Cookie": "session=raw"}, {"Authorization": "a\r\nX-Evil: b"},
                                      {"X-API-Key": "a", "x-api-key": "b"}, {"bad header": "value"}])
def test_invalid_identity_headers_fail_at_configuration(headers):
    config = configuration(); config["identities"][0]["headers"] = headers
    with pytest.raises(ValidationError):
        ar.AuthenticatedResearchPlan.model_validate(config)


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(origin="https://outside.invalid"),
    lambda value: value.update(read_prefixes=[ORIGIN + "/app?query=x"]),
    lambda value: value.update(start_urls=[ORIGIN + "/app?secret=x"]),
    lambda value: value.update(start_urls=[ORIGIN + "/app/delete"]),
    lambda value: value["identities"][0]["verification"].update(url="https://outside.invalid/me"),
    lambda value: value["identities"][0].update(setup=[{"purpose": "login", "method": "GET", "url": "https://outside.invalid/login"}]),
    lambda value: value.update(allowed_mutations=[{"purpose": "login", "url": "https://outside.invalid/login"}]),
])
def test_preflight_checks_all_urls_without_spending_request_budget(mutate):
    config = configuration(); mutate(config)
    plan = ar.AuthenticatedResearchPlan.model_validate(config)
    guard = guard_for(max_total_requests=20)
    with pytest.raises(ValueError, match="Invalid authenticated research scope"):
        plan.validate_scope(guard, ORIGIN + "/app")
    assert guard.requests_made() == 0


def test_path_scoped_engagement_does_not_require_origin_root(monkeypatch):
    config = configuration()
    config["identities"][0]["verification"]["url"] = ORIGIN + "/app/me"
    guard = ScopeGuard.from_engagement(Engagement(authorized_url_prefixes=[ORIGIN + "/app"]))
    plan = ar.AuthenticatedResearchPlan.model_validate(config)
    plan.validate_scope(guard, ORIGIN + "/app")
    assert ar.ResearchRunner(plan, guard).plan.origin == ORIGIN


@pytest.mark.parametrize("change", [
    lambda value: value.update(allow_account_creation=False),
    lambda value: value.update(allowed_mutations=[]),
    lambda value: value["identities"][0]["setup"][1].update(include_hidden_from=ORIGIN + "/different"),
    lambda value: value["allowed_mutations"][0].update(purpose="workflow"),
])
def test_setup_mutations_require_exact_opt_in_and_prior_form_get(change):
    config = configuration(setup=True); change(config)
    with pytest.raises(ValueError):
        ar.AuthenticatedResearchPlan.model_validate(config).validate_scope(guard_for(), ORIGIN + "/app")


def test_anonymous_positive_or_invalid_named_probe_fails_closed(monkeypatch):
    for mode in ("public", "bad_identity", "duplicate_json", "wrong_type"):
        def handler(request):
            if mode == "public":
                return httpx.Response(200, json={"user": {"id": "alice"}})
            if not request.headers.get("cookie"):
                return httpx.Response(401)
            if mode == "duplicate_json":
                return httpx.Response(200, text='{"user":{"id":"other","id":"alice"}}')
            return httpx.Response(200, json={"user": {"id": 1 if mode == "wrong_type" else "other"}})
        with monkeypatch.context() as patch:
            runner = runner_for(patch, handler=handler)
            with pytest.raises(ar.ResearchError, match="identity_verification_failed"):
                runner.run()
            assert runner.verified_identities == set()


def test_distinct_literal_markers_in_same_account_do_not_pass_as_distinct_identities(monkeypatch):
    config = configuration()
    config["identities"][0]["verification"] = {"url": ORIGIN + "/me", "marker": "Owner"}
    other = copy.deepcopy(config["identities"][0]); other["name"] = "bob"
    other["verification"]["marker"] = "Dashboard"
    config["identities"].append(other)
    runner = runner_for(monkeypatch, config, lambda request: httpx.Response(200, text="Owner Dashboard") if request.headers.get("cookie") else httpx.Response(401))
    with pytest.raises(ar.ResearchError, match="identities_not_demonstrably_distinct"):
        runner.run()
    assert runner.verified_identities == set() and runner.identity_fingerprints == {}


def test_cross_origin_redirect_blocked_before_request_even_when_host_is_in_engagement(monkeypatch):
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://other.test/app"}) if request.url.path == "/app" else simple_application(request)
    guard = ScopeGuard.from_engagement(Engagement(authorized_domains=["fixture.test", "other.test"]))
    runner = runner_for(monkeypatch, handler=handler, guard=guard)
    with pytest.raises(ar.ResearchError, match="request_out_of_scope"):
        runner.run()
    assert not any("other.test" in url for url in calls)


def test_each_same_origin_redirect_hop_is_charged(monkeypatch):
    def handler(request):
        return httpx.Response(302, headers={"location": "/app/hidden"}) if request.url.path == "/app" else simple_application(request)
    guard = guard_for(max_total_requests=20)
    runner = runner_for(monkeypatch, handler=handler, guard=guard)
    result = runner.run()
    assert result["page_count"] == 1
    assert runner.request_count == guard.requests_made() == 5


@pytest.mark.parametrize("cap,reason", [("max_requests", "request_budget_exhausted"), ("max_pages", "page_budget_exhausted")])
def test_partial_budget_results_are_explicit(monkeypatch, cap, reason):
    config = configuration(); config[cap] = 1
    result = runner_for(monkeypatch, config).run()
    assert result["partial"] and result["stop_reason"] == reason
    if cap == "max_requests":
        assert not result["identities"][0]["verified"]


def test_engagement_budget_caps_all_probes(monkeypatch):
    runner = runner_for(monkeypatch, guard=guard_for(max_total_requests=1))
    result = runner.run()
    assert result["partial"] and result["stop_reason"] == "engagement_request_budget_exhausted"
    assert runner.request_count == 1 and not runner.verified_identities


def test_deadline_exhaustion_makes_no_requests(monkeypatch):
    runner = runner_for(monkeypatch)
    runner._started -= 601
    result = runner.run()
    assert result["stop_reason"] == "deadline_exhausted" and runner.request_count == 0


def test_rate_limit_wait_cannot_dispatch_after_research_deadline(monkeypatch):
    runner = runner_for(monkeypatch, handler=lambda request: pytest.fail("Expired request must not be sent"))
    original = runner.guard.validate
    def consume_remaining_time(tool, args):
        original(tool, args)
        runner._started -= 601
    monkeypatch.setattr(runner.guard, "validate", consume_remaining_time)
    result = runner.run()
    assert result["stop_reason"] == "deadline_exhausted" and runner.request_count == 0


def test_cookie_header_becomes_host_only_jar_and_server_rotation_is_kept(monkeypatch):
    observed = []
    def handler(request):
        cookie = request.headers.get("cookie", ""); observed.append(cookie)
        if request.url.path == "/me":
            if "session=alice" in cookie or "session=rotated" in cookie:
                return httpx.Response(200, json={"user": {"id": "alice"}}, headers={"Set-Cookie": "session=rotated; Path=/; Secure"})
            return httpx.Response(401)
        return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
    runner = runner_for(monkeypatch, handler=handler)
    result = runner.run()
    assert result["status"] == "completed"
    assert observed == ["", "session=alice", "session=rotated", "session=rotated"]
    session = runner.sessions["alice"]
    assert "Cookie" not in session.static_headers
    cookie = next(iter(session.http_cookies))
    assert not cookie.domain_specified and cookie.domain == "fixture.test"


def test_expired_auth_after_crawl_invalidates_identity(monkeypatch):
    probes = 0
    def handler(request):
        nonlocal probes
        if request.url.path == "/me" and request.headers.get("cookie"):
            probes += 1
            if probes > 1:
                return httpx.Response(200, text="Please sign in")
        return simple_application(request)
    runner = runner_for(monkeypatch, handler=handler)
    with pytest.raises(ar.ResearchError, match="identity_expired_during_crawl"):
        runner.run()
    assert not runner.verified_identities


def test_fresh_session_probe_and_clone_do_not_touch_baseline(monkeypatch):
    runner = runner_for(monkeypatch); runner.run()
    clone = runner.clone_session("alice")
    assert runner.verify_session("alice", session=clone)
    clone.http_cookies.clear()
    assert not runner.verify_session("alice", session=clone)
    assert len(list(runner.sessions["alice"].http_cookies)) == 1
    assert runner.verify_session("anonymous", session=runner.clone_session("anonymous"))
    assert not runner.verify_session("bob", session=clone)


def test_public_requests_cannot_override_identity_or_mutate(monkeypatch):
    runner = runner_for(monkeypatch); runner.run()
    before = runner.request_count
    with pytest.raises(ar.ResearchError, match="identity_override_forbidden"):
        runner.request("alice", "GET", ORIGIN + "/app", headers={"Authorization": "Bearer other-secret"})
    with pytest.raises(ar.ResearchError, match="mutation_not_permitted"):
        runner.request("alice", "POST", ORIGIN + "/app")
    with pytest.raises(ar.ResearchError, match="unknown_identity"):
        runner.request("alice", "GET", ORIGIN + "/app", session=runner.clone_session("anonymous"))
    assert runner.request_count == before


def test_post_errors_are_not_retried_and_exception_is_sanitized(monkeypatch):
    config = configuration()
    config["identities"][0]["setup"] = [{"purpose": "login", "method": "POST", "url": ORIGIN + "/login", "fields": {"password": "private-credential"}}]
    config["allowed_mutations"] = [{"purpose": "login", "url": ORIGIN + "/login"}]
    calls = []
    def handler(request):
        calls.append(request.method)
        raise httpx.ReadTimeout("server exposed private-credential")
    runner = runner_for(monkeypatch, config, handler)
    with pytest.raises(ar.ResearchError, match="^scoped_request_failed$") as caught:
        runner.run()
    assert calls == ["POST"] and caught.value.__suppress_context__


def test_post_preserving_redirect_is_not_replayed(monkeypatch):
    config = configuration()
    config["identities"][0]["setup"] = [{"purpose": "login", "method": "POST", "url": ORIGIN + "/login"}]
    config["allowed_mutations"] = [{"purpose": "login", "url": ORIGIN + "/login"}]
    calls = []
    def handler(request):
        calls.append(request.method)
        return httpx.Response(307, headers={"location": "/login"})
    runner = runner_for(monkeypatch, config, handler)
    with pytest.raises(ar.ResearchError, match="mutation_redirect_requires_operator"):
        runner.run()
    assert calls == ["POST"]


def test_run_cannot_repeat_account_creation(monkeypatch):
    runner = runner_for(monkeypatch); runner.run()
    before = runner.request_count
    with pytest.raises(ar.ResearchError, match="research_already_started"):
        runner.run()
    assert runner.request_count == before


def test_form_metadata_strips_query_credentials_and_never_submits(monkeypatch):
    def handler(request):
        if request.url.path == "/app":
            return httpx.Response(200, text='<form action="/app/change?token=private-query-secret" method="POST">'
                                  '<input type name="username"><input type="password" value="private-body-secret"></form>',
                                  headers={"content-type": "text/html"})
        return simple_application(request)
    summary = runner_for(monkeypatch, handler=handler).run()
    form = next(item for item in summary["observations"] if item["kind"] == "form")
    assert form["url"] == ORIGIN + "/app/change" and not form["submitted"]
    assert "private-query-secret" not in json.dumps(summary)
    assert "private-body-secret" not in json.dumps(summary)


def test_oversized_links_are_not_truncated_into_new_requests(monkeypatch):
    calls = []
    def handler(request):
        calls.append(str(request.url))
        if request.url.path == "/app":
            return httpx.Response(200, text='<a href="/app/' + 'x' * 3000 + '">Oversized</a>', headers={"content-type": "text/html"})
        return simple_application(request)
    result = runner_for(monkeypatch, handler=handler).run()
    assert result["page_count"] == 1
    assert all(len(url) < 2048 for url in calls)


@pytest.mark.parametrize("body", [
    '<form method="POST" action="/login"><input type="hidden" name="csrf" value="first"><input type="hidden" name="csrf" value="second"></form>',
    '<form method="POST" action="/login"></form><form method="POST" action="/login"></form>',
    '<form method="POST" action="/other"></form>',
])
def test_hidden_form_must_unambiguously_match_operator_post_url(monkeypatch, body):
    config = configuration()
    config["identities"][0]["setup"] = [
        {"purpose": "login", "method": "GET", "url": ORIGIN + "/login"},
        {"purpose": "login", "method": "POST", "url": ORIGIN + "/login", "include_hidden_from": ORIGIN + "/login"},
    ]
    config["allowed_mutations"] = [{"purpose": "login", "url": ORIGIN + "/login"}]
    calls = []
    def handler(request):
        calls.append(request.method)
        return httpx.Response(200, text=body)
    runner = runner_for(monkeypatch, config, handler)
    with pytest.raises(ar.ResearchError, match="hidden_form_ambiguous"):
        runner.run()
    assert calls == ["GET"]


def test_setup_response_failure_prevents_later_mutation(monkeypatch):
    config = configuration(setup=True)
    calls = []
    def handler(request):
        calls.append(request.method)
        return httpx.Response(503, text="private server error")
    runner = runner_for(monkeypatch, config, handler)
    with pytest.raises(ar.ResearchError, match="setup_failed_or_needs_operator"):
        runner.run()
    assert calls == ["GET"] and not runner.verified_identities


def test_loopback_registration_csrf_login_and_hidden_authenticated_crawl():
    """Actual HTTP only to a stdlib server bound to 127.0.0.1:ephemeral."""
    registered = set()
    events = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, code, body="", headers=None):
            payload = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Content-Type", "text/html")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers(); self.wfile.write(payload)

        def do_GET(self):
            events.append(("GET", self.path))
            cookie = self.headers.get("Cookie", "")
            if self.path in {"/register", "/login"}:
                self.reply(200, f'<form method="POST" action="{self.path}"><input type="hidden" name="csrf" value="csrf-fixture-secret"></form>',
                           {"Set-Cookie": "csrf=csrf-fixture-secret; Path=/; HttpOnly"})
            elif self.path == "/me":
                self.reply(200, '{"user":{"id":"alice"}}') if "session=alice" in cookie else self.reply(401)
            elif self.path == "/app" and "session=alice" in cookie:
                self.reply(200, '<a href="/app/hidden">Hidden</a><a href="/app/logout">Logout</a><form method="POST" action="/app/delete"><input name="id"></form>')
            elif self.path == "/app/hidden" and "session=alice" in cookie:
                self.reply(200, "Private fixture body")
            else:
                self.reply(403)

        def do_POST(self):
            events.append(("POST", self.path))
            fields = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
            correct = fields.get("csrf") == ["csrf-fixture-secret"] and "csrf=csrf-fixture-secret" in self.headers.get("Cookie", "")
            if not correct or fields.get("password") != ["fixture-password"]:
                self.reply(403); return
            if self.path == "/register":
                registered.add(fields["username"][0]); self.reply(201, "Registered")
            elif self.path == "/login" and fields.get("username", [""])[0] in registered:
                self.reply(200, "Logged in", {"Set-Cookie": "session=alice; Path=/; HttpOnly"})
            else:
                self.reply(403)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        plan = ar.AuthenticatedResearchPlan.model_validate(configuration(origin, setup=True))
        runner = ar.ResearchRunner(plan, guard_for(origin))
        result = runner.run()
        assert result["status"] == "completed" and result["page_count"] == 2
        assert registered == {"alice"}
        assert [event for event in events if event[0] == "POST"] == [("POST", "/register"), ("POST", "/login")]
        assert ("GET", "/app/hidden") in events
        assert not any("delete" in path or "logout" in path for _, path in events)
        for secret in ("csrf-fixture-secret", "fixture-password", "Private fixture body"):
            assert secret not in json.dumps(result)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
