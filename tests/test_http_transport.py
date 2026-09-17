"""Native transport and shell integration tested against in-memory HTTP fixtures."""
import json
import shlex
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import httpx
import pytest

from hacking_agent.core import http_transport, sessions, tools
from hacking_agent.core.engagement import Engagement
from hacking_agent.core.scope import RateLimitExceeded, ScopeGuard, ScopeViolation


@pytest.fixture
def mock_http(monkeypatch):
    original_client = httpx.Client
    options = []
    seen = []

    def install(handler):
        def dispatch(request):
            seen.append(request)
            return handler(request)

        def client(**kwargs):
            options.append(kwargs)
            return original_client(transport=httpx.MockTransport(dispatch), **kwargs)

        monkeypatch.setattr(http_transport.httpx, "Client", client)
        return seen, options

    return install


def make_guard(**kwargs):
    return ScopeGuard.from_engagement(Engagement(authorized_domains=["a.test", "b.test"], **kwargs))


def send(guard=None, identity=None, url="https://a.test/start", method="GET", headers=None, data=None, **kwargs):
    guard = guard or make_guard()
    guard.validate("http_request", {"url": url, "method": method, "data": data})
    return http_transport.request(
        guard, identity or sessions.AuthSession("user"), url=url, method=method,
        headers=headers or {}, data=data, follow_redirects=kwargs.pop("follow_redirects", True), **kwargs,
    )


def test_foreign_redirect_is_checked_before_network(mock_http):
    seen, _ = mock_http(lambda request: httpx.Response(302, headers={"Location": "https://outside.test/"}))
    with pytest.raises(ScopeViolation):
        send()
    assert [str(request.url) for request in seen] == ["https://a.test/start"]


def test_redirect_cannot_escape_path_scope(mock_http):
    seen, _ = mock_http(lambda request: httpx.Response(302, headers={"Location": "../admin"}))
    guard = ScopeGuard.from_engagement(Engagement(authorized_url_prefixes=["https://a.test/docs"]))
    with pytest.raises(ScopeViolation):
        send(guard, url="https://a.test/docs/start")
    assert len(seen) == 1


def test_first_destination_is_rechecked_even_after_prior_authorization(mock_http):
    seen, _ = mock_http(lambda request: httpx.Response(200))
    with pytest.raises(ScopeViolation):
        http_transport.request(make_guard(), sessions.AuthSession("user"), url="https://outside.test/",
                               method="GET", headers={}, data=None, follow_redirects=True)
    assert seen == []


def test_each_redirect_is_charged_before_it_runs(mock_http):
    seen, _ = mock_http(lambda request: httpx.Response(302, headers={"Location": "/next"}))
    guard = make_guard(max_total_requests=2)
    with pytest.raises(RateLimitExceeded):
        send(guard)
    assert len(seen) == guard.requests_made() == 2


def test_testing_window_is_rechecked_on_redirect(mock_http):
    active = [True]

    def response(request):
        active[0] = False
        return httpx.Response(302, headers={"Location": "/next"})

    seen, _ = mock_http(response)
    guard = make_guard()
    with patch.object(guard._engagement, "is_within_window", side_effect=lambda: active[0]):
        with pytest.raises(ScopeViolation, match="TESTING WINDOW CLOSED"):
            send(guard)
    assert len(seen) == 1


def test_rate_limiter_counts_redirects(mock_http):
    responses = iter([httpx.Response(302, headers={"Location": "/next"}), httpx.Response(200)])
    seen, _ = mock_http(lambda request: next(responses))
    guard = make_guard(max_requests_per_second=2)
    clock = [0.0]
    waits = []
    guard._now = lambda: clock[0]

    def sleep(seconds):
        waits.append(seconds)
        clock[0] += seconds

    guard._sleep = sleep
    send(guard)
    assert len(seen) == guard.requests_made() == 2
    assert waits == [0.5]


def test_cross_origin_redirect_strips_custom_and_sensitive_headers(mock_http):
    responses = iter([httpx.Response(302, headers={"Location": "https://b.test/end"}), httpx.Response(200)])
    seen, _ = mock_http(lambda request: next(responses))
    send(headers={"Authorization": "Bearer fixture", "Cookie": "session=fixture", "X-Api-Key": "fixture",
                  "Referer": "https://a.test/private?token=fixture", "Accept": "application/json"})
    for key in ("authorization", "cookie", "x-api-key", "referer"):
        assert key in seen[0].headers
        assert key not in seen[1].headers
    assert seen[1].headers["accept"] == "application/json"


@pytest.mark.parametrize("status", [307, 308])
def test_cross_origin_preserved_body_fails_closed(mock_http, status):
    seen, _ = mock_http(lambda request: httpx.Response(status, headers={"Location": "https://b.test/end"}))
    with pytest.raises(ScopeViolation, match="forward a request body"):
        send(method="POST", data="password=fixture")
    assert len(seen) == 1


@pytest.mark.parametrize("status", [301, 302, 303])
def test_post_redirect_to_get_discards_body_and_content_type(mock_http, status):
    responses = iter([httpx.Response(status, headers={"Location": "https://b.test/end"}), httpx.Response(200)])
    seen, _ = mock_http(lambda request: next(responses))
    send(method="POST", data="password=fixture", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert seen[1].method == "GET"
    assert seen[1].content == b""
    assert "content-type" not in seen[1].headers


def test_same_origin_307_preserves_method_body_and_identity(mock_http):
    responses = iter([httpx.Response(307, headers={"Location": "/end"}), httpx.Response(200)])
    seen, _ = mock_http(lambda request: next(responses))
    send(method="POST", data="value=fixture", headers={"Authorization": "Bearer fixture"})
    assert seen[1].method == "POST"
    assert seen[1].content == b"value=fixture"
    assert seen[1].headers["authorization"] == "Bearer fixture"


def test_redirect_limit_and_opt_out(mock_http, monkeypatch):
    seen, _ = mock_http(lambda request: httpx.Response(302, headers={"Location": "/loop"}))
    monkeypatch.setattr(http_transport, "MAX_REDIRECTS", 2)
    with pytest.raises(ScopeViolation, match="redirect limit"):
        send()
    assert len(seen) == 3
    assert send(follow_redirects=False)["status_code"] == 302
    assert len(seen) == 4


@pytest.mark.parametrize("size,truncated", [(7, False), (8, False), (9, True)])
def test_response_truncation_is_explicit(mock_http, monkeypatch, size, truncated):
    mock_http(lambda request: httpx.Response(200, content=b"x" * size))
    monkeypatch.setattr(http_transport, "MAX_RESPONSE_BYTES", 8)
    result = send()
    assert result["response"].split("\r\n\r\n", 1)[1] == "x" * min(size, 8)
    assert result["truncated"] is truncated


@pytest.mark.parametrize("key", ["Host", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Authorization"])
def test_production_rejects_routing_and_framing_overrides(mock_http, key):
    seen, _ = mock_http(lambda request: httpx.Response(200))
    with pytest.raises(ScopeViolation, match="Routing/framing"):
        send(headers={key: "fixture"})
    assert seen == []


def test_tls_verification_and_no_ambient_proxy_by_default(mock_http):
    _, options = mock_http(lambda request: httpx.Response(200))
    send()
    send(insecure=True)
    assert options[0]["verify"] is True
    assert options[1]["verify"] is False
    assert all(option["trust_env"] is False and option["follow_redirects"] is False for option in options)


def test_invalid_http_method_is_rejected_before_network(mock_http):
    seen, _ = mock_http(lambda request: httpx.Response(200))
    with pytest.raises(ValueError, match="Unsupported HTTP method"):
        send(method="POST;ignored")
    assert seen == []


def test_baseline_wrappers_use_tls_verification(monkeypatch):
    http = Mock(return_value=json.dumps({"response": "HTTP/1.1 200 OK\r\n\r\nfixture", "session": "user"}))
    monkeypatch.setattr(tools, "http_request", http)
    store = Mock()
    store.capture.return_value.to_dict.return_value = {"name": "fixture"}
    store.diff.return_value = {"baseline": "fixture"}
    monkeypatch.setattr(tools.differ_mod, "get_store", lambda: store)
    tools.capture_baseline("fixture", "https://a.test")
    tools.diff_against_baseline("fixture", "https://a.test")
    assert len(http.call_args_list) == 2
    assert all(call.kwargs["insecure"] is False for call in http.call_args_list)


def test_execution_scope_restores_nested_context_and_does_not_leak_to_threads():
    a, b = make_guard(), make_guard()
    assert http_transport.active_guard() is None
    with http_transport.execution_scope(a):
        with pytest.raises(RuntimeError):
            with http_transport.execution_scope(b):
                assert http_transport.active_guard() is b
                raise RuntimeError("fixture")
        assert http_transport.active_guard() is a
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(http_transport.active_guard).result() is None
    assert http_transport.active_guard() is None


def test_http_tool_dispatches_to_native_transport_and_merges_header_case(mock_http, monkeypatch):
    monkeypatch.setattr(sessions, "_docker_exec", lambda *args, **kwargs: (0, "", ""))
    registry = sessions.SessionRegistry()
    registry.register(sessions.AuthSession("alice", static_headers={"Authorization": "Bearer old"}))
    monkeypatch.setattr(sessions, "get_registry", lambda: registry)
    docker = Mock(side_effect=AssertionError("Native request must not dispatch curl"))
    monkeypatch.setattr(tools, "_docker_exec", docker)
    seen, _ = mock_http(lambda request: httpx.Response(200, text="fixture"))
    guard = make_guard()
    guard.validate("http_request", {"url": "https://a.test/"})
    with http_transport.execution_scope(guard):
        result = json.loads(tools.http_request("https://a.test/", session="alice", headers={"authorization": "Bearer replacement"}))
    assert seen[0].headers.get_list("authorization") == ["Bearer replacement"]
    assert result["session"] == "alice"
    docker.assert_not_called()


def test_legacy_curl_quotes_every_untrusted_argument_and_verifies_tls(monkeypatch):
    identity = sessions.AuthSession("user", cookie_jar="/data/a'; ignored 'b.cookies")
    monkeypatch.setattr(sessions, "get_registry", lambda: Mock(get=lambda name: identity))
    docker = Mock(return_value={"stdout": "", "stderr": "", "exit_code": 0})
    monkeypatch.setattr(tools, "_docker_exec", docker)
    url = "https://a.test/?q=';ignored;#"
    data = "payload=';ignored;#"
    tools.http_request(url, method="POST", data=data, headers={"X-Fixture": "';ignored;#"})
    argv = shlex.split(docker.call_args.args[0])
    assert "-k" not in argv
    assert argv[argv.index("--url") + 1] == url
    assert argv[argv.index("--data-raw") + 1] == data
    assert argv[argv.index("-b") + 1] == identity.cookie_jar
    assert argv[argv.index("-H") + 1] == "x-fixture: ';ignored;#"
    assert argv[argv.index("--proto-redir") + 1] == "=http,https"


def test_file_tool_paths_and_contents_remain_single_shell_arguments(monkeypatch):
    docker = Mock(return_value={"stdout": "fixture", "stderr": "", "exit_code": 0})
    monkeypatch.setattr(tools, "_docker_exec", docker)
    path = "/data/a';ignored;#.txt"
    tools.read_file(path)
    assert shlex.split(docker.call_args.args[0]) == ["cat", "--", path]
    tools.list_dir(path)
    assert shlex.split(docker.call_args.args[0]) == ["ls", "-lah", "--", path, "2>&1"]
    tools.write_file(path, "value';ignored;#")
    assert shlex.split(docker.call_args.args[0]) == ["printf", "%s", "value';ignored;#", ">", path]
