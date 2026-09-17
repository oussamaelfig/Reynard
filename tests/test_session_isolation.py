"""Identity state and cookie transfer tested with local fixtures only."""
import base64
import json
import shlex
from http.cookiejar import Cookie, MozillaCookieJar
from unittest.mock import Mock

import httpx
import pytest

from hacking_agent.core import http_transport, sessions, tools
from hacking_agent.core.engagement import Engagement
from hacking_agent.core.scope import ScopeGuard


@pytest.fixture
def registry(monkeypatch):
    monkeypatch.setattr(sessions, "_docker_exec", lambda *args, **kwargs: (0, "", ""))
    reg = sessions.SessionRegistry()
    monkeypatch.setattr(sessions, "get_registry", lambda: reg)
    return reg


def install_http(monkeypatch, handler):
    original_client = httpx.Client
    monkeypatch.setattr(http_transport.httpx, "Client", lambda **kwargs: original_client(
        transport=httpx.MockTransport(handler), **kwargs,
    ))


def send(identity, url="https://a.test/"):
    guard = ScopeGuard.from_engagement(Engagement(authorized_domains=["a.test", "b.test"]))
    guard.validate("http_request", {"url": url})
    return http_transport.request(guard, identity, url=url, method="GET", headers={}, data=None, follow_redirects=True)


def test_response_cookies_persist_only_for_selected_identity(monkeypatch, registry):
    registry.register(sessions.AuthSession("alice"))
    registry.register(sessions.AuthSession("bob"))
    observed = []

    def handler(request):
        observed.append(request.headers.get("cookie", ""))
        if len(observed) == 1:
            return httpx.Response(200, headers={"Set-Cookie": "session=alice; Path=/; Secure; HttpOnly"})
        return httpx.Response(200)

    install_http(monkeypatch, handler)
    send(registry.get("alice"))
    send(registry.get("bob"))
    send(registry.get("alice"))
    assert observed == ["", "", "session=alice"]
    assert registry.read_cookies("alice") == {"session": "alice"}
    assert registry.read_cookies("bob") == {}


def test_deleted_native_cookie_does_not_resurrect_from_legacy_jar(monkeypatch, registry):
    responses = iter([
        httpx.Response(200, headers={"Set-Cookie": "session=alice; Path=/"}),
        httpx.Response(200, headers={"Set-Cookie": "session=; Path=/; Max-Age=0"}),
    ])
    install_http(monkeypatch, lambda request: next(responses))
    send(registry.get(None))
    assert registry.read_cookies() == {"session": "alice"}
    send(registry.get(None))
    docker = Mock(side_effect=AssertionError("Native cookie state is authoritative"))
    monkeypatch.setattr(sessions, "_docker_exec", docker)
    assert registry.read_cookies() == {}
    docker.assert_not_called()


def test_host_only_cookies_do_not_leak_to_subdomains(monkeypatch):
    observed = []

    def handler(request):
        observed.append(request.headers.get("cookie", ""))
        if len(observed) == 1:
            return httpx.Response(200, headers={"Set-Cookie": "session=host-only; Path=/; Secure"})
        return httpx.Response(200)

    install_http(monkeypatch, handler)
    identity = sessions.AuthSession("user")
    send(identity)
    send(identity, "https://sub.a.test/")
    assert observed == ["", ""]


def test_explicit_domain_cookie_can_be_used_by_permitted_subdomain(monkeypatch):
    observed = []

    def handler(request):
        observed.append(request.headers.get("cookie", ""))
        if len(observed) == 1:
            return httpx.Response(200, headers={"Set-Cookie": "session=shared; Domain=a.test; Path=/; Secure"})
        return httpx.Response(200)

    install_http(monkeypatch, handler)
    identity = sessions.AuthSession("user")
    send(identity)
    send(identity, "https://sub.a.test/")
    assert observed == ["", "session=shared"]


@pytest.mark.parametrize("name", ["unknown", ""])
def test_unknown_or_empty_session_never_falls_back_to_active(registry, monkeypatch, name):
    registry.register(sessions.AuthSession("admin", static_headers={"Authorization": "Bearer fixture"}))
    registry.set_active("admin")
    docker = Mock(side_effect=AssertionError("Unknown identity must fail before dispatch"))
    monkeypatch.setattr(tools, "_docker_exec", docker)
    with pytest.raises(ValueError, match="Unknown auth session"):
        tools.http_request("https://a.test/", session=name)
    assert registry.get(None).name == "admin"
    assert "unknown" not in registry.names()
    docker.assert_not_called()


@pytest.mark.parametrize("name", ["", "../admin", "/admin", "a/b", "a\\b", "bad\nname", "a" * 65, "';id"])
def test_invalid_session_names_fail_before_file_operations(registry, monkeypatch, name):
    docker = Mock(side_effect=AssertionError("Invalid identity must not touch files"))
    monkeypatch.setattr(sessions, "_docker_exec", docker)
    with pytest.raises(ValueError):
        registry.register(sessions.AuthSession(name))
    docker.assert_not_called()


@pytest.mark.parametrize("path", ["relative.cookies", "/", "/data/", "/data/../secret", "/data/a\nfile", "C:\\data\\cookies"])
def test_invalid_cookie_paths_fail_before_file_operations(registry, monkeypatch, path):
    docker = Mock(side_effect=AssertionError("Invalid cookie path must not touch files"))
    monkeypatch.setattr(sessions, "_docker_exec", docker)
    with pytest.raises(ValueError):
        registry.register(sessions.AuthSession("user", cookie_jar=path))
    docker.assert_not_called()


def test_explicit_cookie_path_is_shell_quoted(registry, monkeypatch):
    docker = Mock(return_value=(0, "", ""))
    monkeypatch.setattr(sessions, "_docker_exec", docker)
    path = "/data/a';ignored;#.cookies"
    registry.register(sessions.AuthSession("user", cookie_jar=path))
    assert shlex.split(docker.call_args.args[0]) == ["mkdir", "-p", "--", "/data", "&&", "touch", "--", path]


def test_cookie_transfer_roundtrip_is_independent_and_keeps_attributes(registry):
    registry.register(sessions.AuthSession("alice", static_headers={"Authorization": "Bearer fixture"}))
    original = registry.get("alice")
    original.http_cookies_loaded = True
    original.http_cookies.set_cookie(Cookie(
        version=0, name="session", value="fixture", port=None, port_specified=False,
        domain="a.test", domain_specified=False, domain_initial_dot=False,
        path="/private", path_specified=True, secure=True, expires=None, discard=True,
        comment=None, comment_url=None, rest={"HttpOnly": None, "SameSite": "Strict"}, rfc2109=False,
    ))
    payload = original.to_transfer_dict()
    restored = sessions.AuthSession.from_transfer_dict(json.loads(json.dumps(payload)))
    assert restored.to_transfer_dict() == payload
    restored.static_headers["Authorization"] = "changed"
    restored.http_cookies.clear()
    payload["static_headers"]["Authorization"] = "changed snapshot"
    assert original.static_headers["Authorization"] == "Bearer fixture"
    assert len(list(original.http_cookies)) == 1


def test_cookie_transfer_revalidates_identity():
    with pytest.raises(ValueError):
        sessions.AuthSession.from_transfer_dict({"name": "../admin", "http_cookies": []})


@pytest.mark.parametrize("domain", ["a.test", ".a.test"])
def test_written_netscape_cookies_can_be_imported_without_scope_widening(registry, monkeypatch, tmp_path, domain):
    registry.register(sessions.AuthSession("alice"))
    registry.register(sessions.AuthSession("bob"))
    docker = Mock(return_value=(0, "", ""))
    monkeypatch.setattr(sessions, "_docker_exec", docker)
    registry.write_cookies("alice", {"session": "fixture"}, domain)
    tokens = shlex.split(docker.call_args.args[0])
    payload = base64.b64decode(tokens[tokens.index("echo") + 1])
    cookie_file = tmp_path / "fixture.cookies"
    cookie_file.write_bytes(payload)
    imported = MozillaCookieJar(str(cookie_file))
    imported.load(ignore_discard=True, ignore_expires=True)
    assert len(list(imported)) == 1
    message = registry.import_cookies_from_host("bob", str(cookie_file))
    assert message.startswith("Imported")
    cookie = next(iter(registry.get("bob").http_cookies))
    assert cookie.domain == domain
    assert cookie.domain_specified is domain.startswith(".")
    assert registry.read_cookies("bob") == {"session": "fixture"}


def test_cookie_import_retains_curl_session_cookies_but_drops_expired(registry, tmp_path):
    registry.register(sessions.AuthSession("alice"))
    cookie_file = tmp_path / "fixture.cookies"
    cookie_file.write_text(
        "# Netscape HTTP Cookie File\n"
        "a.test\tFALSE\t/\tTRUE\t0\tsession\tfixture\n"
        "a.test\tFALSE\t/\tTRUE\t1\texpired\tfixture\n"
    )
    registry.import_cookies_from_host("alice", str(cookie_file))
    assert registry.read_cookies("alice") == {"session": "fixture"}
    assert next(iter(registry.get("alice").http_cookies)).expires is None


def test_invalid_cookie_fields_do_not_partially_change_identity(registry):
    registry.register(sessions.AuthSession("alice"))
    with pytest.raises(ValueError):
        registry.write_cookies("alice", {"valid": "fixture", "invalid": "value\nextra"}, "a.test")
    assert list(registry.get("alice").http_cookies) == []
    assert registry.get("alice").http_cookies_loaded is False
