"""Local bridge boundaries, using an in-memory HTTP transport only."""
import httpx
import pytest

from hacking_agent.integrations.caido_local import CaidoLocalBridgeClient


def make_client():
    seen = []
    client = CaidoLocalBridgeClient(token="s" * 32)
    client._client.close()
    client._client = httpx.Client(transport=httpx.MockTransport(
        lambda request: seen.append(request) or httpx.Response(200, json={"ok": True})
    ))
    return client, seen


@pytest.mark.parametrize("url", [
    "https://outside.invalid", "http://127.0.0.1.evil.invalid:17650",
    "http://token@127.0.0.1:17650", "http://127.0.0.1:17650/path",
    "file:///tmp/test", "http://127.0.0.1:17650/#fragment",
])
def test_non_loopback_bridge_configuration_rejected(url):
    with pytest.raises(ValueError):
        CaidoLocalBridgeClient(base_url=url)


@pytest.mark.parametrize("path", [
    "http://127.0.0.1:17650.evil.invalid/status",
    "http://127.0.0.1:17650@evil.invalid/status",
    "http://127.0.0.1:17651/status", "https://127.0.0.1:17650/status",
    "//evil.invalid/status", "/status#secret", "/\\evil.invalid/status",
])
def test_token_cannot_leave_exact_bridge_origin(path):
    client, seen = make_client()
    try:
        assert "error" in client.request("GET", path)
        assert seen == []
    finally:
        client.close()


def test_status_and_all_requests_require_token(monkeypatch):
    monkeypatch.delenv("CAIDO_LOCAL_BRIDGE_TOKEN", raising=False)
    monkeypatch.delenv("CAIDO_BRIDGE_TOKEN", raising=False)
    client = CaidoLocalBridgeClient(token="")
    try:
        assert client.status()["configured"] is False
        assert "error" in client.request("GET", "/status", require_token=False)
    finally:
        client.close()


def test_auth_headers_fixed_ids_encoded_and_no_redirect_follow():
    client, seen = make_client()
    try:
        client.request("GET", "http://127.0.0.1:17650/status", headers={
            "Authorization": "attacker", "Host": "outside.invalid", "Origin": "null",
        })
        assert seen[0].headers["Authorization"] == "Bearer " + "s" * 32
        assert seen[0].headers["host"] == "127.0.0.1:17650"
        assert "origin" not in seen[0].headers
        client.send_replay_session("x/../../history")
        assert b"x%2F..%2F..%2Fhistory/send" in seen[1].url.raw_path
        assert seen[1].headers["content-type"] == "application/json"
    finally:
        client.close()


def test_redirect_response_does_not_send_token_elsewhere():
    client, seen = make_client()
    client._client.close()
    client._client = httpx.Client(transport=httpx.MockTransport(
        lambda request: seen.append(request) or httpx.Response(
            302, headers={"Location": "https://outside.invalid"})
    ), follow_redirects=False)
    try:
        assert client.status()["status_code"] == 302
        assert len(seen) == 1
    finally:
        client.close()
