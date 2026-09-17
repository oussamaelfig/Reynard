"""RunRequest validation + mapping (run harness)."""
from __future__ import annotations

from hacking_agent.harness.models import RunRequest, RunStatus
from hacking_agent.harness.models import AuthSessionSpec
import pytest
from pydantic import ValidationError


def test_authorization_error_requires_ack():
    req = RunRequest(authorized_domains=["example.com"], authorized=False)
    err = req.authorization_error()
    assert err and "authorized" in err.lower()


def test_authorization_error_requires_scope():
    req = RunRequest(authorized=True)  # ack but no scope
    err = req.authorization_error()
    assert err and "scope" in err.lower()


def test_runnable_request_has_no_error():
    req = RunRequest(authorized_domains=["example.com"], authorized=True,
                     description="find idor")
    assert req.authorization_error() is None
    assert req.has_scope() is True


def test_resolved_targets_prefers_explicit_then_domains():
    explicit = RunRequest(targets=["app.example.com", "https://x.example.com/"],
                          authorized_domains=["example.com"], authorized=True)
    assert explicit.resolved_targets() == [
        "https://app.example.com", "https://x.example.com/"]

    from_domains = RunRequest(authorized_domains=["a.com", "b.com"], authorized=True)
    assert from_domains.resolved_targets() == ["https://a.com/", "https://b.com/"]


def test_to_engagement_dict_maps_scope_and_roE():
    req = RunRequest(authorized_domains=["example.com"],
                     authorized_cidrs=["10.0.0.0/24"],
                     out_of_scope=["blog.example.com"],
                     max_requests_per_second=2.0, max_total_requests=500,
                     allow_destructive=True, description="x" * 2000,
                     authorized=True)
    d = req.to_engagement_dict()
    assert d["authorized_domains"] == ["example.com"]
    assert d["authorized_cidrs"] == ["10.0.0.0/24"]
    assert d["out_of_scope"] == ["blog.example.com"]
    assert d["max_requests_per_second"] == 2.0
    assert d["max_total_requests"] == 500
    assert d["allow_destructive"] is True
    assert len(d["notes"]) <= 1000  # description is truncated


def test_status_terminality():
    assert RunStatus.completed.is_terminal
    assert RunStatus.failed.is_terminal
    assert RunStatus.cancelled.is_terminal
    assert not RunStatus.queued.is_terminal
    assert not RunStatus.running.is_terminal


@pytest.mark.parametrize("fields", [
    {"max_iterations": 0}, {"max_iterations": 1001},
    {"per_target_timeout": float("inf")}, {"per_target_timeout": -1},
    {"max_requests_per_second": float("nan")}, {"max_total_requests": -1},
    {"targets": ["x"] * 101}, {"description": "x" * 20001},
    {"mission_mode": "unknown"}, {"authorized_domains": [""]},
])
def test_invalid_unbounded_options_rejected(fields):
    with pytest.raises(ValidationError):
        RunRequest(**fields)


def test_session_header_injection_and_ambiguous_identities_rejected():
    for fields in ({"cookie_header": "cookie=x\r\nHost: evil.invalid"},
                   {"headers": {"X-Test\nInjected": "x"}},
                   {"headers": {"X Test": "x"}},
                   {"headers": {"X-Test": "a\x00b"}}):
        with pytest.raises(ValidationError):
            AuthSessionSpec(name="user", **fields)
    with pytest.raises(ValidationError):
        RunRequest(auth_sessions=[AuthSessionSpec(name="user"), AuthSessionSpec(name="user")])
    with pytest.raises(ValidationError):
        RunRequest(auth_sessions=[AuthSessionSpec(name="user", headers={
            str(i): "x" * 32768 for i in range(9)
        })])


@pytest.mark.parametrize("name", ["../admin", "a" * 65, "user name", ""])
def test_session_name_matches_runtime_registry_contract(name):
    with pytest.raises(ValidationError):
        AuthSessionSpec(name=name)
