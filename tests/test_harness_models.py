"""RunRequest validation + mapping (run harness)."""
from __future__ import annotations

from hacking_agent.harness.models import RunRequest, RunStatus


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
