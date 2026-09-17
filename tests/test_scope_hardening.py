"""Local regression fixtures for authorization boundaries; never perform I/O."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from hacking_agent.core.engagement import Engagement, EngagementError, engagement_from_dict
from hacking_agent.core.scope import ENGAGEMENT_UNBOUNDED_TOOLS, RateLimitExceeded, ScopeGuard, ScopeViolation


def guard(**kwargs):
    return ScopeGuard.from_engagement(Engagement(authorized_domains=["example.com"], **kwargs))


@pytest.mark.parametrize("target", [
    "http://localhost", "http://127.0.0.1", "https://portswigger.net",
    "https://a.web-security-academy.net", "https://a.exploit-server.net",
])
def test_engagement_never_inherits_lab_infrastructure(target):
    g = guard()
    assert g.engagement_attached
    assert not g.is_in_scope(target)
    with pytest.raises(ScopeViolation):
        g.validate("http_request", {"url": target})


def test_loopback_requires_explicit_authorization_in_engagement():
    g = ScopeGuard.from_engagement(Engagement(authorized_domains=["localhost", "127.0.0.1"]))
    assert g.is_in_scope("http://localhost:8000")
    assert g.is_in_scope("http://127.0.0.1:8000")


@pytest.mark.parametrize("target", [
    "https://example.com@evil.test/", "https://evil.test@example.com/",
    "https://example.com\\@evil.test/", "https://example.com\n.evil.test/",
    "https://example.com:99999/", "https://example.com:/", "https://example.com:0/",
    "https://[broken/", "file://example.com/data", "https:///example.com",
    "//example.com/data", "example.com/path", "example.com --script=external",
    "https://example.com%2e.evil.test/", "http://127.1", "http://2130706433",
    "http://0x7f000001", "http://0177.0.0.1", "10.0.0.0/8", "",
])
def test_malformed_or_ambiguous_target_is_not_authorization(target):
    g = guard(authorized_cidrs=["10.0.0.0/24"])
    assert not g.is_in_scope(target)
    with pytest.raises(ScopeViolation):
        g.validate("http_request", {"url": target})


def test_missing_http_target_never_passes_as_local_tool():
    with pytest.raises(ScopeViolation, match="explicit target"):
        guard().validate("http_request", {})


def test_case_idna_and_dns_trailing_dot_are_canonicalized():
    g = ScopeGuard.from_engagement(Engagement(authorized_domains=["EXAMPLE.COM.", "bücher.example"]))
    assert g.is_in_scope("https://APP.Example.COM./x")
    assert g.is_in_scope("https://xn--bcher-kva.example/x")


def test_lossy_idna_mapping_cannot_authorize_a_different_dns_name():
    g = ScopeGuard.from_engagement(Engagement(authorized_domains=["fass.example"]))
    assert not g.is_in_scope("https://faß.example/")
    with pytest.raises(EngagementError):
        ScopeGuard.from_engagement(Engagement(authorized_domains=["faß.example"]))


def test_ip_scope_does_not_allow_dns_names_ending_in_literal():
    g = ScopeGuard.from_engagement(Engagement(authorized_domains=["10.0.0.1"]))
    assert g.is_in_scope("http://10.0.0.1")
    assert not g.is_in_scope("http://untrusted.10.0.0.1")


def test_ipv6_and_denied_cidr():
    g = guard(authorized_cidrs=["10.0.0.0/24", "2001:db8::/32"], out_of_scope=["10.0.0.128/25"])
    assert g.is_in_scope("http://[2001:db8::1]:8080/")
    assert g.is_in_scope("2001:db8::1")
    assert g.is_in_scope("http://10.0.0.127/")
    assert not g.is_in_scope("http://10.0.0.128/")


@pytest.mark.parametrize("tool", sorted(ENGAGEMENT_UNBOUNDED_TOOLS))
def test_unbounded_tools_fail_closed_for_engagement(tool):
    with pytest.raises(ScopeViolation, match="cannot enforce every destination"):
        guard().validate(tool, {"url": "https://example.com", "command": "id"})


@pytest.mark.parametrize("operation", ["send_raw", "create_replay_session", "send_replay_session", "raw_bridge_request"])
def test_caido_replay_or_passthrough_cannot_bypass_boundary(operation):
    with pytest.raises(ScopeViolation):
        guard().validate("caido_local_api", {"operation": operation, "args": {"session_id": "123"}})


def test_raw_extra_args_cannot_smuggle_shell_or_new_targets():
    with pytest.raises(ScopeViolation):
        guard().validate("jwt_tool", {"token": "a.b.c", "extra_args": "; curl https://evil.test"})
    guard().validate("jwt_tool", {"token": "a.b.c"})


def test_web_fetch_scope_is_checked_on_legacy_path_too():
    g = ScopeGuard.from_target_url("https://example.com")
    with pytest.raises(ScopeViolation):
        g.validate("web_fetch", {"url": "https://evil.test"})


def test_lab_names_do_not_exempt_destructive_sql_in_production():
    with pytest.raises(ScopeViolation, match="DESTRUCTIVE"):
        guard().validate("http_request", {"url": "https://example.com", "data": "DELETE FROM users WHERE name='carlos'"})


@pytest.mark.parametrize("config", [
    {"testing_window_start": "not-a-date"},
    {"testing_window_start": "2026-12-01", "testing_window_end": "2026-01-01"},
    {"max_requests_per_second": float("nan")},
    {"max_requests_per_second": float("inf")},
    {"max_total_requests": -1}, {"authorized_domains": ["https://example.com/docs"]},
    {"authorized_domains": ["example.com:443"]}, {"authorized_cidrs": ["not-a-network"]},
    {"out_of_scope": ["bad/deny"]},
    {"authorized_url_prefixes": ["https://example.com/docs/../private"]},
])
def test_invalid_engagement_never_silently_opens_scope(config):
    with pytest.raises(EngagementError):
        engagement_from_dict(config)


def test_aware_and_naive_window_values_use_utc():
    eng = Engagement(testing_window_start="2026-01-01T02:00:00+02:00", testing_window_end="2026-01-01T01:00:00Z")
    assert eng.is_within_window(datetime(2026, 1, 1, 0, 30))
    assert eng.is_within_window(datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc))
    assert not eng.is_within_window(datetime(2026, 1, 1, 1, 1, tzinfo=timezone.utc))


def test_window_rechecked_on_every_target_call_but_allows_local_processing():
    g = guard(testing_window_end="2000-01-01")
    assert g.is_in_scope("https://example.com")  # predicates do not consume policy
    with pytest.raises(ScopeViolation, match="TESTING WINDOW CLOSED"):
        g.validate("http_request", {"url": "https://example.com"})
    g.validate("analyze_response", {"response_body": "saved local response"})
    assert g.requests_made() == 0


def test_rate_wait_cannot_cross_testing_deadline_and_reserve_a_request():
    g = guard(max_requests_per_second=1, max_total_requests=10)
    clock = [0.0]
    g._now = lambda: clock[0]
    g._sleep = lambda seconds: clock.__setitem__(0, clock[0] + seconds)
    with patch.object(g._engagement, "is_within_window", side_effect=lambda: clock[0] < 0.5):
        g.validate("http_request", {"url": "https://example.com/1"})
        with pytest.raises(ScopeViolation, match="TESTING WINDOW CLOSED"):
            g.validate("http_request", {"url": "https://example.com/2"})
    assert g.requests_made() == 1


def test_attached_policy_is_snapshot_of_engagement():
    eng = Engagement(authorized_domains=["example.com"], testing_window_end="2000-01-01")
    g = ScopeGuard.from_engagement(eng)
    eng.testing_window_end = "2100-01-01"
    eng.authorized_domains.append("evil.test")
    assert not g.is_in_scope("https://evil.test")
    with pytest.raises(ScopeViolation, match="TESTING WINDOW CLOSED"):
        g.validate_window()


def test_concurrent_requests_cannot_exceed_atomic_cap():
    g = guard(max_total_requests=7)

    def attempt(_):
        try:
            g.validate("http_request", {"url": "https://example.com"})
            return True
        except RateLimitExceeded:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(30))) == 7
    assert g.requests_made() == 7
