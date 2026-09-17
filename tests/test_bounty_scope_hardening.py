"""Offline import/pagination regressions: no remote API requests are made."""
import json

import pytest

from hacking_agent.core.engagement import EngagementError
from hacking_agent.core.scope import ScopeGuard
from hacking_agent.integrations.bounty import BountyScopeError, HackerOneClient, import_scope_file, parse_structured_scopes


def test_structured_url_scope_does_not_widen_to_host(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"in_scope": ["https://example.com:8443/docs"]}))
    eng = import_scope_file(path)
    g = ScopeGuard.from_engagement(eng)
    assert not eng.authorized_domains
    assert g.is_in_scope("https://example.com:8443/docs/a")
    assert not g.is_in_scope("https://example.com:8443/admin")
    assert not g.is_in_scope("https://example.com/docs")


@pytest.mark.parametrize("eligibility", [False, "false", "False", "0", 0, "no"])
def test_false_eligibility_never_grants_authorization(eligibility):
    scopes = parse_structured_scopes([{
        "asset_type": "URL", "asset_identifier": "example.com", "eligible_for_submission": eligibility,
    }])
    assert scopes.authorized_domains == []
    assert scopes.out_of_scope == ["example.com"]


def test_explicit_testing_prohibition_wins_over_submission_eligibility():
    scopes = parse_structured_scopes([{
        "asset_type": "DOMAIN", "asset_identifier": "example.com",
        "eligible_for_submission": True, "eligible_for_testing": False,
    }])
    assert scopes.authorized_domains == []


@pytest.mark.parametrize("identifier", [
    "https://example.com/docs/../admin", "https://*.example.com/docs",
    "https://user@example.com/docs", "example.com:8443",
])
def test_ambiguous_scope_assets_rejected(identifier):
    with pytest.raises(BountyScopeError):
        parse_structured_scopes([{"asset_type": "URL", "asset_identifier": identifier}])


def test_url_path_without_scheme_is_https_prefix_not_a_cidr():
    scopes = parse_structured_scopes([{"asset_type": "URL", "asset_identifier": "example.com/docs"}])
    assert scopes.authorized_url_prefixes == ["https://example.com/docs"]
    assert scopes.authorized_cidrs == []


def test_imported_bounty_metadata_keeps_testing_window(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"in_scope": ["example.com"], "testing_window": {"end": "2000-01-01"}}))
    assert not import_scope_file(path).is_within_window()
    path.write_text(json.dumps({"in_scope": ["example.com"], "testing_window": {"end": "invalid"}}))
    with pytest.raises(EngagementError):
        import_scope_file(path)


def test_authorized_prefix_only_engagement_file_import(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"authorized_url_prefixes": ["https://example.com/docs"]}))
    assert import_scope_file(path).authorized_url_prefixes == ["https://example.com/docs"]


def test_hackerone_prefix_only_result_is_testable():
    def transport(method, url, headers):
        return 200, {"data": [{"attributes": {"asset_type": "URL", "asset_identifier": "https://example.com/docs"}}]}

    eng = HackerOneClient(username="u", token="t", transport=transport).build_engagement("acme")
    assert eng.authorized_url_prefixes == ["https://example.com/docs"]
    assert eng.authorized_domains == []


@pytest.mark.parametrize("next_url", [
    "https://evil.test/v1/next", "http://api.hackerone.com/v1/next",
    "https://api.hackerone.com:8443/v1/next", "https://api.hackerone.com/outside-api",
    "https://user@api.hackerone.com/v1/next", "https://[broken/",
    "https://api.hackerone.com/v1/%2e%2e/outside-api",
])
def test_pagination_never_sends_credentials_to_foreign_boundary(next_url):
    calls = []

    def transport(method, url, headers):
        calls.append(url)
        return 200, {"data": [], "links": {"next": next_url}}

    with pytest.raises(BountyScopeError):
        HackerOneClient(username="u", token="secret", transport=transport).fetch_structured_scopes("acme")
    assert len(calls) == 1


def test_cyclic_pagination_does_not_return_partial_authorization():
    calls = []

    def transport(method, url, headers):
        calls.append(url)
        return 200, {"data": [], "links": {"next": url}}

    with pytest.raises(BountyScopeError, match="incomplete or cyclic"):
        HackerOneClient(username="u", token="secret", transport=transport).fetch_structured_scopes("acme")
    assert len(calls) == 1


def test_pagination_cap_does_not_drop_later_exclusions():
    calls = []

    def transport(method, url, headers):
        calls.append(url)
        return 200, {"data": [], "links": {"next": f"/v1/next?page={len(calls)}"}}

    with pytest.raises(BountyScopeError, match="incomplete or cyclic"):
        HackerOneClient(username="u", token="secret", transport=transport).fetch_structured_scopes("acme")
    assert len(calls) == 50
