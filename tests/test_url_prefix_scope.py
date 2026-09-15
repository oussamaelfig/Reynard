"""Path-scoped URL prefixes (bounty assets like https://example.com/docs)."""
from __future__ import annotations

import pytest

from hacking_agent.core.engagement import engagement_from_dict
from hacking_agent.core.scope import ScopeGuard, ScopeViolation


def _guard():
    eng = engagement_from_dict({
        "authorized_domains": ["app.example.com"],
        "authorized_url_prefixes": ["https://example.com/docs"],
        "out_of_scope": ["blog.example.com"],
    })
    return ScopeGuard.from_engagement(eng)


def test_prefix_allows_docs_path_not_marketing_apex():
    g = _guard()
    g.validate("http_request", {"url": "https://example.com/docs"})
    g.validate("http_request", {"url": "https://example.com/docs/home"})
    g.validate("http_request", {"url": "https://app.example.com/login"})
    with pytest.raises(ScopeViolation):
        g.validate("http_request", {"url": "https://example.com/"})
    with pytest.raises(ScopeViolation):
        g.validate("http_request", {"url": "https://example.com/pricing"})
    with pytest.raises(ScopeViolation):
        g.validate("http_request", {"url": "https://blog.example.com/"})


def test_host_only_target_does_not_inherit_url_prefix():
    g = _guard()
    with pytest.raises(ScopeViolation):
        g.validate("dns_recon", {"domain": "example.com"})


def test_attach_engagement_does_not_keep_inferred_target_host():
    """A docs URL must not authorize the marketing apex."""
    g = ScopeGuard.from_target_url("https://example.com/docs")
    assert g.is_in_scope("https://example.com/pricing")  # inferred host, pre-attach
    eng = engagement_from_dict({
        "authorized_domains": ["app.example.com"],
        "authorized_url_prefixes": ["https://example.com/docs"],
    })
    g.attach_engagement(eng)
    g.validate("http_request", {"url": "https://example.com/docs/home"})
    g.validate("http_request", {"url": "https://app.example.com/"})
    with pytest.raises(ScopeViolation):
        g.validate("http_request", {"url": "https://example.com/"})
    with pytest.raises(ScopeViolation):
        g.validate("http_request", {"url": "https://example.com/pricing"})
