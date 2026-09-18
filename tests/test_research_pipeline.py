"""Authenticated research admission, private IPC, and agent handoff (no targets)."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from hacking_agent.core.engagement import Engagement
from hacking_agent.core.scope import ScopeGuard
from hacking_agent.core import research_pipeline as pipeline
from hacking_agent.harness.models import RunRequest
from hacking_agent.harness.store import RunStore


def research_plan():
    origin = "https://fixture.invalid"
    return {
        "origin": origin,
        "identities": [{
            "name": "alice", "cookie_header": "sid=private-test-cookie",
            "verification": {"url": origin + "/api/me", "json_path": "/id", "expected": "alice"},
        }],
        "read_prefixes": [origin + "/api", origin + "/account"],
        "max_requests": 100,
    }


def business_rule():
    return {
        "name": "private-record", "url": "https://fixture.invalid/api/record/42",
        "owner_identity": "alice", "denied_identity": "anonymous",
        "json_path": "/id", "expected_value": "private-object-42",
    }


def research_request(**overrides):
    values = {"targets": ["https://fixture.invalid/"], "authorized": True,
              "authorized_domains": ["fixture.invalid"],
              "authenticated_research": research_plan(), "business_rules": [business_rule()]}
    values.update(overrides)
    return RunRequest(**values)


def guard():
    return ScopeGuard.from_engagement(Engagement(authorized_domains=["fixture.invalid"]))


def test_authorized_plan_admitted_without_request_or_budget_consumption():
    scope = guard()
    plan, rules = pipeline.parse_research_inputs(research_plan(), [business_rule()], scope,
                                               "https://fixture.invalid/")
    assert len(plan.identities) == len(rules) == 1
    assert scope._request_count == 0
    assert research_request().authorization_error() is None


def test_documented_local_sample_validates_without_network():
    root = Path(__file__).resolve().parents[1]
    raw = json.loads((root / "eval/authenticated-research.sample.json").read_text(encoding="utf-8"))
    scope = ScopeGuard.from_engagement(Engagement(authorized_url_prefixes=["http://127.0.0.1:8080/"]))
    parsed, rules = pipeline.parse_research_inputs(raw, [], scope, "http://127.0.0.1:8080/")
    assert len(parsed.identities) == 2 and rules == []
    assert scope._request_count == 0


@pytest.mark.parametrize("overrides", [
    {"authenticated_research": None},
    {"auth_sessions": [{"name": "legacy", "cookie_header": "sid=x"}]},
    {"targets": ["https://fixture.invalid/", "https://fixture.invalid/second"]},
])
def test_ambiguous_or_missing_plan_rejected(overrides):
    with pytest.raises(ValueError):
        research_request(**overrides)


@pytest.mark.parametrize("change", [
    {"url": "https://outside.invalid/api/record"},
    {"url": "https://fixture.invalid/not-approved/record"},
    {"url": "https://fixture.invalid/api/record?id=42"},
    {"owner_identity": "undeclared"},
    {"denied_identity": "alice"},
])
def test_bad_business_rule_refused_before_execution(change):
    rule = {**business_rule(), **change}
    with pytest.raises(ValueError, match="invalid authenticated research configuration"):
        pipeline.parse_research_inputs(research_plan(), [rule], guard(), "https://fixture.invalid/")


def test_duplicate_business_rule_names_rejected():
    with pytest.raises(ValueError):
        pipeline.parse_research_inputs(research_plan(), [business_rule(), business_rule()],
                                       guard(), "https://fixture.invalid/")


def test_scope_failure_does_not_echo_private_config():
    request = research_request(authorized_url_prefixes=["https://fixture.invalid/account"],
                              authorized_domains=[], targets=["https://fixture.invalid/account"])
    message = request.authorization_error()
    assert message and "Invalid authenticated research" in message
    assert "private-test-cookie" not in message


def test_all_private_plan_fields_are_ephemeral_and_consumed_once(tmp_path):
    with_store = RunStore(root=tmp_path)
    try:
        rec = with_store.create(research_request())
        for path in tmp_path.rglob("*"):
            if path.is_file():
                contents = path.read_bytes()
                assert b"private-test-cookie" not in contents
                assert b"private-object-42" not in contents
        restored = with_store.load_request(rec.id)
        assert restored.authenticated_research is None and restored.business_rules == []
        private = with_store.take_worker_inputs(rec.id)
        assert private["authenticated_research"]["identities"][0]["cookie_header"] == "sid=private-test-cookie"
        assert private["business_rules"][0]["expected_value"] == "private-object-42"
        assert with_store.take_worker_inputs(rec.id) == []
    finally:
        with_store.close()


def test_restart_discards_private_plans(tmp_path):
    store = RunStore(root=tmp_path)
    try:
        rec = store.create(research_request())
        store.recover_interrupted()
        assert store.take_worker_inputs(rec.id) == []
    finally:
        store.close()


def test_observations_enter_agent_surface_without_promoting_findings(monkeypatch):
    scope = guard()
    research = {"observations": [{"kind": "page", "url": "https://fixture.invalid/account/deep", "identity": "alice"}],
                "requests": 7}
    runner = SimpleNamespace(run=Mock(return_value=research), sessions={"secret": "never transfer"},
                             verified_identities={"alice"}, request_count=21)
    constructor = Mock(return_value=runner)
    monkeypatch.setattr(pipeline, "ResearchRunner", constructor)
    monkeypatch.setattr(pipeline, "evaluate_business_rules", Mock(return_value={"results": [{"status": "candidate"}]}))
    events = Mock()
    monkeypatch.setattr(pipeline, "emit", events)
    orch = SimpleNamespace(scope_guard=scope, memory=Mock(), surface=Mock())
    summary = pipeline.prepare_authenticated_research(orch, research_plan(), [business_rule()],
                                                      "https://fixture.invalid/")
    assert constructor.call_args.args[1] is scope
    assert summary["reportable"] is False
    assert summary["verification_status"] == "observation"
    assert summary["research"]["total_request_count"] == 21
    assert "private-test-cookie" not in json.dumps(summary)
    assert "never transfer" not in str(orch.memory.mock_calls)
    orch.surface.add_endpoint.assert_called_once_with(
        "https://fixture.invalid/account/deep", source="authenticated_research",
        attrs={"identity": "alice", "discovery_only": True})
    orch.surface.project_to_memory.assert_called_once_with(orch.memory)
    assert events.call_args.args[0] == "research_summary"


def test_authentication_failure_is_sanitized_and_blocks_agent_handoff(monkeypatch):
    runner = SimpleNamespace(run=Mock(side_effect=ValueError("password=private-test-cookie")))
    monkeypatch.setattr(pipeline, "ResearchRunner", Mock(return_value=runner))
    checks = Mock()
    monkeypatch.setattr(pipeline, "evaluate_business_rules", checks)
    events = Mock()
    monkeypatch.setattr(pipeline, "emit", events)
    orch = SimpleNamespace(scope_guard=guard(), memory=Mock(), surface=Mock())
    with pytest.raises(RuntimeError, match="authenticated research failed") as error:
        pipeline.prepare_authenticated_research(orch, research_plan(), [], "https://fixture.invalid/")
    assert "private-test-cookie" not in str(error.value)
    assert "private-test-cookie" not in str(events.mock_calls)
    checks.assert_not_called()
    orch.memory.add_fact.assert_not_called()


def test_partial_identity_setup_never_falls_back_to_anonymous_agent_execution(monkeypatch):
    runner = SimpleNamespace(run=lambda: {"partial": True}, verified_identities=set())
    monkeypatch.setattr(pipeline, "ResearchRunner", Mock(return_value=runner))
    checks = Mock()
    monkeypatch.setattr(pipeline, "evaluate_business_rules", checks)
    orch = SimpleNamespace(scope_guard=guard(), memory=Mock(), surface=Mock())
    with pytest.raises(RuntimeError, match="authenticated research failed"):
        pipeline.prepare_authenticated_research(orch, research_plan(), [], "https://fixture.invalid/")
    checks.assert_not_called()
    orch.memory.add_fact.assert_not_called()
