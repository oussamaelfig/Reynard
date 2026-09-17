"""Offline regressions for orchestration, budgets, and captured evidence."""
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import BaseModel

from hacking_agent.agents.base import BudgetedToolExecutor
from hacking_agent.agents.validator import ValidatorAgent
from hacking_agent.core.engagement import Engagement
from hacking_agent.core.events import EventBus
from hacking_agent.core.http_transport import execution_scope
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.metering import TokenMeter
from hacking_agent.core import providers
from hacking_agent.core.schemas import AgentResult, ProviderConfig, ToolDecision
from hacking_agent.core.scope import ScopeGuard
from hacking_agent.core.state_machine import StateMachine
from hacking_agent.core.strategy import StallDetector
from hacking_agent.core.subagents import BoundedSubagentScheduler, SubagentPolicy, SubagentSpec
from hacking_agent.core.tool_catalog import render_tool_catalog


def decision():
    return ToolDecision(tool="http_request", args={"url": "https://app.example.test/items?q=fixture"},
                        reasoning="Offline fixture", expected_signal="Recorded response")


@pytest.mark.parametrize("lane", ["exploitation", "validation"])
def test_sensitive_lanes_are_serial_even_if_caller_omits_mutation_flag(lane):
    spec = SubagentSpec("lane", lane, lambda: AgentResult(success=True, summary="done"))
    scheduler = BoundedSubagentScheduler()
    assert not scheduler.can_parallelize(spec)
    blocked = BoundedSubagentScheduler(SubagentPolicy(allow_stateful_serial=False)).run([spec])
    assert blocked[0].status == "skipped"


def test_parallel_results_keep_input_order_despite_completion_order():
    released = threading.Event()
    def first():
        assert released.wait(2)
        return AgentResult(success=True, summary="first")
    def second():
        released.set()
        return AgentResult(success=True, summary="second")
    runs = BoundedSubagentScheduler().run([
        SubagentSpec("first", "analysis", first), SubagentSpec("second", "readiness", second),
    ])
    assert [run.name for run in runs] == ["first", "second"]


def test_hypothesis_progress_is_not_hidden_by_another_advanced_hypothesis():
    detector = StallDetector(patience=2)
    def record(hypothesis, phase):
        return detector.record(agent="exploitation", phase=phase, hypothesis_id=hypothesis,
                               kg_count=3, evidence_count=0)
    assert not record("A", "exploit")
    assert not record("B", "recon")
    assert not record("B", "injection")
    assert detector.stall_count == 0
    assert not record("A", "exploit")
    assert record("B", "injection")  # Switching alone cannot keep the run alive.


def test_concurrent_events_publish_and_persist_in_id_order(monkeypatch):
    bus = EventBus()
    sink = []
    def append(event):
        if event.id == 1:
            time.sleep(0.025)
        sink.append(event.id)
    monkeypatch.setattr(bus, "_write_sink", append)
    subscriber = bus.subscribe(max_queue=100)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: bus.emit("fixture"), range(40)))
    expected = list(range(1, 41))
    assert sink == expected
    assert [subscriber.get_nowait().id for _ in expected] == expected
    assert [event.id for event in bus.history_since()] == expected


def test_executor_serializes_dedup_and_allows_budgeted_validator_replays(monkeypatch):
    calls = []
    def execute(tool, args):
        calls.append(tool)
        time.sleep(0.01)
        return json.dumps({"response": "HTTP/1.1 200 OK\nfixture", "exit_code": 0})
    monkeypatch.setattr("hacking_agent.agents.base.execute_tool", execute)
    executor = BudgetedToolExecutor(AgentMemory(), StateMachine())
    monkeypatch.setattr(executor, "_active_session_tag", lambda: "anonymous")
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(lambda _: executor.call(decision(), "recon"), range(4)))
    assert sum(not outcome["blocked"] for outcome in outcomes) == 1
    assert len(calls) == 1
    assert not executor.call(decision(), "validator", phase="validate")["blocked"]
    assert not executor.call(decision(), "validator", phase="validate")["blocked"]
    assert len(calls) == 3


def test_validator_replay_does_not_bypass_scope_or_request_cap(monkeypatch):
    guard = ScopeGuard.from_target_url("https://app.example.test")
    guard.attach_engagement(Engagement(authorized_domains=["app.example.test"],
                                      max_total_requests=1, max_requests_per_second=1000))
    execute = Mock(return_value='{"response":"HTTP/1.1 200 OK\\nfixture"}')
    monkeypatch.setattr("hacking_agent.agents.base.execute_tool", execute)
    executor = BudgetedToolExecutor(AgentMemory(), StateMachine(), scope_guard=guard)
    assert not executor.call(decision(), "validator", phase="validate")["blocked"]
    assert executor.call(decision(), "validator", phase="validate")["blocked"]
    assert execute.call_count == 1


def test_production_catalog_does_not_offer_opaque_or_account_admin_tools():
    catalog = render_tool_catalog(production=True)
    for name in ("http_request", "register_session", "capture_baseline"):
        assert name in catalog
    for name in ("run_shell", "nuclei_scan", "Caido Cloud API", "metasploit"):
        assert name not in catalog
    guard = ScopeGuard.from_target_url("https://app.example.test")
    guard.attach_engagement(Engagement(authorized_domains=["app.example.test"]))
    with execution_scope(guard):
        assert render_tool_catalog() == catalog
    assert "Caido Cloud API" in render_tool_catalog(production=False)


@pytest.fixture
def meter(monkeypatch):
    for name in ("LLM_MAX_TOKENS_BUDGET", "LLM_MAX_COST_BUDGET",
                 "LLM_INPUT_PRICE_PER_1K", "LLM_OUTPUT_PRICE_PER_1K"):
        monkeypatch.delenv(name, raising=False)
    meter = TokenMeter()
    monkeypatch.setattr(providers, "get_token_meter", lambda: meter)
    return meter


@pytest.mark.parametrize("adapter", [providers.OpenAICompatibleProvider, providers.AnthropicProvider])
@pytest.mark.parametrize("mode", ["typed", "text"])
def test_exhausted_budget_blocks_every_provider_entry_before_network(monkeypatch, meter, adapter, mode):
    monkeypatch.setenv("LLM_MAX_TOKENS_BUDGET", "10")
    meter.record("fixture", prompt_tokens=10)
    provider = object.__new__(adapter)
    provider.config = ProviderConfig(role="validator", model="fixture", api_key="test")
    provider._client = Mock()
    class Output(BaseModel):
        value: str
    with pytest.raises(providers.ProviderError, match="budget exhausted"):
        if mode == "typed":
            provider.call_typed("system", "user", Output)
        else:
            provider.call_text("system", "user")
    assert provider._client.mock_calls == []


@pytest.mark.parametrize("value", ["nan", "inf", "-1", "not-a-number"])
def test_invalid_budget_fails_closed(monkeypatch, meter, value):
    monkeypatch.setenv("LLM_MAX_TOKENS_BUDGET", value)
    with pytest.raises(providers.ProviderError, match="Invalid nonnegative budget"):
        providers._enforce_usage_budget()


def test_cost_budget_requires_prices_and_stops_at_measured_limit(monkeypatch, meter):
    monkeypatch.setenv("LLM_MAX_COST_BUDGET", "1")
    with pytest.raises(providers.ProviderError, match="requires configured token prices"):
        providers._enforce_usage_budget()
    monkeypatch.setenv("LLM_INPUT_PRICE_PER_1K", "1")
    providers._enforce_usage_budget()
    meter.record("fixture", prompt_tokens=1000)
    with pytest.raises(providers.ProviderError, match="cost budget exhausted"):
        providers._enforce_usage_budget()


def test_retry_rechecks_budget_after_failed_provider_call(monkeypatch, meter):
    monkeypatch.setenv("LLM_MAX_TOKENS_BUDGET", "10")
    provider = object.__new__(providers.OpenAICompatibleProvider)
    provider.config = ProviderConfig(role="validator", model="fixture", api_key="test")
    provider._client = Mock()
    provider._stream_usage = True
    def first_call(**kwargs):
        meter.record("fixture", prompt_tokens=10)
        raise RuntimeError("response_format not supported")
    provider._client.chat.completions.create.side_effect = first_call
    with pytest.raises(providers.ProviderError, match="budget exhausted"):
        provider.call_text("system", "user")
    assert provider._client.chat.completions.create.call_count == 1


@pytest.fixture
def validator(monkeypatch, tmp_path):
    monkeypatch.delenv("REYNARD_HOST_EXEC", raising=False)
    monkeypatch.delenv("REYNARD_VALIDATION_HMAC_KEY", raising=False)
    monkeypatch.setenv("REYNARD_VALIDATION_STATE_DIR", str(tmp_path / "authority"))
    agent = object.__new__(ValidatorAgent)
    agent.validator_instance_id = "validator:offline-test"
    agent.memory = AgentMemory(target_url="https://app.example.test")
    return agent


@pytest.mark.parametrize("problem", [{"truncated": True}, {"exit_code": 1}, {"error": "offline failure"},
                                     {"response": "x" * 5001}])
def test_failed_or_clipped_captures_cannot_mint_positive_effect(validator, problem):
    raw = {"response": "HTTP/1.1 200 OK\nfixture", "status_code": 200, **problem}
    attempt = validator._capture_attempt(
        index=1, probe_kind="replay", decision=decision(), observation="model prose",
        outcome={"result": json.dumps(raw), "signals": {"angular_evaluated": True}},
        context={"run_id": "fixture-run", "engagement_id": "fixture-engagement"},
    )
    assert attempt["blocked"]
    assert not attempt["trusted_observation"]["effect_kind"]


def test_capture_uses_actual_transport_status_url_method_and_identity(validator):
    raw = {"response": {"raw_response": "HTTP/1.1 201 Created\nfixture"},
           "url": "https://app.example.test/final", "method": "POST", "session": "user2"}
    attempt = validator._capture_attempt(
        index=1, probe_kind="replay", decision=decision(), observation="model prose",
        outcome={"result": json.dumps(raw)},
        context={"run_id": "fixture-run", "engagement_id": "fixture-engagement"},
    )
    assert not attempt["blocked"]
    captured = attempt["trusted_observation"]
    assert captured["status_code"] == 201
    assert captured["url"] == raw["url"]
    assert captured["method"] == "POST"
    assert captured["identity"] == "user2"
    assert "model prose" not in captured["response"]


def test_attached_engagement_overrides_benchmark_in_orchestrator(monkeypatch):
    from hacking_agent.cli.orchestrator import Orchestrator
    monkeypatch.setenv("DEEPSEEK_API_KEY", "offline-test")
    monkeypatch.setenv("REYNARD_DURABLE_MEMORY", "0")
    monkeypatch.setenv("REYNARD_EMBEDDINGS", "lexical")
    engagement = Engagement(authorized_domains=["app.example.test"])
    orch = Orchestrator("https://app.example.test", engagement=engagement,
                        mission_mode="benchmark", subagents_enabled=False,
                        exploit_server_url="https://callback.example.test")
    try:
        assert orch.mission.is_production
        assert orch.scope_guard.engagement_attached
        assert not orch.scope_guard.is_in_scope("https://callback.example.test")
    finally:
        orch.logger.close()
