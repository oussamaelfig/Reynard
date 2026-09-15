"""Shared imports + helpers for the split regression suite.

Auto-extracted from the former monolithic test_core_regressions.py so per-subsystem test files can `from regression_common import *`."""
import os
import base64
import json
import re
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from hacking_agent.agents.base import BudgetedToolExecutor
from hacking_agent.agents.analyst import AnalystAgent
from hacking_agent.agents.exploitation import ExploitationAgent
from hacking_agent.core.evidence import EvidenceStore
from hacking_agent.cli.lab_eval import DEFAULT_CASES, evaluate_case
from hacking_agent.core.expert_playbooks import EXPERT_PLAYBOOKS, render_playbook_context
from hacking_agent.core.failure import classify_failure
from hacking_agent.core import deserial
from hacking_agent.core import misc_web
from hacking_agent.core.lab_intel import (
    category_playbooks,
    detect_lab_profile,
    detect_target_category,
    extract_credentials,
    normalize_target_input,
)
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.paths import LOG_DIR
from hacking_agent.core.providers import (
    ProviderRegistry,
    _apply_openai_compatible_params,
    _provider_display_name,
)
from hacking_agent.core.schemas import AgentResult, AgentTask, PoC, ToolDecision
from hacking_agent.core.schemas import CoordinatorDecision, PivotDecision, ProviderConfig
from hacking_agent.core.scope import ScopeGuard, ScopeViolation, RateLimitExceeded
from hacking_agent.core.engagement import (
    Engagement,
    EngagementError,
    engagement_from_dict,
    load_engagement,
)
from hacking_agent.core.state_machine import Event, StateMachine
from hacking_agent.core.subagents import (
    BoundedSubagentScheduler,
    SubagentPolicy,
    SubagentSpec,
)
from hacking_agent.core.tool_catalog import render_tool_catalog
from hacking_agent.core.tools import TOOL_FUNCTIONS, TOOL_SCHEMAS, execute_tool

def _build_offline_orchestrator(target, objective="", lab_profile=None,
                                max_iterations=12):
    """Construct an Orchestrator fully offline (dummy key, no durable DB, no
    subagents, lexical RAG). Never makes a network call."""
    from hacking_agent.cli.orchestrator import Orchestrator

    env = {
        "DEEPSEEK_API_KEY": "test-key",
        "REYNARD_DURABLE_MEMORY": "0",
        "REYNARD_EMBEDDINGS": "lexical",
    }
    with patch.dict(os.environ, env, clear=False):
        return Orchestrator(
            target_url=target,
            objective=objective,
            lab_profile=lab_profile,
            subagents_enabled=False,
            max_iterations=max_iterations,
        )
class _FakeProvider:
    """Offline stand-in for an LLMProvider (pivot/self-critique role)."""

    def call_typed(self, system, user, schema, max_retries=0):
        return schema(diagnosis="surface exhausted", give_up=True)

    def call_text(self, system, user, max_retries=0):
        return ""
class _ScriptedCoordinator:
    """Always routes to exploitation so the specialist outcome script drives
    the agenda mechanics deterministically."""

    def decide(self, **kwargs):
        return CoordinatorDecision(
            done=False,
            next_agent="exploitation",
            task=AgentTask(task_description="pursue active hypothesis", context={}),
            reasoning="scripted route",
        )
class _ScriptedSpecialist:
    """Returns queued success/failure outcomes, then defaults to success."""

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls = 0

    def execute(self, task):
        self.calls += 1
        ok = self._outcomes.pop(0) if self._outcomes else True
        return AgentResult(success=ok, summary="signal" if ok else "no signal")
class _InjectionFakeExecutor:
    """Scriptable tool executor for injection fast-path tests."""

    def __init__(self, responder):
        self.calls = []
        self._responder = responder

    def call(self, decision, agent_name, phase="general", iteration=0):
        self.calls.append(decision)
        return {
            "blocked": False,
            "blocked_reason": "",
            "signals": None,
            "result": self._responder(decision),
        }
class _ClientFakeExecutor:
    """Scriptable tool executor for client-side fast-path tests.

    The responder returns ``(result_str, signals_or_None)`` for each decision.
    """

    def __init__(self, responder):
        self.calls = []
        self._responder = responder

    def call(self, decision, agent_name, phase="general", iteration=0):
        self.calls.append(decision)
        result, signals = self._responder(decision)
        return {
            "blocked": False,
            "blocked_reason": "",
            "signals": signals,
            "result": result,
        }
class _AuthzFakeExecutor:
    """Scriptable tool executor for authz fast-path tests (single result)."""

    def __init__(self, responder):
        self.calls = []
        self._responder = responder

    def call(self, decision, agent_name, phase="general", iteration=0):
        self.calls.append(decision)
        return {"blocked": False, "blocked_reason": "", "signals": None,
                "result": self._responder(decision)}


__all__ = [
    "AgentMemory",
    "AgentResult",
    "AgentTask",
    "AnalystAgent",
    "BoundedSubagentScheduler",
    "BudgetedToolExecutor",
    "CoordinatorDecision",
    "DEFAULT_CASES",
    "EXPERT_PLAYBOOKS",
    "Engagement",
    "EngagementError",
    "Event",
    "EvidenceStore",
    "ExploitationAgent",
    "LOG_DIR",
    "PivotDecision",
    "PoC",
    "ProviderConfig",
    "ProviderRegistry",
    "RateLimitExceeded",
    "ScopeGuard",
    "ScopeViolation",
    "StateMachine",
    "SubagentPolicy",
    "SubagentSpec",
    "TOOL_FUNCTIONS",
    "TOOL_SCHEMAS",
    "ThreadPoolExecutor",
    "ToolDecision",
    "_AuthzFakeExecutor",
    "_ClientFakeExecutor",
    "_FakeProvider",
    "_InjectionFakeExecutor",
    "_ScriptedCoordinator",
    "_ScriptedSpecialist",
    "_apply_openai_compatible_params",
    "_build_offline_orchestrator",
    "_provider_display_name",
    "base64",
    "category_playbooks",
    "classify_failure",
    "deserial",
    "detect_lab_profile",
    "detect_target_category",
    "engagement_from_dict",
    "evaluate_case",
    "execute_tool",
    "extract_credentials",
    "json",
    "load_engagement",
    "misc_web",
    "normalize_target_input",
    "os",
    "patch",
    "re",
    "render_playbook_context",
    "render_tool_catalog",
    "time",
    "unittest",
]
