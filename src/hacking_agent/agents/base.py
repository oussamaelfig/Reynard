"""
=============================================================================
Reynard — BaseAgent + BudgetedToolExecutor
=============================================================================
Shared infrastructure for all specialists.

  - `BaseAgent`              ABC every specialist inherits from. Owns the
                             provider, memory, state machine, evidence
                             store, and (optionally) a tool executor.

  - `BudgetedToolExecutor`   Wraps `tools.execute_tool` with three things
                             agents must NOT bypass:
                               1. State-machine per-tool budget enforcement
                               2. Payload deduplication via shared memory
                               3. Auto-analysis of HTTP/browser responses
                                  via analyzer.py — extracted signals are
                                  promoted to facts in memory.
=============================================================================
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, TypeVar
from urllib.parse import unquote

from pydantic import BaseModel
from rich.console import Console

from hacking_agent.core.analyzer import ResponseAnalyzer
from hacking_agent.core.evidence import EvidenceStore
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.providers import LLMProvider
from hacking_agent.core.schemas import AgentResult, AgentTask, ToolDecision
from hacking_agent.core.state_machine import StateMachine
from hacking_agent.core.tools import execute_tool

T = TypeVar("T", bound=BaseModel)
console = Console()


# =============================================================================
# BudgetedToolExecutor
# =============================================================================

class BudgetedToolExecutor:
    """Single chokepoint between agents and tools.py.

    Enforces budgets, dedup, and auto-analysis so individual agents can
    focus on reasoning. Returns a uniform dict so callers always know what
    they got back.
    """

    REPEATABLE_TOOLS = {
        "oob_poll",
        "list_sessions",
        "swap_session",
        "burp_get_scanner_issues",
        "burp_get_collaborator_interactions",
        "caido_cloud_api",
    }

    def __init__(self, memory: AgentMemory, state_machine: StateMachine):
        self.memory = memory
        self.sm = state_machine
        self.analyzer = ResponseAnalyzer()

    def call(self, decision: ToolDecision, agent_name: str,
             phase: str = "general", iteration: int = 0) -> dict[str, Any]:
        """Execute a typed ToolDecision.

        Returns: {
            "blocked": bool,
            "blocked_reason": str,
            "result": str,                     # raw tool stdout (JSON string)
            "signals": dict | None,            # auto-analyzer output (HTTP only)
        }
        """
        # ----- budget gate -----
        if not self.sm.can_call_tool(decision.tool):
            reason = (f"Tool budget exhausted for {decision.tool} "
                       f"(remaining={self.sm.remaining_tool_budget(decision.tool)})")
            console.print(f"[yellow]⛔ {reason}[/]")
            return {"blocked": True, "blocked_reason": reason,
                    "result": "", "signals": None}

        # ----- dedup gate -----
        payload_str = self._extract_payload(decision.tool, decision.args)
        if payload_str and self.memory.is_duplicate(payload_str):
            reason = f"Duplicate payload (already sent): {payload_str[:80]}"
            console.print(f"[yellow]⚠ {reason}[/]")
            return {"blocked": True, "blocked_reason": reason,
                    "result": "", "signals": None}

        if (
            decision.tool not in self.REPEATABLE_TOOLS
            and self.memory.is_known_failed_attempt(decision.tool, decision.args)
        ):
            reason = (
                f"Known failed attempt blocked: {decision.tool} "
                f"{self._brief_args(decision.tool, decision.args)}"
            )
            console.print(f"[yellow]âš  {reason}[/]")
            return {"blocked": True, "blocked_reason": reason,
                    "result": "", "signals": None}

        # ----- execute -----
        self.sm.record_tool_call(decision.tool)
        console.print(
            f"[cyan]🔧 [{agent_name}/{decision.tool}][/] "
            f"{self._brief_args(decision.tool, decision.args)}"
        )
        raw_result = execute_tool(decision.tool, decision.args)

        # ----- auto-analyze HTTP/browser responses -----
        signals = self._auto_analyze(decision.tool, decision.args, raw_result)
        if signals:
            self._signals_to_facts(signals, agent_name, iteration)
            findings = self._format_findings(signals)
            if findings:
                console.print(f"[green]   📊 {findings}[/]")

        # ----- record payload (with dedup hash) -----
        if payload_str:
            result_summary = self._classify_result(raw_result, signals)
            self.memory.add_payload(
                payload=payload_str,
                hypothesis=decision.reasoning,
                phase=phase,
                result=result_summary,
                signals=signals or {},
                iteration=iteration,
            )

        failure_reason = self._failure_reason(raw_result, signals)
        if failure_reason:
            self.memory.add_failed_attempt(
                tool=decision.tool,
                args=decision.args,
                phase=phase,
                reason=failure_reason,
                lesson="Do not repeat this exact tool call; vary payload, endpoint, session, or detection primitive.",
                iteration=iteration,
            )

        return {"blocked": False, "blocked_reason": "",
                "result": raw_result, "signals": signals}

    # ----- helpers --------------------------------------------------------

    def _extract_payload(self, tool_name: str, args: dict) -> str | None:
        """Build a stable string representing this tool call for dedup."""
        if tool_name == "http_request":
            url = args.get("url", "")
            data = args.get("data", "")
            method = args.get("method", "GET")
            return f"{method} {url}" + (f" body={data}" if data else "")
        if tool_name == "browser_navigate":
            return f"BROWSE {args.get('url', '')}"
        if tool_name == "browser_execute_js":
            return f"JS@{args.get('url', '')} :: {args.get('script', '')[:80]}"
        if tool_name == "browser_interact":
            return (f"INTERACT@{args.get('url', '')} :: "
                    f"{json.dumps(args.get('actions', []))[:80]}")
        if tool_name == "run_shell":
            cmd = args.get("command", "")
            if "curl" in cmd:
                return f"SHELL_CURL {cmd[:120]}"
        if tool_name == "caido_cloud_api":
            return f"CAIDO {args.get('operation', '')} {json.dumps(args.get('args', {}), sort_keys=True)[:120]}"
        if tool_name == "caido_cloud_request":
            return f"CAIDO_RAW {args.get('method', 'GET')} {args.get('path', '')}"
        return None

    def _brief_args(self, tool_name: str, args: dict) -> str:
        if tool_name == "run_shell":
            return f"$ {args.get('command', '')[:100]}"
        if tool_name == "http_request":
            return f"{args.get('method', 'GET')} {args.get('url', '')[:100]}"
        if tool_name in ("browser_navigate", "browser_execute_js", "browser_interact"):
            return args.get("url", "")[:100]
        if tool_name in ("read_file", "write_file", "list_dir"):
            return args.get("path", "")
        if tool_name == "caido_cloud_api":
            return f"{args.get('operation', '')} {json.dumps(args.get('args', {}))[:80]}"
        if tool_name == "caido_cloud_request":
            return f"{args.get('method', 'GET')} {args.get('path', '')[:100]}"
        return json.dumps(args)[:100]

    def _auto_analyze(self, tool_name: str, args: dict, result: str) -> dict | None:
        if tool_name not in {"http_request", "browser_navigate",
                              "browser_execute_js", "browser_interact"}:
            return None
        try:
            payload = ""
            if tool_name == "http_request":
                url = args.get("url", "")
                if "?" in url:
                    for p in url.split("?", 1)[1].split("&"):
                        if "=" in p:
                            payload = p.split("=", 1)[1]
                if args.get("data"):
                    d = args["data"]
                    payload = d.split("=")[-1] if "=" in d else d
            try:
                rd = json.loads(result)
                response_text = (
                    rd.get("response") or rd.get("rendered_content")
                    or rd.get("rendered_html") or ""
                )
            except (json.JSONDecodeError, TypeError):
                response_text = result
            if not response_text:
                return None
            return self.analyzer.analyze(
                response_text=response_text,
                payload=unquote(payload) if payload else "",
                url=args.get("url", ""),
            )
        except Exception:
            return None

    def _classify_result(self, raw_result: str, signals: dict | None) -> str:
        if signals:
            if signals.get("lab_solved"):    return "SOLVED"
            if signals.get("waf_detected"):  return "blocked"
            if signals.get("reflected"):     return "reflected"
            if signals.get("error_detected"):return "error"
        return "error" if '"error"' in raw_result[:200] else "ok"

    def _failure_reason(self, raw_result: str, signals: dict | None) -> str:
        if signals:
            if signals.get("waf_detected"):
                return "Target or proxy appears to have blocked the request."
            if signals.get("error_detected"):
                return "Response analyzer detected an application error."
        try:
            parsed = json.loads(raw_result)
        except (json.JSONDecodeError, TypeError):
            return "Tool returned an error string." if '"error"' in raw_result[:300] else ""
        if isinstance(parsed, dict):
            if parsed.get("error"):
                return str(parsed.get("error"))[:300]
            status = parsed.get("status_code")
            if isinstance(status, int) and status >= 400:
                return f"HTTP status {status} for exact request."
            if parsed.get("ok") is False:
                return "Tool returned ok=false."
        return ""

    def _signals_to_facts(self, signals: dict, agent_name: str, iteration: int) -> None:
        """Promote analyzer signals to global facts in memory."""
        src = f"{agent_name}/auto_analyzer"
        if signals.get("reflected"):
            self.memory.add_fact("reflection_confirmed", True, source=src, iteration=iteration)
        if signals.get("reflection_context"):
            self.memory.add_fact("context", signals["reflection_context"], source=src, iteration=iteration)
        if signals.get("angular_detected"):
            self.memory.add_fact("technology_stack", "AngularJS", source=src, iteration=iteration)
        if signals.get("angular_version"):
            self.memory.add_fact("angular_version", signals["angular_version"], source=src, iteration=iteration)
        if signals.get("angular_evaluated"):
            self.memory.add_fact("angular_evaluated", True, source=src, iteration=iteration)
        if signals.get("csp_header"):
            self.memory.add_fact("csp", signals["csp_header"], source=src, iteration=iteration)
        if signals.get("html_encoded"):
            self.memory.add_fact("html_encoding_active", True, source=src, iteration=iteration)
        if signals.get("waf_detected"):
            self.memory.add_fact("waf_detected", True, source=src, iteration=iteration)
        if signals.get("lab_solved"):
            self.memory.add_fact("lab_solved", True, source=src, iteration=iteration)

    def _format_findings(self, signals: dict) -> str:
        out: list[str] = []
        if signals.get("reflected"):
            out.append(f"reflected (ctx={signals.get('reflection_context','?')})")
        if signals.get("angular_detected"):
            out.append(f"angular={signals.get('angular_version','?')}")
        if signals.get("angular_evaluated"):
            out.append("angular_evaluated=TRUE")
        if signals.get("waf_detected"):
            out.append("WAF_DETECTED")
        if signals.get("lab_solved"):
            out.append("🎉 LAB_SOLVED")
        return " | ".join(out)


# =============================================================================
# BaseAgent
# =============================================================================

class BaseAgent(ABC):
    """Abstract specialist. Subclasses must set `name` and implement `execute`."""

    name: str = ""
    role: str = ""

    def __init__(self, provider: LLMProvider, memory: AgentMemory,
                  state_machine: StateMachine, evidence: EvidenceStore,
                  tool_executor: BudgetedToolExecutor | None = None):
        self.provider = provider
        self.memory = memory
        self.sm = state_machine
        self.evidence = evidence
        self.tools = tool_executor    # may be None for coordinator/reporter
        if not self.name:
            raise NotImplementedError(f"{self.__class__.__name__} must set `name`")

    # --- typed LLM helpers ------------------------------------------------

    def call_typed(self, system: str, user: str, schema: type[T]) -> T:
        return self.provider.call_typed(system, user, schema)

    def call_text(self, system: str, user: str) -> str:
        return self.provider.call_text(system, user)

    # --- shared prompt helpers --------------------------------------------

    def kg_summary(self) -> str:
        return self.memory.kg_snapshot() + "\n\n" + self.memory.failure_summary(10)

    def state_summary(self) -> str:
        return self.sm.snapshot()

    # --- contract ---------------------------------------------------------

    @abstractmethod
    def execute(self, task: AgentTask) -> AgentResult:
        """Run this specialist on a task. Always returns a typed AgentResult."""
