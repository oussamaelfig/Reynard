"""
=============================================================================
Reynard — Orchestrator State Machine
=============================================================================
Deterministic state machine that drives the multi-agent orchestrator.

This is the OUTER state machine — it routes between specialists. The INNER
6-phase exploitation pipeline (RECON → … → EXPLOIT) lives in strategy.py
and is consumed by the recon/analyst/exploitation agents.

Hard guarantees this layer enforces:

  1. Per-tool budgets        (e.g. max 80 run_shell calls per session)
  2. Iteration budget        (max specialist dispatches)
  3. Consecutive-failure pivot — after N agent failures the orchestrator
                                 forces ESCALATING → fresh specialist
  4. Closed transition table — invalid (state, event) pairs raise instead
                                 of silently doing nothing

No "freeform ReAct loop" survives this layer: the orchestrator can only
move along the allowed edges.
=============================================================================
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum


# =============================================================================
# State / Event enums
# =============================================================================

class State(str, Enum):
    PLANNING = "PLANNING"        # Initial — before any agent has run
    ROUTING = "ROUTING"          # Coordinator deciding next agent
    EXECUTING = "EXECUTING"      # Specialist actively running
    OBSERVING = "OBSERVING"      # Result coming in
    UPDATING = "UPDATING"        # Memory / evidence write
    ESCALATING = "ESCALATING"    # Pivot — too many consecutive failures
    REPORTING = "REPORTING"      # Reporter compiling final
    TERMINATED = "TERMINATED"    # Done (success, exhaustion, or fatal error)


class Event(str, Enum):
    START = "START"
    DECISION_DONE = "DECISION_DONE"
    AGENT_STARTED = "AGENT_STARTED"
    AGENT_SUCCEEDED = "AGENT_SUCCEEDED"
    AGENT_FAILED = "AGENT_FAILED"
    OBSERVATION_LOGGED = "OBSERVATION_LOGGED"
    PIVOT_REQUESTED = "PIVOT_REQUESTED"
    REPORT_REQUESTED = "REPORT_REQUESTED"
    REPORT_DONE = "REPORT_DONE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


# Closed transition table — only these (state, event) pairs are allowed.
_TRANSITIONS: dict[tuple[State, Event], State] = {
    (State.PLANNING, Event.START):                State.ROUTING,

    (State.ROUTING, Event.DECISION_DONE):         State.EXECUTING,
    (State.ROUTING, Event.REPORT_REQUESTED):      State.REPORTING,
    (State.ROUTING, Event.BUDGET_EXHAUSTED):      State.TERMINATED,

    (State.EXECUTING, Event.AGENT_STARTED):       State.EXECUTING,
    (State.EXECUTING, Event.AGENT_SUCCEEDED):     State.OBSERVING,
    (State.EXECUTING, Event.AGENT_FAILED):        State.OBSERVING,

    (State.OBSERVING, Event.OBSERVATION_LOGGED):  State.UPDATING,

    (State.UPDATING, Event.PIVOT_REQUESTED):      State.ESCALATING,
    (State.UPDATING, Event.DECISION_DONE):        State.ROUTING,
    (State.UPDATING, Event.REPORT_REQUESTED):     State.REPORTING,
    (State.UPDATING, Event.BUDGET_EXHAUSTED):     State.TERMINATED,

    (State.ESCALATING, Event.DECISION_DONE):      State.ROUTING,
    (State.ESCALATING, Event.BUDGET_EXHAUSTED):   State.TERMINATED,

    (State.REPORTING, Event.REPORT_DONE):         State.TERMINATED,
}


# =============================================================================
# Records
# =============================================================================

@dataclass
class StateTransition:
    from_state: State
    event: Event
    to_state: State
    note: str = ""


@dataclass
class StateMachineConfig:
    """Tunables. Override per-run via orchestrator CLI flags."""
    max_iterations: int = 30                  # Max specialist dispatches
    max_consecutive_failures: int = 3         # Force pivot after this many
    per_tool_budgets: dict[str, int] = field(default_factory=lambda: {
        "run_shell":              80,
        "request_smuggling_probe": 30,
        "tool_inventory":         30,
        "http_request":           150,   # bumped — used by diff/baseline tools too
        "browser_navigate":       40,
        "browser_execute_js":     40,
        "browser_interact":       30,
        "read_file":              30,
        "write_file":             30,
        "list_dir":               20,
        "analyze_response":       20,
        # OOB
        "oob_get_domain":         60,
        "oob_poll":               80,
        # Sessions (cheap, mostly bookkeeping)
        "swap_session":           60,
        "list_sessions":          20,
        # Differential
        "capture_baseline":       30,
        "diff_against_baseline":  60,
        # Recon expansions
        "nuclei_scan":             5,    # nuclei is heavy — keep tight
        "extract_js_endpoints":   10,
        "discover_apis":          10,
        # Structured scanner wrappers (heavy — keep tight)
        "ffuf_fuzz":              10,
        "sqlmap_run":              8,
        "nmap_scan":               8,
        # Automatic tool selection (cheap advisory calls)
        "recommend_tools":        40,
        # Session registration (cheap bookkeeping)
        "register_session":       30,
        # Caido Cloud API
        "caido_cloud_api":        60,
        "caido_cloud_request":    60,
        "caido_local_api":        100,
        # Web research
        "web_search":             30,
        "web_fetch":              40,
        # Burp Suite MCP
        "burp_send_http1_request": 80,
        "burp_get_scanner_issues": 20,
        "burp_generate_collaborator_payload": 30,
        "burp_get_collaborator_interactions": 60,
        "burp_create_repeater_tab": 30,
        "burp_send_to_intruder":   20,
        "burp_get_proxy_history":  40,
        "burp_get_proxy_history_regex": 40,
        "burp_set_intercept":      10,
        # Cross-domain (WS5): network / pwn — heavy/slow tools kept tight.
        "metasploit_run":          12,
        "msfvenom_generate":       15,
        "radare2_analyze":         40,
        "gdb_debug":               20,
        "pwn_template":            20,
        # Cross-domain (WS5): mobile — decompile is heavy, analysis lighter.
        "apk_decompile":           10,
        "apk_analyze":             20,
        "frida_hook":              12,
        # Cross-domain (WS5): CTF misc — light/repeatable helpers run higher.
        "stego_extract":           20,
        "hash_crack":              10,
        "crypto_helper":           40,
        "forensics_triage":        20,
        "flag_hunter":             60,
    })


class StateMachineError(RuntimeError):
    """Raised on invalid transition attempts."""


# =============================================================================
# StateMachine
# =============================================================================

class StateMachine:
    """Tracks orchestrator state, dispatches, tool calls, and failures."""

    def __init__(self, config: StateMachineConfig | None = None):
        self._lock = threading.RLock()
        self.config = config or StateMachineConfig()
        self.state: State = State.PLANNING
        self.iteration: int = 0                          # specialist dispatches
        self.consecutive_failures: int = 0
        self.history: list[StateTransition] = []
        self.tool_calls: dict[str, int] = {}
        self.agent_dispatches: dict[str, int] = {}
        self.last_failed_agent: str | None = None

    # ---- transitions -----------------------------------------------------

    def transition(self, event: Event, note: str = "") -> State:
        """Move to the next state. Raises if (state, event) is invalid."""
        with self._lock:
            key = (self.state, event)
            if key not in _TRANSITIONS:
                raise StateMachineError(
                    f"Invalid transition: {self.state.value} + {event.value}"
                )
            new = _TRANSITIONS[key]
            self.history.append(StateTransition(self.state, event, new, note))
            self.state = new
            return new

    def can_transition(self, event: Event) -> bool:
        with self._lock:
            return (self.state, event) in _TRANSITIONS

    # ---- bookkeeping ----------------------------------------------------

    def record_dispatch(self, agent_name: str) -> None:
        with self._lock:
            self.iteration += 1
            self.agent_dispatches[agent_name] = self.agent_dispatches.get(agent_name, 0) + 1

    def record_agent_outcome(self, agent_name: str, success: bool) -> None:
        with self._lock:
            if success:
                self.consecutive_failures = 0
            else:
                self.consecutive_failures += 1
                self.last_failed_agent = agent_name

    def record_tool_call(self, tool_name: str) -> None:
        with self._lock:
            self.tool_calls[tool_name] = self.tool_calls.get(tool_name, 0) + 1

    def try_record_tool_call(self, tool_name: str) -> bool:
        """Atomically reserve one tool-call budget slot."""
        with self._lock:
            budget = self.config.per_tool_budgets.get(tool_name, 999)
            current = self.tool_calls.get(tool_name, 0)
            if current >= budget:
                return False
            self.tool_calls[tool_name] = current + 1
            return True

    def release_tool_call(self, tool_name: str) -> None:
        """Return a reserved tool-call slot when execution is skipped."""
        with self._lock:
            current = self.tool_calls.get(tool_name, 0)
            if current <= 1:
                self.tool_calls.pop(tool_name, None)
            else:
                self.tool_calls[tool_name] = current - 1

    # ---- budgets --------------------------------------------------------

    def can_call_tool(self, tool_name: str) -> bool:
        with self._lock:
            budget = self.config.per_tool_budgets.get(tool_name, 999)
            return self.tool_calls.get(tool_name, 0) < budget

    def remaining_tool_budget(self, tool_name: str) -> int:
        with self._lock:
            budget = self.config.per_tool_budgets.get(tool_name, 999)
            return max(0, budget - self.tool_calls.get(tool_name, 0))

    def should_pivot(self) -> bool:
        with self._lock:
            return self.consecutive_failures >= self.config.max_consecutive_failures

    def is_iteration_exhausted(self) -> bool:
        with self._lock:
            return self.iteration >= self.config.max_iterations

    def is_terminated(self) -> bool:
        with self._lock:
            return self.state == State.TERMINATED

    # ---- snapshot -------------------------------------------------------

    def snapshot(self) -> str:
        """Compact human-readable state summary for prompt injection."""
        with self._lock:
            tool_str = ", ".join(f"{n}={c}" for n, c in self.tool_calls.items()) or "(none)"
            agent_str = ", ".join(f"{n}={c}" for n, c in self.agent_dispatches.items()) or "(none)"
            return (
                f"State: {self.state.value}\n"
                f"Iteration: {self.iteration}/{self.config.max_iterations}\n"
                f"Consecutive failures: {self.consecutive_failures}/{self.config.max_consecutive_failures}\n"
                f"Last failed agent: {self.last_failed_agent or 'none'}\n"
                f"Tool calls: {tool_str}\n"
                f"Agent dispatches: {agent_str}"
            )
