#!/usr/bin/env python3
"""
=============================================================================
Reynard — Multi-Agent Orchestrator (Entry Point)
=============================================================================
The main control loop that wires together:

  - ProviderRegistry       per-agent LLM bindings
  - StateMachine           deterministic transitions (PLANNING → … → TERMINATED)
  - AgentMemory            shared knowledge graph + global facts
  - EvidenceStore          append-only PoC store
  - BudgetedToolExecutor   budget / dedup / auto-analysis chokepoint

  - CoordinatorAgent       LLM-driven routing (decides next specialist)
  - ReconAgent             black-box reconnaissance
  - AnalystAgent           theoretical vulnerability analysis
  - ExploitationAgent      PoC builder & verifier
  - ReporterAgent          pentest report synthesis

State Machine Flow
──────────────────
  PLANNING → ROUTING → EXECUTING → OBSERVING → UPDATING → ROUTING …
                                                        ↘ ESCALATING → ROUTING
                                                        ↘ REPORTING → TERMINATED
                                   ROUTING → TERMINATED (budget exhausted)

Usage
─────
  python orchestrator.py "https://TARGET_URL" [--max-iterations 30] [--interactive]
  python orchestrator.py --help
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ---- project imports ----
from hacking_agent.agents import (
    AnalystAgent,
    BudgetedToolExecutor,
    CoordinatorAgent,
    ExploitationAgent,
    ReconAgent,
    ReporterAgent,
    ValidatorAgent,
)
from hacking_agent.core.durable import open_durable_store
from hacking_agent.core.evidence import EvidenceStore
from hacking_agent.core.events import emit
from hacking_agent.core.expert_playbooks import enrich_lab_profile, render_playbook_context
from hacking_agent.core.failure import classify_failure
from hacking_agent.core.lab_corpus import normalize_lab_level
from hacking_agent.core.lab_intel import (
    detect_lab_profile,
    extract_exploit_server_url,
    normalize_target_input,
)
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.metering import get_token_meter
from hacking_agent.core.paths import ENV_FILE, LOG_DIR, METHODOLOGIES_DIR, ensure_runtime_dirs
from hacking_agent.core.preflight import has_fatal_failure, run_preflight
from hacking_agent.core.providers import ProviderRegistry
from hacking_agent.core.schemas import (
    AgentName, AgentResult, AgentTask, CoordinatorDecision, Hypothesis,
    PivotDecision, ToolDecision,
)
from hacking_agent.core.scope import ScopeGuard
from hacking_agent.core.strategy import (
    HypothesisAgenda, PHASE_SEQUENCE, PHASE_TO_AGENT, StallDetector,
    StrategyEngine, next_phase,
)
from hacking_agent.core.subagents import BoundedSubagentScheduler, SubagentPolicy, SubagentSpec
from hacking_agent.core import sessions as session_mod
from hacking_agent.core import lab_intel as lab_intel_mod
from hacking_agent.core.tool_selector import render_recommendations
from hacking_agent.integrations import burp as burp_mod
from hacking_agent.integrations import caido as caido_mod
from hacking_agent.integrations import caido_local as caido_local_mod
from hacking_agent.core.state_machine import Event, State, StateMachine, StateMachineConfig
from hacking_agent.ui.live import start_dashboard


def _force_utf8_console() -> None:
    """Make stdout/stderr tolerant of non-UTF-8 consoles (e.g. Windows cp1252).

    Rich renders emoji/box-drawing glyphs in the banner and panels; on a fresh
    Windows PowerShell the console defaults to cp1252 and encoding those glyphs
    raises UnicodeEncodeError, crashing the run. We reconfigure the streams to
    UTF-8 with a replacement error handler so output degrades gracefully instead
    of aborting. Best-effort and safe when streams are redirected or already
    UTF-8.
    """
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        current = (getattr(stream, "encoding", "") or "").lower()
        try:
            if current not in ("utf-8", "utf8"):
                reconfigure(encoding="utf-8", errors="replace")
            elif getattr(stream, "errors", "") not in ("replace", "backslashreplace"):
                reconfigure(errors="replace")
        except Exception:
            pass


_force_utf8_console()

console = Console()

PIVOT_SYSTEM = """You are the PIVOT strategist for an autonomous pentest run that is STUCK.
You are invoked only after repeated failures. Think hard and diagnose the
root cause, then propose the single most promising CONCRETE next vector that
has NOT already been tried and failed.

You will be shown: the target, the hypothesis agenda (with per-vector status,
heat, and fail counts), the current evidence, and the recent failed attempts.

Rules:
- Do NOT repeat a demoted/failed vector verbatim — change the primitive,
  parameter, endpoint, encoding, session, or detection channel (in-band ->
  OOB -> differential).
- Prefer a specific, testable vector over generic advice.
- Set give_up=true ONLY when every plausible vector is genuinely exhausted.

Output a SINGLE PivotDecision JSON object. No prose, no markdown fences.
EXAMPLE:
{"diagnosis":"Login GET was deduped so no fresh CSRF token was ever obtained.",
 "new_hypothesis":"Re-fetch /login for a fresh token+cookie, then host an auto-submit CSRF form on the exploit server and deliver to victim.",
 "new_vuln_type":"csrf","recommended_agent":"exploitation",
 "recommended_vector":"email change form","give_up":false}
"""

SELF_CRITIQUE_SYSTEM = """You are the SELF-CRITIQUE reviewer. The run is about to be
concluded as a FAILURE (no verified finding). Before it stops, review the full
evidence and the failed-attempt log and decide whether ONE more concrete,
previously-untried vector is worth trying.

Be honest: if the surface is genuinely exhausted, set give_up=true and do not
invent noise. Otherwise propose exactly one concrete, actionable vector with a
specific parameter/endpoint/technique.

Output a SINGLE PivotDecision JSON object.
"""

AUTH_HEAVY_PLAYBOOKS = {
    "authentication",
    "oauth",
    "jwt",
    "access_control_idor",
    "csrf",
    "cors",
    "graphql_api",
    "race_condition",
    "business_logic",
    "api_testing",
    "web_llm_attacks",
}

# =============================================================================
# Session logger (reuses the same format as agent.py for consistency)
# =============================================================================

class SessionLogger:
    """Append-only session log saved to logs/orchestrator_<timestamp>.log."""

    def __init__(self):
        ensure_runtime_dirs()
        log_dir = LOG_DIR
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.path = log_dir / f"orchestrator_{ts}.log"
        self._file = open(self.path, "w", encoding="utf-8")
        self.log(f"Session started at {ts}")

    def log(self, msg: str) -> None:
        ts = datetime.utcnow().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self._file.write(line + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()


# =============================================================================
# Methodology loader
# =============================================================================

# Corrected keyword -> methodology file map. Used only as a FALLBACK when the
# RAG retriever returns nothing (empty corpus / cold cache). The previous
# version mis-routed authentication/api -> idor_authz, host header ->
# cache_poisoning, and xxe/command injection -> blind; those are fixed here and
# the newly authored class files are wired in.
_METHODOLOGY_FALLBACK: list[tuple[str, str]] = [
    ("cross-site scripting",          "xss_advanced.md"),
    ("xss",                           "xss_advanced.md"),
    ("sql injection",                 "sqli.md"),
    ("sqli",                          "sqli.md"),
    ("nosql",                         "nosqli.md"),
    ("mongo",                         "nosqli.md"),
    ("ssrf",                          "ssrf.md"),
    ("server-side request",           "ssrf.md"),
    ("ssti",                          "ssti.md"),
    ("template injection",            "ssti.md"),
    ("idor",                          "idor_authz.md"),
    ("insecure direct object",        "idor_authz.md"),
    ("access control",                "idor_authz.md"),
    ("authorization",                 "idor_authz.md"),
    ("authz",                         "idor_authz.md"),
    ("broken access",                 "idor_authz.md"),
    ("privilege",                     "idor_authz.md"),
    ("authentication",                "authentication.md"),
    ("login",                         "authentication.md"),
    ("password reset",                "authentication.md"),
    ("mfa",                           "authentication.md"),
    ("2fa",                           "authentication.md"),
    ("jwt",                           "jwt.md"),
    ("json web token",                "jwt.md"),
    ("oauth",                         "oauth.md"),
    ("openid",                        "oauth.md"),
    ("oidc",                          "oauth.md"),
    ("deserial",                      "deserialization.md"),
    ("pickle",                        "deserialization.md"),
    ("smuggl",                        "request_smuggling.md"),
    ("desync",                        "request_smuggling.md"),
    ("cache deception",               "web_cache_deception.md"),
    ("cache poison",                  "cache_poisoning.md"),
    ("host header",                   "host_header.md"),
    ("x-forwarded-host",              "host_header.md"),
    ("xxe",                           "xxe.md"),
    ("xml external",                  "xxe.md"),
    ("command injection",             "command_injection.md"),
    ("os command",                    "command_injection.md"),
    ("csrf",                          "csrf.md"),
    ("cross-site request forgery",    "csrf.md"),
    ("cors",                          "cors.md"),
    ("cross-origin",                  "cors.md"),
    ("clickjack",                     "clickjacking.md"),
    ("path traversal",                "path_traversal.md"),
    ("directory traversal",           "path_traversal.md"),
    ("file upload",                   "file_upload.md"),
    ("web shell",                     "file_upload.md"),
    ("race condition",                "race_conditions.md"),
    ("business logic",                "business_logic.md"),
    ("logic flaw",                    "business_logic.md"),
    ("information disclosure",        "information_disclosure.md"),
    ("info disclosure",               "information_disclosure.md"),
    ("websocket",                     "websockets.md"),
    ("graphql",                       "graphql.md"),
    ("prototype pollution",           "prototype_pollution.md"),
    ("web llm",                       "web_llm.md"),
    ("llm attack",                    "web_llm.md"),
    ("prompt injection",              "web_llm.md"),
    ("android",                       "android_frida_root_bypass.md"),
    ("frida",                         "android_frida_root_bypass.md"),
    ("rce",                           "command_injection.md"),
    ("log4",                          "blind.md"),
    ("jndi",                          "blind.md"),
]


def _methodology_from_files(vuln_type: str) -> str:
    """Fallback keyword-based single-file load (RAG-independent)."""
    method_dir = METHODOLOGIES_DIR
    if not method_dir.is_dir():
        return ""
    vuln_lower = vuln_type.lower()
    sections: list[str] = []
    seen: set[str] = set()
    for keyword, filename in _METHODOLOGY_FALLBACK:
        if keyword in vuln_lower and filename not in seen:
            path = method_dir / filename
            if path.exists():
                content = path.read_text(encoding="utf-8")
                sections.append(f"\n\n# METHODOLOGY REFERENCE ({filename})\n{content}")
                seen.add(filename)
                break
    if "blind.md" not in seen:
        blind_path = method_dir / "blind.md"
        if blind_path.exists():
            content = blind_path.read_text(encoding="utf-8")
            sections.append(f"\n\n# CROSS-CUTTING (blind.md)\n{content}")
    return "".join(sections)


def load_methodology(vuln_type: str | None, hypothesis: str = "",
                     phase: str = "", k: int = 6) -> str:
    """Retrieve relevant methodology via local RAG over methodologies/.

    A query is built from the vuln class + current hypothesis + phase and the
    top-k retrieved technique chunks (source file + heading) are injected. This
    replaces the old keyword first-match single-file load. If the retriever
    yields nothing (no corpus / cold cache / offline), it degrades to corrected
    keyword-based file loading so the feature never hard-fails.
    """
    query = " ".join(p for p in (vuln_type, hypothesis, phase) if p).strip()
    if not query:
        return ""
    try:
        from hacking_agent.core.knowledge import retrieve_context
        rag = retrieve_context(query, k=k)
    except Exception:
        rag = ""
    if rag:
        return rag
    return _methodology_from_files(vuln_type or "")


# =============================================================================
# Orchestrator
# =============================================================================

class Orchestrator:
    """Multi-agent control loop with deterministic state transitions."""

    def __init__(
        self,
        target_url: str,
        max_iterations: int = 30,
        interactive: bool = False,
        objective: str = "",
        lab_profile: dict | None = None,
        scope_domains: list[str] | None = None,
        scope_cidrs: list[str] | None = None,
        subagents_enabled: bool = True,
        max_subagents: int = 4,
        exploit_server_url: str = "",
    ):
        self.target_url = target_url
        self.objective = objective
        self.exploit_server_url = (exploit_server_url or "").strip()
        self.lab_profile = enrich_lab_profile(lab_profile or {}, objective)
        self.playbook_context = render_playbook_context(self.lab_profile)
        self.interactive = interactive
        self.subagents_enabled = subagents_enabled
        self.max_subagents = max(1, max_subagents)
        # Cost-budget caps (0 = disabled). When exceeded mid-run, the
        # orchestrator stops dispatching specialists and forces a final report.
        self.max_tokens_budget = int(os.getenv("LLM_MAX_TOKENS_BUDGET", "0") or 0)
        self.max_cost_budget = float(os.getenv("LLM_MAX_COST_BUDGET", "0") or 0)
        self.token_meter = get_token_meter()
        self.logger = SessionLogger()
        scope_domains = list(scope_domains or [])
        exploit_host = ""
        if self.exploit_server_url:
            exploit_host = (urlparse(self.exploit_server_url).hostname or "").lower()
            if exploit_host and exploit_host not in scope_domains:
                scope_domains.append(exploit_host)
        self.scope_guard = ScopeGuard.from_target_url(
            target_url,
            extra_domains=scope_domains,
            extra_cidrs=scope_cidrs,
        )

        # ---- shared subsystems ----
        self.memory = AgentMemory(target_url=target_url)
        if self.objective:
            self.memory.add_fact("task_objective", self.objective, source="cli")
        if self.exploit_server_url:
            self.memory.add_fact(
                "exploit_server_url", self.exploit_server_url, source="lab_intel/cli"
            )
        if self.lab_profile:
            self.memory.add_fact(
                "lab_profile", self.lab_profile.get("id", "unknown"), source="cli"
            )
            if self.lab_profile.get("platform"):
                self.memory.add_fact("platform", self.lab_profile["platform"], source="cli")
            if self.lab_profile.get("playbook_id"):
                self.memory.add_fact(
                    "expert_playbook", self.lab_profile["playbook_id"], source="cli"
                )
            for tool in self.lab_profile.get("primary_tools", [])[:6]:
                self.memory.add_fact(
                    f"preferred_tool_{tool}", tool, source="expert_playbook"
                )
            for credential in self.lab_profile.get("credentials", []):
                username = credential.get("username")
                password = credential.get("password")
                if not username or not password:
                    continue
                cred_entity = self.memory.add_entity("Credential", {
                    "username": username,
                    "password": password,
                    "source": "lab_profile",
                })
                self.memory.add_fact(
                    "credential_hint",
                    f"{username}:{password}",
                    source="lab_profile",
                    entity_id=cred_entity.id,
                )
        self.sm = StateMachine(
            StateMachineConfig(max_iterations=max_iterations)
        )
        self.evidence = EvidenceStore()

        # ---- durable cross-run memory (opt-in-safe; None => in-memory only) --
        # Disable explicitly with REYNARD_DURABLE_MEMORY=0. Any open failure
        # degrades silently to the current per-run behaviour.
        self.durable = None
        if os.getenv("REYNARD_DURABLE_MEMORY", "1").lower() not in ("0", "false", "no"):
            self.durable = open_durable_store()
        self.durable_target = (urlparse(target_url).netloc or target_url or "").lower()
        self.lab_class = str(
            self.lab_profile.get("playbook_id")
            or self.lab_profile.get("vulnerability")
            or "web"
        ).lower()
        # Difficulty tier of the lab (APPRENTICE/PRACTITIONER/EXPERT), populated
        # from the corpus/objective via the lab profile. Drives strong-tier
        # escalation on EXPERT labs.
        self.lab_level = normalize_lab_level(
            self.lab_profile.get("lab_level") or self.lab_profile.get("level")
        )
        if self.lab_level:
            self.lab_profile.setdefault("lab_level", self.lab_level)

        self.registry = ProviderRegistry.from_env()
        self.tool_executor = BudgetedToolExecutor(
            self.memory, self.sm, scope_guard=self.scope_guard
        )
        self.subagent_scheduler = BoundedSubagentScheduler(
            SubagentPolicy(
                enabled=self.subagents_enabled,
                max_parallel=self.max_subagents,
                allow_stateful_parallel=False,
                allow_stateful_serial=True,
            )
        )
        self.memory.add_fact(
            "subagents_enabled",
            self.subagents_enabled,
            source="orchestrator",
        )

        # ---- agents ----
        self.coordinator = CoordinatorAgent(
            provider=self.registry.get("coordinator"),
            memory=self.memory,
            state_machine=self.sm,
            evidence=self.evidence,
        )
        self.specialists: dict[str, ReconAgent | AnalystAgent | ExploitationAgent | ReporterAgent | ValidatorAgent] = {
            "recon": ReconAgent(
                provider=self.registry.get("recon"),
                memory=self.memory,
                state_machine=self.sm,
                evidence=self.evidence,
                tool_executor=self.tool_executor,
            ),
            "analyst": AnalystAgent(
                provider=self.registry.get("analyst"),
                memory=self.memory,
                state_machine=self.sm,
                evidence=self.evidence,
            ),
            "exploitation": ExploitationAgent(
                provider=self.registry.get("exploitation"),
                memory=self.memory,
                state_machine=self.sm,
                evidence=self.evidence,
                tool_executor=self.tool_executor,
            ),
            "validator": ValidatorAgent(
                provider=self.registry.get("validator"),
                memory=self.memory,
                state_machine=self.sm,
                evidence=self.evidence,
                tool_executor=self.tool_executor,
            ),
            "reporter": ReporterAgent(
                provider=self.registry.get("reporter"),
                memory=self.memory,
                state_machine=self.sm,
                evidence=self.evidence,
            ),
        }

        self.last_result: AgentResult | None = None
        self.session_start = time.time()

        # ---- WS2: strategy engine + first-class hypothesis agenda ----
        self.strategy = StrategyEngine()
        self.agenda = HypothesisAgenda()
        self.active_hypothesis: Hypothesis | None = None
        self.target_category = self._detect_target_category()
        if self.target_category:
            self.memory.add_fact(
                "target_category", self.target_category, source="lab_intel/category"
            )
        self._needs_pivot = False
        self._pivot_used = 0
        self._self_critique_done = False

        # ---- tiered model escalation (strong reasoning tier) ----
        # Cheap default runs normally; the coordinator + exploitation dispatch
        # swap to the `strong` provider when the run stalls / backtracks, on
        # EXPERT-tier labs, or when forced (training-loop re-run pass). Reuses
        # the existing pivot escalation path; no budget/metering duplication.
        self._tier_escalation_enabled = os.getenv(
            "REYNARD_TIER_ESCALATION", "1"
        ).lower() not in ("0", "false", "no", "off")
        self._escalate_on_expert = os.getenv(
            "REYNARD_ESCALATE_ON_EXPERT", "1"
        ).lower() not in ("0", "false", "no", "off")
        self._force_strong_tier = os.getenv(
            "REYNARD_FORCE_STRONG_TIER", "0"
        ).lower() in ("1", "true", "yes", "on")
        # Pinned = stay escalated for the whole run (EXPERT / forced) rather
        # than reverting once unstuck.
        self._tier_pinned_strong = self._force_strong_tier or (
            self._escalate_on_expert and self.lab_level == "EXPERT"
        )
        self._tier_escalated = False
        self._tier_escalations = 0

        # ---- imp-loop: anti-loop / no-progress intelligence ----
        # A stall = N consecutive outer steps with no new KG entities, no new
        # evidence, and no phase advance. On stall we demote the active vector
        # and force a pivot instead of letting a cheap model churn forever.
        self.stall_detector = StallDetector(
            patience=int(os.getenv("REYNARD_STALL_PATIENCE", "3") or 3)
        )
        self._stall_forced_pivots = 0
        # Redundant-recon guard: hypothesis signatures whose recon surface
        # (endpoints/params) is already materialized, so we advance the phase
        # instead of re-dispatching recon for the same vector.
        self._recon_guard_enabled = os.getenv(
            "REYNARD_RECON_GUARD", "1"
        ).lower() not in ("0", "false", "no")
        self._recon_materialized: set[str] = set()
        self._report_gate_count = 0
        self._max_report_gates = int(os.getenv("REYNARD_MAX_REPORT_GATES", "6") or 6)
        self._report_gating_enabled = os.getenv(
            "REYNARD_REPORT_GATING", "1"
        ).lower() not in ("0", "false", "no")

    # ---- category-profiler routing hook (shared with WS5 sibling) --------

    def _detect_target_category(self) -> str:
        """Best-effort category detection via lab_intel, guarded so it works
        whether or not the concurrent WS5 sibling has landed a detector."""
        cat = str((self.lab_profile or {}).get("category", "") or "")
        if cat:
            return cat
        fn = getattr(lab_intel_mod, "detect_target_category", None)
        if callable(fn):
            for args in (
                (self.target_url, self.objective, self.lab_profile),
                (self.target_url, self.objective),
                (self.lab_profile,),
                (self.target_url,),
            ):
                try:
                    res = fn(*args)
                except TypeError:
                    continue
                except Exception:
                    break
                if res:
                    return str(res)
        return ""

    # ---- main loop -------------------------------------------------------

    def run(self) -> AgentResult | None:
        """Execute the full multi-agent pipeline. Returns the final report
        result, or None if budget was exhausted without producing one."""
        self._print_banner()
        emit("session_start", {
            "target": self.target_url,
            "objective": self.objective,
            "lab_profile": self.lab_profile,
            "max_iterations": self.sm.config.max_iterations,
            "subagents_enabled": self.subagents_enabled,
            "max_subagents": self.max_subagents,
            "providers": self.registry.describe(),
        })
        self.logger.log(f"Target: {self.target_url}")
        if self.objective:
            self.logger.log(f"Objective: {self.objective}")
        if self.lab_profile:
            self.logger.log(f"Lab profile: {json.dumps(self.lab_profile, default=str)}")
        self.logger.log(f"Config: max_iter={self.sm.config.max_iterations}")
        self.logger.log(
            f"Subagents: enabled={self.subagents_enabled}, max={self.max_subagents}"
        )
        self.logger.log(f"Scope: {self.scope_guard.describe()}")
        self.logger.log(f"Providers:\n{self.registry.describe()}")

        # PLANNING → ROUTING
        self.sm.transition(Event.START, "Session initialized")
        emit("state", {"state": self.sm.state.value, "message": "Session initialized"})
        self._rehydrate_durable()
        self._run_bootstrap_subagents()
        self._seed_hypotheses()
        self._maybe_start_escalated()

        final_result: AgentResult | None = None

        while not self.sm.is_terminated():
            # ---- iteration guard ----
            if self.sm.is_iteration_exhausted():
                console.print(
                    "[red bold]⛔ Iteration budget exhausted — "
                    "forcing report.[/]"
                )
                self.logger.log("Budget exhausted — forcing report")
                # Try to report before terminating
                final_result = self._dispatch_reporter()
                if self.sm.can_transition(Event.BUDGET_EXHAUSTED):
                    self.sm.transition(Event.BUDGET_EXHAUSTED, "max iterations reached")
                break

            # ---- cost/token budget guard ----
            budget_hit = self._budget_exceeded()
            if budget_hit:
                console.print(
                    f"[red bold]⛔ Cost budget exceeded ({budget_hit}) — "
                    "forcing report.[/]"
                )
                self.logger.log(f"Cost budget exceeded ({budget_hit}) — forcing report")
                emit("budget_exceeded", {
                    "reason": budget_hit,
                    **self._token_cost_snapshot(),
                })
                final_result = self._dispatch_reporter()
                break

            try:
                result = self._step()
                if result is not None:
                    final_result = result
            except KeyboardInterrupt:
                console.print("\n[yellow]⚠ Interrupted by user[/]")
                self.logger.log("User interrupt")
                break
            except Exception as e:
                console.print(f"[red bold]💀 Fatal error: {e}[/]")
                self.logger.log(f"FATAL: {e}")
                import traceback
                traceback.print_exc()
                break

        self._persist_durable()
        self._print_summary()
        emit("session_end", {
            "target": self.target_url,
            "success": bool(final_result and final_result.success),
            "iterations": self.sm.iteration,
            "tool_calls": sum(self.sm.tool_calls.values()),
            **self._token_cost_snapshot(),
        })
        self.logger.log(f"Session ended. Duration: {time.time() - self.session_start:.1f}s")
        self.logger.close()

        return final_result

    def _step(self) -> AgentResult | None:
        """Execute one orchestrator step. Returns AgentResult only when
        the reporter produces output."""

        assert self.sm.state == State.ROUTING, \
            f"Expected ROUTING, got {self.sm.state}"

        # ---- ROUTING: coordinator decides ----
        self._print_state_panel()
        console.print("[bold cyan]🧠 Coordinator deciding...[/]")
        self.logger.log(f"[ROUTING] iteration={self.sm.iteration}")

        # Refresh the hottest OPEN hypothesis + mirror its phase into memory so
        # the coordinator and RAG methodology loader see the active vector/phase.
        self._select_active_hypothesis()

        try:
            decision: CoordinatorDecision = self.coordinator.decide(
                target_url=self.target_url,
                last_result=self.last_result,
                objective=self.objective,
                lab_profile=self.lab_profile,
                agenda_context=self._agenda_context(),
            )
        except Exception as e:
            console.print(f"[red]Coordinator failure: {e}[/]")
            self.logger.log(f"Coordinator error: {e}")
            # If the coordinator fails, try to recover by dispatching recon
            if self.sm.iteration == 0:
                decision = CoordinatorDecision(
                    done=False,
                    next_agent="recon",
                    task=AgentTask(
                        task_description="Perform initial reconnaissance on the target.",
                        context={
                            "target_url": self.target_url,
                            "objective": self.objective,
                            "lab_profile": self.lab_profile,
                        },
                    ),
                    reasoning="Coordinator failed — fallback to recon.",
                )
            else:
                # Terminate gracefully
                if self.sm.can_transition(Event.BUDGET_EXHAUSTED):
                    self.sm.transition(Event.BUDGET_EXHAUSTED, "coordinator failure")
                return None

        self.logger.log(
            f"Decision: done={decision.done}, "
            f"agent={decision.next_agent}, "
            f"reasoning={decision.reasoning[:120]}"
        )
        emit("reasoning_note", {
            "agent": "coordinator",
            "text": decision.reasoning,
            "next_agent": decision.next_agent,
            "done": decision.done,
        })

        # ---- REPORTING gate ----
        # WS2/WS6: don't let the coordinator report prematurely. If the
        # hypothesis agenda still has untried actionable vectors (and no
        # verified evidence yet), force progress; and run one self-critique
        # pass proposing a fresh vector before we ever conclude failure.
        decision = self._intercept_done(decision)
        if decision.done:
            console.print("[bold green]✅ Coordinator says: DONE → reporting[/]")
            self.sm.transition(Event.REPORT_REQUESTED, "coordinator done=True")
            result = self._execute_reporter(decision)
            self.sm.transition(Event.REPORT_DONE, "report generated")
            return result

        # ---- EXECUTING: dispatch specialist ----
        agent_name: AgentName = decision.next_agent  # type: ignore[assignment]
        task: AgentTask = decision.task  # type: ignore[assignment]

        # ---- imp-loop: redundant-recon guard ----
        # If recon already materialized the surface for the active hypothesis,
        # don't re-run it; advance the phase and hand off to the phase owner.
        if agent_name == "recon" and self._recon_is_redundant(task):
            agent_name, task = self._advance_past_recon(task)

        # Inject shared context (target/objective/lab/playbook), the active
        # StrategyEngine phase + agenda, deterministic tool recommendations,
        # and RAG methodology keyed on the ACTIVE hypothesis + phase.
        task = self._inject_task_context(task, agent_name)

        # ---- routing guard: exploitation ALWAYS needs a Vulnerability id ----
        # Coordinators (esp. cheap models) frequently route to exploitation
        # without target_vulnerability_id. Resolve one from the active
        # hypothesis / KG, create+link one if needed, or gracefully re-route to
        # the analyst instead of hard-failing inside the exploitation agent.
        if agent_name == "exploitation":
            agent_name, task = self._ensure_exploitation_target(agent_name, task)

        self.sm.transition(Event.DECISION_DONE, f"dispatching {agent_name}")
        self.sm.record_dispatch(agent_name)
        emit("agent_start", {
            "agent": agent_name,
            "task": task.task_description,
            "iteration": self.sm.iteration,
            "max_iterations": self.sm.config.max_iterations,
            "state": self.sm.state.value,
        })

        console.print(
            f"\n[bold magenta]🚀 Dispatching [{agent_name}] "
            f"(iter {self.sm.iteration}/{self.sm.config.max_iterations})[/]"
        )
        console.print(f"   Task: {task.task_description[:120]}")
        self.logger.log(f"[EXECUTING] agent={agent_name}, task={task.task_description[:120]}")

        if self.interactive:
            if input("  Press Enter to continue (or 'q' to quit): ").strip().lower() == "q":
                if self.sm.can_transition(Event.BUDGET_EXHAUSTED):
                    self.sm.transition(Event.BUDGET_EXHAUSTED, "user quit")
                return None

        # ---- execute specialist ----
        specialist = self.specialists[agent_name]
        try:
            result: AgentResult = specialist.execute(task)
        except Exception as e:
            console.print(f"[red]Agent {agent_name} crashed: {e}[/]")
            self.logger.log(f"Agent {agent_name} crash: {e}")
            result = AgentResult(
                success=False,
                summary=f"Agent {agent_name} crashed: {e}",
            )

        self.last_result = result
        emit("agent_result", {
            "agent": agent_name,
            "success": result.success,
            "summary": result.summary,
            "facts_added": len(result.facts_added),
            "vulnerabilities_found": len(result.vulnerabilities_found),
            "pocs_recorded": len(result.pocs_recorded),
        })
        if not result.success:
            failure = classify_failure(
                result.summary,
                self.memory.get_recent_failures(8),
                result,
            )
            self.memory.add_fact(
                "last_failure_class",
                failure["category"],
                confidence="suspected",
                source=f"{agent_name}/failure_classifier",
                iteration=self.sm.iteration,
            )
            self.memory.add_fact(
                "last_failure_guidance",
                failure["guidance"],
                confidence="suspected",
                source=f"{agent_name}/failure_classifier",
                iteration=self.sm.iteration,
            )
            emit("failure_classification", {
                "agent": agent_name,
                **failure,
            })
            self.logger.log(
                f"[FAILURE_CLASSIFICATION] {failure['category']} "
                f"confidence={failure['confidence']}: {failure['guidance'][:160]}"
            )

        # ---- OBSERVING ----
        success_icon = "✅" if result.success else "❌"
        self.sm.transition(
            Event.AGENT_SUCCEEDED if result.success else Event.AGENT_FAILED,
            f"{agent_name} → {'success' if result.success else 'failure'}"
        )
        console.print(
            f"[bold]   {success_icon} {agent_name}: {result.summary[:200]}[/]"
        )
        self.logger.log(
            f"[OBSERVING] {agent_name} success={result.success}, "
            f"summary={result.summary[:200]}"
        )

        self.sm.transition(Event.OBSERVATION_LOGGED, "observation processed")

        # ---- UPDATING: record outcome ----
        self.sm.record_agent_outcome(agent_name, result.success)

        # ---- imp-loop: mark recon surface as materialized for this vector ----
        if agent_name == "recon" and result.success and self._has_recon_surface():
            sig = self._recon_signature(self.active_hypothesis)
            if sig:
                self._recon_materialized.add(sig)

        # ---- WS2: advance/backtrack the active hypothesis + phase ----
        self._update_agenda_after_outcome(agent_name, result)

        # ---- imp-loop: no-progress / loop detection ----
        # Record this outer step's progress signature; a stall forces a
        # backtrack (demote the active vector) + pivot instead of churning.
        self._check_stall(agent_name)

        # ---- Pheromone boosting ----
        # Boost pheromone on verified vulnerabilities so they stay hot
        # for the reporter. Decay-based prioritisation would otherwise
        # let them go cold before the report is generated.
        if result.success and result.pocs_recorded:
            for poc in result.pocs_recorded:
                if poc.verdict == "success" and poc.vuln_id:
                    self.memory.boost_entity(poc.vuln_id, new_base=1.0)

        # ---- Auto-validate successful exploitation PoCs ----
        # The exploitation agent is incentivised toward "success"; the
        # validator's incentive is the opposite. Customers see only the
        # post-validator verdict, so a true positive survives a re-test
        # and a flaky one gets demoted before it ever lands in the report.
        if (agent_name == "exploitation" and result.success
                and result.pocs_recorded):
            for poc in result.pocs_recorded:
                if poc.verdict != "success" or not poc.vuln_id:
                    continue
                if poc.request_summary.startswith("FAST_PATH_VALIDATED:"):
                    self.logger.log(
                        f"Skipping validator for {poc.id} "
                        "(deterministic fast-path already compared baseline/probe)"
                    )
                    continue
                if not self.sm.can_call_tool("http_request"):
                    # Don't burn the last drop of budget on validation -
                    # better to ship the unvalidated PoC than nothing.
                    self.logger.log(f"Skipping validator for {poc.id} (budget tight)")
                    continue
                self._dispatch_validator(poc.id, poc.vuln_id)

        # Check for lab_solved in global facts
        lab_solved = self.memory.get_fact("lab_solved")
        if lab_solved:
            console.print("[green bold]🎉 LAB SOLVED — heading to report[/]")
            self.logger.log("LAB_SOLVED detected — reporting")
            self.sm.transition(Event.REPORT_REQUESTED, "lab_solved=True")
            report = self._execute_reporter(decision=None)
            self.sm.transition(Event.REPORT_DONE, "report after lab_solved")
            return report

        # Check for pivot — triggered by consecutive failures OR by the
        # hypothesis agenda demoting a vector (real backtracking).
        if self._needs_pivot or self.sm.should_pivot():
            reason = "agenda backtrack" if self._needs_pivot else "consecutive failure threshold"
            self._needs_pivot = False
            console.print(
                f"[yellow bold]🔄 PIVOT ({reason}) — {self.sm.consecutive_failures} "
                f"consecutive failures (last: {self.sm.last_failed_agent})[/]"
            )
            self.logger.log(
                f"[ESCALATING] reason={reason} "
                f"consecutive_failures={self.sm.consecutive_failures}, "
                f"last_failed={self.sm.last_failed_agent}"
            )
            self.sm.transition(Event.PIVOT_REQUESTED, reason)
            # Tier escalation: swap coordinator+exploitation to the strong model
            # while stuck (stall / agenda backtrack), then run the pivot.
            self._escalate_tier(reason)
            # High-reasoning escalation: only when stuck, then back to routing.
            self._run_pivot(reason)
            # Reset failure counter and re-route
            self.sm.consecutive_failures = 0
            self.sm.transition(Event.DECISION_DONE, "post-pivot re-route")
            # Jump back to ROUTING on next iteration
            # (we moved to ROUTING via ESCALATING → DECISION_DONE → ROUTING)
            return None

        # Normal: go back to ROUTING
        self.sm.transition(Event.DECISION_DONE, "cycle back to routing")
        return None

    # ---- WS2: hypothesis agenda + strategy phase chaining ----------------

    def _seed_hypotheses(self) -> None:
        """Seed the agenda from the lab profile, target category, durable
        successful techniques, and any rehydrated theoretical vulnerabilities."""
        try:
            playbook_id = str(self.lab_profile.get("playbook_id") or "")
            vuln = str(
                self.lab_profile.get("vulnerability")
                or playbook_id
                or self.target_category
                or ""
            )
            if vuln:
                self.agenda.add(
                    text=(
                        f"Confirm {vuln} on {self.target_url} per lab profile "
                        f"{self.lab_profile.get('id', 'n/a')}."
                    ),
                    vuln_type=vuln,
                    vector=str(self.lab_profile.get("parameter") or ""),
                    phase="recon",
                    heat=1.2,
                    notes="seed:lab_profile",
                )
            # Durable memory: boost previously successful techniques for this class.
            if self.durable is not None:
                try:
                    for w in self.durable.successful_techniques(self.lab_class)[:6]:
                        self.agenda.add(
                            text=f"Retry known-good technique: {w['technique']} via {w['tool']}.",
                            vuln_type=str(w.get("technique", "")),
                            vector=str(w.get("tool", "")),
                            phase="injection",
                            heat=1.5,
                            notes="seed:durable_win",
                        )
                except Exception:
                    pass
            # Non-web categories: seed from the category profiler's playbooks so
            # network/binary/mobile/crypto/stego/forensics targets get a
            # populated, category-appropriate agenda (not just web/PortSwigger).
            self._seed_category_hypotheses()
            self._sync_agenda_from_memory()
            if self.agenda.all():
                self.logger.log(
                    f"[AGENDA] seeded {len(self.agenda.all())} hypotheses "
                    f"(category={self.target_category or 'n/a'})"
                )
                emit("hypothesis_agenda", {
                    "count": len(self.agenda.all()),
                    "category": self.target_category,
                })
        except Exception as e:
            self.logger.log(f"[AGENDA] seed failed (degrading): {e}")

    def _sync_agenda_from_memory(self) -> None:
        """Fold theoretical Vulnerability entities (e.g. analyst output) into
        the agenda as ranked hypotheses, deduped."""
        try:
            for v in self.memory.ranked_query(
                "Vulnerability", min_pheromone=0.0, status="theoretical"
            ):
                self.agenda.add(
                    text=str(v.attrs.get("hypothesis", ""))[:300]
                        or str(v.attrs.get("vuln_type", "")),
                    vuln_type=str(v.attrs.get("vuln_type", "")),
                    vector=str(v.attrs.get("parameter") or ""),
                    target_entity_id=v.id,
                    phase="injection",
                    heat=max(0.5, float(v.pheromone_weight())),
                    notes="seed:analyst",
                    resurrect=False,
                )
        except Exception:
            pass

    # Entry phase per non-web category. Crypto challenges are usually acted on
    # directly (no recon surface), everything else starts with enumeration.
    _CATEGORY_SEED_PHASE: dict[str, str] = {
        "network": "recon",
        "binary": "recon",
        "mobile": "recon",
        "crypto": "injection",
        "stego": "recon",
        "forensics": "recon",
        "misc": "recon",
    }

    def _seed_category_hypotheses(self) -> None:
        """Seed the agenda from category_playbooks() for a detected NON-web
        category. Web/PortSwigger targets are seeded by the existing lab-profile
        path and are intentionally skipped here (backward-compatible)."""
        category = (self.target_category or "").strip().lower()
        if not category or category == "web":
            return
        fn = getattr(lab_intel_mod, "category_playbooks", None)
        if not callable(fn):
            return
        try:
            playbooks = fn(category)
        except Exception:
            return
        if not playbooks:
            return
        phase = self._CATEGORY_SEED_PHASE.get(category, "recon")
        for idx, playbook in enumerate(playbooks):
            self.agenda.add(
                text=(
                    f"Pursue the {category} playbook '{playbook}' against "
                    f"{self.target_url}."
                ),
                vuln_type=category,
                vector=str(playbook),
                phase=phase,
                heat=1.15 - (0.05 * idx),
                notes="seed:category_playbook",
            )

    def _select_active_hypothesis(self) -> Hypothesis | None:
        self._sync_agenda_from_memory()
        h = self.agenda.hottest_open()
        self.active_hypothesis = h
        if h:
            self.memory.current_hypothesis = h.text
            self._sync_memory_phase(h.phase)
        return h

    def _sync_memory_phase(self, phase: str) -> None:
        """Mirror the active hypothesis phase into memory.progress so
        get_current_phase() (used by RAG methodology loading) stays aligned."""
        if phase not in PHASE_SEQUENCE:
            return
        cur_idx = PHASE_SEQUENCE.index(phase)
        try:
            for p in self.memory.DEFAULT_PHASES:
                if p not in PHASE_SEQUENCE:
                    continue
                p_idx = PHASE_SEQUENCE.index(p)
                if p_idx < cur_idx:
                    self.memory.update_progress(p, "done")
                elif p_idx == cur_idx:
                    self.memory.update_progress(p, "in_progress")
        except Exception:
            pass

    def _agenda_context(self) -> str:
        parts = [self.agenda.render()]
        if self.active_hypothesis is not None:
            h = self.active_hypothesis
            parts.append(
                f"\n# ACTIVE HYPOTHESIS (pursue this via forced phase chaining)\n"
                f"  vector: {h.vuln_type or '?'} @ {h.vector or 'n/a'}\n"
                f"  phase: {h.phase} (StrategyEngine)\n"
                f"  text: {h.text[:200]}"
            )
        if self.target_category:
            parts.append(f"\n# TARGET CATEGORY\n  {self.target_category}")
        return "\n".join(parts)

    def _inner_budget_hint(self) -> int:
        """Adaptive inner-loop budget: deeper for hard/expert playbooks."""
        base = int(os.getenv("REYNARD_INNER_BUDGET", "0") or 0)
        difficulty = str(self.lab_profile.get("difficulty", "")).lower()
        playbook_id = str(self.lab_profile.get("playbook_id", ""))
        hint = base
        if any(k in difficulty for k in ("expert", "advanced", "hard", "practitioner")):
            hint = max(hint, 16)
        if playbook_id in AUTH_HEAVY_PLAYBOOKS:
            hint = max(hint, 14)
        return hint

    def _inject_task_context(self, task: AgentTask, agent_name: str) -> AgentTask:
        context = {**task.context, "target_url": self.target_url}
        if self.objective:
            context["objective"] = self.objective
        if self.lab_profile:
            context["lab_profile"] = self.lab_profile
        if self.playbook_context:
            context["expert_playbook"] = self.playbook_context

        inner_hint = self._inner_budget_hint()
        if inner_hint:
            context["inner_budget"] = inner_hint

        # imp-loop: session-aware skip. Surface "already authenticated as
        # <user>" so agents reuse the live jar instead of re-logging-in.
        try:
            active = session_mod.get_registry().active()
            context["active_session"] = active.name
            context["session_authenticated"] = bool(active.authenticated)
            if active.authenticated:
                who = active.auth_detail or active.role_hint or active.name
                context["auth_status"] = (
                    f"already authenticated as {who} (session '{active.name}') — "
                    "do NOT re-login; reuse the existing session cookie jar."
                )
        except Exception:
            pass

        # Active StrategyEngine phase + agenda.
        phase = ""
        if self.active_hypothesis is not None:
            phase = self.active_hypothesis.phase
            context["strategy_phase"] = phase
            context["active_hypothesis"] = self.active_hypothesis.text
            context["hypothesis_agenda"] = self.agenda.render()
            try:
                context["phase_instructions"] = self.strategy.get_phase_prompt(
                    phase, self.memory.get_all_facts()
                )
            except Exception:
                pass

        # Resolve a vuln_type for tool-selection + methodology.
        vuln_type = self._resolve_vuln_type(task)

        # WS1: deterministic tool recommendations at phase entry, folding in
        # durable cross-run signals (boost prior wins, demote known dead-ends).
        try:
            tech = self.memory.get_fact("technology_stack") or ""
            boost_tools, demote_tools, wins = self._durable_tool_signals()
            recs = render_recommendations(
                vuln_class=vuln_type or self.target_category or None,
                phase=phase or self.memory.get_current_phase(),
                tech=tech,
                boost_tools=boost_tools or None,
                demote_tools=demote_tools or None,
            )
            if recs:
                if wins:
                    recs += "\n# PRIOR WINS (durable memory): " + ", ".join(
                        sorted({str(w["tool"]) for w in wins})
                    )
                context["tool_recommendations"] = recs
        except Exception:
            pass

        # WS3: RAG methodology keyed on ACTIVE hypothesis + phase, for every
        # specialist that can act on it (not just exploitation).
        if agent_name in ("exploitation", "recon", "analyst", "validator") and vuln_type:
            try:
                methodology = load_methodology(
                    vuln_type,
                    hypothesis=self.memory.current_hypothesis or "",
                    phase=phase or self.memory.get_current_phase(),
                )
                if methodology:
                    context["methodology"] = methodology
                    self.logger.log(
                        f"[METHODOLOGY] Injected RAG methodology for "
                        f"vuln_type={vuln_type} agent={agent_name} phase={phase}"
                    )
            except Exception:
                pass

        return task.model_copy(update={"context": context})

    def _resolve_vuln_type(self, task: AgentTask) -> str:
        if self.active_hypothesis is not None and self.active_hypothesis.vuln_type:
            return self.active_hypothesis.vuln_type
        if task.target_vulnerability_id:
            ve = self.memory.get_entity(task.target_vulnerability_id)
            if ve:
                vt = ve.attrs.get("vuln_type", "")
                if vt:
                    return vt
        vulns = self.memory.ranked_query(
            "Vulnerability", min_pheromone=0.0, status="theoretical"
        )
        if vulns:
            vt = vulns[0].attrs.get("vuln_type", "")
            if vt:
                return vt
        desc_lower = task.task_description.lower()
        for keyword in ["sqli", "sql injection", "xss", "ssrf", "ssti",
                        "idor", "jwt", "deserialization", "smuggling",
                        "cache", "nosql", "command injection", "rce"]:
            if keyword in desc_lower:
                return keyword
        return ""

    # ---- fix-routing: guarantee exploitation gets a Vulnerability id --------

    def _valid_vuln_id(self, vuln_id: str | None) -> bool:
        if not vuln_id:
            return False
        ent = self.memory.get_entity(vuln_id)
        return bool(ent and ent.type == "Vulnerability")

    def _ensure_exploitation_target(
        self, agent_name: str, task: AgentTask
    ) -> tuple[str, AgentTask]:
        """Return (agent_name, task) with a valid target_vulnerability_id set for
        exploitation. Falls back to the analyst when no finding can be resolved
        or created."""
        vuln_id = self._resolve_or_create_vuln_id(task)
        if vuln_id:
            if task.target_vulnerability_id != vuln_id:
                task = task.model_copy(update={"target_vulnerability_id": vuln_id})
                self.logger.log(
                    f"[ROUTING] attached target_vulnerability_id={vuln_id} to exploitation"
                )
            return agent_name, task
        # No finding available → re-route to analyst to produce one first.
        self.logger.log(
            "[ROUTING] exploitation had no resolvable vulnerability; re-routing to analyst"
        )
        emit("routing_recovery", {
            "from": "exploitation", "to": "analyst",
            "reason": "no_target_vulnerability_id",
        })
        analyst_task = task.model_copy(update={
            "task_description": (
                "Produce ONE precise theoretical Vulnerability finding for the "
                "active hypothesis so exploitation can be dispatched with a "
                "target_vulnerability_id. " + task.task_description
            ),
            "target_vulnerability_id": None,
        })
        return "analyst", analyst_task

    def _resolve_or_create_vuln_id(self, task: AgentTask) -> str | None:
        if self._valid_vuln_id(task.target_vulnerability_id):
            return task.target_vulnerability_id
        h = self.active_hypothesis
        if h is not None and self._valid_vuln_id(h.target_entity_id):
            return h.target_entity_id
        theoretical = self._first_theoretical_vuln_id()
        if theoretical:
            return theoretical
        existing = self.memory.query("Vulnerability")
        if existing:
            return existing[0].id
        if h is not None:
            return self._create_vuln_from_hypothesis(h)
        return None

    def _create_vuln_from_hypothesis(self, h: Hypothesis) -> str:
        """Materialize a theoretical Vulnerability entity from a hypothesis so
        exploitation always has a concrete target to work against."""
        target_id = ""
        if h.target_entity_id:
            ent = self.memory.get_entity(h.target_entity_id)
            if ent and ent.type in ("Target", "Endpoint"):
                target_id = ent.id
        if not target_id:
            for etype in ("Endpoint", "Target"):
                ents = self.memory.ranked_query(etype, min_pheromone=0.0)
                if ents:
                    target_id = ents[0].id
                    break
        if not target_id:
            target_id = self.memory.add_entity(
                "Target", {"url": self.target_url}
            ).id
        vuln_type = h.vuln_type or self.target_category or "unknown"
        vuln_entity = self.memory.add_entity("Vulnerability", {
            "vuln_type": vuln_type,
            "severity": "medium",
            "parameter": h.vector or "",
            "hypothesis": h.text or f"Confirm {vuln_type} on {self.target_url}.",
            "status": "theoretical",
            "notes": f"auto-created for exploitation routing ({h.notes or 'hypothesis'})",
            "target_entity_id": target_id,
        })
        try:
            self.memory.add_relationship(
                target_id, "POTENTIALLY_VULNERABLE_TO", vuln_entity.id
            )
        except KeyError:
            pass
        h.target_entity_id = vuln_entity.id
        self.logger.log(
            f"[ROUTING] auto-created {vuln_entity.id} ({vuln_type}) for exploitation "
            f"from hypothesis '{(h.text or '')[:80]}'"
        )
        return vuln_entity.id

    def _update_agenda_after_outcome(self, agent_name: str, result: AgentResult) -> None:
        h = self.active_hypothesis
        if h is None:
            return
        self.agenda.record_attempt(h)
        self._record_incremental_technique(h, result)
        if result.success:
            # Progress = "unstuck": drop back to the cheap default tier (unless
            # pinned strong for an EXPERT-tier / forced run).
            self._revert_tier("progress after success")
            if h.phase == "exploit" or self._hypothesis_has_verified_evidence(h):
                self.agenda.record_success(h)
                self.logger.log(f"[AGENDA] hypothesis VERIFIED: {h.vuln_type}@{h.vector}")
            else:
                new_phase = self.agenda.advance_phase(h)
                self._sync_memory_phase(h.phase)
                self.logger.log(
                    f"[AGENDA] phase advanced -> {new_phase} for {h.vuln_type}@{h.vector}"
                )
        else:
            backtracked = self.agenda.record_failure(h)
            if backtracked:
                self._needs_pivot = True
                self.logger.log(
                    f"[AGENDA] vector DEMOTED (backtrack): {h.vuln_type}@{h.vector} "
                    f"after {h.fail_count} fails"
                )
                emit("hypothesis_demoted", {
                    "vuln_type": h.vuln_type, "vector": h.vector,
                    "fail_count": h.fail_count,
                })

    # ---- imp-loop: redundant-recon guard + stall detection --------------

    @staticmethod
    def _recon_signature(h: Hypothesis | None) -> str:
        if h is None:
            return ""
        return f"{h.vuln_type.lower()}|{h.vector.lower()}|{(h.text or '')[:60].lower()}"

    def _has_recon_surface(self) -> bool:
        """True once recon has materialized endpoints/params into the KG."""
        try:
            return bool(self.memory.query("Endpoint") or self.memory.query("Parameter"))
        except Exception:
            return False

    def _recon_is_redundant(self, task: AgentTask) -> bool:
        """True if recon already materialized the surface for the active
        hypothesis and the task isn't explicitly asking for new surface."""
        if not self._recon_guard_enabled:
            return False
        h = self.active_hypothesis
        if h is None:
            return False
        sig = self._recon_signature(h)
        if not sig or sig not in self._recon_materialized:
            return False
        if not self._has_recon_surface():
            return False
        desc = (task.task_description or "").lower()
        # Honor explicit requests for deeper/new enumeration.
        if any(k in desc for k in (
            "new endpoint", "deeper", "additional", "expand", "re-enumerate",
            "different endpoint", "more surface",
        )):
            return False
        return True

    def _advance_past_recon(self, task: AgentTask) -> tuple[str, AgentTask]:
        """Advance the active hypothesis past the recon phase and hand off to
        the phase owner instead of re-dispatching recon."""
        h = self.active_hypothesis
        if h is not None and h.phase == "recon":
            self.agenda.advance_phase(h)
            self._sync_memory_phase(h.phase)
        routed = PHASE_TO_AGENT.get(h.phase if h else "", "analyst") or "analyst"
        if routed == "recon":
            routed = "analyst"
        self.logger.log(
            f"[RECON_GUARD] recon redundant for '{self._recon_signature(h)}'; "
            f"advancing to phase={h.phase if h else '?'} via {routed}"
        )
        emit("recon_guard", {
            "reason": "recon_surface_already_materialized",
            "routed_to": routed,
            "phase": h.phase if h else "",
        })
        new_task = task.model_copy(update={
            "task_description": (
                "[recon-guard] Recon surface is already materialized for the "
                f"active hypothesis; pursue the {h.phase if h else 'next'} phase "
                f"instead of re-running recon. {task.task_description}"
            ),
        })
        return routed, new_task

    def _check_stall(self, agent_name: str) -> None:
        """Record the outer-step progress signature; on stall, force a
        backtrack (demote the active vector) + pivot instead of repeating."""
        h = self.active_hypothesis
        stalled = self.stall_detector.record(
            agent=agent_name,
            phase=(h.phase if h else self.memory.get_current_phase() or "recon"),
            hypothesis_id=self._recon_signature(h) or (h.text[:40] if h else ""),
            kg_count=len(self.memory.entities),
            evidence_count=len(self.evidence.all_pocs()),
        )
        if not stalled:
            return
        self._stall_forced_pivots += 1
        self.stall_detector.reset()
        if h is not None:
            self.agenda.demote(h)
            self.logger.log(
                f"[STALL] no progress for {self.stall_detector.patience} steps; "
                f"demoting {h.vuln_type}@{h.vector} and forcing pivot "
                f"(stall_pivots={self._stall_forced_pivots})"
            )
        else:
            self.logger.log(
                f"[STALL] no progress for {self.stall_detector.patience} steps; "
                f"forcing pivot (stall_pivots={self._stall_forced_pivots})"
            )
        emit("stall_detected", {
            "patience": self.stall_detector.patience,
            "forced_pivots": self._stall_forced_pivots,
            "demoted": bool(h),
            "vuln_type": h.vuln_type if h else "",
            "vector": h.vector if h else "",
        })
        console.print(
            f"[yellow bold]🌀 Stall detected (no progress x"
            f"{self.stall_detector.patience}) — backtracking + pivot.[/]"
        )
        self._needs_pivot = True

    def _hypothesis_has_verified_evidence(self, h: Hypothesis) -> bool:
        try:
            if h.target_entity_id:
                ent = self.memory.get_entity(h.target_entity_id)
                if ent and ent.attrs.get("status") == "verified":
                    return True
                if self.evidence.is_verified(h.target_entity_id):
                    return True
        except Exception:
            pass
        return bool(self.memory.get_fact("lab_solved"))

    def _has_verified_evidence(self) -> bool:
        try:
            if any(p.verdict == "success" for p in self.evidence.all_pocs()):
                return True
        except Exception:
            pass
        return bool(self.memory.get_fact("lab_solved"))

    # ---- tiered model escalation (strong reasoning tier) ----------------

    def _escalate_tier(self, reason: str) -> None:
        """Swap the coordinator + exploitation dispatch to the strong provider.

        Idempotent and best-effort: disabled via REYNARD_TIER_ESCALATION, and a
        provider-build failure degrades silently to the cheap default. The
        budget/metering is unchanged — only the model binding is swapped.
        """
        if not self._tier_escalation_enabled or self._tier_escalated:
            return
        try:
            strong = self.registry.get("strong")
        except Exception as e:  # noqa: BLE001 - degrade to cheap default
            self.logger.log(f"[TIER] strong provider unavailable: {e}")
            return
        self.coordinator.provider = strong
        self.specialists["exploitation"].provider = strong
        self._tier_escalated = True
        self._tier_escalations += 1
        self.logger.log(
            f"[TIER] escalated coordinator+exploitation to strong tier "
            f"(reason={reason}, count={self._tier_escalations})"
        )
        emit("tier_escalated", {
            "reason": reason,
            "count": self._tier_escalations,
            "model": getattr(getattr(strong, "config", None), "model", ""),
        })
        console.print(f"[magenta]⬆ Tier escalation → strong model ({reason}).[/]")

    def _revert_tier(self, reason: str) -> None:
        """Revert the coordinator + exploitation dispatch to the cheap default.

        No-op when not escalated or when the strong tier is pinned for the whole
        run (EXPERT-tier / forced training re-run)."""
        if not self._tier_escalated or self._tier_pinned_strong:
            return
        try:
            self.coordinator.provider = self.registry.get("coordinator")
            self.specialists["exploitation"].provider = self.registry.get("exploitation")
        except Exception as e:  # noqa: BLE001 - keep strong binding on failure
            self.logger.log(f"[TIER] revert failed (staying on strong): {e}")
            return
        self._tier_escalated = False
        self.logger.log(f"[TIER] reverted to cheap default tier (reason={reason})")
        emit("tier_reverted", {"reason": reason})
        console.print(f"[cyan]⬇ Tier reverted → default model ({reason}).[/]")

    def _maybe_start_escalated(self) -> None:
        """Escalate from the first step for EXPERT-tier / forced runs."""
        if self._tier_pinned_strong:
            reason = "forced strong tier" if self._force_strong_tier else (
                f"EXPERT-tier lab ({self.lab_class})"
            )
            self._escalate_tier(reason)

    # ---- WS2: pivot escalation (high reasoning, only when stuck) ---------

    def _run_pivot(self, reason: str) -> None:
        if self._budget_exceeded():
            return
        try:
            provider = self.registry.get("pivot")
        except Exception as e:
            self.logger.log(f"[PIVOT] provider unavailable: {e}")
            return
        try:
            decision: PivotDecision = provider.call_typed(
                PIVOT_SYSTEM, self._build_pivot_prompt(reason), PivotDecision
            )
        except Exception as e:
            self.logger.log(f"[PIVOT] escalation failed (degrading): {e}")
            return
        self._pivot_used += 1
        self.logger.log(f"[PIVOT] diagnosis={decision.diagnosis[:200]}")
        emit("reasoning_note", {
            "agent": "pivot",
            "text": decision.diagnosis,
            "new_hypothesis": decision.new_hypothesis,
        })
        console.print(f"[magenta]🧭 Pivot: {decision.diagnosis[:160]}[/]")
        self._apply_pivot(decision, default_heat=1.8)

    def _apply_pivot(self, decision: PivotDecision, default_heat: float) -> None:
        if decision.new_hypothesis:
            self.agenda.add(
                text=decision.new_hypothesis,
                vuln_type=decision.new_vuln_type,
                vector=decision.recommended_vector,
                phase="injection",
                heat=default_heat,
                notes="pivot",
            )
        # Boost any existing hypothesis matching the recommended vector.
        if decision.recommended_vector:
            needle = decision.recommended_vector.lower()
            for h in self.agenda.open_hypotheses():
                if needle and (needle in h.vector.lower() or needle in h.text.lower()):
                    h.heat = min(1.0 + default_heat, h.heat + 0.5)

    def _build_pivot_prompt(self, reason: str) -> str:
        sections = [
            f"# TARGET\n{self.target_url}",
            f"\n# WHY INVOKED\n{reason}",
        ]
        if self.objective:
            sections.append(f"\n# OBJECTIVE\n{self.objective}")
        if self.target_category:
            sections.append(f"\n# TARGET CATEGORY\n{self.target_category}")
        sections.append(f"\n{self.agenda.render(limit=12)}")
        try:
            sections.append(f"\n{self.evidence.summarize()}")
        except Exception:
            pass
        try:
            sections.append(f"\n{self.memory.failure_summary(12)}")
        except Exception:
            pass
        sections.append(
            "\n# YOUR OUTPUT\nDiagnose the blocker and propose ONE concrete, "
            "untried vector. Output a single PivotDecision JSON."
        )
        return "\n".join(sections)

    # ---- WS6: report gating + self-critique before failure --------------

    def _intercept_done(self, decision: CoordinatorDecision) -> CoordinatorDecision:
        if not decision.done:
            return decision
        if self._has_verified_evidence() or self.agenda.any_verified():
            return decision
        # 1. Gate premature reporting while untried actionable vectors remain.
        if self._should_gate_report():
            override = self._forced_dispatch_decision()
            if override is not None:
                self._report_gate_count += 1
                console.print(
                    "[yellow]⛔ Report gated — hypothesis agenda not exhausted; "
                    "forcing progress.[/]"
                )
                self.logger.log(
                    f"[GATE] premature report suppressed "
                    f"(gate #{self._report_gate_count})"
                )
                emit("report_gated", {
                    "gate_count": self._report_gate_count,
                    "next_agent": override.next_agent,
                })
                return override
        # 2. Self-critique once: propose one more concrete vector, then try it.
        if self._maybe_self_critique():
            override = self._forced_dispatch_decision()
            if override is not None:
                console.print(
                    "[cyan]🔎 Self-critique proposed a new vector — trying once.[/]"
                )
                return override
        return decision

    def _should_gate_report(self) -> bool:
        if not self._report_gating_enabled:
            return False
        if self.sm.iteration >= int(self.sm.config.max_iterations * 0.9):
            return False
        if self._budget_exceeded():
            return False
        if self._report_gate_count >= self._max_report_gates:
            return False
        return self.agenda.has_unattempted()

    def _forced_dispatch_decision(self) -> CoordinatorDecision | None:
        h = self._select_active_hypothesis()
        if h is None:
            return None
        agent = PHASE_TO_AGENT.get(h.phase, "exploitation")
        target_vuln = h.target_entity_id or self._first_theoretical_vuln_id()
        if agent == "exploitation" and not target_vuln:
            # Need a theoretical finding first.
            agent = "analyst"
        task = AgentTask(
            task_description=(
                f"[forced] Pursue hypothesis ({h.phase} phase): {h.text}"
            ),
            context={},
            target_vulnerability_id=target_vuln if agent == "exploitation" else None,
        )
        return CoordinatorDecision(
            done=False,
            next_agent=agent,  # type: ignore[arg-type]
            task=task,
            reasoning=(
                "Report gated / self-critique: agenda not exhausted; forcing "
                f"progress on hottest hypothesis via {agent}."
            ),
        )

    def _first_theoretical_vuln_id(self) -> str | None:
        vulns = self.memory.ranked_query(
            "Vulnerability", min_pheromone=0.0, status="theoretical"
        )
        return vulns[0].id if vulns else None

    def _maybe_self_critique(self) -> bool:
        if self._self_critique_done:
            return False
        self._self_critique_done = True
        if self._has_verified_evidence() or self.agenda.any_verified():
            return False
        if self.sm.is_iteration_exhausted() or self._budget_exceeded():
            return False
        try:
            provider = self.registry.get("pivot")
            decision: PivotDecision = provider.call_typed(
                SELF_CRITIQUE_SYSTEM,
                self._build_pivot_prompt("final self-critique before failure"),
                PivotDecision,
            )
        except Exception as e:
            self.logger.log(f"[SELF_CRITIQUE] failed (degrading): {e}")
            return False
        if decision.give_up or not decision.new_hypothesis:
            self.logger.log("[SELF_CRITIQUE] no actionable vector; concluding.")
            return False
        self._apply_pivot(decision, default_heat=2.0)
        self.logger.log(
            f"[SELF_CRITIQUE] added vector: {decision.new_hypothesis[:140]}"
        )
        emit("self_critique", {
            "diagnosis": decision.diagnosis,
            "new_hypothesis": decision.new_hypothesis,
        })
        return True

    def _record_incremental_technique(self, h: Hypothesis, result: AgentResult) -> None:
        """WS3: record per-outcome technique success/dead-end into durable
        memory inside the loop (not only at run end)."""
        if self.durable is None or h is None:
            return
        try:
            outcome = "success" if result.success else "deadend"
            technique = h.vuln_type or (h.text[:60] if h.text else self.lab_class)
            tool = h.vector or PHASE_TO_AGENT.get(h.phase, "exploitation")
            self.durable.record_technique(
                self.lab_class,
                technique=technique,
                tool=tool,
                outcome=outcome,
                detail=str(result.summary)[:200],
            )
        except Exception as e:
            self.logger.log(f"[DURABLE] incremental record failed: {e}")

    # ---- durable cross-run memory hooks ---------------------------------

    def _durable_tool_signals(self) -> tuple[list[str], list[str], list[dict]]:
        """Return (boost_tools, demote_tools, wins) from durable memory for the
        active lab class. `tool_selector.rank_tools` folds boost/demote into the
        deterministic ranking so learned experience steers tool selection."""
        if self.durable is None:
            return [], [], []
        wins: list[dict] = []
        boost: list[str] = []
        demote: list[str] = []
        try:
            wins = self.durable.successful_techniques(self.lab_class)[:8]
            boost = [str(w["tool"]) for w in wins if w.get("tool")]
        except Exception:
            wins = []
        try:
            deads = self.durable.known_deadends(self.lab_class)[:8]
            demote = [str(d["tool"]) for d in deads if d.get("tool")]
        except Exception:
            pass
        # Never demote a tool that is also a known win for this class.
        demote = [t for t in demote if t not in set(boost)]
        return boost, demote, wins

    def _rehydrate_durable(self) -> None:
        """Prime the run with prior knowledge for this target/lab-class.

        Rehydrated entities are treated as WARM (see AgentMemory.rehydrate) so
        stale monotonic decay timestamps never make a cold finding look hot.
        Successful techniques / known dead-ends for the lab class are surfaced
        as suspected facts so the coordinator can prime and avoid them.
        """
        if self.durable is None:
            return
        try:
            n_kg = self.memory.rehydrate(
                self.durable, self.durable_target, self.lab_class)
            n_ev = self.evidence.rehydrate(
                self.durable, self.durable_target, self.lab_class)
            wins = self.durable.successful_techniques(self.lab_class)
            deads = self.durable.known_deadends(self.lab_class)
            if wins:
                self.memory.add_fact(
                    "primed_successful_techniques",
                    "; ".join(f"{w['technique']} via {w['tool']} (x{w['count']})"
                              for w in wins[:8]),
                    confidence="suspected", source="durable_memory",
                )
            if deads:
                self.memory.add_fact(
                    "primed_known_deadends",
                    "; ".join(f"{d['technique']}/{d['tool']} (x{d['count']})"
                              for d in deads[:8]),
                    confidence="suspected", source="durable_memory",
                )
            if n_kg or n_ev or wins or deads:
                console.print(
                    f"[dim]🧠 Durable memory primed: {n_kg} entities, {n_ev} PoCs, "
                    f"{len(wins)} known-good, {len(deads)} dead-ends[/]"
                )
            self.logger.log(
                f"[DURABLE] rehydrated kg={n_kg} pocs={n_ev} wins={len(wins)} "
                f"deadends={len(deads)} (target={self.durable_target}, "
                f"class={self.lab_class})"
            )
            emit("durable_rehydrate", {
                "entities": n_kg, "pocs": n_ev,
                "successful_techniques": len(wins), "known_deadends": len(deads),
                "lab_class": self.lab_class,
            })
        except Exception as e:
            self.logger.log(f"[DURABLE] rehydrate failed (degrading): {e}")

    def _record_learned_techniques(self) -> None:
        """Derive success / dead-end technique records from this run's outcome."""
        if self.durable is None:
            return
        try:
            for vuln in self.memory.query("Vulnerability"):
                if not self.evidence.is_verified(vuln.id):
                    continue
                technique = vuln.attrs.get("vuln_type") or self.lab_class
                self.durable.record_technique(
                    self.lab_class, technique=technique,
                    tool=str(self.lab_profile.get("playbook_id", "exploitation")),
                    outcome="success",
                    detail=str(vuln.attrs.get("description", ""))[:200],
                )
            for fr in self.memory.failed_attempts:
                self.durable.record_technique(
                    self.lab_class, technique=fr.phase or "attempt",
                    tool=fr.tool, outcome="deadend", detail=fr.reason,
                )
        except Exception as e:
            self.logger.log(f"[DURABLE] technique recording failed: {e}")

    def _persist_durable(self) -> None:
        """Persist KG + evidence + learned techniques at run end."""
        if self.durable is None:
            return
        try:
            self._record_learned_techniques()
            ok_mem = self.memory.persist(
                self.durable, self.durable_target, self.lab_class)
            ok_ev = self.evidence.persist(
                self.durable, self.durable_target, self.lab_class)
            self.logger.log(
                f"[DURABLE] persisted memory={ok_mem} evidence={ok_ev} "
                f"(target={self.durable_target}, class={self.lab_class})"
            )
            emit("durable_persist", {
                "memory": ok_mem, "evidence": ok_ev, "lab_class": self.lab_class,
            })
        except Exception as e:
            self.logger.log(f"[DURABLE] persist failed: {e}")
        finally:
            try:
                self.durable.close()
            except Exception:
                pass

    # ---- bounded subagent bootstrap -------------------------------------

    def _run_bootstrap_subagents(self) -> None:
        """Run safe parallel sidecars before the first coordinator decision."""
        specs = self._build_bootstrap_subagents()
        if not specs:
            return

        console.print(
            f"[bold cyan]Launching {len(specs)} bounded bootstrap subagent(s)...[/]"
        )
        self.logger.log(
            "Bootstrap subagents: "
            + ", ".join(f"{spec.name}/{spec.lane}" for spec in specs)
        )
        runs = self.subagent_scheduler.run(specs, lab_profile=self.lab_profile)
        successes = sum(1 for run in runs if run.success)
        self.memory.add_fact(
            "bootstrap_subagents",
            {
                "total": len(runs),
                "successes": successes,
                "runs": [run.__dict__ for run in runs],
            },
            source="orchestrator/subagents",
        )
        self.logger.log(
            f"Bootstrap subagents completed: successes={successes}/{len(runs)}"
        )
        for run in runs:
            style = "green" if run.success else ("yellow" if run.status == "skipped" else "red")
            console.print(
                f"[{style}]subagent {run.name}[/] "
                f"{run.status} in {run.elapsed_sec:.2f}s: {run.summary[:140]}"
            )

    def _build_bootstrap_subagents(self) -> list[SubagentSpec]:
        specs: list[SubagentSpec] = []
        playbook_id = self.lab_profile.get("playbook_id", "")
        primary_tools = set(self.lab_profile.get("primary_tools", []))

        if playbook_id:
            specs.append(SubagentSpec(
                name="profile-analyst",
                lane="analysis",
                reason="Create one focused theoretical finding from the detected expert lab profile.",
                run=self._profile_analyst_subagent,
                mutates_target=False,
            ))

        if "caido_local_api" in primary_tools:
            specs.append(SubagentSpec(
                name="caido-readiness",
                lane="readiness",
                reason="Check whether the Caido local Replay/history bridge is available.",
                run=self._caido_readiness_subagent,
                mutates_target=False,
            ))

        if self._profile_requires_auth():
            specs.append(SubagentSpec(
                name="session-readiness",
                lane="readiness",
                reason="Inventory configured auth sessions before auth-heavy lab execution.",
                run=self._session_readiness_subagent,
                mutates_target=False,
            ))

        if any(tool.startswith("oob_") for tool in primary_tools):
            specs.append(SubagentSpec(
                name="oob-readiness",
                lane="readiness",
                reason="Record that this playbook depends on OOB callback readiness.",
                run=self._oob_readiness_subagent,
                mutates_target=False,
            ))

        return specs

    def _profile_analyst_subagent(self) -> AgentResult:
        analyst = self.specialists["analyst"]
        task = AgentTask(
            task_description=(
                "Bootstrap a single focused theoretical finding from the "
                "detected expert lab profile. Do not speculate beyond the playbook."
            ),
            context={
                "target_url": self.target_url,
                "objective": self.objective,
                "lab_profile": self.lab_profile,
                "expert_playbook": self.playbook_context,
                "subagent_lane": "profile-analyst",
            },
        )
        return analyst.execute(task)

    def _caido_readiness_subagent(self) -> AgentResult:
        outcome = self.tool_executor.call(
            ToolDecision(
                tool="caido_local_api",
                args={"operation": "status", "args": {}},
                reasoning="Read-only readiness check for Caido local bridge.",
                expected_signal="Bridge returns ok=true if Replay/history API is reachable.",
            ),
            agent_name="subagent:caido-readiness",
            phase="readiness",
            iteration=self.sm.iteration,
        )
        ready = False
        message = outcome["blocked_reason"] if outcome["blocked"] else outcome["result"]
        if not outcome["blocked"]:
            try:
                parsed = json.loads(outcome["result"])
                ready = bool(parsed.get("ok"))
                message = parsed.get("message") or parsed.get("status") or outcome["result"]
            except (json.JSONDecodeError, TypeError):
                ready = '"ok": true' in outcome["result"].lower()
        self.memory.add_fact(
            "caido_local_ready",
            ready,
            confidence="confirmed",
            source="subagent/caido-readiness",
            iteration=self.sm.iteration,
        )
        return AgentResult(
            success=True,
            summary=(
                "Caido local bridge reachable."
                if ready else
                f"Caido local bridge not confirmed: {str(message)[:180]}"
            ),
        )

    def _session_readiness_subagent(self) -> AgentResult:
        outcome = self.tool_executor.call(
            ToolDecision(
                tool="list_sessions",
                args={},
                reasoning="Read-only inventory of configured sessions for auth-heavy labs.",
                expected_signal="List of available named sessions and active identity.",
            ),
            agent_name="subagent:session-readiness",
            phase="readiness",
            iteration=self.sm.iteration,
        )
        session_count = 0
        active = ""
        if not outcome["blocked"]:
            try:
                parsed = json.loads(outcome["result"])
                sessions = parsed.get("sessions") or []
                session_count = len(sessions)
                active = str(parsed.get("active") or "")
            except (json.JSONDecodeError, TypeError):
                pass
        self.memory.add_fact(
            "configured_session_count",
            session_count,
            source="subagent/session-readiness",
            iteration=self.sm.iteration,
        )
        if active:
            self.memory.add_fact(
                "active_session",
                active,
                source="subagent/session-readiness",
                iteration=self.sm.iteration,
            )
        return AgentResult(
            success=True,
            summary=(
                f"Session readiness: {session_count} configured session(s)"
                + (f", active={active}." if active else ".")
            ),
        )

    def _oob_readiness_subagent(self) -> AgentResult:
        self.memory.add_fact(
            "oob_required",
            True,
            source="subagent/oob-readiness",
            iteration=self.sm.iteration,
        )
        self.memory.add_fact(
            "oob_guidance",
            "Verify interactsh/OOB availability before blind exploitation.",
            source="subagent/oob-readiness",
            iteration=self.sm.iteration,
        )
        return AgentResult(
            success=True,
            summary="OOB callbacks are required by this playbook; readiness guidance recorded.",
        )

    def _profile_requires_auth(self) -> bool:
        return bool(
            self.lab_profile.get("credentials")
            or self.lab_profile.get("playbook_id") in AUTH_HEAVY_PLAYBOOKS
        )

    # ---- reporter dispatch ------------------------------------------------

    def _execute_reporter(self, decision: CoordinatorDecision | None) -> AgentResult:
        """Run the reporter agent and return its result."""
        task = AgentTask(
            task_description="Generate the final penetration test report.",
            context={
                "target_url": self.target_url,
                "objective": self.objective,
                "lab_profile": self.lab_profile,
                "expert_playbook": self.playbook_context,
                "session_duration": f"{time.time() - self.session_start:.1f}s",
                "total_iterations": self.sm.iteration,
            },
        )
        reporter = self.specialists["reporter"]
        try:
            return reporter.execute(task)
        except Exception as e:
            console.print(f"[red]Reporter failure: {e}[/]")
            self.logger.log(f"Reporter error: {e}")
            return AgentResult(
                success=False,
                summary=f"Reporter failed: {e}",
            )

    def _dispatch_validator(self, poc_id: str, vuln_id: str) -> AgentResult:
        """Re-test a freshly-claimed PoC. Doesn't consume an iteration budget
        slot (validation is a sub-step of exploitation, not a peer dispatch).

        Side-effect: mutates the vuln entity's status to verified /
        informational / false_positive based on the validator's verdict.
        """
        console.print(
            f"[cyan]🔍 Auto-validating PoC {poc_id} for {vuln_id}...[/]"
        )
        self.logger.log(f"[VALIDATING] poc_id={poc_id} vuln_id={vuln_id}")

        validator = self.specialists["validator"]
        active_session = ""
        session_authenticated = False
        try:
            active = session_mod.get_registry().active()
            active_session = active.name
            session_authenticated = bool(active.authenticated)
        except Exception:
            pass
        task = AgentTask(
            task_description=(
                f"Re-test PoC {poc_id} for vulnerability {vuln_id}. "
                "Run replay, counter-probe, and causal-vary to confirm or refute."
            ),
            context={
                "poc_id": poc_id,
                "vuln_id": vuln_id,
                "target_url": self.target_url,
                "objective": self.objective,
                "lab_profile": self.lab_profile,
                "expert_playbook": self.playbook_context,
                "active_session": active_session,
                "session_authenticated": session_authenticated,
                "credential_hint": self.memory.get_fact("credential_hint", ""),
            },
        )
        try:
            res: AgentResult = validator.execute(task)
        except Exception as e:
            console.print(f"[red]Validator crashed: {e}[/]")
            self.logger.log(f"Validator crash: {e}")
            return AgentResult(success=False, summary=f"Validator crashed: {e}")

        self.logger.log(
            f"[VALIDATED] poc_id={poc_id} -> success={res.success} "
            f"summary={res.summary[:160]}"
        )
        return res

    def _dispatch_reporter(self) -> AgentResult:
        """Force-dispatch reporter (budget exhaustion path)."""
        if self.sm.can_transition(Event.REPORT_REQUESTED):
            self.sm.transition(Event.REPORT_REQUESTED, "forced by budget exhaustion")
        result = self._execute_reporter(decision=None)
        if self.sm.can_transition(Event.REPORT_DONE):
            self.sm.transition(Event.REPORT_DONE, "forced report completed")
        return result

    # ---- cost/token budget ------------------------------------------------

    def _token_cost_snapshot(self) -> dict:
        """Cumulative token totals + estimated cost for UI / logs / result."""
        totals = self.token_meter.totals()
        return {
            "prompt_tokens": totals["prompt_tokens"],
            "completion_tokens": totals["completion_tokens"],
            "total_tokens": totals["total_tokens"],
            "llm_calls": totals["calls"],
            "estimated_cost_usd": self.token_meter.estimated_cost(),
        }

    def _budget_exceeded(self) -> str | None:
        """Return a human-readable reason if a configured budget cap is hit."""
        if self.max_tokens_budget or self.max_cost_budget:
            snap = self._token_cost_snapshot()
            if self.max_tokens_budget and snap["total_tokens"] >= self.max_tokens_budget:
                return (
                    f"tokens {snap['total_tokens']} >= "
                    f"LLM_MAX_TOKENS_BUDGET {self.max_tokens_budget}"
                )
            if self.max_cost_budget and snap["estimated_cost_usd"] >= self.max_cost_budget:
                return (
                    f"cost ${snap['estimated_cost_usd']} >= "
                    f"LLM_MAX_COST_BUDGET ${self.max_cost_budget}"
                )
        return None

    # ---- display helpers --------------------------------------------------

    def _print_banner(self) -> None:
        burp_status = "[green]Reachable[/]" if burp_mod.get_client().is_available() else "[red]Offline (MCP extension not running)[/]"
        caido_local_status = "[green]Reachable[/]" if caido_local_mod.CaidoLocalBridgeClient(timeout=1.0).status().get("ok") else "[yellow]Offline (local bridge not running)[/]"
        caido_status = "[green]Configured[/]" if caido_mod.get_client().is_configured() else "[yellow]Not configured (set CAIDO_PAT)[/]"
        objective_line = (
            f"[bold white]Objective:[/] {self.objective[:160]}\n"
            if self.objective else ""
        )
        profile_line = (
            f"[bold white]Lab profile:[/] {self.lab_profile.get('id', '')}\n"
            if self.lab_profile else ""
        )
        banner = Panel(
            f"[bold white]🎯 Target:[/] {self.target_url}\n"
            f"{objective_line}"
            f"{profile_line}"
            f"[bold white]Scope:[/] {self.scope_guard.describe()}\n"
            f"[bold white]⚙  Max iterations:[/] {self.sm.config.max_iterations}\n"
            f"[bold white]Bounded subagents:[/] "
            f"{'enabled' if self.subagents_enabled else 'disabled'} "
            f"(max {self.max_subagents})\n"
            f"[bold white]Caido Local Bridge:[/] {caido_local_status}\n"
            f"[bold white]Caido Cloud API:[/] {caido_status}\n"
            f"[bold white]🔍 Burp Suite MCP:[/] {burp_status} (fallback)\n"
            f"[bold white]🤖 Providers:[/]\n{self.registry.describe()}\n"
            f"[bold white]📂 Log:[/] {self.logger.path}",
            title="[bold cyan]Multi-Agent Orchestrator[/]",
            border_style="cyan",
            expand=False,
        )
        console.print(banner)

    def _print_state_panel(self) -> None:
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="bold", width=20)
        table.add_column()
        table.add_row("State", self.sm.state.value)
        table.add_row("Iteration", f"{self.sm.iteration}/{self.sm.config.max_iterations}")
        table.add_row("Failures", f"{self.sm.consecutive_failures}/{self.sm.config.max_consecutive_failures}")
        table.add_row("KG entities", str(len(self.memory.entities)))
        table.add_row("Evidence", f"{len(self.evidence.all_pocs())} PoC(s)")
        snap = self._token_cost_snapshot()
        budget_hint = ""
        if self.max_tokens_budget:
            budget_hint = f" / {self.max_tokens_budget}"
        table.add_row("Tokens", f"{snap['total_tokens']}{budget_hint}")
        if self.max_cost_budget or snap["estimated_cost_usd"]:
            table.add_row("Est. cost", f"${snap['estimated_cost_usd']}")
        console.print(Panel(table, title="[dim]Orchestrator State[/]", border_style="dim", expand=False))

    def _print_summary(self) -> None:
        duration = time.time() - self.session_start
        all_pocs = self.evidence.all_pocs()
        verified = sum(1 for p in all_pocs if p.verdict == "success")
        snap = self._token_cost_snapshot()
        cost_line = (
            f"[bold]Est. cost:[/] ${snap['estimated_cost_usd']}\n"
            if (self.max_cost_budget or snap["estimated_cost_usd"]) else ""
        )

        summary = Panel(
            f"[bold]Duration:[/] {duration:.1f}s\n"
            f"[bold]Iterations:[/] {self.sm.iteration}\n"
            f"[bold]Tool calls:[/] {sum(self.sm.tool_calls.values())}\n"
            f"[bold]Agent dispatches:[/] {json.dumps(self.sm.agent_dispatches)}\n"
            f"[bold]KG entities:[/] {len(self.memory.entities)}\n"
            f"[bold]PoCs recorded:[/] {len(all_pocs)} ({verified} verified)\n"
            f"[bold]Tokens:[/] {snap['total_tokens']} "
            f"(prompt {snap['prompt_tokens']} / completion {snap['completion_tokens']}, "
            f"{snap['llm_calls']} LLM calls)\n"
            f"{cost_line}"
            f"[bold]Log:[/] {self.logger.path}",
            title="[bold green]Session Summary[/]",
            border_style="green",
            expand=False,
        )
        console.print(summary)


# =============================================================================
# CLI
# =============================================================================

def _print_extended_readiness() -> None:
    """WS6: surface the check_runtime self-check (Kali tools + Chromium/
    Playwright + Caido bridge + readiness score) from the orchestrator
    --preflight path. Single source of truth lives in scripts/check_runtime.py.
    """
    try:
        import importlib.util
        cr_path = Path(__file__).resolve().parents[3] / "scripts" / "check_runtime.py"
        if not cr_path.exists():
            return
        spec = importlib.util.spec_from_file_location("reynard_check_runtime", cr_path)
        if spec is None or spec.loader is None:
            return
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.run_self_check()
        score = report["readiness_score"]
        style = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
        console.print(f"[{style}]preflight readiness score: {score}/100[/]")
        for tool, status in report["kali_tools"].items():
            tstyle = "green" if status == "ok" else ("yellow" if status == "unknown" else "red")
            console.print(f"  [{tstyle}]kali:{tool}[/] {status}")
        pw = report["playwright"]
        console.print(f"  chromium/playwright: {pw['status']} — {pw['message']}")
        cd = report["caido_bridge"]
        console.print(f"  caido_bridge: {cd['status']} — {cd['message']}")
    except Exception as exc:
        console.print(f"[yellow]extended readiness check skipped: {exc}[/]")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="orchestrator",
        description=(
            "Multi-Agent Penetration Testing Orchestrator. "
            "Coordinates recon, analysis, exploitation, and reporting "
            "agents against a target URL."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target URL to test (e.g. https://TARGET.web-security-academy.net)",
    )
    parser.add_argument(
        "--max-iterations", "-n",
        type=int,
        default=int(os.getenv("MAX_ITERATIONS", "30")),
        help="Maximum specialist dispatches (default: 30 or MAX_ITERATIONS env var)",
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Pause before each specialist dispatch for manual review",
    )
    parser.add_argument(
        "--no-subagents",
        action="store_true",
        help="Disable bounded bootstrap subagents and run the legacy serial orchestrator.",
    )
    parser.add_argument(
        "--max-subagents",
        type=int,
        default=int(os.getenv("MAX_SUBAGENTS", "4")),
        help="Maximum safe bootstrap subagents to run in parallel (default 4).",
    )
    parser.add_argument(
        "--auth-file",
        type=str,
        default=None,
        help=(
            "Path to a JSON/YAML file describing auth sessions "
            "(see sessions.py docstring). Loads identities like 'admin', "
            "'user1', 'user2', 'unauth' for IDOR/authz testing."
        ),
    )
    parser.add_argument(
        "--scope-domain",
        action="append",
        default=[],
        help=(
            "Additional in-scope domain. Can be repeated. The target host is "
            "always included automatically."
        ),
    )
    parser.add_argument(
        "--scope-cidr",
        action="append",
        default=[],
        help="Additional in-scope CIDR range, e.g. 10.10.10.0/24. Can be repeated.",
    )
    parser.add_argument(
        "--no-oob",
        action="store_true",
        help="Disable interactsh OOB session (skip the startup probe).",
    )
    parser.add_argument(
        "--interactsh-server",
        type=str,
        default=None,
        help="Override interactsh server (default oast.pro or $INTERACTSH_SERVER).",
    )
    parser.add_argument(
        "--ui",
        action="store_true",
        default=os.getenv("LIVE_UI", "false").lower() == "true",
        help="Start the live browser dashboard while the agent runs.",
    )
    parser.add_argument(
        "--ui-host",
        type=str,
        default=os.getenv("LIVE_UI_HOST", "127.0.0.1"),
        help="Live dashboard host (default 127.0.0.1).",
    )
    parser.add_argument(
        "--ui-port",
        type=int,
        default=int(os.getenv("LIVE_UI_PORT", "8765")),
        help="Live dashboard port (default 8765).",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run preflight checks and exit without starting the orchestrator.",
    )
    return parser.parse_args()


def main() -> None:
    _force_utf8_console()
    # Load .env from the project root
    env_path = ENV_FILE
    if env_path.exists():
        load_dotenv(env_path)
        console.print(f"[dim]Loaded .env from {env_path}[/]")

    args = parse_args()

    if not args.target:
        console.print("[red]Error: target URL is required.[/]")
        console.print("Usage: python orchestrator.py \"https://TARGET_URL\"")
        sys.exit(1)

    raw_target = args.target
    target_url, objective = normalize_target_input(raw_target)
    lab_profile = detect_lab_profile(raw_target, target_url)
    exploit_server_url = extract_exploit_server_url(raw_target)
    if target_url != raw_target:
        console.print(f"[dim]Parsed target URL: {target_url}[/]")
    if lab_profile:
        console.print(f"[dim]Detected lab profile: {lab_profile.get('id')}[/]")
    if exploit_server_url:
        console.print(f"[dim]Detected exploit server: {exploit_server_url}[/]")

    scope_domains = list(args.scope_domain or [])
    if exploit_server_url:
        exploit_host = (urlparse(exploit_server_url).hostname or "").lower()
        if exploit_host and exploit_host not in scope_domains:
            scope_domains.append(exploit_host)
    scope_guard = ScopeGuard.from_target_url(
        target_url,
        extra_domains=scope_domains,
        extra_cidrs=args.scope_cidr,
    )
    preflight_checks = run_preflight(target_url, scope_guard)
    for check in preflight_checks:
        style = "green" if check.ok else ("red" if check.fatal else "yellow")
        status = "OK" if check.ok else ("FAIL" if check.fatal else "WARN")
        console.print(f"[{style}]preflight {status}[/] {check.name}: {check.message}")
    if args.preflight:
        _print_extended_readiness()
        sys.exit(1 if has_fatal_failure(preflight_checks) else 0)
    if has_fatal_failure(preflight_checks):
        console.print("[red]Fatal preflight failure; refusing to start run.[/]")
        sys.exit(1)

    dashboard = None
    if args.ui:
        dashboard = start_dashboard(args.ui_host, args.ui_port)
        console.print(f"[bold green]Live dashboard:[/] {dashboard.url}")

    # Load auth sessions BEFORE orchestrator startup so http_request etc.
    # see them on first call.
    if args.auth_file:
        msgs = session_mod.load_from_file(args.auth_file)
        for m in msgs:
            console.print(f"[dim]auth: {m}[/]")
    reg = session_mod.get_registry()
    sess_summary = reg.describe()
    console.print(
        f"[dim]Sessions registered: {[s['name'] for s in sess_summary['sessions']]}"
        f" (active={sess_summary['active']})[/]"
    )

    # Initialise OOB unless disabled.
    if not args.no_oob:
        if args.interactsh_server:
            os.environ["INTERACTSH_SERVER"] = args.interactsh_server
        try:
            from hacking_agent.core import oob
            oob_sess = oob.get_session()
            console.print(f"[dim]{oob_sess.describe()}[/]")
        except Exception as e:
            console.print(f"[yellow]OOB init failed: {e}[/]")

    orchestrator = Orchestrator(
        target_url=target_url,
        max_iterations=args.max_iterations,
        interactive=args.interactive,
        objective=objective,
        lab_profile=lab_profile,
        scope_domains=scope_domains,
        scope_cidrs=args.scope_cidr,
        subagents_enabled=not args.no_subagents,
        max_subagents=args.max_subagents,
        exploit_server_url=exploit_server_url,
    )

    result = orchestrator.run()

    if result and result.success:
        console.print("\n[bold green]✅ Session completed successfully.[/]")
        if result.artifact:
            console.print(f"[green]Report preview (first 500 chars):[/]")
            console.print(result.artifact[:500])
    else:
        console.print("\n[bold yellow]⚠ Session ended without a successful report.[/]")
        if result:
            console.print(f"Summary: {result.summary}")

    sys.exit(0 if (result and result.success) else 1)


if __name__ == "__main__":
    main()
