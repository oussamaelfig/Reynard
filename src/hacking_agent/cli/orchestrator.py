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
from hacking_agent.core.evidence import EvidenceStore
from hacking_agent.core.events import emit
from hacking_agent.core.expert_playbooks import enrich_lab_profile, render_playbook_context
from hacking_agent.core.failure import classify_failure
from hacking_agent.core.lab_intel import detect_lab_profile, normalize_target_input
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.paths import ENV_FILE, LOG_DIR, METHODOLOGIES_DIR, ensure_runtime_dirs
from hacking_agent.core.preflight import has_fatal_failure, run_preflight
from hacking_agent.core.providers import ProviderRegistry
from hacking_agent.core.schemas import AgentName, AgentResult, AgentTask, CoordinatorDecision, ToolDecision
from hacking_agent.core.scope import ScopeGuard
from hacking_agent.core.subagents import BoundedSubagentScheduler, SubagentPolicy, SubagentSpec
from hacking_agent.core import sessions as session_mod
from hacking_agent.integrations import burp as burp_mod
from hacking_agent.integrations import caido as caido_mod
from hacking_agent.integrations import caido_local as caido_local_mod
from hacking_agent.core.state_machine import Event, State, StateMachine, StateMachineConfig
from hacking_agent.ui.live import start_dashboard

console = Console()

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

def load_methodology(vuln_type: str | None) -> str:
    """Load a relevant methodology file based on vulnerability type.

    The coordinator specifies the vulnerability type in the task context,
    and we match it against the methodology filenames to keep context
    windows lean (only load what's needed, not all 37KB).
    """
    if not vuln_type:
        return ""
    method_dir = METHODOLOGIES_DIR
    if not method_dir.is_dir():
        return ""

    # Keyword -> primary methodology file (first-match wins).
    vuln_lower = vuln_type.lower()
    mapping: list[tuple[str, str]] = [
        # Primary keywords (longest-prefix-ish first)
        ("cross-site scripting", "xss_advanced.md"),
        ("xss",                   "xss_advanced.md"),
        ("sql injection",         "sqli.md"),
        ("sqli",                  "sqli.md"),
        ("sql",                   "sqli.md"),
        ("nosql",                 "nosqli.md"),
        ("mongo",                 "nosqli.md"),
        ("ssrf",                  "ssrf.md"),
        ("server-side request",   "ssrf.md"),
        ("ssti",                  "ssti.md"),
        ("template injection",    "ssti.md"),
        ("api testing",           "idor_authz.md"),
        ("api",                   "idor_authz.md"),
        ("authentication",        "idor_authz.md"),
        ("idor",                  "idor_authz.md"),
        ("authz",                 "idor_authz.md"),
        ("authorization",         "idor_authz.md"),
        ("broken access",         "idor_authz.md"),
        ("privilege",             "idor_authz.md"),
        ("jwt",                   "jwt.md"),
        ("token",                 "jwt.md"),
        ("deserial",              "deserialization.md"),
        ("pickle",                "deserialization.md"),
        ("smuggl",                "request_smuggling.md"),
        ("desync",                "request_smuggling.md"),
        ("cache deception",       "web_cache_deception.md"),
        ("cache poison",          "cache_poisoning.md"),
        ("cache",                 "cache_poisoning.md"),
        ("host header",           "cache_poisoning.md"),
        ("xxe",                   "blind.md"),
        ("xml external",          "blind.md"),
        ("command injection",     "blind.md"),
        ("rce",                   "blind.md"),
        ("log4",                  "blind.md"),
        ("jndi",                  "blind.md"),
        ("android",               "android_frida_root_bypass.md"),
        ("frida",                 "android_frida_root_bypass.md"),
    ]
    sections: list[str] = []
    seen: set[str] = set()
    for keyword, filename in mapping:
        if keyword in vuln_lower and filename not in seen:
            path = method_dir / filename
            if path.exists():
                content = path.read_text(encoding="utf-8")
                sections.append(f"\n\n# METHODOLOGY REFERENCE ({filename})\n{content}")
                seen.add(filename)
                # Stop at first hit — don't pile on multiple ~10KB files.
                break

    # Always append the cross-cutting blind-vuln playbook unless it was
    # already the primary match. The blind playbook is short and generic;
    # it tells the model how to use OOB and differential tools regardless
    # of bug class.
    if "blind.md" not in seen:
        blind_path = method_dir / "blind.md"
        if blind_path.exists():
            content = blind_path.read_text(encoding="utf-8")
            sections.append(f"\n\n# CROSS-CUTTING (blind.md)\n{content}")

    return "".join(sections)


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
    ):
        self.target_url = target_url
        self.objective = objective
        self.lab_profile = enrich_lab_profile(lab_profile or {}, objective)
        self.playbook_context = render_playbook_context(self.lab_profile)
        self.interactive = interactive
        self.subagents_enabled = subagents_enabled
        self.max_subagents = max(1, max_subagents)
        self.logger = SessionLogger()
        self.scope_guard = ScopeGuard.from_target_url(
            target_url,
            extra_domains=scope_domains,
            extra_cidrs=scope_cidrs,
        )

        # ---- shared subsystems ----
        self.memory = AgentMemory(target_url=target_url)
        if self.objective:
            self.memory.add_fact("task_objective", self.objective, source="cli")
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
        self._run_bootstrap_subagents()

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

        self._print_summary()
        emit("session_end", {
            "target": self.target_url,
            "success": bool(final_result and final_result.success),
            "iterations": self.sm.iteration,
            "tool_calls": sum(self.sm.tool_calls.values()),
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

        try:
            decision: CoordinatorDecision = self.coordinator.decide(
                target_url=self.target_url,
                last_result=self.last_result,
                objective=self.objective,
                lab_profile=self.lab_profile,
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
        if decision.done:
            console.print("[bold green]✅ Coordinator says: DONE → reporting[/]")
            self.sm.transition(Event.REPORT_REQUESTED, "coordinator done=True")
            result = self._execute_reporter(decision)
            self.sm.transition(Event.REPORT_DONE, "report generated")
            return result

        # ---- EXECUTING: dispatch specialist ----
        agent_name: AgentName = decision.next_agent  # type: ignore[assignment]
        task: AgentTask = decision.task  # type: ignore[assignment]

        # Inject normalized target/objective/lab profile into every specialist task.
        context = {**task.context, "target_url": self.target_url}
        if self.objective:
            context["objective"] = self.objective
        if self.lab_profile:
            context["lab_profile"] = self.lab_profile
        if self.playbook_context:
            context["expert_playbook"] = self.playbook_context
        task = task.model_copy(update={"context": context})

        # Inject methodology for exploitation tasks
        if agent_name == "exploitation":
            vuln_type = ""
            # Try 1: Get vuln_type from the explicit target vulnerability entity
            if task.target_vulnerability_id:
                vuln_entity = self.memory.get_entity(task.target_vulnerability_id)
                if vuln_entity:
                    vuln_type = vuln_entity.attrs.get("vuln_type", "")
            # Try 2: Infer vuln_type from any theoretical vulnerability in the KG
            if not vuln_type:
                all_vulns = self.memory.ranked_query(
                    "Vulnerability", min_pheromone=0.0, status="theoretical"
                )
                if all_vulns:
                    vuln_type = all_vulns[0].attrs.get("vuln_type", "")
            # Try 3: Infer from the task description itself
            if not vuln_type:
                desc_lower = task.task_description.lower()
                for keyword in ["sqli", "sql injection", "xss", "ssrf", "ssti",
                                "idor", "jwt", "deserialization", "smuggling",
                                "cache", "nosql", "command injection", "rce"]:
                    if keyword in desc_lower:
                        vuln_type = keyword
                        break
            if vuln_type:
                methodology = load_methodology(vuln_type)
                if methodology:
                    task = task.model_copy(
                        update={"context": {
                            **task.context,
                            "methodology": methodology,
                        }}
                    )
                    self.logger.log(
                        f"[METHODOLOGY] Injected methodology for vuln_type={vuln_type}"
                    )

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

        # Check for pivot
        if self.sm.should_pivot():
            console.print(
                f"[yellow bold]🔄 PIVOT — {self.sm.consecutive_failures} "
                f"consecutive failures (last: {self.sm.last_failed_agent})[/]"
            )
            self.logger.log(
                f"[ESCALATING] consecutive_failures={self.sm.consecutive_failures}, "
                f"last_failed={self.sm.last_failed_agent}"
            )
            self.sm.transition(Event.PIVOT_REQUESTED, "consecutive failure threshold")
            # Reset failure counter and re-route
            self.sm.consecutive_failures = 0
            self.sm.transition(Event.DECISION_DONE, "post-pivot re-route")
            # Jump back to ROUTING on next iteration
            # (we moved to ROUTING via ESCALATING → DECISION_DONE → ROUTING)
            return None

        # Normal: go back to ROUTING
        self.sm.transition(Event.DECISION_DONE, "cycle back to routing")
        return None

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
        console.print(Panel(table, title="[dim]Orchestrator State[/]", border_style="dim", expand=False))

    def _print_summary(self) -> None:
        duration = time.time() - self.session_start
        all_pocs = self.evidence.all_pocs()
        verified = sum(1 for p in all_pocs if p.verdict == "success")

        summary = Panel(
            f"[bold]Duration:[/] {duration:.1f}s\n"
            f"[bold]Iterations:[/] {self.sm.iteration}\n"
            f"[bold]Tool calls:[/] {sum(self.sm.tool_calls.values())}\n"
            f"[bold]Agent dispatches:[/] {json.dumps(self.sm.agent_dispatches)}\n"
            f"[bold]KG entities:[/] {len(self.memory.entities)}\n"
            f"[bold]PoCs recorded:[/] {len(all_pocs)} ({verified} verified)\n"
            f"[bold]Log:[/] {self.logger.path}",
            title="[bold green]Session Summary[/]",
            border_style="green",
            expand=False,
        )
        console.print(summary)


# =============================================================================
# CLI
# =============================================================================

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
    if target_url != raw_target:
        console.print(f"[dim]Parsed target URL: {target_url}[/]")
    if lab_profile:
        console.print(f"[dim]Detected lab profile: {lab_profile.get('id')}[/]")

    scope_guard = ScopeGuard.from_target_url(
        target_url,
        extra_domains=args.scope_domain,
        extra_cidrs=args.scope_cidr,
    )
    preflight_checks = run_preflight(target_url, scope_guard)
    for check in preflight_checks:
        style = "green" if check.ok else ("red" if check.fatal else "yellow")
        status = "OK" if check.ok else ("FAIL" if check.fatal else "WARN")
        console.print(f"[{style}]preflight {status}[/] {check.name}: {check.message}")
    if args.preflight:
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
        scope_domains=args.scope_domain,
        scope_cidrs=args.scope_cidr,
        subagents_enabled=not args.no_subagents,
        max_subagents=args.max_subagents,
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
