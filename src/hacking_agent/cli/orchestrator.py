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
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.paths import ENV_FILE, LOG_DIR, METHODOLOGIES_DIR, ensure_runtime_dirs
from hacking_agent.core.providers import ProviderRegistry
from hacking_agent.core.schemas import AgentName, AgentResult, AgentTask, CoordinatorDecision
from hacking_agent.core import sessions as session_mod
from hacking_agent.integrations import burp as burp_mod
from hacking_agent.integrations import caido as caido_mod
from hacking_agent.core.state_machine import Event, State, StateMachine, StateMachineConfig

console = Console()

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
        ("cache poison",          "cache_poisoning.md"),
        ("cache deception",       "web_cache_deception.md"),
        ("cache",                 "cache_poisoning.md"),
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
    ):
        self.target_url = target_url
        self.interactive = interactive
        self.logger = SessionLogger()

        # ---- shared subsystems ----
        self.memory = AgentMemory(target_url=target_url)
        self.sm = StateMachine(
            StateMachineConfig(max_iterations=max_iterations)
        )
        self.evidence = EvidenceStore()
        self.registry = ProviderRegistry.from_env()
        self.tool_executor = BudgetedToolExecutor(self.memory, self.sm)

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
        self.logger.log(f"Target: {self.target_url}")
        self.logger.log(f"Config: max_iter={self.sm.config.max_iterations}")
        self.logger.log(f"Providers:\n{self.registry.describe()}")

        # PLANNING → ROUTING
        self.sm.transition(Event.START, "Session initialized")

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
                        context={"target_url": self.target_url},
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

        # Inject target_url into context if missing
        if "target_url" not in task.context:
            task = task.model_copy(
                update={"context": {**task.context, "target_url": self.target_url}}
            )

        # Inject methodology for exploitation tasks
        if agent_name == "exploitation" and task.target_vulnerability_id:
            vuln_entity = self.memory.get_entity(task.target_vulnerability_id)
            if vuln_entity:
                vuln_type = vuln_entity.attrs.get("vuln_type", "")
                methodology = load_methodology(vuln_type)
                if methodology:
                    task = task.model_copy(
                        update={"context": {
                            **task.context,
                            "methodology": methodology,
                        }}
                    )

        self.sm.transition(Event.DECISION_DONE, f"dispatching {agent_name}")
        self.sm.record_dispatch(agent_name)

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

    # ---- reporter dispatch ------------------------------------------------

    def _execute_reporter(self, decision: CoordinatorDecision | None) -> AgentResult:
        """Run the reporter agent and return its result."""
        task = AgentTask(
            task_description="Generate the final penetration test report.",
            context={
                "target_url": self.target_url,
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
        caido_status = "[green]Configured[/]" if caido_mod.get_client().is_configured() else "[yellow]Not configured (set CAIDO_PAT)[/]"
        banner = Panel(
            f"[bold white]🎯 Target:[/] {self.target_url}\n"
            f"[bold white]⚙  Max iterations:[/] {self.sm.config.max_iterations}\n"
            f"[bold white]🔍 Burp Suite MCP:[/] {burp_status}\n"
            f"[bold white]Caido Cloud API:[/] {caido_status}\n"
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
            import oob
            oob_sess = oob.get_session()
            console.print(f"[dim]{oob_sess.describe()}[/]")
        except Exception as e:
            console.print(f"[yellow]OOB init failed: {e}[/]")

    orchestrator = Orchestrator(
        target_url=args.target,
        max_iterations=args.max_iterations,
        interactive=args.interactive,
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
