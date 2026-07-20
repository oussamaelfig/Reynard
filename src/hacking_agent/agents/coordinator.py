"""
=============================================================================
Reynard — Coordinator (Routing Brain)
=============================================================================
Top-level routing agent. Reads memory + evidence + state machine, returns
a strictly-typed `CoordinatorDecision` indicating which specialist to run
next OR `done=True` to trigger reporting.

The Coordinator NEVER calls tools directly. It only routes.

Why a separate agent and not a hardcoded if/else? Because the routing
heuristics ("we have endpoints but no vulns yet → analyst") are fuzzy
enough that an LLM with full memory access produces better decisions
than a static decision tree, especially when failures push it to
pivot to a different vector.
=============================================================================
"""
from __future__ import annotations

from typing import Any

from rich.console import Console

from hacking_agent.core import context as ctx_mod
from hacking_agent.core.expert_playbooks import render_playbook_context
from hacking_agent.core.evidence import EvidenceStore
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.paths import METHODOLOGIES_DIR
from hacking_agent.core.providers import LLMProvider
from hacking_agent.core.schemas import AgentResult, AgentTask, CoordinatorDecision
from hacking_agent.core.state_machine import StateMachine
from hacking_agent.core.tool_catalog import render_tool_catalog

console = Console()


COORDINATOR_SYSTEM = """You are the COORDINATOR of an autonomous penetration-testing system.
You DO NOT execute tools. You ONLY decide which specialist runs next.

# AVAILABLE SPECIALISTS
- recon         : Black-box reconnaissance — fingerprints the target,
                  discovers endpoints, parameters, and technologies. Run
                  FIRST on any new target.
- analyst       : Deep analysis of frontend JS and API responses already
                  gathered by recon. Produces theoretical Vulnerability
                  claims. Treat as "white-box-by-observation".
- exploitation  : Builds and executes Proof-of-Concept payloads against
                  ONE specific Vulnerability (set target_vulnerability_id
                  in the AgentTask). REQUIRED to mark a finding VERIFIED.
- reporter      : Produces the final markdown report. Use ONLY when there
                  is at least one VERIFIED finding OR budget is exhausted.

# RESEARCH ESCALATION
Recon and exploitation can use web_search/web_fetch for authorized CTF/lab
writeups, public CVEs, official docs, and service/version exploit notes.
When the system is stuck or a precise challenge/service name is known, route
to recon or exploitation with instructions to do focused web research.

# PROXY / REPLAY TOOLING
Prefer Caido Local Bridge for API testing, Replay, request collections, and
HTTP history when reachable. Caido Cloud API is only for Caido account/team/
workspace/PAT management. Use Burp MCP as a fallback for Burp-specific
Collaborator, Scanner, Intruder, or existing Burp workflows.

# PHEROMONE PRIORITY SYSTEM
Every finding in the Knowledge Graph has a HEAT score ([HOT] > [WARM] >
[COOL] > [COLD]). Heat decays over time -- recent findings are hotter.
Always prefer working on the HOTTEST findings first.

# ROUTING RULES (apply in order; first match wins)
0. If a high-confidence lab profile is supplied, avoid broad generic recon.
   Route only enough recon to confirm the named endpoint/parameter, then
   analyst/exploitation. Do not ask recon to repeat discover_apis on simple
   single-purpose PortSwigger labs.
0b. If GLOBAL FACTS include last_failure_class/last_failure_guidance, use that
    guidance to change primitive, tool, endpoint, or specialist. Do not route
    back into the same failed pattern unless new evidence justifies it.
1. KG has no Target with technology fact     → recon
2. KG has endpoints/JS but zero Vulnerability entities → analyst
3. KG has Vulnerability with status=theoretical AND no PoC yet
       → exploitation (prefer the HOTTEST vulnerability —
         set target_vulnerability_id to the highest-heat vuln)
4. All theoretical vulns have been attempted, OR iteration budget < 25% remaining
       → reporter (set done=true)
5. Coordinator receives PIVOT_REQUESTED state → choose a SPECIALIST OTHER
       THAN the last_failed_agent, preferring HOT/WARM findings over COOL/COLD

# BUDGET AWARENESS
You will see iteration count and per-tool remaining budget. As budget
approaches exhaustion, prefer EXPLOITATION of existing theoretical findings
over new RECON. Ignore [COLD] findings entirely when budget < 50%.

# OUTPUT
A SINGLE CoordinatorDecision JSON. Set `done=true` ONLY when reporter
should run, or budget is hopeless.
"""


class CoordinatorAgent:
    """Router. Not a BaseAgent subclass because it has no `execute(task)`
    contract — its method is `decide()`."""

    name = "coordinator"
    role = "router"

    def __init__(self, provider: LLMProvider, memory: AgentMemory,
                  state_machine: StateMachine, evidence: EvidenceStore):
        self.provider = provider
        self.memory = memory
        self.sm = state_machine
        self.evidence = evidence
        # WS4: per-turn incremental KG context (diff vs. last snapshot) instead
        # of re-sending the full snapshot every routing turn.
        self._ctx_snapshot: dict[str, Any] | None = None

    def decide(self, target_url: str,
               last_result: AgentResult | None = None,
               objective: str = "",
               lab_profile: dict | None = None,
               agenda_context: str = "") -> CoordinatorDecision:
        """Pick the next specialist. Validates output strictly via Pydantic."""
        prompt = self._build_user_prompt(
            target_url, last_result, objective, lab_profile, agenda_context
        )
        decision = self.provider.call_typed(
            COORDINATOR_SYSTEM, prompt, CoordinatorDecision
        )

        # Cross-field consistency check (Pydantic doesn't enforce this).
        if not decision.done and (decision.next_agent is None or decision.task is None):
            raise ValueError(
                "Coordinator returned done=False but missing next_agent or task. "
                f"Got: agent={decision.next_agent}, task={decision.task}"
            )
        return decision

    def _build_user_prompt(self, target_url: str,
                            last_result: AgentResult | None,
                            objective: str = "",
                            lab_profile: dict | None = None,
                            agenda_context: str = "") -> str:
        kg_context, self._ctx_snapshot = ctx_mod.build_incremental_context(
            self.memory, self._ctx_snapshot
        )
        sections: list[str] = [
            f"# TARGET\n{target_url}",
            f"\n# STATE MACHINE\n{self.sm.snapshot()}",
            f"\n{render_tool_catalog('general')}",
            f"\n{kg_context}",
            f"\n{self.evidence.summarize()}",
        ]
        if agenda_context:
            sections.append(
                f"\n{agenda_context}\n"
                "Prefer the hottest OPEN/ACTIVE hypothesis. Follow the forced "
                "phase chain (RECON -> INJECTION -> CONTEXT -> ... -> EXPLOIT) "
                "for the active vector; do not report while untried hypotheses "
                "remain and no finding is verified."
            )
        if objective:
            sections.insert(1, f"\n# USER OBJECTIVE\n{objective}")
        if lab_profile:
            playbook_context = render_playbook_context(lab_profile)
            playbook_section = (
                f"\n\n{playbook_context}"
                if playbook_context else ""
            )
            sections.insert(
                2,
                f"\n# LAB PROFILE\n{lab_profile}\n"
                "Use this as a high-confidence prior. Confirm with the target, "
                "but do not waste iterations rediscovering generic surface area."
                f"{playbook_section}"
            )

        # ---- Pheromone-ranked priority queue ----
        # Present theoretical vulnerabilities sorted by heat so the
        # Coordinator naturally targets the hottest lead.
        hot_vulns = self.memory.ranked_query(
            "Vulnerability", min_pheromone=0.1, status="theoretical"
        )
        if hot_vulns:
            priority_lines = ["\n# VULNERABILITY PRIORITY QUEUE (hottest first)"]
            for v in hot_vulns:
                heat = v.heat_label()
                w = f"{v.pheromone_weight():.2f}"
                vuln_type = v.attrs.get('vuln_type', '?')
                param = v.attrs.get('parameter', 'N/A')
                hyp = str(v.attrs.get('hypothesis', ''))[:120]
                has_poc = bool(self.evidence.get_by_vuln(v.id))
                poc_tag = " [HAS PoC]" if has_poc else ""
                priority_lines.append(
                    f"  {heat} w={w} | {v.id} | {vuln_type} @ {param}{poc_tag}"
                    f"\n         {hyp}"
                )
            sections.append("\n".join(priority_lines))

        # Global facts (legacy layer — includes lab_solved, technology_stack, etc.)
        global_facts = self.memory.get_all_facts()
        if global_facts:
            facts_str = "\n".join(
                f"  {k}: {v}" for k, v in global_facts.items()
            )
            sections.append(f"\n# GLOBAL FACTS\n{facts_str}")

        # Available methodologies (so coordinator can reference them in tasks)
        method_dir = METHODOLOGIES_DIR
        if method_dir.is_dir():
            method_files = [f.stem for f in method_dir.glob("*.md")]
            if method_files:
                sections.append(
                    f"\n# AVAILABLE METHODOLOGIES\n"
                    f"  {', '.join(method_files)}\n"
                    f"  (set vuln_type in Vulnerability to match these for "
                    f"methodology-guided exploitation)"
                )

        if last_result:
            sections.append(
                f"\n# LAST AGENT RESULT\n"
                f"  success: {last_result.success}\n"
                f"  summary: {last_result.summary}\n"
                f"  facts_added: {len(last_result.facts_added)}\n"
                f"  vulns_found: {len(last_result.vulnerabilities_found)}\n"
                f"  pocs_recorded: {len(last_result.pocs_recorded)}\n"
                f"  recommendation: {last_result.next_recommendation or '(none)'}"
            )
        sections.append(
            "\n# YOUR DECISION\n"
            "Pick the next specialist or set done=true. Output ONLY a "
            "CoordinatorDecision JSON object."
        )
        return "\n".join(sections)
