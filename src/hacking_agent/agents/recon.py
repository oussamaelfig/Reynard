"""
=============================================================================
Reynard — Reconnaissance Specialist
=============================================================================
Black-box recon. Maps the target's surface area:
  - Tech stack fingerprinting (whatweb, response headers, JS patterns)
  - Endpoint discovery (manual probes, sitemap, robots.txt, gobuster)
  - Parameter enumeration
  - Initial response capture for the analyst to digest

Writes Target / Endpoint / Parameter / Technology entities into the KG.

Bounded by an inner iteration ceiling (`MAX_INNER_ITER`) so a misbehaving
LLM cannot loop forever. Tool calls go through `BudgetedToolExecutor` so
they're also subject to the orchestrator's per-tool budget.
=============================================================================
"""
from __future__ import annotations

import json

from rich.console import Console

from hacking_agent.agents.base import BaseAgent
from hacking_agent.core.schemas import AgentResult, AgentTask, FactClaim, ReconFinding

console = Console()


RECON_SYSTEM = """You are the RECONNAISSANCE specialist agent.

# YOUR MISSION
Build a structured map of the target. Each iteration you produce a
ReconFinding describing what you learned and (if not done) the next tool
call to make.

# RECOMMENDED RECON ORDER (highest yield first)
1. http_request GET / -> page shape, server header, framework hints
2. discover_apis(base_url) -> swagger / openapi / graphql / robots.txt
   sitemap / .well-known. Single cheap call, often the biggest unlock.
3. extract_js_endpoints(url) -> mines every JS file for hidden API
   endpoints + parameter names. SPAs leak the entire backend here.
4. nuclei_scan(url, severity="medium,high,critical") -> known-CVE pass.
   Tight iteration budget on this one (heavy); run ONCE early and let
   findings inform later analysis.
5. http_request to interesting endpoints discovered above to fingerprint
   parameters and capture sample responses.
6. browser_navigate ONLY if curl returns an empty/SPA shell.

# RULES
1. ONE tool call per step. After each result emit a fresh ReconFinding.
2. Prefer http_request for endpoint mapping; use browser_navigate only
   when the page is JS-heavy and curl returns an empty/SPA shell.
3. DO NOT attempt exploitation. That is the exploitation agent's job.
   But DO record probable injection points so analyst/exploitation can
   pursue them.
4. Recon is COMPLETE (set recon_complete=true) once you have:
     - At least one technology fingerprint
     - At least one endpoint or parameter that takes input
     - The base response behaviour observed
     - Run discover_apis at least once
   For modern SPAs / API-heavy targets, also run extract_js_endpoints
   before completing.
5. Available tools (besides the standard http_request / run_shell etc.):
   - discover_apis(base_url)              # swagger/openapi/graphql/well-known
   - extract_js_endpoints(url)            # mine JS for hidden endpoints
   - nuclei_scan(url, severity, ...)      # known CVE/misconfig pass
   - list_sessions()                      # see configured auth identities
   - caido_cloud_api(status/get_user/...) # Caido Cloud account/team context
   - caido_cloud_request(method,path,...) # raw Cloud API fallback
6. NEVER invent data. If a finding isn't in the response, don't claim it.
7. When you discover an authentication-gated area, NOTE which sessions
   are configured (via list_sessions). The analyst will use them later
   for IDOR/authz testing.

# OUTPUT
A SINGLE ReconFinding JSON object. No prose. No markdown fences.
"""


class ReconAgent(BaseAgent):
    name = "recon"
    role = "reconnaissance"

    MAX_INNER_ITER = 12

    def execute(self, task: AgentTask) -> AgentResult:
        target_url = (task.context.get("target_url")
                      or self.memory.target_url or "")
        if not target_url:
            return AgentResult(success=False, summary="No target URL provided.")

        # Ensure the Target entity exists.
        existing = self.memory.query("Target", url=target_url)
        target = existing[0] if existing else self.memory.add_entity(
            "Target", {"url": target_url}
        )

        facts_added: list[FactClaim] = []
        last_observation = ""

        for inner in range(self.MAX_INNER_ITER):
            user_prompt = self._build_prompt(
                task, target.id, target_url, last_observation, inner
            )
            try:
                finding: ReconFinding = self.call_typed(
                    RECON_SYSTEM, user_prompt, ReconFinding
                )
            except Exception as e:
                return AgentResult(
                    success=False,
                    summary=f"Recon LLM failure at iter {inner}: {e}",
                    facts_added=facts_added,
                )

            # ----- materialize findings into the KG -----
            for tech in finding.technologies_detected:
                tech_entity = self.memory.add_entity("Technology", {"name": tech})
                self.memory.add_relationship(target.id, "USES_TECHNOLOGY", tech_entity.id)
                self.memory.add_fact(
                    "technology_stack", tech, source=f"recon/iter{inner}",
                    iteration=self.sm.iteration, entity_id=target.id,
                )
                facts_added.append(FactClaim(
                    entity_id=target.id, key="technology_stack", value=tech,
                    confidence="confirmed", source=f"recon/iter{inner}",
                ))

            for ep in finding.endpoints_discovered:
                ep_entity = self.memory.add_entity("Endpoint", {
                    "url": ep.url, "method": ep.method, "notes": ep.notes,
                })
                self.memory.add_relationship(target.id, "HAS_ENDPOINT", ep_entity.id)
                # Also propagate as a global fact for analyst convenience.
                self.memory.add_fact(
                    "injection_point", ep.url, source=f"recon/iter{inner}",
                    iteration=self.sm.iteration, entity_id=ep_entity.id,
                )
                for p in ep.parameters:
                    p_entity = self.memory.add_entity("Parameter", {"name": p})
                    self.memory.add_relationship(ep_entity.id, "HAS_PARAMETER", p_entity.id)

            # ----- termination check -----
            if finding.recon_complete:
                self.memory.update_progress("recon", "done")
                return AgentResult(
                    success=True,
                    summary=(
                        f"Recon complete after {inner+1} iter. "
                        f"tech={finding.technologies_detected}, "
                        f"endpoints={len(finding.endpoints_discovered)}"
                    ),
                    facts_added=facts_added,
                    next_recommendation="Hand off to analyst for vulnerability analysis.",
                )

            # ----- run next tool decision (if any) -----
            if not finding.next_action:
                # Model didn't ask for a tool but isn't done — accept what we have
                # if anything was collected, otherwise fail.
                self.memory.update_progress("recon", "done" if facts_added else "skipped")
                return AgentResult(
                    success=bool(facts_added),
                    summary=f"Recon stopped without explicit completion at iter {inner}.",
                    facts_added=facts_added,
                    next_recommendation=(
                        "Hand off to analyst." if facts_added
                        else "Re-dispatch recon with a more specific task."
                    ),
                )

            outcome = self.tools.call(
                finding.next_action, agent_name=self.name,
                phase="recon", iteration=self.sm.iteration,
            )
            if outcome["blocked"]:
                last_observation = f"BLOCKED: {outcome['blocked_reason']}"
                continue
            last_observation = self._summarize_result(outcome["result"], outcome["signals"])

        # Inner-loop budget exhausted.
        self.memory.update_progress("recon", "skipped")
        return AgentResult(
            success=bool(facts_added),
            summary=f"Recon hit inner iter ceiling ({self.MAX_INNER_ITER}).",
            facts_added=facts_added,
            next_recommendation="Coordinator: consider re-dispatch or moving on.",
        )

    # ----- helpers --------------------------------------------------------

    def _build_prompt(self, task: AgentTask, target_id: str, target_url: str,
                       last_observation: str, inner: int) -> str:
        lines = [
            f"# TARGET (id={target_id})\n{target_url}",
            f"\n# TASK\n{task.task_description}",
            f"\n{self.kg_summary()}",
            f"\n# RECON ITERATION: {inner+1}/{self.MAX_INNER_ITER}",
        ]
        if last_observation:
            lines.append(f"\n# LAST OBSERVATION (truncated)\n{last_observation[:4000]}")
        lines.append(
            "\n# OUTPUT\n"
            "Return a single ReconFinding. Set recon_complete=true if you have "
            "enough surface-area mapped; otherwise set next_action."
        )
        return "\n".join(lines)

    def _summarize_result(self, raw: str, signals: dict | None) -> str:
        try:
            parsed = json.loads(raw)
            text = (parsed.get("response") or parsed.get("stdout")
                    or parsed.get("rendered_content") or parsed.get("content")
                    or parsed.get("contents") or "")
        except (json.JSONDecodeError, TypeError):
            text = raw
        text = text[:3000]
        if signals:
            keep = {k: v for k, v in signals.items()
                    if v not in (None, False, [], 0, "")}
            if keep:
                text += f"\n\n[ANALYZER SIGNALS]\n{json.dumps(keep, indent=2)[:1200]}"
        return text
