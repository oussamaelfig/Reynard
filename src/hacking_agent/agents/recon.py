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
import re
from html import unescape as html_unescape
from urllib.parse import unquote, urljoin

from rich.console import Console

from hacking_agent.agents.base import BaseAgent
from hacking_agent.core.schemas import (
    AgentResult, AgentTask, FactClaim, ReconFinding, ToolDecision,
)
from hacking_agent.core.tool_catalog import render_tool_catalog

console = Console()


RECON_SYSTEM = """You are the RECONNAISSANCE specialist agent.

# YOUR MISSION
Build a structured map of the target. Each iteration you produce a
ReconFinding describing what you learned and (if not done) the next tool
call to make.

# RECOMMENDED RECON ORDER (highest yield first)
0. If task.context.lab_profile is present, use it as a high-confidence prior.
   For simple single-purpose PortSwigger labs, confirm the named endpoint and
   parameter once, then complete. Do NOT run repeated generic discovery.
1. http_request GET / -> page shape, server header, framework hints.
   IMPORTANT: Look for <a href=...> links, <form> actions, and URL
   patterns in the HTML to find injection points and parameters.
2. discover_apis(base_url) -> swagger / openapi / graphql / robots.txt
   sitemap / .well-known. Single cheap call, often the biggest unlock.
   ⚠ RUN THIS EXACTLY ONCE. If you've already run it, do NOT re-run.
3. extract_js_endpoints(url) -> mines every JS file for hidden API
   endpoints + parameter names. SPAs leak the entire backend here.
4. nuclei_scan(url, severity="medium,high,critical") -> known-CVE pass.
   Run ONCE early and let findings inform later analysis.
5. http_request to interesting endpoints discovered above to fingerprint
   parameters and capture sample responses.
6. browser_navigate ONLY if curl returns an empty/SPA shell.

# SHELL TOOLS
You have `run_shell` for executing commands inside the Kali Docker container:
  - nmap, ffuf, gobuster, whatweb, nikto, curl, etc.
  - Use run_shell(command="whatweb <target>") for fast tech fingerprinting
  - Use run_shell(command="curl -sI <target>") for header analysis
  - If unsure what fits, call tool_inventory(role="recon", check_container=true)

# RULES
1. ONE tool call per step. After each result emit a fresh ReconFinding.
2. If task.context.lab_profile is present, use it as a high-confidence prior.
   For simple single-purpose PortSwigger labs, confirm the named endpoint and
   parameter once, then complete. Do NOT run repeated generic discovery.
3. Prefer http_request for endpoint mapping; use browser_navigate only
   when the page is JS-heavy and curl returns an empty/SPA shell.
4. DO NOT attempt exploitation. That is the exploitation agent's job.
   But DO record probable injection points so analyst/exploitation can
   pursue them.
5. Recon is COMPLETE (set recon_complete=true) once you have:
     - At least one technology fingerprint
     - At least one endpoint or parameter that takes input
     - The base response behaviour observed
   Do NOT loop waiting for discover_apis if you already have findings.
   If you have solid endpoints and parameters, mark recon_complete=true.
6. Available tools (besides http_request / run_shell):
   - discover_apis(base_url)              # swagger/openapi/graphql/well-known
   - extract_js_endpoints(url)            # mine JS for hidden endpoints
   - nuclei_scan(url, severity, ...)      # known CVE/misconfig pass
   - tool_inventory(role, check_container) # tool catalog and availability
   - web_search(query, focus)             # CTF writeups / CVEs / docs
   - web_fetch(url)                       # fetch promising research pages
   - list_sessions()                      # see configured auth identities
7. NEVER invent data. If a finding isn't in the response, don't claim it.
   A lab_profile may be used as a stated prior, but keep response-observed
   facts separate from profile-derived hints.
8. When you discover an authentication-gated area, NOTE which sessions
   are configured (via list_sessions). The analyst will use them later
   for IDOR/authz testing.
9. BE EFFICIENT: For known lab types (PortSwigger etc.), 3-4 iterations
   should be enough. Don't over-explore.

# OUTPUT
A SINGLE ReconFinding JSON object. No prose. No markdown fences.
"""


class ReconAgent(BaseAgent):
    name = "recon"
    role = "reconnaissance"

    MAX_INNER_ITER = 8

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

        lab_profile = task.context.get("lab_profile")
        if isinstance(lab_profile, dict) and lab_profile.get("id") == "portswigger_sqli_hidden_data":
            fast_result = self._fast_portswigger_sqli_hidden_data(
                task, target.id, target_url, lab_profile
            )
            if fast_result:
                return fast_result

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

    def _fast_portswigger_sqli_hidden_data(
        self,
        task: AgentTask,
        target_id: str,
        target_url: str,
        lab_profile: dict,
    ) -> AgentResult | None:
        """Confirm the standard PortSwigger product-category SQLi surface once.

        This avoids the expensive generic recon loop for a lab whose objective
        already identifies the vulnerability class and likely parameter.
        """
        if not self.tools:
            return None

        decision = ToolDecision(
            tool="http_request",
            args={"url": target_url, "method": "GET"},
            reasoning="Fast-path confirm PortSwigger lab homepage and category filter links.",
            expected_signal="HTML contains product category filter links using /filter?category=...",
        )
        outcome = self.tools.call(
            decision, agent_name=self.name, phase="recon", iteration=self.sm.iteration
        )
        if outcome["blocked"]:
            return None

        response = self._response_text(outcome["result"])
        body = self._body_only(response)
        categories = self._extract_categories(body)
        sample_category = (
            categories[0]
            if categories
            else lab_profile.get("sample_category", "Gifts")
        )

        endpoint_url = urljoin(target_url.rstrip("/") + "/", "filter")
        tech_names = ["PortSwigger Web Security Academy"]
        server = self._extract_server_header(response)
        if server:
            tech_names.append(server)

        facts_added: list[FactClaim] = []
        for tech in tech_names:
            tech_entity = self.memory.add_entity("Technology", {"name": tech})
            self.memory.add_relationship(target_id, "USES_TECHNOLOGY", tech_entity.id)
            self.memory.add_fact(
                "technology_stack", tech, source="recon/fast_path",
                iteration=self.sm.iteration, entity_id=target_id,
            )
            facts_added.append(FactClaim(
                entity_id=target_id,
                key="technology_stack",
                value=tech,
                confidence="confirmed",
                source="recon/fast_path",
            ))

        ep_entity = self.memory.add_entity("Endpoint", {
            "url": endpoint_url,
            "method": "GET",
            "notes": (
                "Product category filter endpoint. Profile target is SQLi in "
                "WHERE clause allowing hidden product retrieval."
            ),
        })
        self.memory.add_relationship(target_id, "HAS_ENDPOINT", ep_entity.id)
        param_entity = self.memory.add_entity("Parameter", {"name": "category"})
        self.memory.add_relationship(ep_entity.id, "HAS_PARAMETER", param_entity.id)

        fact_pairs = {
            "platform": "portswigger",
            "lab_profile": lab_profile.get("id", "portswigger_sqli_hidden_data"),
            "injection_point": endpoint_url,
            "injection_parameter": "category",
            "sample_category": sample_category,
        }
        for key, value in fact_pairs.items():
            self.memory.add_fact(
                key, value, source="recon/fast_path", iteration=self.sm.iteration,
                entity_id=ep_entity.id if key in {"injection_point", "injection_parameter"} else None,
            )
            facts_added.append(FactClaim(
                entity_id=ep_entity.id if key in {"injection_point", "injection_parameter"} else None,
                key=key,
                value=value,
                confidence="confirmed" if categories or key != "sample_category" else "suspected",
                source="recon/fast_path",
            ))

        self.memory.update_progress("recon", "done")
        found = f" observed categories={categories[:5]}" if categories else " using profile category hint"
        return AgentResult(
            success=True,
            summary=(
                "Fast-path recon complete for PortSwigger hidden-data SQLi: "
                f"endpoint={endpoint_url}, parameter=category,{found}."
            ),
            facts_added=facts_added,
            next_recommendation="Hand off to analyst for a precise SQL injection finding.",
        )

    def _response_text(self, raw: str) -> str:
        try:
            parsed = json.loads(raw)
            return (
                parsed.get("response") or parsed.get("stdout")
                or parsed.get("rendered_content") or parsed.get("content")
                or parsed.get("contents") or ""
            )
        except (json.JSONDecodeError, TypeError):
            return raw or ""

    def _body_only(self, response: str) -> str:
        if "\r\n\r\n" in response:
            return response.split("\r\n\r\n")[-1]
        if "\n\n" in response:
            return response.split("\n\n")[-1]
        return response

    def _extract_server_header(self, response: str) -> str:
        match = re.search(r"(?im)^server:\s*([^\r\n]+)", response or "")
        return match.group(1).strip() if match else ""

    def _extract_categories(self, body: str) -> list[str]:
        categories: list[str] = []
        for href in re.findall(r"""href=["']([^"']*filter\?category=[^"']+)["']""", body or "", re.I):
            href = html_unescape(href)
            if "category=" not in href:
                continue
            value = href.split("category=", 1)[1].split("&", 1)[0]
            category = unquote(value.replace("+", " ")).strip()
            if category and category not in categories:
                categories.append(category)
        return categories

    def _build_prompt(self, task: AgentTask, target_id: str, target_url: str,
                       last_observation: str, inner: int) -> str:
        lines = [
            f"# TARGET (id={target_id})\n{target_url}",
            f"\n# TASK\n{task.task_description}",
            f"\n{render_tool_catalog('recon')}",
            f"\n{self.kg_summary()}",
            f"\n# RECON ITERATION: {inner+1}/{self.MAX_INNER_ITER}",
        ]
        if last_observation:
            lines.append(f"\n# LAST OBSERVATION (truncated)\n{last_observation[:6000]}")
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
        text = text[:6000]
        if signals:
            keep = {k: v for k, v in signals.items()
                    if v not in (None, False, [], 0, "")}
            if keep:
                text += f"\n\n[ANALYZER SIGNALS]\n{json.dumps(keep, indent=2)[:1200]}"
        return text
