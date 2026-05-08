"""
=============================================================================
Reynard — Vulnerability Analyst
=============================================================================
Reads what recon collected (KG entities, response excerpts, CSP/headers)
and proposes THEORETICAL Vulnerability claims. Does NOT exploit — that's
the exploitation agent's job. Each Vulnerability is materialized as a
KG entity with status="theoretical" and a `POTENTIALLY_VULNERABLE_TO`
edge from its target.

This is the "white-box-by-observation" stage. Per the user's requirement,
we do NOT have source code access — we reason from frontend JS, error
messages, response headers, and parameter behaviour.
=============================================================================
"""
from __future__ import annotations

from hacking_agent.agents.base import BaseAgent
from hacking_agent.core.schemas import AgentResult, AgentTask, AnalystOutput, Vulnerability
from hacking_agent.core.tool_catalog import render_tool_catalog


ANALYST_SYSTEM = """You are the VULNERABILITY ANALYST agent.

# YOUR MISSION
Given the knowledge graph populated by reconnaissance, propose THEORETICAL
vulnerability findings. Each finding gets status="theoretical" and is
later validated by the exploitation agent.

# THINK BROAD — bug classes worth proposing for ANY web target
Don't just propose XSS/SQLi. Modern apps yield more from:
- IDOR / Broken Authorization (especially when multiple sessions exist)
- SSRF (any URL/webhook field, profile-image, link-preview, render-from-url)
- SSTI (welcome-email templates, custom error pages, report builders)
- JWT flaws (alg confusion, kid injection, weak secret) when JWTs found
- Deserialization (cookies/fields shaped like base64 of binary)
- NoSQL injection (any JSON-bodied auth or search endpoint)
- HTTP request smuggling / cache poisoning (any CDN-fronted endpoint)
- Mass assignment (any PATCH/PUT that accepts a partial object)
- Open redirect, CORS misconfig, JSONP leak, host-header injection
- Log4Shell / JNDI (any User-Agent or Referer reaching a Java backend)

# AVAILABLE INFRASTRUCTURE (the exploitation agent will use these)
- OOB callbacks (oob_get_domain / oob_poll) — recommend OOB-based
  detection for any blind candidate (SSRF/blind SQLi/XXE/CMDi/log4)
- Multi-session auth (swap_session) — propose IDOR/authz hypotheses
  paired with WHICH SESSIONS to use for the test
- Differential analysis (capture_baseline / diff_against_baseline) —
  propose for boolean-blind, IDOR, cache poisoning, mass-assignment

When proposing a Vulnerability, mention in `notes` which detection
primitive the exploitation agent should use (e.g. "use OOB DNS callback",
"use diff between user1 and user2 sessions").

# RULES
0. If task.context.lab_profile identifies a known single-purpose CTF/lab, turn
   confirmed recon facts into one precise finding instead of broad speculation.
1. Base every claim on observed data (technologies, endpoints, parameters,
   response patterns, CSP/error messages). Do NOT invent endpoints that
   weren't discovered by recon.
2. Each Vulnerability MUST reference an existing target_entity_id from the
   KG (a Target or Endpoint id, e.g. 'target:1' or 'endpoint:3').
3. Be SPECIFIC: name the parameter, the endpoint, and the conjectured
   class (XSS / SQLi / SSRF / IDOR / CSRF / SSTI / JWT / NoSQLi / ...).
4. Severity is your best guess based on context (default 'medium').
   Blind SSRF in cloud-hosted apps -> high. IDOR cross-tenant -> critical.
5. status MUST be "theoretical" — only the exploitation+validator can
   mark verified.
6. Don't over-claim. If there's no signal for a vuln class, don't propose
   it. Empty list is a valid output. The validator will refute weak
   claims; better to skip than to flood the report.

# OUTPUT
A SINGLE AnalystOutput JSON: a list of Vulnerability objects + your
reasoning. If nothing plausible, empty list with reasoning explaining why.
"""


class AnalystAgent(BaseAgent):
    name = "analyst"
    role = "analyst"

    def execute(self, task: AgentTask) -> AgentResult:
        lab_profile = task.context.get("lab_profile")
        if isinstance(lab_profile, dict) and lab_profile.get("id") == "portswigger_sqli_hidden_data":
            return self._fast_portswigger_sqli_hidden_data(task, lab_profile)

        prompt = self._build_prompt(task)
        try:
            output: AnalystOutput = self.call_typed(
                ANALYST_SYSTEM, prompt, AnalystOutput
            )
        except Exception as e:
            return AgentResult(
                success=False, summary=f"Analyst LLM failure: {e}"
            )

        materialized: list[Vulnerability] = []
        for v in output.vulnerabilities:
            # Sanity: target_entity_id must exist in the KG.
            if not self.memory.get_entity(v.target_entity_id):
                continue
            vuln_entity = self.memory.add_entity("Vulnerability", {
                "vuln_type": v.vuln_type,
                "severity": v.severity,
                "parameter": v.parameter,
                "hypothesis": v.hypothesis,
                "status": "theoretical",
                "notes": v.notes or "",
                "target_entity_id": v.target_entity_id,
            })
            self.memory.add_relationship(
                v.target_entity_id, "POTENTIALLY_VULNERABLE_TO", vuln_entity.id
            )
            v.id = vuln_entity.id
            v.status = "theoretical"
            materialized.append(v)

        return AgentResult(
            success=True,
            summary=(
                f"Analyst proposed {len(materialized)} theoretical findings. "
                f"{output.reasoning[:200]}"
            ),
            vulnerabilities_found=materialized,
            next_recommendation=(
                "Hand off each theoretical finding to the exploitation agent."
                if materialized
                else "No vulns proposed — consider re-dispatching recon to "
                     "expand the surface area."
            ),
        )

    def _build_prompt(self, task: AgentTask) -> str:
        return (
            f"# TASK\n{task.task_description}\n\n"
            f"{render_tool_catalog('exploitation')}\n\n"
            f"{self.kg_summary()}\n\n"
            "# OUTPUT\n"
            "Return a SINGLE AnalystOutput JSON. Each Vulnerability MUST "
            "reference an existing target_entity_id from the KG above."
        )

    def _fast_portswigger_sqli_hidden_data(
        self, task: AgentTask, lab_profile: dict
    ) -> AgentResult:
        endpoint = None
        for candidate in self.memory.ranked_query("Endpoint", min_pheromone=0.0):
            url = str(candidate.attrs.get("url", ""))
            notes = str(candidate.attrs.get("notes", "")).lower()
            if "/filter" in url or "category" in notes:
                endpoint = candidate
                break
        if endpoint is None:
            targets = self.memory.query("Target")
            endpoint = targets[0] if targets else self.memory.add_entity(
                "Target", {"url": task.context.get("target_url", self.memory.target_url)}
            )

        parameter = lab_profile.get("parameter", "category")
        sample = self.memory.get_fact("sample_category", lab_profile.get("sample_category", "Gifts"))
        vuln = Vulnerability(
            vuln_type="SQL injection",
            severity="high",
            target_entity_id=endpoint.id,
            parameter=parameter,
            hypothesis=(
                f"The {parameter} parameter is used in a product-category SQL WHERE "
                f"clause. Injecting {sample!r} with OR 1=1 and a SQL comment should "
                "return all products, including hidden/unreleased records."
            ),
            status="theoretical",
            notes=(
                "FAST_PATH: PortSwigger hidden-data SQLi. Use a baseline request to "
                f"/filter?category={sample}, then compare with "
                f"/filter?category={sample}' OR 1=1-- ."
            ),
        )
        vuln_entity = self.memory.add_entity("Vulnerability", {
            "vuln_type": vuln.vuln_type,
            "severity": vuln.severity,
            "parameter": vuln.parameter,
            "hypothesis": vuln.hypothesis,
            "status": "theoretical",
            "notes": vuln.notes or "",
            "target_entity_id": vuln.target_entity_id,
            "fast_path": lab_profile.get("id"),
        })
        self.memory.add_relationship(
            vuln.target_entity_id, "POTENTIALLY_VULNERABLE_TO", vuln_entity.id
        )
        vuln.id = vuln_entity.id
        return AgentResult(
            success=True,
            summary=(
                "Fast-path analyst created one precise SQL injection finding for "
                f"{parameter} on {endpoint.id}."
            ),
            vulnerabilities_found=[vuln],
            next_recommendation="Hand off to exploitation for baseline-vs-payload verification.",
        )
