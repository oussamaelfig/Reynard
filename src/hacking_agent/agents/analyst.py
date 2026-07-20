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
from hacking_agent.core import context
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
        if isinstance(lab_profile, dict) and lab_profile.get("playbook_id"):
            return self._profile_driven_finding(task, lab_profile)

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
        stable = [f"# TASK\n{task.task_description}"]
        if task.context.get("expert_playbook"):
            stable.append(f"\n{task.context['expert_playbook']}")
        if task.context.get("hypothesis_agenda"):
            stable.append(f"\n{task.context['hypothesis_agenda']}")
        if task.context.get("tool_recommendations"):
            stable.append(f"\n{task.context['tool_recommendations']}")
        if task.context.get("methodology"):
            stable.append(f"\n{task.context['methodology']}")
        stable.append(f"\n{render_tool_catalog('exploitation')}")
        volatile = [
            f"\n{self.kg_summary()}",
            "\n# OUTPUT\n"
            "Return a SINGLE AnalystOutput JSON. Each Vulnerability MUST "
            "reference an existing target_entity_id from the KG above.",
        ]
        return context.assemble_prompt(stable, volatile)

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

    def _profile_driven_finding(
        self, task: AgentTask, lab_profile: dict
    ) -> AgentResult:
        """Create one focused theoretical finding from a recognized lab profile.

        This is intentionally still theoretical. It prevents known PortSwigger
        practitioner/expert lab classes from stalling in the analyst LLM when
        the user objective already names the bug class.
        """
        target = self._best_profile_target(task, lab_profile)
        playbook = lab_profile.get("expert_playbook") or {}
        playbook_id = lab_profile.get("playbook_id", "")
        vulnerability_name = (
            playbook.get("vulnerability")
            or lab_profile.get("vulnerability")
            or playbook_id.replace("_", " ").title()
        )
        severity = self._profile_severity(playbook_id)
        parameter = lab_profile.get("parameter") or self._profile_parameter_hint(playbook_id)
        artifacts = "; ".join(str(item) for item in lab_profile.get("required_artifacts", [])[:4])
        validation = "; ".join(str(item) for item in lab_profile.get("success_indicators", [])[:4])

        vuln = Vulnerability(
            vuln_type=vulnerability_name,
            severity=severity,
            target_entity_id=target.id,
            parameter=parameter,
            hypothesis=(
                f"The lab profile {lab_profile.get('id')} indicates {vulnerability_name}. "
                f"Use the expert playbook {playbook_id} to confirm the named behavior "
                "against observed target responses."
            ),
            status="theoretical",
            notes=(
                f"PROFILE_DRIVEN: {lab_profile.get('purpose', '')} "
                f"Required artifacts: {artifacts}. Validation: {validation}."
            )[:1000],
        )
        vuln_entity = self.memory.add_entity("Vulnerability", {
            "vuln_type": vuln.vuln_type,
            "severity": vuln.severity,
            "parameter": vuln.parameter,
            "hypothesis": vuln.hypothesis,
            "status": "theoretical",
            "notes": vuln.notes or "",
            "target_entity_id": vuln.target_entity_id,
            "profile_driven": lab_profile.get("id"),
            "playbook_id": playbook_id,
        })
        self.memory.add_relationship(
            vuln.target_entity_id, "POTENTIALLY_VULNERABLE_TO", vuln_entity.id
        )
        vuln.id = vuln_entity.id
        return AgentResult(
            success=True,
            summary=(
                "Profile-driven analyst created one focused theoretical finding: "
                f"{vulnerability_name} on {target.id}."
            ),
            vulnerabilities_found=[vuln],
            next_recommendation=(
                "Hand off to exploitation with the expert playbook and require "
                "concrete validation artifacts."
            ),
        )

    def _best_profile_target(self, task: AgentTask, lab_profile: dict):
        endpoint_hint = str(lab_profile.get("endpoint_hint", ""))
        if endpoint_hint:
            for candidate in self.memory.ranked_query("Endpoint", min_pheromone=0.0):
                url = str(candidate.attrs.get("url", ""))
                if endpoint_hint in url:
                    return candidate
        endpoints = self.memory.ranked_query("Endpoint", min_pheromone=0.0)
        if endpoints:
            return endpoints[0]
        targets = self.memory.ranked_query("Target", min_pheromone=0.0)
        if targets:
            return targets[0]
        return self.memory.add_entity(
            "Target", {"url": task.context.get("target_url", self.memory.target_url)}
        )

    def _profile_severity(self, playbook_id: str) -> str:
        high = {
            "oauth_ssrf_dynamic_registration",
            "oauth",
            "ssrf",
            "blind_xxe_oob",
            "xxe",
            "os_command_injection",
            "sqli",
            "nosql_injection",
            "ssti",
            "deserialization",
            "request_smuggling",
            "web_cache_poisoning",
            "web_cache_deception",
            "jwt",
            "authentication",
            "access_control_idor",
            "graphql_api",
            "api_testing",
            "race_condition",
            "file_upload",
            "path_traversal",
            "business_logic",
            "host_header",
            "web_llm_attacks",
        }
        medium = {
            "xss",
            "dom_xss",
            "dom_based",
            "csrf",
            "cors",
            "websocket",
            "prototype_pollution",
            "clickjacking",
            "information_disclosure",
            "essential_skills",
        }
        if playbook_id in high:
            return "high"
        if playbook_id in medium:
            return "medium"
        return "medium"

    def _profile_parameter_hint(self, playbook_id: str) -> str | None:
        hints = {
            "ssrf": "url",
            "oauth_ssrf_dynamic_registration": "client metadata URL",
            "oauth": "OAuth flow parameter",
            "blind_xxe_oob": "XML body",
            "xxe": "XML body",
            "os_command_injection": "command-adjacent parameter",
            "sqli": "input parameter",
            "nosql_injection": "JSON body",
            "jwt": "JWT",
            "access_control_idor": "object identifier",
            "request_smuggling": "raw HTTP framing",
            "web_cache_poisoning": "unkeyed input",
            "web_cache_deception": "URL path/cache key",
            "ssti": "template parameter",
            "deserialization": "serialized value",
            "prototype_pollution": "__proto__/constructor input",
            "graphql_api": "GraphQL query/mutation",
            "api_testing": "API endpoint/object identifier",
            "race_condition": "state-changing request",
            "xss": "reflected/stored input",
            "dom_based": "DOM source/sink",
            "dom_xss": "DOM source",
            "clickjacking": "framed UI action",
            "file_upload": "uploaded file",
            "path_traversal": "filename/path parameter",
            "csrf": "state-changing form",
            "cors": "Origin header",
            "websocket": "WebSocket message",
            "business_logic": "workflow parameter",
            "authentication": "authentication flow",
            "information_disclosure": "disclosure endpoint",
            "host_header": "Host/header input",
            "essential_skills": "lab workflow",
            "web_llm_attacks": "LLM prompt/tool input",
        }
        return hints.get(playbook_id)
