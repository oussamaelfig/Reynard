"""
=============================================================================
Hacking Agent — Reporter Specialist
=============================================================================
Synthesises a professional penetration-test report from the knowledge graph
and evidence store.

HARD RULE:  A finding appears under "Verified Vulnerabilities" ONLY if
            `evidence.is_verified(vuln_id)` returns True. Everything else
            is "Informational / Unverified."

The reporter does NOT call any tools. It reads memory + evidence, calls the
LLM once for free-form markdown (call_text), and returns the report as
`AgentResult.artifact`.

Reports are also written to `logs/report_<timestamp>.md`.
=============================================================================
"""
from __future__ import annotations

import json
import os
from datetime import datetime

from rich.console import Console

from hacking_agent.agents.base import BaseAgent
from hacking_agent.core.schemas import AgentResult, AgentTask, PoC, Vulnerability

console = Console()

REPORTER_SYSTEM = """You are the REPORTING specialist for an autonomous penetration-testing system.

# YOUR MISSION
Produce a professional penetration-test report in Markdown. The report is
for a technical audience (security engineers, developers).

# STRUCTURE (follow this order)
1. **Executive Summary** — 2-3 sentences: target, scope, key result.
2. **Methodology** — Briefly describe the multi-agent pipeline: recon →
   analysis → exploitation → verification.
3. **Verified Vulnerabilities** — One subsection per finding with:
     - **Title** (e.g. "Reflected XSS via `search` parameter")
     - **Severity** (Critical / High / Medium / Low / Info)
     - **Endpoint & Parameter**
     - **Description** — What the vulnerability is and why it matters
     - **Proof of Concept** — The exact request/payload and the response
       excerpt proving exploitation (provided to you as PoC data)
     - **Remediation** — Concrete fix recommendation
4. **Informational Findings** — Theoretical or partial findings that could
   not be conclusively verified. Same subsection format minus the PoC.
5. **Reconnaissance Summary** — Technologies, endpoints, and parameters
   discovered.
6. **Appendix** — Session statistics (iterations, tool calls, agent
   dispatches).

# RULES
- NEVER invent a PoC that wasn't provided to you.
- NEVER upgrade an INFORMATIONAL finding to VERIFIED — only the evidence
  store controls that classification.
- Use Markdown code blocks for PoC payloads and responses.
- Be concise but thorough.

# OUTPUT
A single Markdown document (no JSON wrapper). Start with `# Penetration Test Report`.
"""


class ReporterAgent(BaseAgent):
    name = "reporter"
    role = "reporter"

    def execute(self, task: AgentTask) -> AgentResult:
        prompt = self._build_prompt(task)
        try:
            report_md = self.call_text(REPORTER_SYSTEM, prompt)
        except Exception as e:
            return AgentResult(
                success=False, summary=f"Reporter LLM failure: {e}"
            )

        # ---- persist to disk ----
        report_path = self._save_report(report_md)
        console.print(f"[green bold]📄 Report saved → {report_path}[/]")

        # ---- build summary JSON ----
        verified, informational = self._classify_vulns()
        summary_json = {
            "generated_at": datetime.utcnow().isoformat(),
            "target": task.context.get("target_url", "unknown"),
            "verified_count": len(verified),
            "informational_count": len(informational),
            "total_pocs": len(self.evidence.all_pocs()),
            "report_path": report_path,
        }
        json_path = report_path.replace(".md", ".json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary_json, f, indent=2)
        console.print(f"[green]   📊 Summary JSON → {json_path}[/]")

        return AgentResult(
            success=True,
            summary=(
                f"Report generated: {len(verified)} verified, "
                f"{len(informational)} informational."
            ),
            artifact=report_md,
        )

    # ---- helpers --------------------------------------------------------

    def _classify_vulns(self) -> tuple[list[dict], list[dict]]:
        """Split KG Vulnerability entities into verified vs informational."""
        verified: list[dict] = []
        informational: list[dict] = []
        for entity in self.memory.query("Vulnerability"):
            vuln_id = entity.id
            if self.evidence.is_verified(vuln_id):
                verified.append({"id": vuln_id, **entity.attrs})
            else:
                status = entity.attrs.get("status", "theoretical")
                if status != "false_positive":
                    informational.append({"id": vuln_id, **entity.attrs})
        return verified, informational

    def _build_prompt(self, task: AgentTask) -> str:
        target_url = task.context.get("target_url", "unknown")
        verified, informational = self._classify_vulns()
        all_pocs = self.evidence.all_pocs()

        sections: list[str] = [
            f"# TARGET\n{target_url}",
            f"\n{self.kg_summary()}",
            f"\n{self.state_summary()}",
        ]

        # ---- verified findings + PoCs ----
        if verified:
            sections.append("\n# VERIFIED VULNERABILITIES (evidence-gated)")
            for v in verified:
                vid = v["id"]
                pocs = self.evidence.get_by_vuln(vid)
                poc_text = "\n".join(self._format_poc(p) for p in pocs)
                sections.append(
                    f"\n## {v.get('vuln_type', '?')} — {v.get('parameter', 'N/A')}\n"
                    f"  Severity: {v.get('severity', 'medium')}\n"
                    f"  Hypothesis: {v.get('hypothesis', '')}\n"
                    f"  Status: VERIFIED\n"
                    f"  PoCs:\n{poc_text}"
                )
        else:
            sections.append(
                "\n# VERIFIED VULNERABILITIES\n  (none — no finding passed "
                "the evidence gate)"
            )

        # ---- informational ----
        if informational:
            sections.append("\n# INFORMATIONAL / UNVERIFIED FINDINGS")
            for v in informational:
                sections.append(
                    f"\n## {v.get('vuln_type', '?')} — {v.get('parameter', 'N/A')}\n"
                    f"  Severity: {v.get('severity', 'medium')}\n"
                    f"  Hypothesis: {v.get('hypothesis', '')}\n"
                    f"  Status: {v.get('status', 'theoretical')}"
                )

        sections.append(
            "\n# YOUR TASK\n"
            "Write the full Markdown report following the structure in your "
            "system prompt. Use the data above as your sole source of truth."
        )
        return "\n".join(sections)

    def _format_poc(self, poc: PoC) -> str:
        return (
            f"    - [{poc.verdict.upper()}] payload: {poc.payload[:200]}\n"
            f"      request: {poc.request_summary[:200]}\n"
            f"      response: {poc.response_excerpt[:300]}\n"
            f"      agent: {poc.agent_name} @ {poc.timestamp}"
        )

    def _save_report(self, content: str) -> str:
        log_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(log_dir, f"report_{ts}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path
