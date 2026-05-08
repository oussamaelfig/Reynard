"""
=============================================================================
Hacking Agent - PoC Validator (False-Positive Triage)
=============================================================================
Re-tests every PoC the exploitation agent flagged success/partial before
the orchestrator includes it in the final report.

Why this exists: real-world reports lose credibility on the FIRST false
positive. The exploitation loop is incentivised to claim success once it
sees a plausible signal. The validator's incentive is the opposite -
prove the PoC is NOT a fluke. It runs in three independent probes:

  1. Replay: re-run the original PoC verbatim. Did it still trigger?
  2. Counter-probe: run a deliberately neutered variant of the payload.
     If THAT also triggers the "success" signal, the signal is environmental
     (e.g. random reflection, generic error page, cached response).
  3. Causal vary: perturb one element of the payload (encoding, parameter,
     position). The success signal should change in a way consistent with
     the vulnerability hypothesis.

Output: a ValidationOutput. The orchestrator uses `confirmed` to decide
whether to keep the PoC verified or demote the vuln entity.

This agent ONLY uses tools through BudgetedToolExecutor (rate-limit safe)
and writes a new PoC entity for each re-test so the audit trail is
complete in the report.
=============================================================================
"""
from __future__ import annotations

import json

from rich.console import Console

from hacking_agent.agents.base import BaseAgent
from hacking_agent.core.schemas import AgentResult, AgentTask, PoC, ValidationOutput

console = Console()


VALIDATOR_SYSTEM = """You are the VALIDATOR specialist agent.

# YOUR MISSION
Confirm or refute a Proof-of-Concept that the exploitation agent claimed
worked. You are the LAST gate before a finding goes into the customer
report. Your bias must be SKEPTICAL - prefer false_positive over
verified when in doubt. Customers tolerate "we tried but couldn't
prove it" better than "we said it was real and it wasn't".

# RE-TEST PROTOCOL (run probes in this order)
1. REPLAY  - Re-run the exact same payload. Same effect? Still works?
2. COUNTER - Run a NEUTERED variant (e.g. for SQLi: same param but
             benign value; for XSS: same trigger context but text only;
             for SSRF: same parameter, internal IP that DOESN'T exist).
             If the success signal STILL appears, the signal is
             environmental and the original PoC was a false positive.
3. VARY    - Perturb the payload predictably (encoding, position, case).
             The signal should change in a way consistent with the vuln.
             For OOB-based PoCs: re-mint a fresh OOB token, re-deliver,
             confirm a NEW callback (proves the previous one wasn't
             ambient noise from your domain).

# RULES (NON-NEGOTIABLE)
1. NEVER call confirmed=True without a CONCRETE causal observation.
   "It returned 200" is NOT enough. "Payload X reflected unencoded in
   <script> body and our controlled JS executed" is enough.
2. If your replay differs from the original observation, mark
   reproducibility=flaky and confirmed=False.
3. If the counter-probe (neutered variant) ALSO triggers the success
   signal, set confirmed=False, fp_reason="signal is environmental".
4. ONE next_probe per turn. After observing, judge.
5. final=True ends iteration. You MUST set final=True before returning
   confirmed=True - i.e. you can only confirm AFTER finishing all probes.

# OUTPUT
A SINGLE ValidationOutput JSON. While iterating, supply next_probe and
final=False. When done, set final=True and a definitive confirmed bool.
"""


class ValidatorAgent(BaseAgent):
    name = "validator"
    role = "validator"

    MAX_INNER_ITER = 6

    def execute(self, task: AgentTask) -> AgentResult:
        poc_id = task.context.get("poc_id")
        vuln_id = task.context.get("vuln_id")
        if not poc_id or not vuln_id:
            return AgentResult(
                success=False,
                summary="Validator requires poc_id and vuln_id in task.context.",
            )

        # Fetch the PoC + vuln we're validating.
        target_poc = next(
            (p for p in self.evidence.all_pocs() if p.id == poc_id), None,
        )
        vuln_entity = self.memory.get_entity(vuln_id)
        if target_poc is None or vuln_entity is None:
            return AgentResult(
                success=False,
                summary=f"Validator: poc {poc_id} or vuln {vuln_id} not found.",
            )

        attempts: list[dict] = []
        last_observation = ""
        final_output: ValidationOutput | None = None

        for inner in range(self.MAX_INNER_ITER):
            prompt = self._build_prompt(
                target_poc, vuln_entity, attempts, last_observation, inner,
            )
            try:
                out: ValidationOutput = self.call_typed(
                    VALIDATOR_SYSTEM, prompt, ValidationOutput,
                )
            except Exception as e:
                return AgentResult(
                    success=False,
                    summary=f"Validator LLM failure at iter {inner}: {e}",
                )

            if out.final:
                final_output = out
                break

            if not out.next_probe:
                final_output = out
                break

            outcome = self.tools.call(
                out.next_probe, agent_name=self.name,
                phase="validate", iteration=self.sm.iteration,
            )
            if outcome["blocked"]:
                last_observation = f"BLOCKED: {outcome['blocked_reason']}"
            else:
                last_observation = self._summarize_result(
                    outcome["result"], outcome["signals"],
                )
            attempts.append({
                "step": inner + 1,
                "tool": out.next_probe.tool,
                "args": str(out.next_probe.args)[:200],
                "observation": last_observation[:400],
                "signals": outcome.get("signals") or {},
            })

        if final_output is None:
            # Inner-loop budget exhausted before final - treat as ambiguous.
            return AgentResult(
                success=False,
                summary=(
                    f"Validator hit inner ceiling on {poc_id} - "
                    f"no definitive verdict. Demoting to informational."
                ),
                next_recommendation=(
                    f"Manual review of {poc_id}: validator could not "
                    "complete its protocol within budget."
                ),
            )

        # Apply the verdict to the underlying entities.
        if final_output.confirmed:
            # Re-confirm: keep status verified, append a validator-source PoC
            # so the audit trail shows the second confirmation.
            confirm_poc = PoC(
                id=self.evidence.next_poc_id(),
                vuln_id=vuln_id,
                payload=target_poc.payload,
                request_summary=f"VALIDATED: {target_poc.request_summary}"[:300],
                response_excerpt=final_output.causal_signal[:500],
                verdict="success",
                agent_name=self.name,
            )
            self.evidence.record(confirm_poc)
            vuln_entity.attrs["status"] = "verified"
            vuln_entity.attrs["validator_confirmed"] = True
            vuln_entity.attrs["validator_reproducibility"] = final_output.reproducibility
            console.print(
                f"[green]✅ Validator CONFIRMED {poc_id} ({final_output.reproducibility})[/]"
            )
            return AgentResult(
                success=True,
                summary=(
                    f"PoC {poc_id} confirmed. reproducibility="
                    f"{final_output.reproducibility}. {final_output.reasoning[:200]}"
                ),
                pocs_recorded=[confirm_poc],
                next_recommendation="Include in report under VERIFIED.",
            )

        # confirmed = False -> demote
        vuln_entity.attrs["validator_confirmed"] = False
        vuln_entity.attrs["validator_fp_reason"] = final_output.fp_reason
        # Demote: if there's any signal at all, "informational"; else "false_positive".
        if final_output.reproducibility in ("flaky", "ambiguous"):
            vuln_entity.attrs["status"] = "informational"
            verdict_msg = "DEMOTED to informational"
        else:
            vuln_entity.attrs["status"] = "false_positive"
            verdict_msg = "DEMOTED to false_positive"

        # Record a refutation PoC for the audit trail.
        refute_poc = PoC(
            id=self.evidence.next_poc_id(),
            vuln_id=vuln_id,
            payload=target_poc.payload,
            request_summary=f"REFUTED: {target_poc.request_summary}"[:300],
            response_excerpt=final_output.fp_reason[:500],
            verdict="failure",
            agent_name=self.name,
        )
        self.evidence.record(refute_poc)

        console.print(
            f"[yellow]⚠ Validator REJECTED {poc_id}: {final_output.fp_reason[:120]}[/]"
        )
        return AgentResult(
            success=False,
            summary=(
                f"PoC {poc_id} {verdict_msg}: {final_output.fp_reason[:200]}"
            ),
            pocs_recorded=[refute_poc],
            next_recommendation=(
                f"Do NOT include {vuln_id} in customer report as verified."
            ),
        )

    # ---- helpers --------------------------------------------------------

    def _build_prompt(self, poc: PoC, vuln_entity, attempts: list[dict],
                      last_observation: str, inner: int) -> str:
        attempts_str = (
            "\n".join(
                f"  step {a['step']}: [{a['tool']}] {a['args'][:120]}\n"
                f"    -> {a['observation'][:200]}"
                for a in attempts
            )
            or "  (none yet)"
        )
        return (
            f"# POC TO VALIDATE\n"
            f"poc_id: {poc.id}\n"
            f"vuln_id: {poc.vuln_id}\n"
            f"original verdict: {poc.verdict}\n"
            f"payload: {poc.payload[:300]}\n"
            f"request_summary: {poc.request_summary[:300]}\n"
            f"response_excerpt: {poc.response_excerpt[:500]}\n\n"
            f"# VULN ENTITY\n"
            f"{json.dumps(vuln_entity.attrs, indent=2, default=str)}\n\n"
            f"{self.kg_summary()}\n\n"
            f"# RE-TEST PROBES SO FAR ({len(attempts)})\n{attempts_str}\n\n"
            f"# LAST OBSERVATION\n{last_observation[:2500]}\n\n"
            f"# ITERATION {inner+1}/{self.MAX_INNER_ITER}\n"
            "Decide what re-test probe to run next (replay -> counter -> vary). "
            "When you are confident, set final=True and confirmed=true|false. "
            "Return a SINGLE ValidationOutput JSON."
        )

    def _summarize_result(self, raw: str, signals: dict | None) -> str:
        try:
            parsed = json.loads(raw)
            text = (parsed.get("response") or parsed.get("stdout")
                    or parsed.get("rendered_content") or parsed.get("rendered_html")
                    or parsed.get("summary") or "")
        except (json.JSONDecodeError, TypeError):
            text = raw
        text = text[:2500]
        if signals:
            keep = {k: v for k, v in signals.items()
                    if v not in (None, False, [], 0, "")}
            if keep:
                text += f"\n\n[ANALYZER SIGNALS]\n{json.dumps(keep, indent=2)[:1000]}"
        return text
