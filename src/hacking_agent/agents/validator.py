"""
=============================================================================
Reynard - PoC Validator (False-Positive Triage)
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
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from rich.console import Console

from hacking_agent.agents.base import BaseAgent
from hacking_agent.core.evidence_bundle import sanitize_text
from hacking_agent.core.schemas import AgentResult, AgentTask, PoC, ValidationOutput
from hacking_agent.core.validation_provenance import (
    capture_observation,
    derive_executor_effect,
    issue_protocol_receipt,
    sha256_text,
    validator_identity,
)

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
2. REPLAY AGAIN in a fresh or explicitly controlled context. One response is
             never enough.
3. COUNTER - Run a NEUTERED variant (e.g. for SQLi: same param but
             benign value; for XSS: same trigger context but text only;
             for SSRF: same parameter, internal IP that DOESN'T exist).
             If the success signal STILL appears, the signal is
             environmental and the original PoC was a false positive.
4. VARY    - Perturb the payload predictably (encoding, position, case).
             The signal should change in a way consistent with the vuln.
             For OOB-based PoCs: re-mint a fresh OOB token, re-deliver,
             confirm a NEW callback (proves the previous one wasn't
             ambient noise from your domain).

# SESSION / COOKIES (CRITICAL)
The active authenticated session's cookies are injected AUTOMATICALLY by
http_request and browser_* from the shared cookie jar. NEVER fabricate or
hardcode a Cookie header or session token (e.g. session=abc123) — doing so
replays with a FAKE identity and guarantees a false negative. Simply issue the
request WITHOUT a Cookie header and your real authenticated cookies are used.
If you need a fresh CSRF token, GET the page that renders the form first (the
token and session cookie are refreshed together), then submit.

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
6. Every next_probe MUST include probe_kind. On the final response, provide
   attempt_results only as your advisory interpretation. Your outcomes,
   behavioral signals, notes, context IDs, and proof metadata NEVER establish
   reportability. The control plane independently captures requests/responses,
   derives supported structured effects, creates context/capture IDs, and
   authenticates two replays plus a matched control.
7. Supply validation_context, exact reproduction_steps, and class-specific
   proof_type/proof_metadata for operator diagnostics only. Unsupported
   executor evidence is suppressed even when you claim confirmed=True.

# OUTPUT
A SINGLE ValidationOutput JSON. While iterating, supply next_probe and
final=False. When done, set final=True and a definitive confirmed bool.
"""


class ValidatorAgent(BaseAgent):
    name = "validator"
    role = "validator"

    VERSION = "reynard-validator/1"
    MAX_INNER_ITER = 8

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.validator_instance_id = f"validator:{uuid.uuid4().hex}"

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
                task.context,
            )
            try:
                out: ValidationOutput = self.call_typed(
                    VALIDATOR_SYSTEM, prompt, ValidationOutput,
                )
            except Exception as e:
                return self._record_validation_error(
                    target_poc, vuln_entity,
                    f"validator_llm_error: {type(e).__name__}: {e}",
                )

            if out.final:
                final_output = out
                break

            if not out.next_probe:
                final_output = out
                break
            if not out.probe_kind:
                return self._record_validation_error(
                    target_poc, vuln_entity,
                    "validator_protocol_incomplete: next probe omitted probe_kind",
                )
            required_sequence = (
                "replay", "fresh_context_replay", "control",
            )
            if len(attempts) < len(required_sequence):
                expected_kind = required_sequence[len(attempts)]
                if out.probe_kind != expected_kind:
                    return self._record_validation_error(
                        target_poc,
                        vuln_entity,
                        (
                            "validator_protocol_incomplete: expected "
                            f"{expected_kind}, received {out.probe_kind}"
                        ),
                        attempts=attempts,
                    )

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
            try:
                attempts.append(self._capture_attempt(
                    index=inner + 1,
                    probe_kind=out.probe_kind,
                    decision=out.next_probe,
                    outcome=outcome,
                    observation=last_observation,
                    context=task.context,
                ))
            except Exception as exc:
                return self._record_validation_error(
                    target_poc,
                    vuln_entity,
                    (
                        "validator_executor_capture_failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                    attempts=attempts,
                )

        if final_output is None:
            # Inner-loop budget exhausted before final - treat as ambiguous.
            return self._record_validation_error(
                target_poc, vuln_entity,
                "validator_protocol_incomplete: probe ceiling reached",
            )

        # Apply the verdict to the underlying entities.
        if final_output.confirmed:
            metadata, protocol_error = self._validated_metadata(
                final_output, attempts, task.context,
            )
            if protocol_error:
                return self._record_validation_error(
                    target_poc, vuln_entity, protocol_error,
                    attempts=attempts,
                )
            # Re-confirm: keep status verified, append a validator-source PoC
            # so the audit trail shows the second confirmation.
            confirm_poc = PoC(
                id=self.evidence.next_poc_id(),
                vuln_id=vuln_id,
                payload=target_poc.payload,
                request_summary=f"VALIDATED: {target_poc.request_summary}"[:300],
                response_excerpt=str(
                    metadata["validation_protocol"]["causal_signal"]
                )[:500],
                verdict="success",
                agent_name=self.name,
                validation_metadata=metadata,
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
            validation_metadata={
                "validation_schema_version": 2,
                "protocol_valid": False,
                "validator_identity": validator_identity(
                    instance_id=self.validator_instance_id,
                    version=self.VERSION,
                ),
                "validator_version": self.VERSION,
                "validated_at": datetime.utcnow().isoformat(),
                "rejection_reason": final_output.fp_reason[:500],
                "attempts": attempts,
            },
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

    def _capture_attempt(
        self,
        *,
        index: int,
        probe_kind: str,
        decision: Any,
        outcome: dict[str, Any],
        observation: str,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        args = dict(getattr(decision, "args", {}) or {})
        raw = str(outcome.get("result") or "")
        parsed: dict[str, Any] = {}
        try:
            candidate = json.loads(raw)
            if isinstance(candidate, dict):
                parsed = candidate
        except (json.JSONDecodeError, TypeError):
            pass
        response = (
            parsed.get("response")
            or parsed.get("body")
            or parsed.get("rendered_content")
            or parsed.get("rendered_html")
            or parsed.get("stdout")
            or raw
        )
        request = (
            args.get("raw_request")
            or args.get("request")
            or json.dumps(
                {"tool": getattr(decision, "tool", ""), "args": args},
                sort_keys=True, default=str,
            )
        )
        captured_at = datetime.now(timezone.utc).isoformat()
        status_code = (
            parsed.get("status_code")
            if parsed.get("status_code") is not None
            else parsed.get("status")
        )
        if status_code is None:
            status_code = (outcome.get("signals") or {}).get("status_code")
        try:
            status_code = int(status_code)
        except (TypeError, ValueError):
            status_code = 0
        tool = str(getattr(decision, "tool", "") or "")
        run_id, engagement_id = self._runtime_binding(context)
        safe_request = sanitize_text(str(request)[:4000])
        safe_response = sanitize_text(str(response)[:5000])
        trusted_effect = derive_executor_effect(
            tool=tool,
            raw_result=raw,
            signals=outcome.get("signals") or {},
        )
        trusted_observation = capture_observation(
            attempt_index=index,
            probe_kind=probe_kind,
            tool=tool,
            request=safe_request,
            response=safe_response,
            status_code=status_code,
            identity=str(
                args.get("session")
                or args.get("identity")
                or context.get("active_session")
                or "anonymous"
            ),
            url=str(args.get("url") or context.get("target_url") or ""),
            method=str(args.get("method") or "GET").upper(),
            captured_at=captured_at,
            run_id=run_id,
            engagement_id=engagement_id,
            validator_instance_id=self.validator_instance_id,
            trusted_effect=trusted_effect,
        )
        return {
            "step": index,
            "attempt_index": index,
            "probe_kind": probe_kind,
            "tool": tool,
            "args": json.dumps(args, sort_keys=True, default=str)[:1200],
            "description": str(getattr(decision, "reasoning", "") or "")[:500],
            "request": safe_request,
            "response": safe_response,
            "url": str(args.get("url") or context.get("target_url") or ""),
            "method": str(args.get("method") or "GET").upper(),
            "identity": str(
                args.get("session")
                or args.get("identity")
                or context.get("active_session")
                or "anonymous"
            ),
            "status_code": status_code,
            "timestamp": captured_at,
            "observation": observation[:1000],
            "signals": outcome.get("signals") or {},
            "blocked": bool(outcome.get("blocked")),
            "trusted_observation": trusted_observation,
        }

    def _validated_metadata(
        self,
        output: ValidationOutput,
        attempts: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        """Issue a receipt only for independently derived executor effects."""
        prefix = "validator_protocol_incomplete: "
        if not output.final:
            return {}, prefix + "confirmed verdict was not final"
        if output.reproducibility != "reproducible":
            return {}, prefix + "confirmed verdict was not reproducible"
        if any(attempt.get("blocked") for attempt in attempts[:3]):
            return {}, prefix + "a required validation probe failed or was blocked"
        observations = [
            dict(attempt.get("trusted_observation") or {})
            for attempt in attempts
            if attempt.get("trusted_observation")
        ]
        run_id, engagement_id = self._runtime_binding(context)
        protocol, reason = issue_protocol_receipt(
            observations,
            run_id=run_id,
            engagement_id=engagement_id,
            validator_instance_id=self.validator_instance_id,
            validator_version=self.VERSION,
        )
        if protocol is None:
            return {}, prefix + reason
        metadata = {
            "validation_schema_version": 2,
            "protocol_valid": True,
            "validation_protocol": protocol,
            "validation_error": "",
        }
        return metadata, ""

    def _runtime_binding(
        self,
        context: dict[str, Any],
    ) -> tuple[str, str]:
        target = str(context.get("target_url") or self.memory.target_url or "")
        run_id = str(
            context.get("run_id")
            or os.getenv("REYNARD_RUN_ID")
            or f"standalone:{sha256_text(target)[:16]}"
        )
        engagement_id = str(
            context.get("engagement_id")
            or os.getenv("REYNARD_ENGAGEMENT_ID")
            or f"engagement:{sha256_text(target)[:16]}"
        )
        return run_id, engagement_id

    def _record_validation_error(
        self,
        target_poc: PoC,
        vuln_entity: Any,
        reason: str,
        *,
        attempts: list[dict[str, Any]] | None = None,
    ) -> AgentResult:
        """Persist validator exceptions/incomplete protocols as suppression."""
        vuln_entity.attrs["validator_confirmed"] = False
        vuln_entity.attrs["validator_error"] = reason[:500]
        vuln_entity.attrs["status"] = "informational"
        error_poc = PoC(
            id=self.evidence.next_poc_id(),
            vuln_id=target_poc.vuln_id,
            payload=target_poc.payload,
            request_summary=f"VALIDATOR_ERROR: {target_poc.request_summary}"[:300],
            response_excerpt=reason[:500],
            verdict="failure",
            agent_name=self.name,
            validation_metadata={
                "validation_schema_version": 2,
                "protocol_valid": False,
                "validator_identity": validator_identity(
                    instance_id=self.validator_instance_id,
                    version=self.VERSION,
                ),
                "validator_version": self.VERSION,
                "validated_at": datetime.utcnow().isoformat(),
                "validation_error": reason[:500],
                "attempts": list(attempts or []),
            },
        )
        self.evidence.record(error_poc)
        console.print(
            f"[yellow]⚠ Validator suppressed {target_poc.id}: {reason[:120]}[/]"
        )
        return AgentResult(
            success=False,
            summary=f"PoC {target_poc.id} suppressed: {reason[:240]}",
            pocs_recorded=[error_poc],
            next_recommendation=(
                "Do not report; validation did not complete successfully."
            ),
        )

    def _build_prompt(self, poc: PoC, vuln_entity, attempts: list[dict],
                      last_observation: str, inner: int,
                      ctx: dict | None = None) -> str:
        attempts_str = (
            "\n".join(
                f"  step {a['step']}: [{a['tool']}] {a['args'][:120]}\n"
                f"    -> {a['observation'][:200]}"
                for a in attempts
            )
            or "  (none yet)"
        )
        session_section = ""
        if isinstance(ctx, dict):
            active_session = ctx.get("active_session")
            if active_session:
                auth = "authenticated" if ctx.get("session_authenticated") else "not yet authenticated"
                cred = ctx.get("credential_hint") or ""
                session_section = (
                    f"\n# ACTIVE SESSION\n"
                    f"  name: {active_session} ({auth})\n"
                    "  Its cookies are injected automatically — do NOT send a "
                    "Cookie header or invent a session token.\n"
                    + (f"  credentials (to re-login if needed): {cred}\n" if cred else "")
                )
        exploit_server = ""
        if isinstance(ctx, dict):
            exploit_server = ctx.get("exploit_server_url", "") or ""
        if not exploit_server and self.memory:
            exploit_server = self.memory.get_fact("exploit_server_url", "") or ""
        exploit_server_section = (
            f"\n# EXPLOIT SERVER (use this EXACT url; do not invent one)\n"
            f"  {exploit_server}\n"
            if exploit_server else ""
        )
        return (
            f"{session_section}"
            f"{exploit_server_section}"
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
            "Decide what re-test probe to run next (two replays -> control -> vary). "
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
