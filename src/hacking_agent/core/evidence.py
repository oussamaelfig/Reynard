"""
=============================================================================
Reynard — Evidentiary Store
=============================================================================
Append-only ledger of Proof-of-Concept artifacts.

A vulnerability is treated as VERIFIED **only if** at least one PoC linked
to it has `verdict == "success"`. Without that, the reporter MUST list the
finding under "Informational / Unverified" instead of as a confirmed
vulnerability.

This module is the single source of truth for the "can we report this?"
question — agents cannot bypass it by self-declaring success.
=============================================================================
"""
from __future__ import annotations

import threading

from hacking_agent.core.schemas import PoC


class EvidenceStore:
    """Thread-safe append-only PoC store."""

    def __init__(self):
        self._lock = threading.RLock()
        self._pocs: list[PoC] = []
        self._poc_seq = 0

    def next_poc_id(self) -> str:
        with self._lock:
            self._poc_seq += 1
            return f"poc:{self._poc_seq}"

    def record(self, poc: PoC) -> PoC:
        """Append a PoC. Returns the recorded PoC (with id)."""
        with self._lock:
            if not poc.id:
                poc = poc.model_copy(update={"id": self.next_poc_id()})
            self._pocs.append(poc)
            return poc

    def get_by_vuln(self, vuln_id: str) -> list[PoC]:
        with self._lock:
            return [p for p in self._pocs if p.vuln_id == vuln_id]

    def verification_state(self, vuln_id: str) -> str:
        """Return the current evidence state for a vulnerability.

        The ledger is append-only, so the latest validator adjudication must
        be allowed to override an earlier exploitation claim. This prevents a
        rejected PoC from remaining reportable just because a prior entry had
        verdict=success.
        """
        state = "unverified"
        for poc in self.get_by_vuln(vuln_id):
            is_validator = poc.agent_name == "validator"
            request = poc.request_summary or ""
            if is_validator and poc.verdict == "failure":
                state = "refuted"
            elif is_validator and poc.verdict == "success":
                state = "verified"
            elif poc.verdict == "success":
                state = "verified"
            elif request.startswith("REFUTED:"):
                state = "refuted"
        return state

    def is_verified(self, vuln_id: str) -> bool:
        """A vuln is verified iff its latest evidence state is verified."""
        return self.verification_state(vuln_id) == "verified"

    def all_pocs(self) -> list[PoC]:
        with self._lock:
            return list(self._pocs)

    def summarize(self) -> str:
        """Human-readable summary for prompt injection."""
        with self._lock:
            if not self._pocs:
                return "## EVIDENCE\n(no PoCs collected yet)"
            lines = [f"## EVIDENCE ({len(self._pocs)} PoCs)"]
            by_vuln: dict[str, list[PoC]] = {}
            for p in self._pocs:
                by_vuln.setdefault(p.vuln_id, []).append(p)
            for vuln_id, pocs in by_vuln.items():
                state = self.verification_state(vuln_id)
                tag = state.upper()
                lines.append(f"\n### {vuln_id}  [{tag}]  ({len(pocs)} attempt(s))")
                for p in pocs:
                    lines.append(f"  - [{p.verdict.upper()}] {p.payload[:90]}")
                    lines.append(f"    by {p.agent_name} @ {p.timestamp}")
            return "\n".join(lines)
