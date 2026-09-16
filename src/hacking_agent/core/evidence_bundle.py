"""
=============================================================================
Reynard — EvidenceBundle
=============================================================================
A finding is only real when it is backed by concrete, reproducible evidence.
An ``EvidenceBundle`` is that evidence, structured so a human (or a bounty
triager) can reproduce it without trusting any LLM claim:

  - sanitized request/response exchanges (secrets redacted)
  - the identity/session each exchange ran as
  - the affected endpoint + target
  - timestamps
  - CONTROL tests (the "why it's causal" — baseline / neutered / cross-identity)
  - reproduction steps
  - screenshots (when a browser proof exists)
  - out-of-band interactions (Interactsh/Collaborator)
  - a verification status: unverified | verified | refuted | needs_review

Reports are generated FROM these bundles, not from model narration. Scanner
output alone never produces a ``verified`` bundle — verification requires a
concrete behavioural signal recorded here (successful execution, data access,
an authorization difference, an OOB interaction, a browser proof, or a
reproducible control-vs-test response).
=============================================================================
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

# ---- verification vocabulary ----
V_UNVERIFIED = "unverified"
V_VERIFIED = "verified"
V_REFUTED = "refuted"
V_NEEDS_REVIEW = "needs_review"


def _now() -> str:
    return datetime.utcnow().isoformat()


# =============================================================================
# Sanitization
# =============================================================================

SENSITIVE_KEYS = (
    "authorization", "cookie", "set-cookie", "x-api-key", "api-key", "apikey",
    "api_key", "token", "access_token", "refresh_token", "password", "passwd",
    "pwd", "secret", "client_secret", "session", "csrf", "x-csrf-token",
    "x-auth-token", "bearer",
)

_HEADER_RE = re.compile(
    r"(?im)^(?P<name>[A-Za-z0-9\-]+)\s*:\s*(?P<val>.+)$"
)
_KV_RE = re.compile(
    r"(?i)(?P<key>[A-Za-z0-9_\-]+)\s*=\s*(?P<val>[^&\s;]+)"
)
_JSON_KV_RE = re.compile(
    r'(?i)"(?P<key>[A-Za-z0-9_\-]+)"\s*:\s*"(?P<val>[^"]*)"'
)

REDACTED = "[REDACTED]"


def _is_sensitive(name: str) -> bool:
    n = name.strip().lower()
    return any(s in n for s in SENSITIVE_KEYS)


def sanitize_text(text: str, extra_secrets: tuple[str, ...] = ()) -> str:
    """Redact secrets from a request/response blob.

    Redacts sensitive header lines (Authorization/Cookie/...), sensitive
    key=value and JSON "key":"value" pairs, and any explicit secret strings
    (e.g. live cookie values pulled from the session registry).
    """
    if not text:
        return text or ""
    out = text

    def _hdr(m: re.Match) -> str:
        return f"{m.group('name')}: {REDACTED}" if _is_sensitive(m.group("name")) else m.group(0)
    out = _HEADER_RE.sub(_hdr, out)

    def _kv(m: re.Match) -> str:
        return f"{m.group('key')}={REDACTED}" if _is_sensitive(m.group("key")) else m.group(0)
    out = _KV_RE.sub(_kv, out)

    def _jkv(m: re.Match) -> str:
        return f'"{m.group("key")}": "{REDACTED}"' if _is_sensitive(m.group("key")) else m.group(0)
    out = _JSON_KV_RE.sub(_jkv, out)

    for secret in extra_secrets:
        if secret and len(secret) >= 6:
            out = out.replace(secret, REDACTED)
    return out


def sanitize_structure(value: Any, extra_secrets: tuple[str, ...] = (),
                       key: str = "") -> Any:
    """Recursively sanitize persisted evidence and validator metadata."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, item in value.items():
            item_key = str(raw_key)
            if _is_sensitive(item_key):
                out[item_key] = REDACTED
            else:
                out[item_key] = sanitize_structure(
                    item, extra_secrets, item_key,
                )
        return out
    if isinstance(value, list):
        return [sanitize_structure(item, extra_secrets, key) for item in value]
    if isinstance(value, tuple):
        return [sanitize_structure(item, extra_secrets, key) for item in value]
    if isinstance(value, str):
        return sanitize_text(value, extra_secrets)
    return value


# =============================================================================
# Records
# =============================================================================

@dataclass
class SanitizedExchange:
    """One request/response pair, secrets redacted."""
    label: str = "test"              # test | control | replay | oob | baseline
    identity: str = ""               # session/principal this ran as
    method: str = "GET"
    url: str = ""
    request: str = ""                # sanitized raw request or summary
    response: str = ""               # sanitized response excerpt
    status_code: Optional[int] = None
    timestamp: str = field(default_factory=_now)
    notes: str = ""
    source: str = ""
    context_id: str = ""
    attempt_index: int = 0
    capture_id: str = ""
    request_sha256: str = ""
    response_sha256: str = ""

    @classmethod
    def build(cls, *, label: str = "test", identity: str = "", method: str = "GET",
              url: str = "", request: str = "", response: str = "",
              status_code: Optional[int] = None, notes: str = "",
              source: str = "", context_id: str = "", attempt_index: int = 0,
              capture_id: str = "", request_sha256: str = "",
              response_sha256: str = "",
              extra_secrets: tuple[str, ...] = ()) -> "SanitizedExchange":
        return cls(
            label=label, identity=identity, method=method, url=url,
            request=sanitize_text(request, extra_secrets),
            response=sanitize_text(response, extra_secrets),
            status_code=status_code, notes=notes, source=source,
            context_id=context_id, attempt_index=attempt_index,
            capture_id=capture_id, request_sha256=request_sha256,
            response_sha256=response_sha256,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label, "identity": self.identity, "method": self.method,
            "url": self.url, "request": self.request, "response": self.response,
            "status_code": self.status_code, "timestamp": self.timestamp,
            "notes": self.notes, "source": self.source,
            "context_id": self.context_id, "attempt_index": self.attempt_index,
            "capture_id": self.capture_id,
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SanitizedExchange":
        return cls(label=d.get("label", "test"), identity=d.get("identity", ""),
                   method=d.get("method", "GET"), url=d.get("url", ""),
                   request=d.get("request", ""), response=d.get("response", ""),
                   status_code=d.get("status_code"),
                   timestamp=d.get("timestamp") or _now(), notes=d.get("notes", ""),
                   source=d.get("source", ""), context_id=d.get("context_id", ""),
                   attempt_index=int(d.get("attempt_index", 0) or 0),
                   capture_id=d.get("capture_id", ""),
                   request_sha256=d.get("request_sha256", ""),
                   response_sha256=d.get("response_sha256", ""))


@dataclass
class ControlTest:
    """A control observation proving the effect is causally tied to the input
    (baseline vs test, neutered payload, or a different identity)."""
    description: str
    exchange: Optional[SanitizedExchange] = None
    result: str = ""                 # what the control showed (e.g. "denied 403")

    def to_dict(self) -> dict[str, Any]:
        return {"description": self.description,
                "exchange": self.exchange.to_dict() if self.exchange else None,
                "result": self.result}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ControlTest":
        ex = d.get("exchange")
        return cls(description=d.get("description", ""),
                   exchange=SanitizedExchange.from_dict(ex) if ex else None,
                   result=d.get("result", ""))


@dataclass
class EvidenceBundle:
    """Reproducible evidence for a single finding."""
    id: str
    title: str = ""
    vuln_type: str = ""
    severity: str = "info"
    target: str = ""
    endpoint: str = ""
    identity: str = ""
    vuln_id: str = ""
    finding_id: str = ""
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    test_exchanges: list[SanitizedExchange] = field(default_factory=list)
    control_tests: list[ControlTest] = field(default_factory=list)
    oob_interactions: list[str] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    causal_signal: str = ""
    verification_status: str = V_UNVERIFIED
    verified_by: str = ""
    notes: str = ""
    # Strict validation envelope.  Legacy bundles omit these fields and are
    # intentionally non-reportable.
    validation_schema_version: int = 0
    discovered_by: str = ""
    validator_identity: dict[str, Any] = field(default_factory=dict)
    validator_version: str = ""
    validation_method: str = ""
    validation_context: str = ""
    validated_at: str = ""
    replay_count: int = 0
    replay_results: list[dict[str, Any]] = field(default_factory=list)
    proof_type: str = ""
    proof_metadata: dict[str, Any] = field(default_factory=dict)
    validation_protocol: dict[str, Any] = field(default_factory=dict)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    customer_projection: dict[str, Any] = field(default_factory=dict)
    validation_error: str = ""
    integrity_sha256: str = ""
    authenticity: dict[str, Any] = field(default_factory=dict)
    suppression_reason_code: str = ""
    suppression_rationale: str = ""

    def _touch(self) -> None:
        self.updated_at = _now()
        self.integrity_sha256 = ""
        self.authenticity = {}

    # ---- mutation ----
    def add_test(self, exchange: SanitizedExchange) -> None:
        self.test_exchanges.append(exchange)
        self._touch()

    def add_control(self, control: ControlTest) -> None:
        self.control_tests.append(control)
        self._touch()

    def add_oob(self, interaction: str) -> None:
        if interaction and interaction not in self.oob_interactions:
            self.oob_interactions.append(interaction)
            self._touch()

    def add_screenshot(self, path: str) -> None:
        if path and path not in self.screenshots:
            self.screenshots.append(path)
            self._touch()

    def set_verification(self, status: str, *, verified_by: str = "",
                         causal_signal: str = "") -> None:
        if status in (V_UNVERIFIED, V_VERIFIED, V_REFUTED, V_NEEDS_REVIEW):
            self.verification_status = status
        if verified_by:
            self.verified_by = verified_by
        if causal_signal:
            self.causal_signal = causal_signal
        self._touch()

    @property
    def is_verified(self) -> bool:
        # Status alone is a legacy hint, never a promotion decision.
        from hacking_agent.core.finding_validation import is_reportable
        return is_reportable(evidence_bundle=self)

    @property
    def is_reportable(self) -> bool:
        return self.is_verified

    def seal(self, *, extra_secrets: tuple[str, ...] = ()) -> str:
        """Sanitize and digest the bundle.

        A digest detects accidental changes but is not authentic.  Only
        :meth:`attest` creates the control-plane HMAC required for reporting.
        """
        self.title = sanitize_text(self.title, extra_secrets)
        self.vuln_type = sanitize_text(self.vuln_type, extra_secrets)
        self.target = sanitize_text(self.target, extra_secrets)
        self.endpoint = sanitize_text(self.endpoint, extra_secrets)
        self.identity = sanitize_text(self.identity, extra_secrets)
        self.causal_signal = sanitize_text(self.causal_signal, extra_secrets)
        self.notes = sanitize_text(self.notes, extra_secrets)
        self.validation_error = sanitize_text(self.validation_error, extra_secrets)
        self.reproduction_steps = [
            sanitize_text(step, extra_secrets) for step in self.reproduction_steps
        ]
        self.oob_interactions = [
            sanitize_text(item, extra_secrets) for item in self.oob_interactions
        ]
        self.screenshots = [
            sanitize_text(item, extra_secrets) for item in self.screenshots
        ]
        for exchange in self.test_exchanges:
            exchange.identity = sanitize_text(exchange.identity, extra_secrets)
            exchange.url = sanitize_text(exchange.url, extra_secrets)
            exchange.request = sanitize_text(exchange.request, extra_secrets)
            exchange.response = sanitize_text(exchange.response, extra_secrets)
            exchange.notes = sanitize_text(exchange.notes, extra_secrets)
            exchange.context_id = sanitize_text(
                exchange.context_id, extra_secrets,
            )
        for control in self.control_tests:
            control.description = sanitize_text(control.description, extra_secrets)
            control.result = sanitize_text(control.result, extra_secrets)
            if control.exchange:
                control.exchange.identity = sanitize_text(
                    control.exchange.identity, extra_secrets,
                )
                control.exchange.url = sanitize_text(
                    control.exchange.url, extra_secrets,
                )
                control.exchange.request = sanitize_text(
                    control.exchange.request, extra_secrets,
                )
                control.exchange.response = sanitize_text(
                    control.exchange.response, extra_secrets,
                )
                control.exchange.notes = sanitize_text(
                    control.exchange.notes, extra_secrets,
                )
                control.exchange.context_id = sanitize_text(
                    control.exchange.context_id, extra_secrets,
                )
        self.replay_results = sanitize_structure(
            self.replay_results, extra_secrets,
        )
        self.proof_metadata = sanitize_structure(
            self.proof_metadata, extra_secrets,
        )
        self.customer_projection = sanitize_structure(
            self.customer_projection, extra_secrets,
        )
        self.updated_at = _now()
        self.integrity_sha256 = ""
        self.authenticity = {}
        from hacking_agent.core.finding_validation import evidence_integrity_digest
        self.integrity_sha256 = evidence_integrity_digest(self)
        return self.integrity_sha256

    def attest(self, *, extra_secrets: tuple[str, ...] = ()) -> str:
        """Create a control-plane authenticity receipt for a trusted protocol."""
        self.seal(extra_secrets=extra_secrets)
        from hacking_agent.core.validation_provenance import attest_bundle
        self.authenticity = attest_bundle(self)
        return str(self.authenticity.get("signature") or "")

    def apply_reportability(self) -> bool:
        """Evaluate and retain a concise internal suppression diagnostic."""
        from hacking_agent.core.finding_validation import evaluate_reportability
        decision = evaluate_reportability(evidence_bundle=self)
        self.suppression_reason_code = (
            "" if decision.reportable else decision.reason_code
        )
        self.suppression_rationale = (
            "" if decision.reportable else decision.rationale
        )
        return decision.reportable

    def has_concrete_evidence(self) -> bool:
        """True when the bundle carries at least one concrete behavioural signal
        that could justify a verified status (a control-vs-test comparison, an
        OOB interaction, a browser screenshot, or a stated causal signal)."""
        return bool(self.control_tests or self.oob_interactions
                    or self.screenshots or self.causal_signal.strip())

    # ---- rendering ----
    def render_markdown(self, *, internal: bool = False) -> str:
        if not internal and not self.is_reportable:
            return ""
        lines = [f"### {self.title or self.vuln_type or self.id}"]
        meta = [f"**Type:** {self.vuln_type or 'n/a'}",
                f"**Severity:** {self.severity}",
                f"**Status:** {self.verification_status}"]
        if self.verified_by:
            meta.append(f"**Verified by:** {self.verified_by}")
        lines.append(" · ".join(meta))
        if self.endpoint:
            lines.append(f"**Endpoint:** `{self.endpoint}`")
        if self.identity:
            lines.append(f"**Identity:** {self.identity}")
        if self.causal_signal:
            lines.append(f"**Causal signal:** {self.causal_signal}")
        if self.reproduction_steps:
            lines.append("\n**Reproduction steps:**")
            for i, step in enumerate(self.reproduction_steps, 1):
                lines.append(f"{i}. {step}")
        for ex in self.test_exchanges:
            lines.append(f"\n**Exchange ({ex.label}, as {ex.identity or 'anonymous'}):**")
            if ex.request:
                lines.append("```http\n" + ex.request.strip()[:1500] + "\n```")
            if ex.response:
                status = f" (status {ex.status_code})" if ex.status_code else ""
                lines.append(f"Response{status}:")
                lines.append("```\n" + ex.response.strip()[:1200] + "\n```")
        for ct in self.control_tests:
            lines.append(f"\n**Control:** {ct.description}")
            if ct.result:
                lines.append(f"  Result: {ct.result}")
        if self.oob_interactions:
            lines.append("\n**Out-of-band interactions:**")
            for oob in self.oob_interactions:
                lines.append(f"- {oob}")
        if self.screenshots:
            lines.append("\n**Screenshots:**")
            for s in self.screenshots:
                lines.append(f"- {s}")
        return "\n".join(lines)

    # ---- serialization ----
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "vuln_type": self.vuln_type,
            "severity": self.severity, "target": self.target,
            "endpoint": self.endpoint, "identity": self.identity,
            "vuln_id": self.vuln_id, "finding_id": self.finding_id,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "test_exchanges": [e.to_dict() for e in self.test_exchanges],
            "control_tests": [c.to_dict() for c in self.control_tests],
            "oob_interactions": list(self.oob_interactions),
            "screenshots": list(self.screenshots),
            "reproduction_steps": list(self.reproduction_steps),
            "causal_signal": self.causal_signal,
            "verification_status": self.verification_status,
            "verified_by": self.verified_by, "notes": self.notes,
            "validation_schema_version": self.validation_schema_version,
            "discovered_by": self.discovered_by,
            "validator_identity": self.validator_identity,
            "validator_version": self.validator_version,
            "validation_method": self.validation_method,
            "validation_context": self.validation_context,
            "validated_at": self.validated_at,
            "replay_count": self.replay_count,
            "replay_results": list(self.replay_results),
            "proof_type": self.proof_type,
            "proof_metadata": dict(self.proof_metadata),
            "validation_protocol": dict(self.validation_protocol),
            "artifacts": list(self.artifacts),
            "customer_projection": dict(self.customer_projection),
            "validation_error": self.validation_error,
            "integrity_sha256": self.integrity_sha256,
            "authenticity": dict(self.authenticity),
            "suppression_reason_code": self.suppression_reason_code,
            "suppression_rationale": self.suppression_rationale,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EvidenceBundle":
        b = cls(
            id=d["id"], title=d.get("title", ""), vuln_type=d.get("vuln_type", ""),
            severity=d.get("severity", "info"), target=d.get("target", ""),
            endpoint=d.get("endpoint", ""), identity=d.get("identity", ""),
            vuln_id=d.get("vuln_id", ""), finding_id=d.get("finding_id", ""),
            created_at=d.get("created_at") or _now(),
            updated_at=d.get("updated_at") or _now(),
            oob_interactions=list(d.get("oob_interactions") or []),
            screenshots=list(d.get("screenshots") or []),
            reproduction_steps=list(d.get("reproduction_steps") or []),
            causal_signal=d.get("causal_signal", ""),
            verification_status=d.get("verification_status", V_UNVERIFIED),
            verified_by=d.get("verified_by", ""), notes=d.get("notes", ""),
            validation_schema_version=int(
                d.get("validation_schema_version", 0) or 0
            ),
            discovered_by=d.get("discovered_by", ""),
            validator_identity=(
                dict(d.get("validator_identity") or {})
                if isinstance(d.get("validator_identity"), dict) else {}
            ),
            validator_version=d.get("validator_version", ""),
            validation_method=d.get("validation_method", ""),
            validation_context=d.get("validation_context", ""),
            validated_at=d.get("validated_at", ""),
            replay_count=int(d.get("replay_count", 0) or 0),
            replay_results=list(d.get("replay_results") or []),
            proof_type=d.get("proof_type", ""),
            proof_metadata=dict(d.get("proof_metadata") or {}),
            validation_protocol=dict(d.get("validation_protocol") or {}),
            artifacts=list(d.get("artifacts") or []),
            customer_projection=dict(d.get("customer_projection") or {}),
            validation_error=d.get("validation_error", ""),
            integrity_sha256=d.get("integrity_sha256", ""),
            authenticity=dict(d.get("authenticity") or {}),
            suppression_reason_code=d.get("suppression_reason_code", ""),
            suppression_rationale=d.get("suppression_rationale", ""),
        )
        b.test_exchanges = [SanitizedExchange.from_dict(e)
                            for e in d.get("test_exchanges", [])]
        b.control_tests = [ControlTest.from_dict(c)
                           for c in d.get("control_tests", [])]
        return b


# =============================================================================
# Store
# =============================================================================

class EvidenceBundleStore:
    """Thread-safe collection of evidence bundles, keyed by id and vuln."""

    def __init__(self):
        self._lock = threading.RLock()
        self._bundles: dict[str, EvidenceBundle] = {}
        self._seq = 0

    def _next_id(self) -> str:
        self._seq += 1
        return f"bundle:{self._seq}"

    def create(self, *, vuln_id: str = "", vuln_type: str = "", title: str = "",
               severity: str = "info", target: str = "", endpoint: str = "",
               identity: str = "", finding_id: str = "") -> EvidenceBundle:
        with self._lock:
            b = EvidenceBundle(
                id=self._next_id(), vuln_id=vuln_id, vuln_type=vuln_type,
                title=title or vuln_type, severity=severity, target=target,
                endpoint=endpoint, identity=identity, finding_id=finding_id,
            )
            self._bundles[b.id] = b
            return b

    def add(self, bundle: EvidenceBundle) -> EvidenceBundle:
        with self._lock:
            if not bundle.id:
                bundle.id = self._next_id()
            if not bundle.integrity_sha256:
                bundle.seal()
            bundle.apply_reportability()
            self._bundles[bundle.id] = bundle
            return bundle

    def get(self, bundle_id: str) -> Optional[EvidenceBundle]:
        with self._lock:
            return self._bundles.get(bundle_id)

    def by_vuln(self, vuln_id: str) -> list[EvidenceBundle]:
        with self._lock:
            return [b for b in self._bundles.values() if b.vuln_id == vuln_id]

    def all(self) -> list[EvidenceBundle]:
        with self._lock:
            return list(self._bundles.values())

    def verified(self) -> list[EvidenceBundle]:
        with self._lock:
            return [b for b in self._bundles.values() if b.is_reportable]

    def render_markdown(self, verified_only: bool = True) -> str:
        with self._lock:
            bundles = [b for b in self._bundles.values()
                       if (not verified_only or b.is_reportable)]
        if not bundles:
            return ""
        return "\n\n".join(
            rendered for rendered in (
                b.render_markdown(internal=not verified_only) for b in bundles
            ) if rendered
        )

    # ---- persistence ----
    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {"bundles": [b.to_dict() for b in self._bundles.values()]}

    def load_dict(self, d: dict[str, Any]) -> int:
        n = 0
        for bd in (d or {}).get("bundles", []):
            try:
                b = EvidenceBundle.from_dict(bd)
                b.apply_reportability()
            except Exception:
                continue
            with self._lock:
                self._bundles[b.id] = b
                self._seq = max(self._seq, _seq_of(b.id))
            n += 1
        return n

    def persist(self, store: Any, target: str, scope_key: str) -> bool:
        if store is None:
            return False
        try:
            store.save_evidence_bundles(target, scope_key, self.to_dict())
            return True
        except Exception:
            return False

    def load(self, store: Any, target: str, scope_key: str) -> int:
        if store is None:
            return 0
        try:
            snap = store.load_evidence_bundles(target, scope_key)
        except Exception:
            return 0
        return self.load_dict(snap) if snap else 0


# =============================================================================
# Builders (from the existing PoC ledger)
# =============================================================================

def build_bundle_from_pocs(vuln_id: str, pocs: list[Any], *,
                           verification_status: str = V_UNVERIFIED,
                           vuln_type: str = "", title: str = "",
                           severity: str = "info", target: str = "",
                           endpoint: str = "", identity: str = "",
                           extra_secrets: tuple[str, ...] = ()) -> EvidenceBundle:
    """Assemble an EvidenceBundle from PoC records (schemas.PoC-like objects).

    Only an independent Validator PoC carrying a complete protocol transcript
    can populate the strict validation envelope.  Older/exploitation-only PoCs
    are retained as candidate evidence but cannot become reportable."""
    endpoint = endpoint or target
    identity = identity or "anonymous"
    discovered_by = next(
        (
            str(getattr(poc, "agent_name", "") or "")
            for poc in pocs or []
            if str(getattr(poc, "agent_name", "") or "") != "validator"
        ),
        "unknown",
    )
    validator_records = [
        poc for poc in (pocs or [])
        if str(getattr(poc, "agent_name", "") or "") == "validator"
    ]
    validator_record = validator_records[-1] if validator_records else None
    validation_meta = (
        dict(getattr(validator_record, "validation_metadata", {}) or {})
        if validator_record is not None else {}
    )
    validation_protocol = dict(
        validation_meta.get("validation_protocol") or {}
    )
    from hacking_agent.core.validation_provenance import (
        EXECUTOR_SOURCE,
        verify_protocol,
    )
    protocol_valid, protocol_reason = verify_protocol(validation_protocol)
    strict_status = verification_status
    if strict_status == V_VERIFIED and not protocol_valid:
        strict_status = V_UNVERIFIED

    protocol_identity = (
        dict(validation_protocol.get("validator_identity") or {})
        if protocol_valid else {}
    )
    bundle = EvidenceBundle(
        id="", vuln_id=vuln_id, vuln_type=vuln_type, title=title or vuln_type,
        severity=severity, target=target, endpoint=endpoint, identity=identity,
        verification_status=strict_status,
        discovered_by=discovered_by,
        validation_schema_version=(
            2 if protocol_valid
            else int(validation_meta.get("validation_schema_version", 0) or 0)
        ),
        validator_identity=protocol_identity,
        validator_version=str(protocol_identity.get("version") or ""),
        validation_method=str(
            validation_protocol.get("validation_method") or ""
        ),
        validation_context=str(
            validation_protocol.get("validation_context") or ""
        ),
        validated_at=str(validation_protocol.get("validated_at") or ""),
        replay_count=int(validation_protocol.get("replay_count", 0) or 0),
        replay_results=list(
            validation_protocol.get("replay_results") or []
        ),
        proof_type=str(validation_protocol.get("proof_type") or ""),
        proof_metadata=dict(
            validation_protocol.get("proof_metadata") or {}
        ),
        validation_protocol=validation_protocol,
        artifacts=list(validation_protocol.get("artifacts") or []),
        validation_error=(
            str(validation_meta.get("validation_error") or "")
            or ("" if protocol_valid else protocol_reason)
        ),
        causal_signal=str(validation_protocol.get("causal_signal") or ""),
        verified_by=(protocol_identity.get("role", "") if protocol_valid else ""),
    )

    attempts = list(validation_protocol.get("observations") or [])
    replay_outcomes = {
        int(item.get("attempt_index", 0) or 0): str(item.get("outcome") or "")
        for item in (validation_protocol.get("replay_results") or [])
        if isinstance(item, dict)
    }
    if attempts:
        for attempt in attempts:
            if not isinstance(attempt, dict):
                continue
            probe_kind = str(attempt.get("probe_kind") or "")
            attempt_index = int(attempt.get("attempt_index", 0) or 0)
            outcome = replay_outcomes.get(attempt_index, "")
            exchange = SanitizedExchange.build(
                label=probe_kind or "replay",
                identity=str(attempt.get("identity") or identity),
                method=str(attempt.get("method") or "GET"),
                url=str(attempt.get("url") or endpoint),
                request=str(attempt.get("request") or ""),
                response=str(attempt.get("response") or ""),
                status_code=attempt.get("status_code"),
                notes="",
                source=EXECUTOR_SOURCE,
                context_id=str(attempt.get("context_id") or ""),
                attempt_index=attempt_index,
                capture_id=str(attempt.get("capture_id") or ""),
                request_sha256=str(attempt.get("request_sha256") or ""),
                response_sha256=str(attempt.get("response_sha256") or ""),
                extra_secrets=extra_secrets,
            )
            if attempt.get("captured_at"):
                exchange.timestamp = str(attempt["captured_at"])
            if probe_kind == "control":
                bundle.add_control(ControlTest(
                    description="Matched negative control captured by trusted executor",
                    exchange=exchange,
                    result=f"{outcome} in {exchange.capture_id}",
                ))
            elif (
                probe_kind in {"replay", "fresh_context_replay", "vary"}
                and outcome == "vulnerable_effect"
            ):
                bundle.add_test(exchange)

    first_success: Optional[Any] = None
    for poc in pocs or []:
        if getattr(poc, "verdict", "") == "success" and first_success is None:
            first_success = poc

    # Legacy PoCs remain available internally for debugging, but are only copied
    # into the bundle when there is no strict Validator transcript.
    if not attempts:
        for poc in pocs or []:
            verdict = getattr(poc, "verdict", "")
            agent = getattr(poc, "agent_name", "")
            req = getattr(poc, "request_summary", "") or getattr(poc, "payload", "")
            resp = getattr(poc, "response_excerpt", "")
            label = "control" if verdict == "failure" else "candidate"
            exchange = SanitizedExchange.build(
                label=label, identity=identity, url=endpoint,
                request=req, response=resp, extra_secrets=extra_secrets,
                notes=f"{agent} verdict={verdict}",
            )
            if verdict == "failure":
                bundle.add_control(ControlTest(
                    description=(
                        f"Legacy candidate rejection by {agent or 'unknown agent'}"
                    ),
                    exchange=exchange,
                    result=verdict or "no effect",
                ))
            else:
                bundle.add_test(exchange)

    if first_success is not None and not protocol_valid:
        payload = getattr(first_success, "payload", "")
        request = getattr(first_success, "request_summary", "") or payload
        bundle.reproduction_steps = [
            f"Using the recorded '{identity}' validation context, send the "
            f"sanitized request to `{endpoint}`.",
            f"Deliver the exact recorded payload/request: {request[:300]}",
            "Repeat the request twice and observe the payload-specific effect "
            "recorded by the Validator.",
            "Run the matched negative control and confirm that the exploit "
            "effect is absent.",
        ]
    if protocol_valid:
        bundle.reproduction_steps = [
            str(step)
            for step in (validation_protocol.get("reproduction_steps") or [])
        ]
    bundle.proof_metadata = sanitize_structure(
        bundle.proof_metadata, extra_secrets,
    )
    bundle.replay_results = sanitize_structure(
        bundle.replay_results, extra_secrets,
    )
    return bundle


def _seq_of(ident: str) -> int:
    try:
        return int(str(ident).rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return 0
