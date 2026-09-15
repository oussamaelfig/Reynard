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

    @classmethod
    def build(cls, *, label: str = "test", identity: str = "", method: str = "GET",
              url: str = "", request: str = "", response: str = "",
              status_code: Optional[int] = None, notes: str = "",
              extra_secrets: tuple[str, ...] = ()) -> "SanitizedExchange":
        return cls(
            label=label, identity=identity, method=method, url=url,
            request=sanitize_text(request, extra_secrets),
            response=sanitize_text(response, extra_secrets),
            status_code=status_code, notes=notes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label, "identity": self.identity, "method": self.method,
            "url": self.url, "request": self.request, "response": self.response,
            "status_code": self.status_code, "timestamp": self.timestamp,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SanitizedExchange":
        return cls(label=d.get("label", "test"), identity=d.get("identity", ""),
                   method=d.get("method", "GET"), url=d.get("url", ""),
                   request=d.get("request", ""), response=d.get("response", ""),
                   status_code=d.get("status_code"),
                   timestamp=d.get("timestamp") or _now(), notes=d.get("notes", ""))


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

    # ---- mutation ----
    def add_test(self, exchange: SanitizedExchange) -> None:
        self.test_exchanges.append(exchange)
        self.updated_at = _now()

    def add_control(self, control: ControlTest) -> None:
        self.control_tests.append(control)
        self.updated_at = _now()

    def add_oob(self, interaction: str) -> None:
        if interaction and interaction not in self.oob_interactions:
            self.oob_interactions.append(interaction)
            self.updated_at = _now()

    def add_screenshot(self, path: str) -> None:
        if path and path not in self.screenshots:
            self.screenshots.append(path)
            self.updated_at = _now()

    def set_verification(self, status: str, *, verified_by: str = "",
                         causal_signal: str = "") -> None:
        if status in (V_UNVERIFIED, V_VERIFIED, V_REFUTED, V_NEEDS_REVIEW):
            self.verification_status = status
        if verified_by:
            self.verified_by = verified_by
        if causal_signal:
            self.causal_signal = causal_signal
        self.updated_at = _now()

    @property
    def is_verified(self) -> bool:
        return self.verification_status == V_VERIFIED

    def has_concrete_evidence(self) -> bool:
        """True when the bundle carries at least one concrete behavioural signal
        that could justify a verified status (a control-vs-test comparison, an
        OOB interaction, a browser screenshot, or a stated causal signal)."""
        return bool(self.control_tests or self.oob_interactions
                    or self.screenshots or self.causal_signal.strip())

    # ---- rendering ----
    def render_markdown(self) -> str:
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
            return [b for b in self._bundles.values() if b.is_verified]

    def render_markdown(self, verified_only: bool = False) -> str:
        with self._lock:
            bundles = [b for b in self._bundles.values()
                       if (not verified_only or b.is_verified)]
        if not bundles:
            return ""
        return "\n\n".join(b.render_markdown() for b in bundles)

    # ---- persistence ----
    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {"bundles": [b.to_dict() for b in self._bundles.values()]}

    def load_dict(self, d: dict[str, Any]) -> int:
        n = 0
        for bd in (d or {}).get("bundles", []):
            try:
                b = EvidenceBundle.from_dict(bd)
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

    The success PoC(s) become test exchanges; validator refutations / neutered
    ('COUNTER'/'REFUTED') attempts become control tests. Reproduction steps are
    synthesized from the first successful exchange."""
    bundle = EvidenceBundle(
        id="", vuln_id=vuln_id, vuln_type=vuln_type, title=title or vuln_type,
        severity=severity, target=target, endpoint=endpoint, identity=identity,
        verification_status=verification_status,
    )
    first_success: Optional[Any] = None
    for poc in pocs or []:
        verdict = getattr(poc, "verdict", "")
        agent = getattr(poc, "agent_name", "")
        req = getattr(poc, "request_summary", "") or getattr(poc, "payload", "")
        resp = getattr(poc, "response_excerpt", "")
        is_control = (verdict == "failure"
                      or req.startswith("COUNTER:") or req.startswith("REFUTED:"))
        if is_control:
            bundle.add_control(ControlTest(
                description=f"Control ({agent or 'validator'}): neutered/'{verdict}' attempt",
                exchange=SanitizedExchange.build(
                    label="control", identity=identity, request=req, response=resp,
                    extra_secrets=extra_secrets),
                result=verdict or "no effect",
            ))
        else:
            if verdict == "success" and first_success is None:
                first_success = poc
            bundle.add_test(SanitizedExchange.build(
                label="test", identity=identity, request=req, response=resp,
                extra_secrets=extra_secrets,
                notes=f"{agent} verdict={verdict}"))
    if first_success is not None:
        payload = getattr(first_success, "payload", "")
        bundle.reproduction_steps = [
            f"As identity '{identity or 'the tester'}', send the request shown "
            f"in the test exchange below to `{endpoint or target}`.",
            (f"Payload: {payload}" if payload else "Use the payload in the exchange."),
            "Observe the response matches the recorded proof (and differs from "
            "the control).",
        ]
    return bundle


def _seq_of(ident: str) -> int:
    try:
        return int(str(ident).rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return 0
