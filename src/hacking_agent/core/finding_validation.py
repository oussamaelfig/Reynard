"""Fail-closed policy for promoting candidates to customer-facing findings.

This module is the only authority for reportability.  Discovery confidence,
severity, scanner labels, HTTP status changes, and a bare ``verified`` flag are
deliberately ignored.  A finding is reportable only when a sealed
``EvidenceBundle`` proves that the independent Validator completed a controlled
replay protocol and recorded class-specific behavioural evidence.

The policy is intentionally deterministic and conservative.  Unsupported or
legacy evidence remains useful internally, but is never promoted.
"""
from __future__ import annotations

import json
import math
import re
import statistics
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse


from hacking_agent.core.validation_provenance import (
    EXECUTOR_SOURCE,
    VALIDATOR_IMPLEMENTATION,
    bundle_signing_payload,
    canonical_json,
    sha256_text,
    verify_artifact,
    verify_bundle_authenticity,
    verify_protocol,
)


REPORTABILITY_SCHEMA_VERSION = 2


class SuppressionReason(str, Enum):
    REPORTABLE = "reportable"
    MISSING_EVIDENCE_BUNDLE = "missing_evidence_bundle"
    MALFORMED_EVIDENCE = "malformed_evidence"
    INCOMPLETE_FINDING = "incomplete_finding"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    LEGACY_OR_MISSING_STATUS = "legacy_or_missing_status"
    NOT_INDEPENDENTLY_VALIDATED = "not_independently_validated"
    VALIDATOR_ERROR = "validator_error"
    MISSING_VALIDATOR_METADATA = "missing_validator_metadata"
    EVIDENCE_INTEGRITY_FAILED = "evidence_integrity_failed"
    EVIDENCE_AUTHENTICITY_FAILED = "evidence_authenticity_failed"
    UNTRUSTED_EXECUTOR_PROVENANCE = "untrusted_executor_provenance"
    ARTIFACT_VERIFICATION_FAILED = "artifact_verification_failed"
    UNBOUND_CUSTOMER_CONTENT = "unbound_customer_content"
    UNSANITIZED_EVIDENCE = "unsanitized_evidence"
    INCOMPLETE_EVIDENCE = "incomplete_evidence"
    PLACEHOLDER_EVIDENCE = "placeholder_evidence"
    MISSING_MATCHED_CONTROL = "missing_matched_control"
    INSUFFICIENT_REPLAY = "insufficient_replay"
    UNSUPPORTED_VULNERABILITY_CLASS = "unsupported_vulnerability_class"
    XSS_EXECUTION_NOT_PROVEN = "xss_execution_not_proven"
    INJECTION_ORACLE_NOT_PROVEN = "injection_oracle_not_proven"
    TIME_ORACLE_INSUFFICIENT = "time_oracle_insufficient"
    OOB_ATTRIBUTION_NOT_PROVEN = "oob_attribution_not_proven"
    AUTHORIZATION_IMPACT_NOT_PROVEN = "authorization_impact_not_proven"
    CONCRETE_EXPLOIT_EFFECT_NOT_PROVEN = "concrete_exploit_effect_not_proven"


@dataclass(frozen=True)
class ReportabilityDecision:
    reportable: bool
    reason_code: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "reportable": self.reportable,
            "reason_code": self.reason_code,
            "rationale": self.rationale,
            "policy_version": REPORTABILITY_SCHEMA_VERSION,
        }


_PLACEHOLDER_VALUES = {
    "", "-", "n/a", "na", "none", "null", "unknown", "todo", "tbd",
    "placeholder", "example", "test", "lorem ipsum", "not available",
    "unavailable", "reproduction steps unavailable",
}
_TEMPLATE_RE = re.compile(
    r"(?i)(?:insert\s+(?:proof|request|response|endpoint)\s+here|"
    r"<(?:request|response|proof|endpoint)>|\{\{[^}]+\}\}|\$\{[^}]+\})"
)
_SECRET_RE = re.compile(
    r"""(?ix)
    (?:
      ^\s*(?:authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*
      (?!\[redacted\])
      [^\r\n]+
      |
      ["']?(?:password|passwd|client_secret|access_token|refresh_token|api_key)
      ["']?\s*[:=]\s*["']?
      (?!\[redacted\])
      [^"',\s;&}]+
    )
    """,
    re.MULTILINE,
)
_ISO_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T")
_SUPPORTED_CONTEXTS = {
    "fresh_session", "isolated_browser", "controlled_replay",
    "identity_matrix", "fresh_oob_token", "clean_client",
}


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _items(value: Any, key: str) -> list[Any]:
    raw = _get(value, key, [])
    return list(raw) if isinstance(raw, (list, tuple)) else []


def _text(value: Any) -> str:
    return str(value or "").strip()


def _substantive(value: Any, *, minimum: int = 3) -> bool:
    text = _text(value)
    if len(text) < minimum or text.lower() in _PLACEHOLDER_VALUES:
        return False
    return not bool(_TEMPLATE_RE.search(text))


def _positive_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return parsed if parsed > 0 else 0


def _valid_timestamp(value: Any) -> bool:
    text = _text(value)
    if not _ISO_PREFIX_RE.match(text):
        return False
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            result = to_dict()
            return dict(result) if isinstance(result, Mapping) else {}
        except Exception:
            return {}
    return {}


def _has_unsanitized_secret(value: Any, key: str = "") -> bool:
    sensitive_keys = {
        "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
        "password", "passwd", "client_secret", "access_token",
        "refresh_token", "api_key", "apikey", "token", "session",
        "session_id", "csrf", "csrf_token", "bearer",
    }
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            item_key = str(raw_key).strip().lower()
            if (
                item_key in sensitive_keys
                and _text(item).lower() != "[redacted]"
            ):
                return True
            if _has_unsanitized_secret(item, item_key):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_has_unsanitized_secret(item, key) for item in value)
    return isinstance(value, str) and bool(_SECRET_RE.search(value))


def evidence_integrity_digest(bundle: Any) -> str:
    """Return a stable digest of the persisted, sanitized evidence payload."""
    data = bundle_signing_payload(bundle)
    data.pop("integrity_sha256", None)
    try:
        canonical = canonical_json(data)
    except (TypeError, ValueError):
        canonical = json.dumps(data, sort_keys=True, default=str)
    return sha256_text(canonical)


def _reject(reason: SuppressionReason, rationale: str) -> ReportabilityDecision:
    return ReportabilityDecision(False, reason.value, rationale)


def _complete_exchange(exchange: Any, *, endpoint: str) -> bool:
    request = _text(_get(exchange, "request"))
    response = _text(_get(exchange, "response"))
    url = _text(_get(exchange, "url")) or endpoint
    method = _text(_get(exchange, "method")).upper()
    status_code = _get(exchange, "status_code")
    status_valid = (
        isinstance(status_code, int)
        and not isinstance(status_code, bool)
        and 100 <= status_code <= 599
    )
    return (
        _substantive(request, minimum=5)
        and _substantive(response, minimum=2)
        and _substantive(url, minimum=4)
        and url.rstrip("/") == endpoint.rstrip("/")
        and method in {
            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
            "CONNECT", "TRACE",
        }
        and status_valid
        and _substantive(_get(exchange, "identity"), minimum=3)
        and _substantive(_get(exchange, "context_id"), minimum=4)
        and _substantive(_get(exchange, "capture_id"), minimum=12)
        and _positive_int(_get(exchange, "attempt_index")) > 0
        and _valid_timestamp(_get(exchange, "timestamp"))
        and _text(_get(exchange, "source")) == EXECUTOR_SOURCE
        and _text(_get(exchange, "request_sha256")) == sha256_text(request)
        and _text(_get(exchange, "response_sha256")) == sha256_text(response)
    )


def _trusted_protocol_proof(
    bundle: Any,
    proof_type: str,
    proof: Mapping[str, Any],
    *,
    allowed: set[str],
    required_artifact_kind: str = "",
    allow_any_artifact_kind: bool = False,
) -> bool:
    """Match class proof exclusively to the signed protocol derivation."""
    protocol = _get(bundle, "validation_protocol")
    if not isinstance(protocol, Mapping) or proof_type not in allowed:
        return False
    if proof_type != _text(protocol.get("proof_type")):
        return False
    protocol_proof = protocol.get("proof_metadata")
    if not isinstance(protocol_proof, Mapping):
        return False
    try:
        if canonical_json(dict(proof)) != canonical_json(dict(protocol_proof)):
            return False
    except (TypeError, ValueError):
        return False

    results = list(protocol.get("replay_results") or [])
    positives = [
        item for item in results
        if isinstance(item, Mapping)
        and item.get("probe_kind") in {"replay", "fresh_context_replay"}
        and item.get("outcome") == "vulnerable_effect"
    ]
    controls = [
        item for item in results
        if isinstance(item, Mapping)
        and item.get("probe_kind") == "control"
        and item.get("outcome") == "control_no_effect"
    ]
    fingerprint = _text(proof.get("effect_fingerprint"))
    if (
        len(positives) != 2
        or len(controls) != 1
        or len(fingerprint) != 64
        or any(item.get("source") != EXECUTOR_SOURCE for item in results)
        or any(item.get("effect_kind") != proof_type for item in positives)
        or any(item.get("effect_fingerprint") != fingerprint for item in positives)
        or controls[0].get("effect_kind")
        or list(proof.get("positive_capture_ids") or [])
        != [item.get("capture_id") for item in positives]
        or proof.get("control_capture_id") != controls[0].get("capture_id")
    ):
        return False

    artifacts = _items(bundle, "artifacts")
    artifact_ids = {
        _text(_get(item, "artifact_id")) for item in artifacts
    }
    if set(proof.get("artifact_ids") or []) != artifact_ids:
        return False
    if required_artifact_kind:
        if allow_any_artifact_kind:
            if not artifacts:
                return False
        elif not any(
            _text(_get(item, "kind")) == required_artifact_kind
            for item in artifacts
        ):
            return False
    return True


def _proof_xss(bundle: Any, proof_type: str,
               proof: Mapping[str, Any]) -> ReportabilityDecision | None:
    if not _trusted_protocol_proof(
        bundle,
        proof_type,
        proof,
        allowed={"browser_execution"},
        required_artifact_kind="browser_execution_trace",
    ):
        return _reject(
            SuppressionReason.XSS_EXECUTION_NOT_PROVEN,
            "XSS requires two executor-captured browser executions, a matched "
            "control, and a verified browser trace artifact.",
        )
    return None


def _number_list(value: Any) -> list[float]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[float] = []
    for item in value:
        try:
            number = float(item)
        except (TypeError, ValueError):
            return []
        if not math.isfinite(number) or number < 0:
            return []
        out.append(number)
    return out


def _proof_time_oracle(proof: Mapping[str, Any]) -> ReportabilityDecision | None:
    baseline = _number_list(proof.get("baseline_ms"))
    induced = _number_list(proof.get("payload_ms"))
    control = _number_list(proof.get("control_ms"))
    if len(baseline) < 3 or len(induced) < 2 or len(control) < 2:
        return _reject(
            SuppressionReason.TIME_ORACLE_INSUFFICIENT,
            "Time-based proof needs at least three baseline samples, two "
            "payload samples, and two matched-control samples.",
        )
    base_median = statistics.median(baseline)
    control_median = statistics.median(control)
    combined_normal = baseline + control
    normal_median = statistics.median(combined_normal)
    mad = statistics.median(abs(x - normal_median) for x in combined_normal)
    threshold = max(1000.0, 6.0 * max(mad, 1.0))
    if (
        abs(base_median - control_median) > threshold / 2
        or statistics.median(induced) - normal_median < threshold
        or any(sample - normal_median < threshold for sample in induced)
    ):
        return _reject(
            SuppressionReason.TIME_ORACLE_INSUFFICIENT,
            "Observed latency does not exceed baseline/control jitter "
            "consistently enough to establish a payload-specific oracle.",
        )
    return None


def _proof_injection(proof_type: str,
                     proof: Mapping[str, Any],
                     bundle: Any) -> ReportabilityDecision | None:
    valid = _trusted_protocol_proof(
        bundle,
        proof_type,
        proof,
        allowed={
            "boolean_oracle", "data_extraction", "template_evaluation",
            "command_output", "time_oracle",
        },
    )
    if not valid:
        return _reject(
            SuppressionReason.INJECTION_ORACLE_NOT_PROVEN,
            "Injection proof must be an executor-derived, signed effect "
            "reproduced twice and absent from a separately captured control.",
        )
    return None


def _proof_oob(bundle: Any, proof_type: str,
               proof: Mapping[str, Any]) -> ReportabilityDecision | None:
    valid = _trusted_protocol_proof(
        bundle,
        proof_type,
        proof,
        allowed={"direct_sensitive_resource", "oob_callback"},
    )
    if not valid:
        return _reject(
            SuppressionReason.OOB_ATTRIBUTION_NOT_PROVEN,
            "OOB proof requires a signed executor observation with a fresh "
            "attributable interaction or direct sensitive-resource effect.",
        )
    return None


def _proof_authz(bundle: Any, proof_type: str,
                 proof: Mapping[str, Any]) -> ReportabilityDecision | None:
    valid = _trusted_protocol_proof(
        bundle,
        proof_type,
        proof,
        allowed={"unauthorized_access", "unauthorized_action"},
    )
    if not valid:
        return _reject(
            SuppressionReason.AUTHORIZATION_IMPACT_NOT_PROVEN,
            "Authorization findings require an executor-derived identity/control "
            "effect; model-authored ownership or impact claims are insufficient.",
        )
    return None


def _proof_concrete_effect(vuln_class: str, proof_type: str,
                           proof: Mapping[str, Any],
                           bundle: Any) -> ReportabilityDecision | None:
    valid = _trusted_protocol_proof(
        bundle,
        proof_type,
        proof,
        allowed={"concrete_exploit_effect"},
        required_artifact_kind="validation_trace",
        allow_any_artifact_kind=True,
    )
    if not valid:
        return _reject(
            SuppressionReason.CONCRETE_EXPLOIT_EFFECT_NOT_PROVEN,
            "This vulnerability class requires a signed executor effect, "
            "matched control, and verified content-addressed trace.",
        )
    return None


def _classify(vuln_type: str) -> str:
    text = vuln_type.lower()
    if any(token in text for token in ("xss", "cross-site scripting", "dom-based")):
        return "xss"
    if any(token in text for token in (
        "sql injection", "sqli", "ssti", "template injection",
        "command injection", "os command", "shell injection",
    )):
        return "injection"
    if any(token in text for token in (
        "ssrf", "server-side request forgery", "xxe", "external entity",
        "blind injection",
    )):
        return "oob"
    if "oauth" in text:
        return "oauth"
    if any(token in text for token in (
        "idor", "bola", "bfla", "authorization", "access control", "authz",
    )):
        return "authz"
    if any(token in text for token in ("file upload", "upload")):
        return "upload"
    if any(token in text for token in ("path traversal", "directory traversal")):
        return "path"
    if "cache" in text:
        return "cache"
    if "race" in text:
        return "race"
    if any(token in text for token in ("business logic", "workflow bypass")):
        return "business"
    return ""


_CUSTOMER_PROJECTION_FIELDS = (
    "finding_id", "vuln_id", "title", "vuln_type", "severity", "target",
    "endpoint", "parameter", "description", "impact", "remediation", "cwe",
    "cvss_vector", "cvss_score", "reproduction_steps", "references",
    "evidence", "engagement_id",
)


def _customer_projection_from_finding(finding: Any) -> dict[str, Any]:
    projection: dict[str, Any] = {}
    list_fields = {"reproduction_steps", "references", "evidence"}
    for key in _CUSTOMER_PROJECTION_FIELDS:
        value = _get(finding, key, [] if key in list_fields else "")
        if key in list_fields:
            value = list(value) if isinstance(value, (list, tuple)) else []
        projection[key] = value
    return projection


def _canonical_equal(left: Any, right: Any) -> bool:
    try:
        return canonical_json(left) == canonical_json(right)
    except (TypeError, ValueError):
        return False


def _evaluate_reportability(
    finding: Any = None,
    evidence_bundle: Any = None,
    *,
    expected_run_id: str = "",
    expected_engagement_id: str = "",
) -> ReportabilityDecision:
    """Evaluate a candidate against the complete fail-closed report gate.

    ``verified=True`` and legacy status fields have no authority.  When a
    finding is supplied it must embed (or be paired with) the same sealed bundle
    that will be exported, allowing every API/export boundary to re-run this
    predicate independently.
    """
    bundle = evidence_bundle
    if bundle is None and finding is not None:
        bundle = _get(finding, "evidence_bundle")
    if bundle is None:
        return _reject(
            SuppressionReason.MISSING_EVIDENCE_BUNDLE,
            "No structured EvidenceBundle accompanies this candidate.",
        )
    if isinstance(bundle, Mapping) and not bundle:
        return _reject(
            SuppressionReason.MISSING_EVIDENCE_BUNDLE,
            "No structured EvidenceBundle accompanies this candidate.",
        )
    if not _as_mapping(bundle):
        return _reject(
            SuppressionReason.MALFORMED_EVIDENCE,
            "The evidence bundle is malformed or cannot be serialized.",
        )

    validation_error = _text(_get(bundle, "validation_error"))
    if validation_error:
        return _reject(
            SuppressionReason.VALIDATOR_ERROR,
            "Independent validation did not complete successfully.",
        )

    if finding is not None:
        # A boolean `verified` or legacy `status=verified` is intentionally
        # insufficient at serialization boundaries.
        if _text(_get(finding, "verification_status")) != "verified":
            return _reject(
                SuppressionReason.LEGACY_OR_MISSING_STATUS,
                "Finding lacks the explicit strict verification status.",
            )

    schema_version = _get(bundle, "validation_schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != REPORTABILITY_SCHEMA_VERSION
        or _text(_get(bundle, "verification_status")) != "verified"
    ):
        return _reject(
            SuppressionReason.LEGACY_OR_MISSING_STATUS,
            "Missing, unknown, or legacy verification state fails closed.",
        )

    protocol = _get(bundle, "validation_protocol")
    protocol_ok, protocol_reason = verify_protocol(protocol)
    if not protocol_ok:
        return _reject(
            SuppressionReason.UNTRUSTED_EXECUTOR_PROVENANCE,
            f"Trusted executor protocol failed verification: {protocol_reason}.",
        )
    validator_identity = _get(bundle, "validator_identity")
    protocol_identity = _get(protocol, "validator_identity")
    discovered_by = _text(_get(bundle, "discovered_by")).lower()
    if (
        not isinstance(validator_identity, Mapping)
        or not isinstance(protocol_identity, Mapping)
        or not _canonical_equal(
            dict(validator_identity), dict(protocol_identity),
        )
        or validator_identity.get("role") != "validator"
        or validator_identity.get("implementation") != VALIDATOR_IMPLEMENTATION
        or not _substantive(validator_identity.get("instance_id"), minimum=12)
        or not _substantive(discovered_by)
        or discovered_by == "validator"
        or _text(_get(bundle, "verified_by")).lower() != "validator"
    ):
        return _reject(
            SuppressionReason.NOT_INDEPENDENTLY_VALIDATED,
            "The discovering agent cannot independently validate its own claim.",
        )
    if not (
        _text(_get(bundle, "validator_version"))
        == _text(validator_identity.get("version"))
        and _substantive(_get(bundle, "validation_method"), minimum=5)
        and _valid_timestamp(_get(bundle, "validated_at"))
        and _text(_get(bundle, "validation_context")) in _SUPPORTED_CONTEXTS
        and _text(_get(bundle, "validation_method"))
        == _text(_get(protocol, "validation_method"))
        and _text(_get(bundle, "validation_context"))
        == _text(_get(protocol, "validation_context"))
        and _text(_get(bundle, "validated_at"))
        == _text(_get(protocol, "validated_at"))
    ):
        return _reject(
            SuppressionReason.MISSING_VALIDATOR_METADATA,
            "Validator identity/version/method, time, and controlled context "
            "must all be recorded.",
        )

    expected_digest = _text(_get(bundle, "integrity_sha256"))
    if (
        len(expected_digest) != 64
        or not hmac_compare(expected_digest, evidence_integrity_digest(bundle))
    ):
        return _reject(
            SuppressionReason.EVIDENCE_INTEGRITY_FAILED,
            "The evidence seal is missing or does not match the bundle.",
        )
    authentic, authenticity_reason = verify_bundle_authenticity(
        bundle,
        expected_run_id=expected_run_id,
        expected_engagement_id=expected_engagement_id,
    )
    if not authentic:
        return _reject(
            SuppressionReason.EVIDENCE_AUTHENTICITY_FAILED,
            (
                "Control-plane authenticity verification failed: "
                f"{authenticity_reason}."
            ),
        )
    if _has_unsanitized_secret(_as_mapping(bundle)):
        return _reject(
            SuppressionReason.UNSANITIZED_EVIDENCE,
            "Potential credential or token material remains in persisted evidence.",
        )

    required_text = (
        "id", "finding_id", "vuln_id", "title", "vuln_type", "severity",
        "target", "endpoint", "identity", "created_at", "updated_at",
        "causal_signal", "discovered_by",
    )
    if any(not _substantive(_get(bundle, key), minimum=3) for key in required_text):
        return _reject(
            SuppressionReason.INCOMPLETE_EVIDENCE,
            "Bundle metadata, endpoint/asset, identity context, and causal "
            "signal must be complete.",
        )
    if _text(_get(bundle, "severity")).lower() not in {
        "critical", "high", "medium", "low", "info",
    }:
        return _reject(
            SuppressionReason.INCOMPLETE_EVIDENCE,
            "Evidence severity is missing or outside the supported vocabulary.",
        )
    if not (
        _valid_timestamp(_get(bundle, "created_at"))
        and _valid_timestamp(_get(bundle, "updated_at"))
    ):
        return _reject(
            SuppressionReason.INCOMPLETE_EVIDENCE,
            "Evidence timestamps are missing or malformed.",
        )
    endpoint_url = urlparse(_text(_get(bundle, "endpoint")))
    target_url = urlparse(_text(_get(bundle, "target")))
    if (
        not endpoint_url.scheme
        or not endpoint_url.netloc
        or not target_url.scheme
        or not target_url.netloc
        or endpoint_url.hostname != target_url.hostname
    ):
        return _reject(
            SuppressionReason.EVIDENCE_MISMATCH,
            "The affected endpoint is not bound to the authenticated target asset.",
        )

    run_id = _text(_get(protocol, "run_id"))
    engagement_id = _text(_get(protocol, "engagement_id"))
    instance_id = _text(validator_identity.get("instance_id"))
    artifacts = _items(bundle, "artifacts")
    if not _canonical_equal(
        artifacts, list(_get(protocol, "artifacts") or []),
    ):
        return _reject(
            SuppressionReason.ARTIFACT_VERIFICATION_FAILED,
            "Artifact manifests do not match the authenticated protocol.",
        )
    for artifact in artifacts:
        artifact_ok, artifact_reason = verify_artifact(
            artifact,
            expected_run_id=run_id,
            expected_engagement_id=engagement_id,
            expected_validator_instance_id=instance_id,
        )
        if not artifact_ok:
            return _reject(
                SuppressionReason.ARTIFACT_VERIFICATION_FAILED,
                f"Artifact verification failed: {artifact_reason}.",
            )
    if (
        _text(_get(bundle, "notes"))
        or _items(bundle, "oob_interactions")
        or _items(bundle, "screenshots")
    ):
        return _reject(
            SuppressionReason.UNBOUND_CUSTOMER_CONTENT,
            "Free-form notes and legacy artifact lists are internal-only; "
            "customer evidence must come from the authenticated protocol.",
        )

    customer_projection = _get(bundle, "customer_projection")
    if (
        not isinstance(customer_projection, Mapping)
        or set(customer_projection) != set(_CUSTOMER_PROJECTION_FIELDS)
    ):
        return _reject(
            SuppressionReason.UNBOUND_CUSTOMER_CONTENT,
            "The complete customer finding projection is not authenticity-bound.",
        )
    bundle_projection = {
        "finding_id": _get(bundle, "finding_id"),
        "vuln_id": _get(bundle, "vuln_id"),
        "title": _get(bundle, "title"),
        "vuln_type": _get(bundle, "vuln_type"),
        "severity": _get(bundle, "severity"),
        "target": _get(bundle, "target"),
        "endpoint": _get(bundle, "endpoint"),
        "reproduction_steps": _items(bundle, "reproduction_steps"),
        "engagement_id": engagement_id,
    }
    if any(
        not _canonical_equal(
            customer_projection.get(key), value,
        )
        for key, value in bundle_projection.items()
    ):
        return _reject(
            SuppressionReason.UNBOUND_CUSTOMER_CONTENT,
            "Customer projection metadata differs from authenticated evidence.",
        )

    if finding is not None:
        finding_fields = {
            "title": 3,
            "vuln_type": 3,
            "endpoint": 5,
            "description": 5,
            "impact": 5,
            "remediation": 5,
        }
        if (
            not _substantive(_get(finding, "finding_id"))
            or any(
                not _substantive(_get(finding, key), minimum=minimum)
                for key, minimum in finding_fields.items()
            )
            or _text(_get(finding, "severity")).lower() not in {
                "critical", "high", "medium", "low", "info",
            }
        ):
            return _reject(
                SuppressionReason.INCOMPLETE_FINDING,
                "The customer finding projection is incomplete.",
            )
        if not _canonical_equal(
            _customer_projection_from_finding(finding),
            dict(customer_projection),
        ):
            return _reject(
                SuppressionReason.EVIDENCE_MISMATCH,
                "Customer-visible finding content differs from its authenticated "
                "evidence projection.",
            )

    reproduction = _items(bundle, "reproduction_steps")
    if (
        len(reproduction) < 2
        or any(not _substantive(step, minimum=8) for step in reproduction)
    ):
        return _reject(
            SuppressionReason.PLACEHOLDER_EVIDENCE,
            "Exact, non-template reproduction steps are required.",
        )

    endpoint = _text(_get(bundle, "endpoint"))
    exchanges = _items(bundle, "test_exchanges")
    replay_exchanges = [
        exchange for exchange in exchanges
        if _text(_get(exchange, "label")) in {
            "replay", "fresh_context_replay",
        }
        and _text(_get(exchange, "source")) == EXECUTOR_SOURCE
    ]
    if len(replay_exchanges) < 2 or any(
        not _complete_exchange(exchange, endpoint=endpoint)
        for exchange in replay_exchanges
    ):
        return _reject(
            SuppressionReason.INCOMPLETE_EVIDENCE,
            "At least two complete trusted-executor replay exchanges are "
            "required; prose-only evidence is insufficient.",
        )

    controls = _items(bundle, "control_tests")
    if not controls:
        return _reject(
            SuppressionReason.MISSING_MATCHED_CONTROL,
            "No matched negative/control test was recorded.",
        )
    for control in controls:
        if not (
            _substantive(_get(control, "description"), minimum=8)
            and _substantive(_get(control, "result"), minimum=3)
            and _complete_exchange(_get(control, "exchange"), endpoint=endpoint)
            and _text(_get(_get(control, "exchange"), "source"))
            == EXECUTOR_SOURCE
        ):
            return _reject(
                SuppressionReason.MISSING_MATCHED_CONTROL,
                "Matched controls must include complete request/response evidence.",
            )

    replay_count = _get(bundle, "replay_count")
    replay_results = _items(bundle, "replay_results")
    try:
        replay_count_int = int(replay_count)
    except (TypeError, ValueError):
        replay_count_int = 0
    positive_replays = [
        result for result in replay_results
        if _text(_get(result, "probe_kind")) in {"replay", "fresh_context_replay"}
        and _text(_get(result, "outcome")) == "vulnerable_effect"
        and _valid_timestamp(_get(result, "timestamp"))
        and _substantive(_get(result, "context_id"), minimum=4)
        and _text(_get(result, "source")) == EXECUTOR_SOURCE
        and _substantive(_get(result, "capture_id"), minimum=12)
        and len(_text(_get(result, "effect_fingerprint"))) == 64
    ]
    negative_controls = [
        result for result in replay_results
        if _text(_get(result, "probe_kind")) == "control"
        and _text(_get(result, "outcome")) == "control_no_effect"
        and _valid_timestamp(_get(result, "timestamp"))
        and _substantive(_get(result, "context_id"), minimum=4)
        and _text(_get(result, "source")) == EXECUTOR_SOURCE
        and _substantive(_get(result, "capture_id"), minimum=12)
        and not _text(_get(result, "effect_kind"))
        and not _text(_get(result, "effect_fingerprint"))
    ]
    attempt_ids = {
        _positive_int(_get(result, "attempt_index"))
        for result in positive_replays + negative_controls
    }
    exchange_attempt_ids = {
        _positive_int(_get(exchange, "attempt_index"))
        for exchange in replay_exchanges
    }
    control_attempt_ids = {
        _positive_int(_get(_get(control, "exchange"), "attempt_index"))
        for control in controls
    }
    positive_contexts = {
        _text(_get(result, "context_id")) for result in positive_replays
    }
    exchanges_by_attempt = {
        _positive_int(_get(exchange, "attempt_index")): exchange
        for exchange in replay_exchanges
    }
    controls_by_attempt = {
        _positive_int(_get(_get(control, "exchange"), "attempt_index")): control
        for control in controls
    }
    protocol_observations = {
        _text(_get(item, "capture_id")): item
        for item in _items(protocol, "observations")
    }
    correlated = True
    for result in positive_replays:
        exchange = exchanges_by_attempt.get(
            _positive_int(_get(result, "attempt_index"))
        )
        observation = protocol_observations.get(
            _text(_get(result, "capture_id"))
        )
        correlated = correlated and bool(observation) and all(
            _text(_get(exchange, key)) == _text(_get(observation, key))
            for key in (
                "capture_id", "request", "response", "request_sha256",
                "response_sha256", "context_id",
            )
        )
    for result in negative_controls:
        control = controls_by_attempt.get(
            _positive_int(_get(result, "attempt_index"))
        )
        exchange = _get(control, "exchange")
        observation = protocol_observations.get(
            _text(_get(result, "capture_id"))
        )
        correlated = correlated and bool(observation) and all(
            _text(_get(exchange, key)) == _text(_get(observation, key))
            for key in (
                "capture_id", "request", "response", "request_sha256",
                "response_sha256", "context_id",
            )
        )
    if (
        replay_count_int != 2
        or len(positive_replays) != 2
        or len(negative_controls) != 1
        or len(attempt_ids) != 3
        or 0 in attempt_ids
        or len(positive_contexts) != 2
        or not correlated
        or not _canonical_equal(
            replay_results, list(_get(protocol, "replay_results") or []),
        )
        or not {
            _positive_int(_get(result, "attempt_index"))
            for result in positive_replays
        }.issubset(exchange_attempt_ids)
        or not {
            _positive_int(_get(result, "attempt_index"))
            for result in negative_controls
        }.issubset(control_attempt_ids)
    ):
        return _reject(
            SuppressionReason.INSUFFICIENT_REPLAY,
            "Independent validation requires two positive replays and a "
            "separate negative control with auditable results.",
        )

    vuln_type = _text(_get(bundle, "vuln_type"))
    vuln_class = _classify(vuln_type)
    if not vuln_class:
        return _reject(
            SuppressionReason.UNSUPPORTED_VULNERABILITY_CLASS,
            "No deterministic proof policy is defined for this vulnerability class.",
        )
    proof_type = _text(_get(bundle, "proof_type"))
    proof = _get(bundle, "proof_metadata")
    if not isinstance(proof, Mapping):
        proof = {}

    if vuln_class == "xss":
        rejected = _proof_xss(bundle, proof_type, proof)
    elif vuln_class == "injection":
        rejected = _proof_injection(proof_type, proof, bundle)
    elif vuln_class == "oob":
        rejected = _proof_oob(bundle, proof_type, proof)
    elif vuln_class == "authz":
        rejected = _proof_authz(bundle, proof_type, proof)
    else:
        rejected = _proof_concrete_effect(vuln_class, proof_type, proof, bundle)
    if rejected is not None:
        return rejected

    return ReportabilityDecision(
        True,
        SuppressionReason.REPORTABLE.value,
        "Independent replay, matched controls, complete sealed evidence, and "
        "vulnerability-specific behavioural proof all passed.",
    )


def evaluate_reportability(
    finding: Any = None,
    evidence_bundle: Any = None,
    *,
    expected_run_id: str = "",
    expected_engagement_id: str = "",
) -> ReportabilityDecision:
    """Return a structured, fail-closed decision for every possible input."""
    try:
        return _evaluate_reportability(
            finding,
            evidence_bundle,
            expected_run_id=expected_run_id,
            expected_engagement_id=expected_engagement_id,
        )
    except Exception:
        return _reject(
            SuppressionReason.MALFORMED_EVIDENCE,
            "Unexpected policy evaluation error; candidate suppressed.",
        )


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time digest comparison without importing policy callers."""
    import hmac
    return hmac.compare_digest(left, right)


def is_reportable(
    finding: Any = None,
    evidence_bundle: Any = None,
    *,
    expected_run_id: str = "",
    expected_engagement_id: str = "",
) -> bool:
    """The single boolean predicate customer-facing code must use."""
    try:
        return evaluate_reportability(
            finding,
            evidence_bundle,
            expected_run_id=expected_run_id,
            expected_engagement_id=expected_engagement_id,
        ).reportable
    except Exception:
        # Policy errors are suppression, never promotion.
        return False


def partition_reportable(
    findings: Iterable[Any],
    *,
    expected_run_id: str = "",
    expected_engagement_id: str = "",
) -> tuple[list[Any], list[tuple[Any, ReportabilityDecision]]]:
    confirmed: list[Any] = []
    suppressed: list[tuple[Any, ReportabilityDecision]] = []
    for finding in findings:
        try:
            decision = evaluate_reportability(
                finding,
                expected_run_id=expected_run_id,
                expected_engagement_id=expected_engagement_id,
            )
        except Exception:
            decision = _reject(
                SuppressionReason.MALFORMED_EVIDENCE,
                "Unexpected policy evaluation error; candidate suppressed.",
            )
        if decision.reportable:
            confirmed.append(finding)
        else:
            suppressed.append((finding, decision))
    return confirmed, suppressed


def emit_suppression(finding: Any, decision: ReportabilityDecision) -> None:
    """Emit a secret-free operator event for a rejected candidate."""
    if decision.reportable:
        return
    try:
        from hacking_agent.core.evidence_bundle import sanitize_text
        from hacking_agent.core.events import emit
        payload = {
            "finding_id": sanitize_text(
                _text(_get(finding, "finding_id"))
                or _text(_get(finding, "vuln_id"))
                or _text(_get(finding, "id"))
            )[:160],
            "title": sanitize_text(_text(_get(finding, "title")))[:160],
            "reason_code": decision.reason_code,
        }
        emit("finding_suppressed", payload)
    except Exception:
        # Observability must never alter gate behaviour.
        pass
