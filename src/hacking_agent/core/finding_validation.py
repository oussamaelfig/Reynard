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

import hashlib
import json
import math
import re
import statistics
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Mapping


REPORTABILITY_SCHEMA_VERSION = 1


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
    data = _as_mapping(bundle)
    data.pop("integrity_sha256", None)
    # Suppression diagnostics are mutable policy output, not evidence.
    data.pop("suppression_reason_code", None)
    data.pop("suppression_rationale", None)
    canonical = json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
        and _positive_int(_get(exchange, "attempt_index")) > 0
        and _valid_timestamp(_get(exchange, "timestamp"))
    )


_ARTIFACT_RE = re.compile(
    r"(?i)(?:^|[/\\])[^/\\]+\.(?:png|jpe?g|webp|gif|har|json|zip|pdf)$"
)


def _artifact_reference(value: Any) -> bool:
    text = _text(value)
    return _substantive(text, minimum=5) and bool(_ARTIFACT_RE.search(text))


def _proof_xss(bundle: Any, proof_type: str,
               proof: Mapping[str, Any]) -> ReportabilityDecision | None:
    canary = _text(proof.get("canary"))
    artifact = _text(proof.get("browser_artifact"))
    screenshots = _items(bundle, "screenshots")
    signal = _text(_get(bundle, "causal_signal"))
    context = _text(proof.get("execution_context"))
    if (
        proof_type != "browser_execution"
        or proof.get("executed") is not True
        or not _substantive(canary, minimum=6)
        or canary not in signal
        or context not in {"dom", "script", "event_handler", "javascript_url"}
        or not (any(_artifact_reference(s) for s in screenshots)
                or _artifact_reference(artifact))
    ):
        return _reject(
            SuppressionReason.XSS_EXECUTION_NOT_PROVEN,
            "XSS requires a correlated canary executed in a browser context "
            "and a browser artifact; reflection alone is not proof.",
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
                     proof: Mapping[str, Any]) -> ReportabilityDecision | None:
    if proof_type == "time_oracle":
        return _proof_time_oracle(proof)
    if proof_type == "boolean_oracle":
        valid = (
            proof.get("effect_observed") is True
            and proof.get("control_effect_observed") is False
            and _substantive(proof.get("oracle"), minimum=5)
            and _substantive(proof.get("payload_effect"), minimum=3)
            and _substantive(proof.get("control_effect"), minimum=3)
            and _text(proof.get("payload_effect"))
            != _text(proof.get("control_effect"))
        )
    elif proof_type == "data_extraction":
        valid = (
            _substantive(proof.get("extracted_marker"), minimum=5)
            and proof.get("control_absent") is True
        )
    elif proof_type == "template_evaluation":
        valid = (
            _substantive(proof.get("expression"), minimum=3)
            and _substantive(proof.get("evaluated_result"), minimum=2)
            and proof.get("control_unevaluated") is True
        )
    elif proof_type == "command_output":
        canary = _text(proof.get("canary"))
        valid = (
            _substantive(canary, minimum=6)
            and canary in _text(proof.get("observed_output"))
            and proof.get("control_absent") is True
        )
    else:
        valid = False
    if not valid:
        return _reject(
            SuppressionReason.INJECTION_ORACLE_NOT_PROVEN,
            "Injection proof must establish a payload-specific oracle against "
            "a matched negative control; generic errors or text changes fail.",
        )
    return None


def _proof_oob(bundle: Any, proof_type: str,
               proof: Mapping[str, Any]) -> ReportabilityDecision | None:
    if proof_type == "direct_sensitive_resource":
        marker = _text(proof.get("resource_marker"))
        valid = (
            _substantive(marker, minimum=5)
            and marker in _text(proof.get("observed_response"))
            and proof.get("control_absent") is True
        )
    elif proof_type == "oob_callback":
        correlation = _text(proof.get("correlation_id"))
        protocol = _text(proof.get("interaction_protocol")).lower()
        interactions = " ".join(_text(v) for v in _items(bundle, "oob_interactions"))
        valid = (
            _substantive(correlation, minimum=8)
            and correlation in interactions
            and proof.get("attributable") is True
            and proof.get("fresh_interaction") is True
            and protocol in {"http", "https", "smtp", "ldap"}
            and _valid_timestamp(proof.get("interaction_timestamp"))
        )
    else:
        valid = False
    if not valid:
        return _reject(
            SuppressionReason.OOB_ATTRIBUTION_NOT_PROVEN,
            "Blind SSRF/XXE proof needs a fresh attributable non-DNS callback "
            "with correlation, or direct sensitive-resource evidence.",
        )
    return None


def _proof_authz(bundle: Any, proof_type: str,
                 proof: Mapping[str, Any]) -> ReportabilityDecision | None:
    attacker = _text(proof.get("attacker_identity"))
    owner = _text(proof.get("owner_identity"))
    resource = _text(proof.get("resource_id"))
    test_identities = {
        _text(_get(exchange, "identity"))
        for exchange in _items(bundle, "test_exchanges")
    }
    control_identities = {
        _text(_get(_get(control, "exchange"), "identity"))
        for control in _items(bundle, "control_tests")
    }
    valid = (
        proof_type in {"unauthorized_access", "unauthorized_action"}
        and _substantive(attacker)
        and _substantive(owner)
        and attacker != owner
        and _substantive(resource, minimum=3)
        and _substantive(proof.get("unauthorized_effect"), minimum=5)
        and proof.get("ownership_control_passed") is True
        and proof.get("login_confounder") is False
        and proof.get("cache_confounder") is False
        and attacker in test_identities
        and owner in control_identities
    )
    if not valid:
        return _reject(
            SuppressionReason.AUTHORIZATION_IMPACT_NOT_PROVEN,
            "Authorization findings require distinct controlled identities, "
            "resource ownership proof, and a semantic unauthorized effect.",
        )
    return None


def _proof_concrete_effect(vuln_class: str, proof_type: str,
                           proof: Mapping[str, Any]) -> ReportabilityDecision | None:
    valid = (
        proof_type == "concrete_exploit_effect"
        and _substantive(proof.get("effect"), minimum=8)
        and _artifact_reference(proof.get("artifact"))
        and proof.get("control_effect_absent") is True
    )
    class_requirements: dict[str, tuple[str, ...]] = {
        "upload": ("retrieval_or_execution_proof",),
        "path": ("sensitive_file_marker",),
        "cache": ("independent_client_observation", "cache_key_control"),
        "race": ("concurrent_requests", "repetitions"),
        "business": ("violated_invariant", "durable_state_change"),
        "oauth": ("attacker_identity", "victim_identity", "account_binding_effect"),
    }
    for key in class_requirements.get(vuln_class, ()):
        value = proof.get(key)
        if isinstance(value, bool):
            valid = valid and value
        elif isinstance(value, (int, float)):
            valid = valid and value >= 2
        else:
            valid = valid and _substantive(value, minimum=3)
    if not valid:
        return _reject(
            SuppressionReason.CONCRETE_EXPLOIT_EFFECT_NOT_PROVEN,
            "This vulnerability class requires a concrete exploit effect and "
            "matched control, not a dangerous-looking configuration or header.",
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


def _evaluate_reportability(
    finding: Any = None,
    evidence_bundle: Any = None,
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

    validator_identity = _text(_get(bundle, "validator_identity")).lower()
    discovered_by = _text(_get(bundle, "discovered_by")).lower()
    if (
        validator_identity != "validator"
        or not _substantive(discovered_by)
        or discovered_by == validator_identity
        or _text(_get(bundle, "verified_by")).lower() != validator_identity
    ):
        return _reject(
            SuppressionReason.NOT_INDEPENDENTLY_VALIDATED,
            "The discovering agent cannot independently validate its own claim.",
        )
    if not (
        _substantive(_get(bundle, "validator_version"), minimum=2)
        and _substantive(_get(bundle, "validation_method"), minimum=5)
        and _valid_timestamp(_get(bundle, "validated_at"))
        and _text(_get(bundle, "validation_context")) in _SUPPORTED_CONTEXTS
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

    if finding is not None:
        finding_id = (
            _text(_get(finding, "finding_id"))
            or _text(_get(finding, "vuln_id"))
            or _text(_get(finding, "id"))
        )
        bundle_finding_id = _text(_get(bundle, "finding_id"))
        finding_fields = {
            "title": 3,
            "vuln_type": 3,
            "endpoint": 5,
            "description": 5,
            "impact": 5,
            "remediation": 5,
        }
        if (
            not _substantive(finding_id)
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
        if (
            finding_id != bundle_finding_id
            or _text(_get(finding, "vuln_id")) != _text(_get(bundle, "vuln_id"))
            or _text(_get(finding, "title")) != _text(_get(bundle, "title"))
            or _text(_get(finding, "vuln_type")).lower()
            != _text(_get(bundle, "vuln_type")).lower()
            or _text(_get(finding, "endpoint")).rstrip("/")
            != _text(_get(bundle, "endpoint")).rstrip("/")
            or _text(_get(finding, "severity")).lower()
            != _text(_get(bundle, "severity")).lower()
        ):
            return _reject(
                SuppressionReason.EVIDENCE_MISMATCH,
                "Finding identity, title, endpoint, type, or severity does not "
                "match its sealed evidence bundle.",
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
        and _text(_get(exchange, "source")) == "validator"
    ]
    if len(replay_exchanges) < 2 or any(
        not _complete_exchange(exchange, endpoint=endpoint)
        for exchange in replay_exchanges
    ):
        return _reject(
            SuppressionReason.INCOMPLETE_EVIDENCE,
            "At least two complete sanitized Validator replay exchanges are "
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
            and _text(_get(_get(control, "exchange"), "source")) == "validator"
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
    ]
    negative_controls = [
        result for result in replay_results
        if _text(_get(result, "probe_kind")) == "control"
        and _text(_get(result, "outcome")) == "control_no_effect"
        and _valid_timestamp(_get(result, "timestamp"))
        and _substantive(_get(result, "context_id"), minimum=4)
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
    correlated = True
    for result in positive_replays:
        signal = _text(_get(result, "behavioral_signal")).lower()
        exchange = exchanges_by_attempt.get(
            _positive_int(_get(result, "attempt_index"))
        )
        transcript = " ".join(
            _text(_get(exchange, key))
            for key in ("request", "response", "notes")
        ).lower()
        correlated = correlated and _substantive(signal) and signal in transcript
    for result in negative_controls:
        signal = _text(_get(result, "behavioral_signal")).lower()
        control = controls_by_attempt.get(
            _positive_int(_get(result, "attempt_index"))
        )
        exchange = _get(control, "exchange")
        transcript = " ".join((
            _text(_get(exchange, "request")),
            _text(_get(exchange, "response")),
            _text(_get(exchange, "notes")),
            _text(_get(control, "result")),
        )).lower()
        correlated = correlated and _substantive(signal) and signal in transcript
    if (
        replay_count_int < 2
        or len(positive_replays) < 2
        or len(negative_controls) < 1
        or len(attempt_ids) < 3
        or 0 in attempt_ids
        or len(positive_contexts) < 2
        or not correlated
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
        rejected = _proof_injection(proof_type, proof)
    elif vuln_class == "oob":
        rejected = _proof_oob(bundle, proof_type, proof)
    elif vuln_class == "authz":
        rejected = _proof_authz(bundle, proof_type, proof)
    else:
        rejected = _proof_concrete_effect(vuln_class, proof_type, proof)
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
) -> ReportabilityDecision:
    """Return a structured, fail-closed decision for every possible input."""
    try:
        return _evaluate_reportability(finding, evidence_bundle)
    except Exception:
        return _reject(
            SuppressionReason.MALFORMED_EVIDENCE,
            "Unexpected policy evaluation error; candidate suppressed.",
        )


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time digest comparison without importing policy callers."""
    import hmac
    return hmac.compare_digest(left, right)


def is_reportable(finding: Any = None, evidence_bundle: Any = None) -> bool:
    """The single boolean predicate customer-facing code must use."""
    try:
        return evaluate_reportability(finding, evidence_bundle).reportable
    except Exception:
        # Policy errors are suppression, never promotion.
        return False


def partition_reportable(
    findings: Iterable[Any],
) -> tuple[list[Any], list[tuple[Any, ReportabilityDecision]]]:
    confirmed: list[Any] = []
    suppressed: list[tuple[Any, ReportabilityDecision]] = []
    for finding in findings:
        try:
            decision = evaluate_reportability(finding)
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
