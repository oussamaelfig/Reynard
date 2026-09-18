"""Read-only checks of operator-declared private-resource invariants.

This is deliberately not a general business-logic solver. An operator supplies
an exact GET endpoint, two controlled identities and an object-specific JSON
marker that the second identity must not receive. Every request goes through
the authenticated research runner's scope, origin, deadline and shared-budget
checks. No endpoint generation, form submission, account mutation or retries
are performed here.

Results are observations/candidates, never signed validation evidence. In
particular, an operator's ownership declaration is an assumption to review, not
proof of application policy. A candidate still needs the independent trusted
validation gate before it can enter a customer report.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import re
from typing import Annotated, Any, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator, model_validator

from hacking_agent.core.sessions import AuthSession
from hacking_agent.core.target_address import parse_target, scope_path

MAX_RULES = 20
MAX_BODY_BYTES = 65536
ANONYMOUS = "anonymous"
_MISSING = object()
Marker = StrictStr | Annotated[int, Field(strict=True, ge=-(2**53 - 1), le=2**53 - 1)]


class BusinessRuleSpec(BaseModel):
    """Private operator configuration; do not log or persist its marker/URL.

    ``json_path`` is an RFC 6901 JSON pointer, not executable JSONPath. Use an
    object-specific value (for example a controlled invoice owner identifier),
    not a generic page title or success flag. All requests are GET and must also
    be covered by the runner's explicit read-prefix policy.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    name: StrictStr = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9_. -]*$")
    url: StrictStr = Field(min_length=1, max_length=4096, repr=False)
    owner_identity: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    denied_identity: StrictStr = Field(default=ANONYMOUS, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    json_path: StrictStr = Field(min_length=1, max_length=256, repr=False)
    expected_value: Marker = Field(repr=False)
    expected_denied_statuses: tuple[StrictInt, ...] = Field(
        default=(401, 403, 404), min_length=1, max_length=3,
    )

    @field_validator("url")
    @classmethod
    def exact_http_url(cls, value: str) -> str:
        target = parse_target(value)
        if not target.is_url or "#" in value:
            raise ValueError("Business rules require an exact HTTP(S) URL without fragments")
        scope_path(target.path)
        return value

    @field_validator("json_path")
    @classmethod
    def bounded_json_pointer(cls, value: str) -> str:
        if not value.startswith("/") or len(value.split("/")) > 17:
            raise ValueError("Use a bounded RFC 6901 JSON pointer beginning with /")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("JSON pointers cannot contain control characters")
        for part in value.split("/")[1:]:
            index = 0
            while index < len(part):
                if part[index] == "~":
                    if index + 1 == len(part) or part[index + 1] not in "01":
                        raise ValueError("Invalid JSON pointer escape")
                    index += 1
                index += 1
        return value

    @field_validator("expected_value")
    @classmethod
    def object_specific_marker(cls, value: str | int) -> str | int:
        if isinstance(value, str) and (not value.strip() or len(value) > 512
                                      or any(ord(char) < 32 for char in value)):
            raise ValueError("A marker must be a nonempty bounded single-line string or integer")
        return value

    @field_validator("expected_denied_statuses")
    @classmethod
    def restricted_denial_codes(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if len(set(value)) != len(value) or not set(value) <= {401, 403, 404}:
            raise ValueError("Expected denied statuses must be unique values from 401, 403, 404")
        return value

    @model_validator(mode="after")
    def distinct_controlled_identities(self) -> BusinessRuleSpec:
        if self.owner_identity == ANONYMOUS or self.owner_identity == self.denied_identity:
            raise ValueError("An authenticated owner and a distinct denied identity are required")
        return self


class BusinessRuleRunner(Protocol):
    """Trusted runner contract. Implementations must authorize every request."""

    verified_identities: set[str]

    @property
    def identity_fingerprints(self) -> Mapping[str, str]: ...

    @property
    def sessions(self) -> Mapping[str, AuthSession]: ...

    def clone_session(self, name: str) -> AuthSession: ...

    def verify_session(self, identity_name: str, *, session: AuthSession) -> bool: ...

    def request(self, identity_name: str, method: str, url: str, *,
                data: str | None = None, headers: dict | None = None,
                session: AuthSession | None = None) -> dict: ...


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def _same_resource(left: str, right: str) -> bool:
    try:
        a, b = parse_target(left), parse_target(right)
        return (a.scheme, a.host, a.port, a.path, urlsplit(left).query) == (
            b.scheme, b.host, b.port, b.path, urlsplit(right).query,
        ) and "#" not in right
    except (TypeError, ValueError):
        return False


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Ambiguous duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("Non-finite JSON value")


def _pointer(document: Any, pointer: str) -> Any:
    value = document
    for encoded in pointer.split("/")[1:]:
        part = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            value = value.get(part, _MISSING)
        elif isinstance(value, list) and part.isascii() and part.isdigit():
            if len(part) > 8 or (len(part) > 1 and part.startswith("0")):
                return _MISSING
            index = int(part)
            value = value[index] if index < len(value) else _MISSING
        else:
            return _MISSING
    return value


def _observe(response: Any, rule: BusinessRuleSpec) -> tuple[str, dict[str, Any]]:
    if not isinstance(response, dict):
        return "malformed_response", {}
    status = response.get("status")
    if type(status) is not int or not 100 <= status <= 599:
        return "malformed_response", {}
    evidence: dict[str, Any] = {"status": status}
    body = response.get("body")
    if response.get("error") or response.get("truncated") is not False:
        return "incomplete_response", evidence
    if not isinstance(body, str):
        return "incomplete_response", evidence
    try:
        body_size = len(body.encode("utf-8"))
    except UnicodeError:
        return "incomplete_response", evidence
    if body_size > MAX_BODY_BYTES:
        return "incomplete_response", evidence
    if not _same_resource(rule.url, response.get("final_url", "")):
        return "resource_redirected", evidence
    evidence["response_sha256"] = _digest({"status": status, "body": body})
    marker = _MISSING
    try:
        document = json.loads(body, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        marker = _pointer(document, rule.json_path)
    except (ValueError, TypeError, RecursionError):
        pass
    # bool is a subclass of int: exact types deliberately prevent true == 1.
    present = type(marker) is type(rule.expected_value) and marker == rule.expected_value
    evidence["marker_present"] = present
    if present:
        return ("marker" if 200 <= status < 300 else "marker_in_error_response"), evidence
    if status in rule.expected_denied_statuses:
        return "denied", evidence
    return "marker_missing_or_ambiguous", evidence


def evaluate_business_rules(runner: BusinessRuleRunner,
                            rules: Sequence[BusinessRuleSpec]) -> dict[str, Any]:
    """Evaluate at most twenty GET-only contracts without promoting findings.

    The returned structure contains constant reason codes, status/marker flags
    and hashes, never raw names, identities, URLs, query strings, JSON pointers,
    expected private values, response bodies or exception text. ``rule_index``
    maps it back to the operator's private configuration. Request counts are
    *attempts*, since a runner can block a call before any network activity.
    """
    if len(rules) > MAX_RULES or any(not isinstance(rule, BusinessRuleSpec) for rule in rules):
        raise ValueError("Provide at most twenty validated business rules")
    if len({rule.name for rule in rules}) != len(rules):
        raise ValueError("Business rule names must be unique")
    metrics = {"rules_total": len(rules), "passed_count": 0, "candidate_count": 0,
               "inconclusive_count": 0, "request_attempts": 0, "responses_received": 0,
               "identity_check_attempts": 0, "verified_count": 0, "reportable_count": 0}
    results: list[dict[str, Any]] = []
    for rule_index, rule in enumerate(rules):
        result: dict[str, Any] = {
            "rule_index": rule_index, "rule_id": "rule:" + _digest(rule.model_dump(mode="json")),
            "classification": "inconclusive", "reason": "identity_not_verified",
            "verification_status": "unverified", "customer_reportable": False, "evidence": [],
        }
        results.append(result)
        identities = {rule.owner_identity, rule.denied_identity} - {ANONYMOUS}
        if not identities <= runner.verified_identities:
            metrics["inconclusive_count"] += 1
            continue
        fingerprints = [runner.identity_fingerprints.get(identity, "") for identity in identities]
        if (any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                for value in fingerprints) or len(set(fingerprints)) != len(identities)):
            result["reason"] = "distinct_identities_not_proven"
            metrics["inconclusive_count"] += 1
            continue
        phases = [("owner", rule.owner_identity), ("denied", rule.denied_identity)]
        if rule.denied_identity != ANONYMOUS:
            phases.append(("anonymous_control", ANONYMOUS))
        observations: dict[str, list[str]] = {phase: [] for phase, _ in phases}
        clones: list[AuthSession] = []
        stopped = False
        for attempt in (1, 2):
            for phase, identity in phases:
                try:
                    clone = runner.clone_session(identity)
                    baseline = runner.sessions.get(identity)
                    previous = [*clones, *([baseline] if baseline is not None else [])]
                    if (clone.name != identity or any(
                        clone is item or clone.http_cookies is item.http_cookies
                        or clone.static_headers is item.static_headers for item in previous
                    ) or (identity == ANONYMOUS and (clone.static_headers or list(clone.http_cookies)))):
                        raise ValueError("A fresh isolated identity snapshot is required")
                    clones.append(clone)
                    if identity != ANONYMOUS:
                        metrics["identity_check_attempts"] += 1
                        if runner.verify_session(identity, session=clone) is not True:
                            result["reason"] = "identity_verification_failed"
                            stopped = True
                            break
                    metrics["request_attempts"] += 1
                    response = runner.request(identity, "GET", rule.url, session=clone)
                    metrics["responses_received"] += 1
                    if identity != ANONYMOUS:
                        metrics["identity_check_attempts"] += 1
                        if runner.verify_session(identity, session=clone) is not True:
                            result["reason"] = "identity_verification_failed"
                            stopped = True
                            break
                except Exception:
                    # Scope/window/budget/credential errors must not expose their
                    # URL, token, marker, or backend diagnostic text in artifacts.
                    result["reason"] = "request_blocked_or_failed"
                    stopped = True
                    break
                state, evidence = _observe(response, rule)
                observations[phase].append(state)
                result["evidence"].append({
                    "phase": phase, "attempt": attempt, "observation": state,
                    "request_sha256": _digest({"method": "GET", "url": rule.url, "identity": identity}),
                    **evidence,
                })
                if state not in {"marker", "denied"} or (phase == "owner" and state != "marker"):
                    result["reason"] = "owner_baseline_missing" if phase == "owner" else state
                    stopped = True
                    break
            if stopped:
                break
        if not stopped:
            consistent = all(len(states) == 2 and states[0] == states[1]
                             for states in observations.values())
            if not consistent:
                result["reason"] = "replay_inconsistent"
            elif rule.denied_identity != ANONYMOUS and observations["anonymous_control"] != ["denied", "denied"]:
                result["reason"] = "anonymous_control_not_denied"
            elif observations["denied"] == ["denied", "denied"]:
                result.update(classification="passed", reason="declared_access_denied")
            elif observations["denied"] == ["marker", "marker"]:
                result.update(classification="candidate", reason="private_marker_reproduced")
        metrics[result["classification"] + "_count"] += 1
    return {"schema_version": 1, "mode": "read_only_contracts", "metrics": metrics, "results": results}
