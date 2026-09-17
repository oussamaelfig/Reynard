"""Control-plane provenance and authenticity for reportable evidence.

The trust boundary is the local Reynard control process and its executor.  LLM
output may select probes and describe what it believes happened, but it cannot
mint the HMAC receipts required by this module.  Receipts do *not* defend
against a compromised local process or an operator with access to the key.

The key is generated on first signing use and stored outside the repository at
``~/.local/state/reynard/validation/authority.key`` by default (mode 0600).
Set ``REYNARD_VALIDATION_STATE_DIR`` to relocate the state directory, or
``REYNARD_VALIDATION_HMAC_KEY`` to inject a 32-byte hex/base64 key.  Rotating or
losing the key intentionally makes old receipts unverifiable.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, cast


AUTHORITY_SCHEMA_VERSION = 1
AUTHORITY_NAME = "reynard.local-control-plane"
EXECUTOR_SOURCE = "reynard.trusted-executor"
EXECUTOR_PRODUCER = "reynard.budgeted-tool-executor"
ARTIFACT_PRODUCER = "reynard.validation-artifact-store"
VALIDATOR_IMPLEMENTATION = "hacking_agent.agents.validator.ValidatorAgent"

_ALLOWED_EFFECT_KINDS = {
    "browser_execution",
    "boolean_oracle",
    "data_extraction",
    "template_evaluation",
    "command_output",
    "time_oracle",
    "oob_callback",
    "direct_sensitive_resource",
    "unauthorized_access",
    "unauthorized_action",
    "concrete_exploit_effect",
}
_BINDING_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_ARTIFACT_MEDIA = {
    "browser_execution_trace": {"application/json"},
    "oob_interaction_trace": {"application/json"},
    "validation_trace": {"application/json", "application/octet-stream"},
    "browser_screenshot": {"image/png", "image/jpeg", "image/webp"},
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def _state_dir() -> Path:
    configured = os.getenv("REYNARD_VALIDATION_STATE_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local" / "state" / "reynard" / "validation"


def artifact_root() -> Path:
    return _state_dir() / "artifacts"


def _host_exec_enabled() -> bool:
    return os.getenv("REYNARD_HOST_EXEC", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _decode_env_key(raw: str) -> bytes:
    text = raw.strip()
    try:
        key = bytes.fromhex(text)
    except ValueError:
        try:
            key = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError("invalid REYNARD_VALIDATION_HMAC_KEY") from exc
    if len(key) < 32:
        raise ValueError("validation HMAC key must contain at least 32 bytes")
    return key


def _read_key(*, create: bool) -> bytes:
    if _host_exec_enabled():
        raise PermissionError(
            "validation authority disabled while model tools can execute on "
            "the host (REYNARD_HOST_EXEC)"
        )
    supplied = os.getenv("REYNARD_VALIDATION_HMAC_KEY", "")
    if supplied:
        return _decode_env_key(supplied)

    root = _state_dir()
    key_path = root / "authority.key"
    if key_path.exists():
        if key_path.is_symlink() or not key_path.is_file():
            raise ValueError("validation authority key path is unsafe")
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        data = key_path.read_bytes()
        if len(data) < 32:
            raise ValueError("validation authority key is malformed")
        return data
    if not create:
        raise FileNotFoundError("validation authority key is unavailable")

    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    generated = secrets.token_bytes(32)
    try:
        fd = os.open(
            key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        data = key_path.read_bytes()
        if len(data) < 32:
            raise ValueError("validation authority key is malformed")
        return data
    with os.fdopen(fd, "wb") as handle:
        handle.write(generated)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return generated


def authority_key_id(*, create: bool = False) -> str:
    return sha256_bytes(_read_key(create=create))[:24]


def _envelope_core(
    *,
    kind: str,
    run_id: str,
    engagement_id: str,
    validator_instance_id: str,
    issued_at: str | None = None,
    create_key: bool,
) -> dict[str, Any]:
    return {
        "schema_version": AUTHORITY_SCHEMA_VERSION,
        "authority": AUTHORITY_NAME,
        "algorithm": "HMAC-SHA256",
        "key_id": authority_key_id(create=create_key),
        "kind": kind,
        "run_id": str(run_id or ""),
        "engagement_id": str(engagement_id or ""),
        "validator_instance_id": str(validator_instance_id or ""),
        "issued_at": issued_at or utc_now(),
    }


def sign_payload(
    kind: str,
    payload: Mapping[str, Any],
    *,
    run_id: str,
    engagement_id: str,
    validator_instance_id: str,
) -> dict[str, Any]:
    bindings = {
        "run_id": str(run_id or ""),
        "engagement_id": str(engagement_id or ""),
        "validator_instance_id": str(validator_instance_id or ""),
    }
    invalid = [
        name for name, value in bindings.items()
        if not _BINDING_RE.fullmatch(value)
    ]
    if invalid:
        raise ValueError(
            "missing or unsafe authenticity binding: " + ", ".join(invalid)
        )
    key = _read_key(create=True)
    envelope = _envelope_core(
        kind=kind,
        run_id=run_id,
        engagement_id=engagement_id,
        validator_instance_id=validator_instance_id,
        create_key=True,
    )
    message = canonical_json({"envelope": envelope, "payload": dict(payload)})
    envelope["signature"] = hmac.new(
        key, message.encode("utf-8"), hashlib.sha256,
    ).hexdigest()
    return envelope


def verify_payload(
    envelope: Any,
    kind: str,
    payload: Mapping[str, Any],
    *,
    expected_run_id: str = "",
    expected_engagement_id: str = "",
    expected_validator_instance_id: str = "",
) -> tuple[bool, str]:
    if not isinstance(envelope, Mapping):
        return False, "missing_authenticity"
    core = dict(envelope)
    signature = str(core.pop("signature", "") or "")
    expected_keys = {
        "schema_version", "authority", "algorithm", "key_id", "kind",
        "run_id", "engagement_id", "validator_instance_id", "issued_at",
    }
    if (
        set(core) != expected_keys
        or core.get("schema_version") != AUTHORITY_SCHEMA_VERSION
        or core.get("authority") != AUTHORITY_NAME
        or core.get("algorithm") != "HMAC-SHA256"
        or core.get("kind") != kind
        or len(signature) != 64
        or any(
            not _BINDING_RE.fullmatch(str(core.get(key) or ""))
            for key in ("run_id", "engagement_id", "validator_instance_id")
        )
        or not _valid_timestamp(core.get("issued_at"))
    ):
        return False, "invalid_authenticity_envelope"
    if expected_run_id and core.get("run_id") != expected_run_id:
        return False, "run_binding_mismatch"
    if (
        expected_engagement_id
        and core.get("engagement_id") != expected_engagement_id
    ):
        return False, "engagement_binding_mismatch"
    if (
        expected_validator_instance_id
        and core.get("validator_instance_id")
        != expected_validator_instance_id
    ):
        return False, "validator_binding_mismatch"
    try:
        key = _read_key(create=False)
    except (OSError, ValueError):
        return False, "unknown_validation_key"
    if core.get("key_id") != sha256_bytes(key)[:24]:
        return False, "unknown_validation_key"
    try:
        message = canonical_json({"envelope": core, "payload": dict(payload)})
    except (TypeError, ValueError):
        return False, "malformed_signed_payload"
    expected = hmac.new(
        key, message.encode("utf-8"), hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False, "invalid_authenticity_signature"
    return True, ""


def validator_identity(
    *,
    instance_id: str,
    version: str,
) -> dict[str, Any]:
    """Return a structured, system-derived validator identity."""
    return {
        "role": "validator",
        "implementation": VALIDATOR_IMPLEMENTATION,
        "version": str(version),
        "instance_id": str(instance_id),
        "authority": AUTHORITY_NAME,
        "key_id": authority_key_id(create=True),
    }


def _json_safe_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    try:
        return json.loads(canonical_json(dict(value)))
    except (TypeError, ValueError):
        return {}


def derive_executor_effect(
    *,
    tool: str,
    raw_result: str,
    signals: Any,
) -> dict[str, Any]:
    """Derive the narrow effect vocabulary supported by trusted executors.

    Free-form response text, generic status changes and model prose never create
    an effect.  Only deterministic fields generated by Reynard tooling do.
    """
    safe_signals = _json_safe_mapping(signals)
    parsed: dict[str, Any] = {}
    try:
        candidate = json.loads(raw_result)
        if isinstance(candidate, dict):
            parsed = candidate
    except (json.JSONDecodeError, TypeError):
        pass

    if (
        tool in {"browser_navigate", "browser_execute_js", "browser_interact"}
        and safe_signals.get("dialog_fired") is True
        and isinstance(parsed.get("dialogs"), list)
        and parsed["dialogs"]
    ):
        dialogs = parsed["dialogs"]
        return {
            "kind": "browser_execution",
            "fingerprint": sha256_text(canonical_json(dialogs)),
            "details": {
                "dialog_count": len(dialogs),
                "dialog_types": [
                    str(item.get("type") or "")
                    for item in dialogs if isinstance(item, dict)
                ],
            },
            "artifact_content": canonical_json({
                "tool": tool,
                "dialogs": dialogs,
                "final_url": parsed.get("final_url", ""),
                "status": parsed.get("status"),
            }).encode("utf-8"),
            "artifact_kind": "browser_execution_trace",
            "artifact_media_type": "application/json",
        }
    if safe_signals.get("angular_evaluated") is True:
        return {
            "kind": "template_evaluation",
            "fingerprint": sha256_text("angular_evaluated:true"),
            "details": {"analyzer": "response_analyzer"},
        }
    # A poll can return the same callback repeatedly.  Until the executor can
    # bind two independently minted/delivered correlation tokens, polling output
    # alone is not a replay and deliberately cannot mint an OOB effect.
    return {}


def _artifact_extension(media_type: str) -> str:
    guessed = mimetypes.guess_extension(media_type or "") or ""
    if guessed in {".json", ".png", ".jpg", ".jpeg", ".webp", ".har", ".zip",
                   ".pdf", ".txt"}:
        return guessed
    return ".bin"


def _valid_timestamp(value: Any) -> bool:
    try:
        datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return bool(str(value))
    except (TypeError, ValueError):
        return False


def store_artifact(
    content: bytes,
    *,
    kind: str,
    media_type: str,
    run_id: str,
    engagement_id: str,
    validator_instance_id: str,
) -> dict[str, Any]:
    """Persist content-addressed evidence and return a signed manifest."""
    if not _BINDING_RE.fullmatch(str(run_id or "")):
        raise ValueError("unsafe artifact run binding")
    if (
        kind not in _ARTIFACT_MEDIA
        or media_type not in _ARTIFACT_MEDIA[kind]
    ):
        raise ValueError("unsupported artifact kind or media type")
    digest = sha256_bytes(content)
    extension = _artifact_extension(media_type)
    relative = PurePosixPath(
        str(run_id), digest[:2], f"{digest}{extension}",
    )
    root = artifact_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    try:
        root_resolved = root.resolve(strict=True)
        if root.is_symlink():
            raise ValueError("artifact root is a symlink")
        parent_resolved = root_resolved
        for part in relative.parts[:-1]:
            child = parent_resolved / part
            if child.is_symlink():
                raise ValueError("artifact parent path contains a symlink")
            child.mkdir(mode=0o700, exist_ok=True)
            resolved_child = child.resolve(strict=True)
            resolved_child.relative_to(root_resolved)
            if not resolved_child.is_dir():
                raise ValueError("artifact parent is not a directory")
            parent_resolved = resolved_child
    except (OSError, ValueError) as exc:
        raise ValueError("artifact parent escapes the evidence root") from exc
    try:
        os.chmod(parent_resolved, 0o700)
    except OSError:
        pass
    candidate = parent_resolved / relative.name
    if candidate.exists() or candidate.is_symlink():
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or candidate.read_bytes() != content
        ):
            raise ValueError("content-addressed artifact path is not immutable")
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(candidate, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    record: dict[str, Any] = {
        "artifact_id": f"sha256:{digest}",
        "path": relative.as_posix(),
        "sha256": digest,
        "size": len(content),
        "kind": str(kind),
        "media_type": str(media_type),
        "source": EXECUTOR_SOURCE,
        "producer": ARTIFACT_PRODUCER,
        "captured_at": utc_now(),
        "run_id": str(run_id),
    }
    record["authenticity"] = sign_payload(
        "artifact",
        record,
        run_id=run_id,
        engagement_id=engagement_id,
        validator_instance_id=validator_instance_id,
    )
    return record


def _path_has_symlink(root: Path, relative: PurePosixPath) -> bool:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def verify_artifact(
    record: Any,
    *,
    expected_run_id: str,
    expected_engagement_id: str,
    expected_validator_instance_id: str,
) -> tuple[bool, str]:
    if not isinstance(record, Mapping):
        return False, "malformed_artifact_manifest"
    data = dict(record)
    envelope = data.pop("authenticity", None)
    ok, reason = verify_payload(
        envelope,
        "artifact",
        data,
        expected_run_id=expected_run_id,
        expected_engagement_id=expected_engagement_id,
        expected_validator_instance_id=expected_validator_instance_id,
    )
    if not ok:
        return False, reason
    if (
        data.get("source") != EXECUTOR_SOURCE
        or data.get("producer") != ARTIFACT_PRODUCER
        or data.get("run_id") != expected_run_id
        or not _valid_timestamp(data.get("captured_at"))
    ):
        return False, "untrusted_artifact_provenance"
    raw_path = str(data.get("path") or "")
    relative = PurePosixPath(raw_path)
    if (
        not raw_path
        or relative.is_absolute()
        or ".." in relative.parts
        or "." in relative.parts
        or "\\" in raw_path
        or not relative.parts
        or relative.parts[0] != expected_run_id
    ):
        return False, "artifact_path_escape"
    root = artifact_root()
    try:
        root_resolved = root.resolve(strict=True)
    except OSError:
        return False, "artifact_unreadable"
    if root.is_symlink():
        return False, "artifact_path_escape"
    if _path_has_symlink(root_resolved, relative):
        return False, "artifact_symlink_rejected"
    candidate = root_resolved.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except FileNotFoundError:
        return False, "artifact_unreadable"
    except (OSError, ValueError):
        return False, "artifact_path_escape"
    try:
        info = candidate.lstat()
    except OSError:
        return False, "artifact_unreadable"
    if (
        not stat.S_ISREG(info.st_mode)
        or not isinstance(data.get("size"), int)
        or isinstance(data.get("size"), bool)
        or info.st_size != data.get("size")
    ):
        return False, "artifact_size_mismatch"
    try:
        content = resolved.read_bytes()
        actual_digest = sha256_bytes(content)
    except OSError:
        return False, "artifact_unreadable"
    if (
        actual_digest != data.get("sha256")
        or data.get("artifact_id") != f"sha256:{actual_digest}"
    ):
        return False, "artifact_hash_mismatch"
    kind = str(data.get("kind") or "")
    media_type = str(data.get("media_type") or "")
    expected_path = PurePosixPath(
        expected_run_id,
        actual_digest[:2],
        f"{actual_digest}{_artifact_extension(media_type)}",
    )
    if (
        kind not in _ARTIFACT_MEDIA
        or media_type not in _ARTIFACT_MEDIA[kind]
        or resolved.suffix.lower() != _artifact_extension(media_type)
        or relative != expected_path
    ):
        return False, "malformed_artifact_manifest"
    if media_type == "application/json":
        try:
            json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, "artifact_type_mismatch"
    elif media_type == "image/png" and not content.startswith(b"\x89PNG\r\n\x1a\n"):
        return False, "artifact_type_mismatch"
    elif media_type == "image/jpeg" and not content.startswith(b"\xff\xd8\xff"):
        return False, "artifact_type_mismatch"
    elif media_type == "image/webp" and not (
        content.startswith(b"RIFF") and content[8:12] == b"WEBP"
    ):
        return False, "artifact_type_mismatch"
    return True, ""


def capture_observation(
    *,
    attempt_index: int,
    probe_kind: str,
    tool: str,
    request: str,
    response: str,
    status_code: int,
    identity: str,
    url: str,
    method: str,
    captured_at: str,
    run_id: str,
    engagement_id: str,
    validator_instance_id: str,
    trusted_effect: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create an immutable executor observation.

    ``trusted_effect`` must come from :func:`derive_executor_effect` or another
    deterministic control-plane adapter.  It is never populated from model
    output.
    """
    raw_effect = dict(trusted_effect or {})
    effect = _json_safe_mapping({
        key: value
        for key, value in raw_effect.items()
        if key != "artifact_content"
    })
    kind = str(effect.get("kind") or "")
    fingerprint = str(effect.get("fingerprint") or "")
    if kind and (kind not in _ALLOWED_EFFECT_KINDS or len(fingerprint) != 64):
        raise ValueError("unsupported trusted executor effect")
    artifacts: list[dict[str, Any]] = []
    artifact_content = raw_effect.get("artifact_content")
    if isinstance(artifact_content, bytes):
        artifacts.append(store_artifact(
            artifact_content,
            kind=str(raw_effect.get("artifact_kind") or "validation_trace"),
            media_type=str(
                raw_effect.get("artifact_media_type")
                or "application/octet-stream"
            ),
            run_id=run_id,
            engagement_id=engagement_id,
            validator_instance_id=validator_instance_id,
        ))

    observation: dict[str, Any] = {
        "capture_id": f"capture:{uuid.uuid4().hex}",
        "attempt_index": int(attempt_index),
        "probe_kind": str(probe_kind),
        "tool": str(tool),
        "request": str(request),
        "response": str(response),
        "request_sha256": sha256_text(str(request)),
        "response_sha256": sha256_text(str(response)),
        "status_code": int(status_code),
        "identity": str(identity),
        "url": str(url),
        "method": str(method).upper(),
        "captured_at": str(captured_at),
        "context_id": f"executor-context:{uuid.uuid4().hex}",
        "source": EXECUTOR_SOURCE,
        "producer": EXECUTOR_PRODUCER,
        "run_id": str(run_id),
        "effect_kind": kind,
        "effect_fingerprint": fingerprint,
        "effect_details": effect.get("details", {}) if kind else {},
        "artifacts": artifacts,
    }
    observation["authenticity"] = sign_payload(
        "executor_observation",
        observation,
        run_id=run_id,
        engagement_id=engagement_id,
        validator_instance_id=validator_instance_id,
    )
    return observation


def verify_observation(
    observation: Any,
    *,
    expected_run_id: str,
    expected_engagement_id: str,
    expected_validator_instance_id: str,
) -> tuple[bool, str]:
    if not isinstance(observation, Mapping):
        return False, "malformed_executor_observation"
    data = dict(observation)
    envelope = data.pop("authenticity", None)
    ok, reason = verify_payload(
        envelope,
        "executor_observation",
        data,
        expected_run_id=expected_run_id,
        expected_engagement_id=expected_engagement_id,
        expected_validator_instance_id=expected_validator_instance_id,
    )
    if not ok:
        return False, reason
    if (
        data.get("source") != EXECUTOR_SOURCE
        or data.get("producer") != EXECUTOR_PRODUCER
        or data.get("run_id") != expected_run_id
    ):
        return False, "untrusted_executor_provenance"
    request = str(data.get("request") or "")
    response = str(data.get("response") or "")
    if (
        data.get("request_sha256") != sha256_text(request)
        or data.get("response_sha256") != sha256_text(response)
    ):
        return False, "executor_capture_hash_mismatch"
    if (
        not str(data.get("capture_id") or "").startswith("capture:")
        or not str(data.get("context_id") or "").startswith("executor-context:")
        or not isinstance(data.get("attempt_index"), int)
        or isinstance(data.get("attempt_index"), bool)
        or int(data["attempt_index"]) < 1
        or data.get("probe_kind")
        not in {"replay", "fresh_context_replay", "control", "vary"}
        or data.get("effect_kind") not in _ALLOWED_EFFECT_KINDS | {""}
        or not _valid_timestamp(data.get("captured_at"))
        or not isinstance(data.get("status_code"), int)
        or isinstance(data.get("status_code"), bool)
        or not 100 <= int(data["status_code"]) <= 599
        or str(data.get("method") or "").upper()
        not in {
            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
            "CONNECT", "TRACE",
        }
    ):
        return False, "malformed_executor_observation"
    if data.get("effect_kind") and not re.fullmatch(
        r"[0-9a-f]{64}", str(data.get("effect_fingerprint") or ""),
    ):
        return False, "malformed_executor_effect"
    for artifact in data.get("artifacts") or []:
        ok, reason = verify_artifact(
            artifact,
            expected_run_id=expected_run_id,
            expected_engagement_id=expected_engagement_id,
            expected_validator_instance_id=expected_validator_instance_id,
        )
        if not ok:
            return False, reason
    return True, ""


def _protocol_payload(
    observations: list[dict[str, Any]],
    *,
    run_id: str,
    engagement_id: str,
    validator_instance_id: str,
    validator_version: str,
) -> tuple[dict[str, Any] | None, str]:
    if len(observations) < 3:
        return None, "insufficient_trusted_observations"
    selected = observations[:3]
    expected_kinds = ("replay", "fresh_context_replay", "control")
    for expected, observation in zip(expected_kinds, selected):
        ok, reason = verify_observation(
            observation,
            expected_run_id=run_id,
            expected_engagement_id=engagement_id,
            expected_validator_instance_id=validator_instance_id,
        )
        if not ok:
            return None, reason
        if observation.get("probe_kind") != expected:
            return None, "invalid_probe_sequence"

    capture_ids = [str(item.get("capture_id") or "") for item in selected]
    contexts = [str(item.get("context_id") or "") for item in selected]
    attempt_indices = [int(item.get("attempt_index") or 0) for item in selected]
    if (
        len(set(capture_ids)) != 3
        or len(set(contexts)) != 3
        or len(set(attempt_indices)) != 3
        or attempt_indices != sorted(attempt_indices)
    ):
        return None, "duplicate_executor_provenance"
    positives = selected[:2]
    control = selected[2]
    positive_match_keys = ("tool", "url", "method", "identity")
    positive_match = tuple(
        str(positives[0].get(key) or "") for key in positive_match_keys
    )
    if any(
        tuple(str(item.get(key) or "") for key in positive_match_keys)
        != positive_match
        for item in positives[1:]
    ) or positives[0].get("request_sha256") != positives[1].get(
        "request_sha256"
    ):
        return None, "unmatched_replay_capture"
    control_match_keys = ("tool", "url", "method")
    if tuple(
        str(control.get(key) or "") for key in control_match_keys
    ) != tuple(
        str(positives[0].get(key) or "") for key in control_match_keys
    ):
        return None, "unmatched_control_capture"
    effect_kind = str(positives[0].get("effect_kind") or "")
    effect_fingerprint = str(positives[0].get("effect_fingerprint") or "")
    if (
        not effect_kind
        or effect_kind not in _ALLOWED_EFFECT_KINDS
        or len(effect_fingerprint) != 64
        or any(item.get("effect_kind") != effect_kind for item in positives)
        or any(
            item.get("effect_fingerprint") != effect_fingerprint
            for item in positives
        )
        or control.get("effect_kind")
        or control.get("effect_fingerprint")
    ):
        return None, "executor_effect_not_reproduced"
    positive_identity = str(positives[0].get("identity") or "")
    control_identity = str(control.get("identity") or "")
    authorization_effect = effect_kind in {
        "unauthorized_access", "unauthorized_action",
    }
    if (
        (authorization_effect and control_identity == positive_identity)
        or (not authorization_effect and control_identity != positive_identity)
    ):
        return None, "unmatched_control_identity"
    if any(
        control.get("request_sha256") == item.get("request_sha256")
        for item in positives
    ):
        return None, "duplicated_control_capture"

    artifacts = [
        artifact
        for observation in positives
        for artifact in (observation.get("artifacts") or [])
    ]
    payload: dict[str, Any] = {
        "schema_version": AUTHORITY_SCHEMA_VERSION,
        "run_id": run_id,
        "engagement_id": engagement_id,
        "validator_identity": validator_identity(
            instance_id=validator_instance_id,
            version=validator_version,
        ),
        "validation_method": (
            "trusted executor: two separately captured effects plus matched "
            "negative control"
        ),
        "validation_context": "controlled_replay",
        "validated_at": utc_now(),
        "observations": selected,
        "replay_count": 2,
        "replay_results": [
            {
                "attempt_index": item["attempt_index"],
                "probe_kind": item["probe_kind"],
                "outcome": (
                    "control_no_effect"
                    if item["probe_kind"] == "control"
                    else "vulnerable_effect"
                ),
                "capture_id": item["capture_id"],
                "context_id": item["context_id"],
                "request_sha256": item["request_sha256"],
                "response_sha256": item["response_sha256"],
                "effect_kind": item.get("effect_kind", ""),
                "effect_fingerprint": item.get("effect_fingerprint", ""),
                "timestamp": item["captured_at"],
                "source": EXECUTOR_SOURCE,
            }
            for item in selected
        ],
        "proof_type": effect_kind,
        "proof_metadata": {
            "effect_fingerprint": effect_fingerprint,
            "positive_capture_ids": capture_ids[:2],
            "control_capture_id": capture_ids[2],
            "effect_details": positives[0].get("effect_details") or {},
            "artifact_ids": [
                item.get("artifact_id") for item in artifacts
            ],
        },
        "artifacts": artifacts,
        "causal_signal": (
            f"Executor-derived {effect_kind} effect "
            f"{effect_fingerprint[:16]} reproduced in captures "
            f"{capture_ids[0]} and {capture_ids[1]}; absent in control "
            f"{capture_ids[2]}."
        ),
        "reproduction_steps": [
            f"Replay trusted executor capture {capture_ids[0]} at the bound endpoint.",
            f"Repeat with separately recorded capture {capture_ids[1]}.",
            f"Run matched control capture {capture_ids[2]} and verify the effect is absent.",
        ],
    }
    return payload, ""


def issue_protocol_receipt(
    observations: list[dict[str, Any]],
    *,
    run_id: str,
    engagement_id: str,
    validator_instance_id: str,
    validator_version: str,
) -> tuple[dict[str, Any] | None, str]:
    payload, reason = _protocol_payload(
        observations,
        run_id=run_id,
        engagement_id=engagement_id,
        validator_instance_id=validator_instance_id,
        validator_version=validator_version,
    )
    if payload is None:
        return None, reason
    payload["authenticity"] = sign_payload(
        "validation_protocol",
        payload,
        run_id=run_id,
        engagement_id=engagement_id,
        validator_instance_id=validator_instance_id,
    )
    return payload, ""


def verify_protocol(protocol: Any) -> tuple[bool, str]:
    if not isinstance(protocol, Mapping):
        return False, "missing_trusted_protocol"
    data = dict(protocol)
    envelope = data.pop("authenticity", None)
    run_id = str(data.get("run_id") or "")
    engagement_id = str(data.get("engagement_id") or "")
    identity = data.get("validator_identity")
    if not isinstance(identity, Mapping):
        return False, "untrusted_validator_identity"
    instance_id = str(identity.get("instance_id") or "")
    ok, reason = verify_payload(
        envelope,
        "validation_protocol",
        data,
        expected_run_id=run_id,
        expected_engagement_id=engagement_id,
        expected_validator_instance_id=instance_id,
    )
    if not ok:
        return False, reason
    expected, reason = _protocol_payload(
        list(data.get("observations") or []),
        run_id=run_id,
        engagement_id=engagement_id,
        validator_instance_id=instance_id,
        validator_version=str(identity.get("version") or ""),
    )
    if expected is None:
        return False, reason
    # ``validated_at`` is receipt issuance data rather than derived capture
    # content, so preserve the signed value for deterministic comparison.
    expected["validated_at"] = data.get("validated_at")
    if canonical_json(expected) != canonical_json(data):
        return False, "protocol_derivation_mismatch"
    return True, ""


_BUNDLE_PUBLIC_FIELDS = (
    "id", "title", "vuln_type", "severity", "target", "endpoint", "identity",
    "vuln_id", "finding_id", "created_at", "updated_at", "test_exchanges",
    "control_tests", "oob_interactions", "screenshots", "reproduction_steps",
    "causal_signal", "verification_status", "verified_by", "notes",
    "validation_schema_version", "discovered_by", "validator_identity",
    "validator_version", "validation_method", "validation_context",
    "validated_at", "replay_count", "replay_results", "proof_type",
    "proof_metadata", "validation_protocol", "artifacts",
    "customer_projection", "validation_error", "integrity_sha256",
)


def bundle_signing_payload(bundle: Any) -> dict[str, Any]:
    raw = dict(bundle) if isinstance(bundle, Mapping) else dict(bundle.to_dict())
    return {
        key: raw.get(key)
        for key in _BUNDLE_PUBLIC_FIELDS
    }


def public_evidence_bundle(bundle: Any) -> dict[str, Any]:
    """Return the only EvidenceBundle shape allowed in customer documents."""
    payload = bundle_signing_payload(bundle)
    authenticity = (
        bundle.get("authenticity")
        if isinstance(bundle, Mapping)
        else getattr(bundle, "authenticity", None)
    )
    payload["authenticity"] = dict(authenticity or {})
    return payload


def attest_bundle(bundle: Any) -> dict[str, Any]:
    data = bundle_signing_payload(bundle)
    protocol = data.get("validation_protocol")
    ok, reason = verify_protocol(protocol)
    if not ok:
        raise ValueError(f"cannot attest untrusted bundle: {reason}")
    protocol = cast(Mapping[str, Any], protocol)
    run_id = str(protocol.get("run_id") or "")
    engagement_id = str(protocol.get("engagement_id") or "")
    identity = protocol.get("validator_identity") or {}
    return sign_payload(
        "evidence_bundle",
        data,
        run_id=run_id,
        engagement_id=engagement_id,
        validator_instance_id=str(identity.get("instance_id") or ""),
    )


def verify_bundle_authenticity(
    bundle: Any,
    *,
    expected_run_id: str = "",
    expected_engagement_id: str = "",
) -> tuple[bool, str]:
    data = bundle_signing_payload(bundle)
    envelope = (
        bundle.get("authenticity")
        if isinstance(bundle, Mapping)
        else getattr(bundle, "authenticity", None)
    )
    protocol = data.get("validation_protocol")
    ok, reason = verify_protocol(protocol)
    if not ok:
        return False, reason
    protocol = cast(Mapping[str, Any], protocol)
    run_id = str(protocol.get("run_id") or "")
    engagement_id = str(protocol.get("engagement_id") or "")
    identity = protocol.get("validator_identity") or {}
    return verify_payload(
        envelope,
        "evidence_bundle",
        data,
        expected_run_id=expected_run_id or run_id,
        expected_engagement_id=expected_engagement_id or engagement_id,
        expected_validator_instance_id=str(identity.get("instance_id") or ""),
    )


_REPORT_META_KEYS = {
    "engagement_name", "client", "tester", "targets", "authorized_domains",
    "authorized_cidrs", "out_of_scope", "generated_at", "testing_window",
}


def report_signing_payload(report: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact outward report fields covered by its receipt."""
    payload = {
        key: report.get(key)
        for key in sorted(_REPORT_META_KEYS)
        if key in report
    }
    for key in (
        "reportability_policy_version", "target_count", "finding_count",
        "verified_count", "confirmed_count", "suppressed_count",
        "targets_assessed",
    ):
        payload[key] = report.get(key)
    payload["suppression_semantics"] = report.get(
        "suppression_semantics",
        "report candidates rejected by the customer export gate",
    )
    return payload


def attest_report(
    report: Mapping[str, Any],
    *,
    run_id: str,
    engagement_id: str,
    validator_instance_id: str,
) -> dict[str, Any]:
    return sign_payload(
        "customer_report",
        report_signing_payload(report),
        run_id=run_id,
        engagement_id=engagement_id,
        validator_instance_id=validator_instance_id,
    )


def verify_report_authenticity(
    report: Any,
    *,
    expected_run_id: str = "",
) -> tuple[bool, str]:
    if not isinstance(report, Mapping):
        return False, "malformed_report"
    envelope = report.get("report_authenticity")
    if not isinstance(envelope, Mapping):
        return False, "missing_report_authenticity"
    return verify_payload(
        envelope,
        "customer_report",
        report_signing_payload(report),
        expected_run_id=expected_run_id,
    )
