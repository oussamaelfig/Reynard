"""Failure classification for coordinator pivots.

The goal is not perfect diagnosis. It is to give the next coordinator turn a
compact, actionable reason to switch primitive/tool instead of retrying the
same failed path.
"""
from __future__ import annotations

import re
from typing import Any


FailureResult = dict[str, Any]


GUIDANCE: dict[str, str] = {
    "auth_required": (
        "Authenticate first. Use supplied lab credentials or list/swap sessions, "
        "then replay the same endpoint with session state."
    ),
    "csrf_token": (
        "Capture a fresh form/API request and preserve CSRF token, cookie, "
        "Origin, and Referer behavior before retrying."
    ),
    "oob_unavailable": (
        "Do not loop on blind payloads. Restore interactsh/OOB tooling or pivot "
        "to in-band/time/differential proof where the lab allows it."
    ),
    "caido_bridge_unavailable": (
        "Use direct http_request/run_shell curl for now, or start the Caido local "
        "bridge before relying on Replay/history artifacts."
    ),
    "tool_missing": (
        "Call tool_inventory once, verify installed tooling, then use an "
        "available equivalent instead of repeating the missing command."
    ),
    "scope_blocked": (
        "Adjust the payload so the direct request stays in scope. Internal hosts "
        "are allowed only as SSRF payload destinations through the lab app."
    ),
    "timeout": (
        "Separate target delay from network instability: capture a baseline, "
        "increase timeout once, then use differential or OOB evidence."
    ),
    "schema_llm": (
        "Re-dispatch with a narrower task and require one valid JSON action. "
        "Avoid long prose and unsupported schema fields."
    ),
    "duplicate_loop": (
        "Stop repeating that payload/tool call. Change context, encoding, "
        "detection primitive, or vulnerability hypothesis."
    ),
    "browser_needed": (
        "Use browser tools for JS-rendered flows, DOM sinks, SameSite behavior, "
        "postMessage, or workflows that require real navigation."
    ),
    "wrong_endpoint": (
        "Return to recon/history and confirm the exact observed endpoint, method, "
        "content type, and parameter before exploiting."
    ),
    "weak_signal": (
        "Add a control request and compare baseline vs probe. Do not claim "
        "success until the signal is causal and reproducible."
    ),
    "no_signal": (
        "Switch detection primitive: in-band to differential, differential to "
        "timing, timing to OOB, or pivot to a hotter finding."
    ),
    "unknown": (
        "Summarize the last request/response and pick the smallest next probe "
        "that can confirm or refute the current hypothesis."
    ),
}


PATTERNS: list[tuple[str, list[str], float]] = [
    ("scope_blocked", ["scope violation", "out of scope", "blocked by scope"], 0.95),
    ("auth_required", ["401", "403", "unauthorized", "forbidden", "login required", "not logged in", "authenticate"], 0.85),
    ("csrf_token", ["csrf", "invalid token", "missing token", "anti-csrf", "xsrf"], 0.85),
    ("oob_unavailable", ["interactsh", "oob", "collaborator", "no interactions", "callback server", "oast"], 0.75),
    ("caido_bridge_unavailable", ["caido local", "bridge", "connection refused", "replay unavailable"], 0.8),
    ("tool_missing", ["command not found", "not recognized", "no such file", "missing command", "unknown option", "unrecognized option"], 0.8),
    ("timeout", ["timeout", "timed out", "read timed out", "deadline", "504"], 0.75),
    ("schema_llm", ["validation error", "json", "pydantic", "schema", "coordinator returned"], 0.75),
    ("duplicate_loop", ["duplicate", "already tried", "known failed attempt", "same payload"], 0.8),
    ("browser_needed", ["javascript", "js-heavy", "spa", "dom", "samesite", "postmessage", "browser"], 0.7),
    ("wrong_endpoint", ["404", "not found", "wrong endpoint", "method not allowed", "405", "unsupported media type", "415"], 0.65),
    ("weak_signal", ["partial", "ambiguous", "flaky", "not reproducible", "weak signal", "shaky"], 0.7),
    ("no_signal", ["no effect", "no signal", "unchanged", "did not increase", "could not exploit", "failure"], 0.6),
]


def _flatten(summary: str, recent_failures: list[dict[str, Any]] | None) -> str:
    parts = [summary or ""]
    for item in recent_failures or []:
        parts.extend(
            str(item.get(key, ""))
            for key in ("tool", "phase", "reason", "lesson", "args")
        )
    return " ".join(parts).lower()


def _same_failure_count(recent_failures: list[dict[str, Any]] | None) -> int:
    if not recent_failures:
        return 0
    fingerprints: dict[str, int] = {}
    for item in recent_failures:
        key = "|".join(str(item.get(k, ""))[:80] for k in ("tool", "reason", "lesson"))
        fingerprints[key] = fingerprints.get(key, 0) + 1
    return max(fingerprints.values(), default=0)


def classify_failure(
    summary: str,
    recent_failures: list[dict[str, Any]] | None = None,
    last_result: Any | None = None,
) -> FailureResult:
    """Classify a failed agent/tool outcome into a pivot category."""
    text = _flatten(summary, recent_failures)
    if last_result is not None:
        text += " " + str(getattr(last_result, "next_recommendation", "") or "").lower()

    duplicate_count = _same_failure_count(recent_failures)
    if duplicate_count >= 3:
        category = "duplicate_loop"
        confidence = 0.9
        matched = ["repeated recent failure fingerprint"]
    else:
        category = "unknown"
        confidence = 0.4
        matched = []
        for candidate, needles, score in PATTERNS:
            hits = [needle for needle in needles if needle in text]
            if hits:
                category = candidate
                confidence = score
                matched = hits[:4]
                break

    if category == "unknown" and re.search(r"\b5\d\d\b", text):
        category = "timeout"
        confidence = 0.55
        matched = ["5xx server error"]

    return {
        "category": category,
        "confidence": confidence,
        "matched": matched,
        "guidance": GUIDANCE[category],
    }
