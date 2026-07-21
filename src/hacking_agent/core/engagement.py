"""
=============================================================================
Reynard — Engagement / Rules-of-Engagement Model
=============================================================================
A real, authorized client assessment is bounded by a signed scope and a set
of rules of engagement (RoE): which assets may be tested, which must never be
touched, how fast, for how long, and whether destructive actions are allowed.

This module loads that contract from a YAML/JSON file into a typed
``Engagement`` and hands it to the ``ScopeGuard`` (via ``scope.py``) so every
tool call is validated against it. It is intentionally dependency-light and
side-effect free: it neither performs network I/O nor mutates global state.

Backward compatibility: nothing here is imported by the lab path. When no
engagement file is loaded the ``ScopeGuard`` keeps its original lab behaviour
(open scope from the target URL, no rate limit, destructive actions allowed).

Usage
─────
    from hacking_agent.core.engagement import load_engagement
    from hacking_agent.core.scope import ScopeGuard

    engagement = load_engagement("eval/engagement.sample.yaml")
    guard = ScopeGuard.from_engagement(engagement)
    # ...or attach to an already-built guard:
    guard.attach_engagement(engagement)
=============================================================================
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


class EngagementError(ValueError):
    """Raised when an engagement file is malformed or missing required scope."""


@dataclass
class Engagement:
    """A typed rules-of-engagement contract for an authorized assessment.

    Scope
      - authorized_domains: domains explicitly in scope (subdomains included)
      - authorized_cidrs:   IP ranges explicitly in scope
      - out_of_scope:       hosts/domains that are NEVER in scope, even when
                            they fall inside an authorized domain (a denylist
                            that overrides the allowlist)

    Rules of engagement
      - max_requests_per_second: global min-interval rate limit (0 = unlimited)
      - max_total_requests:      hard cap on scoped requests (0 = unlimited)
      - allow_destructive:       when False, obviously destructive tool/shell
                                 actions are blocked
      - allowed_test_types:      free-form list of permitted test categories
      - testing_window_start/end: ISO-8601 datetimes bounding the window
      - evidence_retention_days:  how long collected evidence may be retained

    Metadata
      - engagement_name / client / tester: report header identity
    """

    engagement_name: str = ""
    client: str = ""
    tester: str = ""

    authorized_domains: list[str] = field(default_factory=list)
    authorized_cidrs: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    max_requests_per_second: float = 0.0
    max_total_requests: int = 0
    allow_destructive: bool = False
    allowed_test_types: list[str] = field(default_factory=list)

    testing_window_start: str = ""
    testing_window_end: str = ""
    evidence_retention_days: int = 0

    notes: str = ""

    # ---- derived checks --------------------------------------------------

    def has_authorized_scope(self) -> bool:
        """True only if at least one authorized domain or CIDR is defined.

        The assessment CLI refuses to run without this — a scope-less
        engagement is not authorization to test anything.
        """
        return bool(self.authorized_domains or self.authorized_cidrs)

    def is_within_window(self, now: datetime | None = None) -> bool:
        """True if ``now`` is inside the testing window.

        An unset start or end is treated as open-ended, so an engagement with
        no window declared is always "within window".
        """
        now = now or datetime.now()
        start = _parse_dt(self.testing_window_start)
        end = _parse_dt(self.testing_window_end)
        if start and now < start:
            return False
        if end and now > end:
            return False
        return True

    def summary(self) -> str:
        """Human-readable one-liner for logging / report headers."""
        parts = [f"engagement={self.engagement_name or 'unnamed'}"]
        if self.client:
            parts.append(f"client={self.client}")
        parts.append(f"domains={self.authorized_domains}")
        if self.authorized_cidrs:
            parts.append(f"cidrs={self.authorized_cidrs}")
        if self.out_of_scope:
            parts.append(f"out_of_scope={self.out_of_scope}")
        parts.append(f"rps={self.max_requests_per_second or 'unlimited'}")
        parts.append(f"max_requests={self.max_total_requests or 'unlimited'}")
        parts.append(f"destructive={'allowed' if self.allow_destructive else 'blocked'}")
        return ", ".join(parts)


# =============================================================================
# Loading
# =============================================================================

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return default


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def _load_raw(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise EngagementError(f"Engagement file not found: {p}")
    text = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()
    raw: Any
    if suffix in (".yaml", ".yml"):
        import yaml

        raw = yaml.safe_load(text)
    else:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            import yaml

            raw = yaml.safe_load(text)
    if raw is None:
        raise EngagementError(f"Engagement file is empty: {p}")
    if isinstance(raw, dict) and isinstance(raw.get("engagement"), dict):
        raw = raw["engagement"]
    if not isinstance(raw, dict):
        raise EngagementError(
            "Engagement file must be a mapping (or a mapping under an "
            "'engagement:' key)."
        )
    return raw


def engagement_from_dict(raw: dict[str, Any]) -> Engagement:
    """Build an ``Engagement`` from a plain dict (already parsed from YAML/JSON).

    Accepts a few aliases so hand-written configs are forgiving:
      - ``domains`` / ``scope`` -> authorized_domains
      - ``cidrs`` -> authorized_cidrs
      - ``deny`` / ``excluded`` -> out_of_scope
      - ``rate_limit_rps`` -> max_requests_per_second
    """
    window = raw.get("testing_window") or {}
    if not isinstance(window, dict):
        window = {}

    return Engagement(
        engagement_name=str(raw.get("engagement_name") or raw.get("name") or ""),
        client=str(raw.get("client") or ""),
        tester=str(raw.get("tester") or ""),
        authorized_domains=_as_str_list(
            raw.get("authorized_domains")
            if raw.get("authorized_domains") is not None
            else raw.get("domains") or raw.get("scope")
        ),
        authorized_cidrs=_as_str_list(
            raw.get("authorized_cidrs")
            if raw.get("authorized_cidrs") is not None
            else raw.get("cidrs")
        ),
        out_of_scope=_as_str_list(
            raw.get("out_of_scope")
            if raw.get("out_of_scope") is not None
            else raw.get("deny") or raw.get("excluded")
        ),
        max_requests_per_second=float(
            raw.get("max_requests_per_second")
            if raw.get("max_requests_per_second") is not None
            else raw.get("rate_limit_rps") or 0.0
        ),
        max_total_requests=int(raw.get("max_total_requests") or 0),
        allow_destructive=_as_bool(raw.get("allow_destructive"), default=False),
        allowed_test_types=_as_str_list(raw.get("allowed_test_types")),
        testing_window_start=str(
            window.get("start") or raw.get("testing_window_start") or ""
        ),
        testing_window_end=str(
            window.get("end") or raw.get("testing_window_end") or ""
        ),
        evidence_retention_days=int(raw.get("evidence_retention_days") or 0),
        notes=str(raw.get("notes") or ""),
    )


def load_engagement(path: str | Path) -> Engagement:
    """Load and validate an engagement config from a YAML or JSON file."""
    raw = _load_raw(path)
    engagement = engagement_from_dict(raw)
    if engagement.max_requests_per_second < 0:
        raise EngagementError("max_requests_per_second cannot be negative.")
    if engagement.max_total_requests < 0:
        raise EngagementError("max_total_requests cannot be negative.")
    return engagement
