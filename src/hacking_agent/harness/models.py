"""Typed models for the run harness (submission requests + run records)."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

ScopeEntry = Annotated[str, Field(min_length=1, max_length=4096)]


class RunStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (RunStatus.completed, RunStatus.failed, RunStatus.cancelled)


class AuthSessionSpec(BaseModel):
    """A controlled identity for authenticated / authorization testing."""
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    role_hint: str = Field(default="user", max_length=128)
    cookie_header: str = Field(default="", max_length=32768)
    headers: dict[str, str] = Field(default_factory=dict, max_length=64)

    @field_validator("cookie_header", "headers")
    @classmethod
    def reject_header_injection(cls, value: Any) -> Any:
        values = [value] if isinstance(value, str) else [*value.keys(), *value.values()]
        if any("\r" in item or "\n" in item or "\x00" in item or len(item) > 32768
               for item in values):
            raise ValueError("session headers must be bounded single-line values")
        if isinstance(value, dict) and any(
            not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) for key in value
        ):
            raise ValueError("invalid session header name")
        return value


class RunRequest(BaseModel):
    """A run submitted from the console form.

    Scope + the explicit ``authorized`` acknowledgement are mandatory: the
    harness refuses to launch anything without an authorized scope (mirroring
    reynard-assess). The LLM API key is NEVER part of this model — it is read
    from the server environment and passed to the worker via env only."""
    targets: list[ScopeEntry] = Field(default_factory=list, max_length=100)
    authorized_domains: list[ScopeEntry] = Field(default_factory=list, max_length=1000)
    authorized_cidrs: list[ScopeEntry] = Field(default_factory=list, max_length=1000)
    authorized_url_prefixes: list[ScopeEntry] = Field(default_factory=list, max_length=1000)
    out_of_scope: list[ScopeEntry] = Field(default_factory=list, max_length=1000)
    description: str = Field(default="", max_length=20000)
    mission_mode: Literal["production", "benchmark"] = "production"
    max_iterations: int = Field(default=30, ge=1, le=1000)
    per_target_timeout: float = Field(default=1800.0, gt=0, le=86400, allow_inf_nan=False)
    max_requests_per_second: float = Field(default=0.0, ge=0, le=1000, allow_inf_nan=False)
    max_total_requests: int = Field(default=0, ge=0, le=1000000)
    allow_destructive: bool = False
    auth_sessions: list[AuthSessionSpec] = Field(default_factory=list, max_length=20)
    enable_browser_use: bool = False
    enable_hexstrike: bool = False
    authorized: bool = False          # explicit "I am authorized to test this scope"

    @field_validator("auth_sessions")
    @classmethod
    def bound_session_payload(cls, value: list[AuthSessionSpec]) -> list[AuthSessionSpec]:
        if sum(len(session.model_dump_json().encode()) for session in value) > 262144:
            raise ValueError("combined auth session configuration exceeds 256 KiB")
        if len({session.name for session in value}) != len(value):
            raise ValueError("auth session names must be unique")
        return value

    def has_scope(self) -> bool:
        return bool(
            self.authorized_domains
            or self.authorized_cidrs
            or self.authorized_url_prefixes
        )

    def authorization_error(self) -> Optional[str]:
        """Return a human-readable refusal reason, or None if runnable."""
        if not self.authorized:
            return ("Authorization required: confirm you are authorized to test "
                    "this scope.")
        if not self.has_scope():
            return ("No authorized scope: provide at least one authorized domain "
                    "or CIDR.")
        if not (self.targets or self.authorized_domains):
            return "Provide at least one target URL or authorized domain."
        from hacking_agent.core.engagement import engagement_from_dict
        from hacking_agent.core.scope import ScopeGuard
        try:
            guard = ScopeGuard.from_engagement(engagement_from_dict(self.to_engagement_dict()))
            if any(not guard.is_in_scope(target) for target in self.resolved_targets()):
                return "Every target must be inside the authorized scope and outside exclusions."
        except ValueError as exc:
            return f"Invalid authorized scope: {exc}"
        return None

    def to_engagement_dict(self) -> dict[str, Any]:
        """Map to the Engagement config shape (see core/engagement.py)."""
        return {
            "engagement_name": "harness-run",
            "authorized_domains": list(self.authorized_domains),
            "authorized_cidrs": list(self.authorized_cidrs),
            "authorized_url_prefixes": list(self.authorized_url_prefixes),
            "out_of_scope": list(self.out_of_scope),
            "max_requests_per_second": self.max_requests_per_second,
            "max_total_requests": self.max_total_requests,
            "allow_destructive": self.allow_destructive,
            "notes": (self.description or "")[:1000],
        }

    def resolved_targets(self) -> list[str]:
        """Explicit targets if given, else derive https URLs from domains."""
        if self.targets:
            return [t if "://" in t else f"https://{t}" for t in self.targets]
        return [f"https://{d.strip()}/" for d in self.authorized_domains if d.strip()]


class RunRecord(BaseModel):
    """Persisted metadata for a run (status index)."""
    id: str
    status: RunStatus = RunStatus.queued
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    targets: list[str] = Field(default_factory=list)
    description: str = ""
    findings_count: int = 0
    verified_count: int = 0
    suppressed_count: int = 0
    error: str = ""
    pid: Optional[int] = None
    exit_code: Optional[int] = None

    def to_row(self) -> dict[str, Any]:
        return self.model_dump()
