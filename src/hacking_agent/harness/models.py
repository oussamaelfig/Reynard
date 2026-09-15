"""Typed models for the run harness (submission requests + run records)."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


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
    name: str
    role_hint: str = "user"           # anonymous | user | admin | ...
    cookie_header: str = ""           # "session=abc; other=def"
    headers: dict[str, str] = Field(default_factory=dict)  # e.g. Authorization: Bearer ...


class RunRequest(BaseModel):
    """A run submitted from the console form.

    Scope + the explicit ``authorized`` acknowledgement are mandatory: the
    harness refuses to launch anything without an authorized scope (mirroring
    reynard-assess). The LLM API key is NEVER part of this model — it is read
    from the server environment and passed to the worker via env only."""
    targets: list[str] = Field(default_factory=list)
    authorized_domains: list[str] = Field(default_factory=list)
    authorized_cidrs: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    description: str = ""              # free-text objective / prompt from the operator
    mission_mode: str = "production"
    max_iterations: int = 30
    per_target_timeout: float = 1800.0
    max_requests_per_second: float = 0.0
    max_total_requests: int = 0
    allow_destructive: bool = False
    auth_sessions: list[AuthSessionSpec] = Field(default_factory=list)
    enable_browser_use: bool = False
    enable_hexstrike: bool = False
    authorized: bool = False          # explicit "I am authorized to test this scope"

    def has_scope(self) -> bool:
        return bool(self.authorized_domains or self.authorized_cidrs)

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
        return None

    def to_engagement_dict(self) -> dict[str, Any]:
        """Map to the Engagement config shape (see core/engagement.py)."""
        return {
            "engagement_name": "harness-run",
            "authorized_domains": list(self.authorized_domains),
            "authorized_cidrs": list(self.authorized_cidrs),
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
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    targets: list[str] = Field(default_factory=list)
    description: str = ""
    findings_count: int = 0
    verified_count: int = 0
    error: str = ""
    pid: Optional[int] = None
    exit_code: Optional[int] = None

    def to_row(self) -> dict[str, Any]:
        return self.model_dump()
