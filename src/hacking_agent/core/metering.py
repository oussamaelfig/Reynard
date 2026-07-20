"""
=============================================================================
Reynard — Token / Cost Metering
=============================================================================
A process-wide, thread-safe accumulator for LLM token usage. Every provider
records prompt/completion tokens per agent role here; the orchestrator and the
live eval harness read the totals to surface cumulative tokens, an estimated
cost, and to enforce a hard token/cost budget cap.

Cost estimation uses configurable per-1k input/output prices via env vars
(LLM_INPUT_PRICE_PER_1K / LLM_OUTPUT_PRICE_PER_1K), defaulting to 0 so no cost
is shown unless the operator supplies prices for their provider.
=============================================================================
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass


def _env_float(name: str, default: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass
class RoleUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def as_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "calls": self.calls,
        }


class TokenMeter:
    """Thread-safe per-role token accumulator with cost estimation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_role: dict[str, RoleUsage] = {}

    def record(self, role: str, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        with self._lock:
            usage = self._by_role.setdefault(role or "default", RoleUsage())
            usage.prompt_tokens += int(prompt_tokens or 0)
            usage.completion_tokens += int(completion_tokens or 0)
            usage.calls += 1

    def totals(self) -> dict[str, int]:
        with self._lock:
            prompt = sum(u.prompt_tokens for u in self._by_role.values())
            completion = sum(u.completion_tokens for u in self._by_role.values())
            calls = sum(u.calls for u in self._by_role.values())
        return {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
            "calls": calls,
        }

    def by_role(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {role: usage.as_dict() for role, usage in self._by_role.items()}

    def estimated_cost(
        self,
        input_price_per_1k: float | None = None,
        output_price_per_1k: float | None = None,
    ) -> float:
        """Estimate USD cost. Prices default to env vars, then to 0."""
        if input_price_per_1k is None:
            input_price_per_1k = _env_float("LLM_INPUT_PRICE_PER_1K", 0.0)
        if output_price_per_1k is None:
            output_price_per_1k = _env_float("LLM_OUTPUT_PRICE_PER_1K", 0.0)
        totals = self.totals()
        cost = (
            (totals["prompt_tokens"] / 1000.0) * input_price_per_1k
            + (totals["completion_tokens"] / 1000.0) * output_price_per_1k
        )
        return round(cost, 6)

    def snapshot(self) -> dict[str, object]:
        """Full metering snapshot for scorecards / final results."""
        return {
            "totals": self.totals(),
            "by_role": self.by_role(),
            "estimated_cost_usd": self.estimated_cost(),
        }

    def reset(self) -> None:
        with self._lock:
            self._by_role.clear()


GLOBAL_TOKEN_METER = TokenMeter()


def get_token_meter() -> TokenMeter:
    return GLOBAL_TOKEN_METER
