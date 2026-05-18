"""Bounded subagent scheduling.

This module deliberately avoids an unconstrained "swarm". It gives the
orchestrator a small, auditable way to run independent lanes in parallel while
serializing anything that can mutate target state.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Literal

from hacking_agent.core.events import emit
from hacking_agent.core.schemas import AgentResult


SubagentLane = Literal[
    "profile",
    "readiness",
    "recon",
    "research",
    "analysis",
    "exploitation",
    "validation",
]

SubagentStatus = Literal["completed", "failed", "skipped"]


@dataclass(frozen=True)
class SubagentSpec:
    """One bounded unit of work for a subagent lane."""

    name: str
    lane: SubagentLane
    run: Callable[[], AgentResult]
    reason: str = ""
    mutates_target: bool = False
    requires_serial: bool = False


@dataclass(frozen=True)
class SubagentRun:
    """Result summary for one subagent lane."""

    name: str
    lane: SubagentLane
    status: SubagentStatus
    success: bool
    summary: str
    elapsed_sec: float = 0.0
    error: str = ""
    parallel: bool = False


@dataclass(frozen=True)
class SubagentPolicy:
    """Safety policy for bounded subagent execution."""

    enabled: bool = True
    max_parallel: int = 4
    allow_stateful_parallel: bool = False
    allow_stateful_serial: bool = True


class BoundedSubagentScheduler:
    """Run independent subagent lanes with explicit state-mutation controls."""

    def __init__(self, policy: SubagentPolicy | None = None):
        self.policy = policy or SubagentPolicy()

    def can_parallelize(
        self,
        spec: SubagentSpec,
        lab_profile: dict | None = None,
    ) -> bool:
        """Return True if this subagent may run in the parallel pool."""
        if not self.policy.enabled:
            return False
        if spec.requires_serial:
            return False
        if not spec.mutates_target:
            return True
        playbook_id = (lab_profile or {}).get("playbook_id")
        return bool(
            self.policy.allow_stateful_parallel
            and spec.lane == "exploitation"
            and playbook_id == "race_condition"
        )

    def run(
        self,
        specs: list[SubagentSpec],
        lab_profile: dict | None = None,
    ) -> list[SubagentRun]:
        """Run safe specs in parallel and stateful specs serially.

        The ordering is intentional: read-only/profile/readiness work enriches
        memory before any serialized state-changing lane can use that context.
        """
        if not specs:
            return []
        if not self.policy.enabled:
            return [
                SubagentRun(
                    name=spec.name,
                    lane=spec.lane,
                    status="skipped",
                    success=False,
                    summary="Subagents disabled by policy.",
                )
                for spec in specs
            ]

        parallel_specs: list[SubagentSpec] = []
        serial_specs: list[SubagentSpec] = []
        skipped: list[SubagentRun] = []
        for spec in specs:
            if self.can_parallelize(spec, lab_profile):
                parallel_specs.append(spec)
            elif spec.mutates_target and not self.policy.allow_stateful_serial:
                skipped.append(SubagentRun(
                    name=spec.name,
                    lane=spec.lane,
                    status="skipped",
                    success=False,
                    summary="State-mutating subagent blocked by policy.",
                ))
            else:
                serial_specs.append(spec)

        results: list[SubagentRun] = []
        results.extend(self._run_parallel(parallel_specs))
        results.extend(self._run_serial(serial_specs))
        results.extend(skipped)
        return results

    def _run_parallel(self, specs: list[SubagentSpec]) -> list[SubagentRun]:
        if not specs:
            return []
        worker_count = max(1, min(self.policy.max_parallel, len(specs)))
        emit("subagents_start", {
            "mode": "parallel",
            "count": len(specs),
            "workers": worker_count,
            "lanes": [spec.lane for spec in specs],
        })
        results: list[SubagentRun] = []
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="subagent") as pool:
            futures = {pool.submit(self._run_one, spec, True): spec for spec in specs}
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                emit("subagent_result", result.__dict__)
        emit("subagents_done", {
            "mode": "parallel",
            "count": len(results),
            "successes": sum(1 for item in results if item.success),
        })
        return results

    def _run_serial(self, specs: list[SubagentSpec]) -> list[SubagentRun]:
        results: list[SubagentRun] = []
        for spec in specs:
            emit("subagents_start", {
                "mode": "serial",
                "count": 1,
                "workers": 1,
                "lanes": [spec.lane],
            })
            result = self._run_one(spec, False)
            results.append(result)
            emit("subagent_result", result.__dict__)
        return results

    def _run_one(self, spec: SubagentSpec, parallel: bool) -> SubagentRun:
        started = time.monotonic()
        try:
            result = spec.run()
            return SubagentRun(
                name=spec.name,
                lane=spec.lane,
                status="completed",
                success=result.success,
                summary=result.summary,
                elapsed_sec=round(time.monotonic() - started, 3),
                parallel=parallel,
            )
        except Exception as exc:
            return SubagentRun(
                name=spec.name,
                lane=spec.lane,
                status="failed",
                success=False,
                summary=f"Subagent crashed: {exc}",
                elapsed_sec=round(time.monotonic() - started, 3),
                error=str(exc),
                parallel=parallel,
            )
