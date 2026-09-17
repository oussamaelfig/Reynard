"""
=============================================================================
Reynard — Mission profile (benchmark vs production)
=============================================================================
Reynard runs in two fundamentally different contexts and they must not share
a decision path:

  - BENCHMARK  — intentionally-vulnerable labs (PortSwigger Web Security
                 Academy, XBOW-style benchmarks, CTF boxes). Success is a
                 lab-specific signal ("Congratulations, you solved the lab").
                 Deterministic lab fast-paths and lab-profile seeding are
                 appropriate here and are used ONLY here. Kept as regression
                 tests / benchmarks.

  - PRODUCTION — authorized real-world pentests and bug-bounty assessments.
                 There is no "solved" banner: a result is real only when it is
                 backed by an independently-verified EvidenceBundle. The
                 researcher maps a broad attack surface, investigates
                 anomalies, and reports evidence — no lab assumptions.

This module is the single source of truth for which mode a run is in. It is a
pure classifier with no side effects; the orchestrator threads the resulting
``Mission`` through the run so lab-specific behaviour is gated behind
``mission.is_benchmark`` and the production path is free of lab assumptions.
=============================================================================
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from hacking_agent.core.target_address import parse_target

MODE_BENCHMARK = "benchmark"
MODE_PRODUCTION = "production"

# Hosts that are known intentionally-vulnerable benchmark infrastructure.
LAB_HOST_MARKERS = (
    "web-security-academy.net",
    "portswigger.net",
    "exploit-server.net",
    "0a.web-security-academy.net",
)

_BENCH_ALIASES = {"benchmark", "bench", "lab", "labs"}
_PROD_ALIASES = {"production", "prod", "pentest", "bounty", "assessment", "assess"}


def _host(target_url: str) -> str:
    if not target_url:
        return ""
    try:
        return parse_target(target_url).host
    except (TypeError, ValueError):
        return ""


def is_lab_host(target_url: str) -> bool:
    host = _host(target_url)
    return any(host == marker or host.endswith(f".{marker}") for marker in LAB_HOST_MARKERS)


def normalize_mode(value: str | None) -> str | None:
    """Map a free-form mode string (CLI flag / env) to a canonical mode."""
    v = (value or "").strip().lower()
    if not v:
        return None
    if v in _BENCH_ALIASES:
        return MODE_BENCHMARK
    if v in _PROD_ALIASES:
        return MODE_PRODUCTION
    return None


def detect_mode(target_url: str = "", objective: str = "", *,
                explicit: str | None = None,
                engagement_attached: bool = False,
                lab_profile: dict | None = None) -> str:
    """Decide the mission mode.

    Precedence:
      1. an attached engagement (reynard-assess) => production
      2. explicit override (CLI flag / REYNARD_MISSION_MODE env)
      3. a non-empty lab profile passed in => benchmark
      4. a known lab host => benchmark
      5. default => production (removes lab assumptions from the default path)
    """
    if engagement_attached:
        return MODE_PRODUCTION
    override = normalize_mode(explicit) or normalize_mode(os.getenv("REYNARD_MISSION_MODE"))
    if override:
        return override
    if lab_profile:
        return MODE_BENCHMARK
    if is_lab_host(target_url):
        return MODE_BENCHMARK
    return MODE_PRODUCTION


@dataclass
class Mission:
    """The resolved mode + context for a single run."""
    mode: str = MODE_PRODUCTION
    target_url: str = ""
    objective: str = ""
    source: str = "default"

    @property
    def is_benchmark(self) -> bool:
        return self.mode == MODE_BENCHMARK

    @property
    def is_production(self) -> bool:
        return self.mode == MODE_PRODUCTION

    def describe(self) -> str:
        return f"mission={self.mode} (via {self.source})"

    @classmethod
    def detect(cls, target_url: str = "", objective: str = "", *,
               explicit: str | None = None, engagement_attached: bool = False,
               lab_profile: dict | None = None) -> "Mission":
        # Determine provenance for transparency in logs.
        if engagement_attached:
            source = "engagement"
        elif normalize_mode(explicit):
            source = "explicit"
        elif normalize_mode(os.getenv("REYNARD_MISSION_MODE")):
            source = "env"
        elif lab_profile:
            source = "lab_profile"
        elif is_lab_host(target_url):
            source = "lab_host"
        else:
            source = "default"
        mode = detect_mode(target_url, objective, explicit=explicit,
                           engagement_attached=engagement_attached,
                           lab_profile=lab_profile)
        return cls(mode=mode, target_url=target_url, objective=objective, source=source)
