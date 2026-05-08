"""
=============================================================================
Hacking Agent — Shared Memory + Knowledge Graph
=============================================================================
Two layers, one store, all agents read/write through it.

  1. KNOWLEDGE GRAPH    Typed entities and relationships:
                          Target -[HAS_ENDPOINT]->     Endpoint
                          Endpoint -[HAS_PARAMETER]->  Parameter
                          Target -[USES_TECHNOLOGY]->  Technology
                          Target -[POTENTIALLY_VULN_TO]-> Vulnerability
                          Vulnerability -[EVIDENCED_BY]-> PoC
                        Each entity has its own attribute bag and fact set,
                        so per-target / per-endpoint state is scoped instead
                        of jumbled in a single global namespace.

  2. LEGACY GLOBAL FACTS / PAYLOAD HISTORY / PROGRESS
                        Preserved verbatim so the existing single-agent
                        `agent.py` and the strategy.py phase pipeline keep
                        working unchanged.

This module is THREAD-SAFE — agents may run concurrently against the same
memory bus.
=============================================================================
"""
from __future__ import annotations

import hashlib
import json
import math
import threading
import time as _time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# =============================================================================
# Pheromone defaults — per entity type
# =============================================================================
# Inspired by Pentest-Swarm-AI's pheromones.yaml.  Higher base = agents
# attend sooner; shorter half-life = stale findings decay faster.

PHEROMONE_DEFAULTS: dict[str, tuple[float, int]] = {
    # entity_type        → (base, half_life_sec)
    "Target":             (1.0,  86400),   # 24h  — root target stays hot
    "Endpoint":           (0.6,  7200),    # 2h
    "Parameter":          (0.7,  3600),    # 1h
    "Technology":         (0.5,  7200),    # 2h
    "Vulnerability":      (0.9,  10800),   # 3h   — vulns are urgent
    "PoC":                (0.7,  1800),    # 30m  — PoCs age out fast
    "Credential":         (0.8,  900),     # 15m  — creds expire quickly
}


# =============================================================================
# Atomic types
# =============================================================================

@dataclass
class PayloadRecord:
    """One payload attempt + its analyzed result. Used for dedup."""
    payload: str
    hypothesis: str
    phase: str
    result: str            # "reflected" | "blocked" | "executed" | "error" | ...
    signals: dict          # Structured analyzer output
    iteration: int


@dataclass
class FailureRecord:
    """A failed tool attempt and the lesson learned from it."""
    fingerprint: str
    tool: str
    args_summary: str
    phase: str
    reason: str
    lesson: str
    iteration: int
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class Fact:
    """A discovered truth — global or scoped to a single Entity."""
    key: str
    value: Any
    confidence: str        # "confirmed" | "suspected" | "disproven"
    source: str
    iteration: int


@dataclass
class Entity:
    """A typed node in the knowledge graph.

    Pheromone fields (inspired by Pentest-Swarm-AI):
      pheromone_base   — initial weight (0–1); higher = more urgent
      half_life_sec    — seconds for the weight to halve; shorter = faster decay
      _created_ts      — monotonic timestamp for decay math
    """
    id: str
    type: str
    attrs: dict[str, Any] = field(default_factory=dict)
    facts: dict[str, Fact] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    pheromone_base: float = 0.5
    half_life_sec: int = 3600
    _created_ts: float = field(default_factory=_time.monotonic)

    def pheromone_weight(self) -> float:
        """Current decayed pheromone weight.

        Formula:  weight = base × 0.5^(age / half_life)
        """
        if self.half_life_sec <= 0:
            return self.pheromone_base
        age = _time.monotonic() - self._created_ts
        return self.pheromone_base * math.pow(0.5, age / self.half_life_sec)

    def heat_label(self) -> str:
        """Human-readable heat indicator for prompt injection."""
        w = self.pheromone_weight()
        if w >= 0.8:
            return "[HOT]"
        if w >= 0.5:
            return "[WARM]"
        if w >= 0.2:
            return "[COOL]"
        return "[COLD]"


@dataclass
class Relationship:
    """A typed directed edge between two entities."""
    from_id: str
    to_id: str
    rel_type: str
    attrs: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# AgentMemory — the shared bus
# =============================================================================

class AgentMemory:
    """Thread-safe shared memory for all agents."""

    # Phases of the inner exploitation pipeline (used by single-agent agent.py
    # and by recon's progress hand-off).
    DEFAULT_PHASES = ("recon", "injection", "context", "capability", "escape", "exploit")

    def __init__(self, target_url: str = ""):
        self._lock = threading.RLock()

        # --- Knowledge graph layer ---
        self._entities: dict[str, Entity] = {}
        self._relationships: list[Relationship] = []
        self._entity_seq: dict[str, int] = {}

        # --- Legacy / global layer ---
        self.facts: dict[str, Fact] = {}
        self.payload_history: list[PayloadRecord] = []
        self._payload_hashes: set[str] = set()
        self.failed_attempts: list[FailureRecord] = []
        self._failed_attempt_hashes: set[str] = set()
        self.progress: dict[str, str] = {p: "pending" for p in self.DEFAULT_PHASES}
        self.current_hypothesis: str = ""
        self.target_url: str = target_url
        self.target_type: str = ""

    # =====================================================================
    # KG: entity access
    # =====================================================================

    @property
    def entities(self) -> dict[str, Entity]:
        """Public read-only access to the entity store."""
        return self._entities

    # =====================================================================
    # KG: entities
    # =====================================================================

    def new_entity_id(self, entity_type: str) -> str:
        with self._lock:
            self._entity_seq[entity_type] = self._entity_seq.get(entity_type, 0) + 1
            return f"{entity_type.lower()}:{self._entity_seq[entity_type]}"

    def add_entity(self, entity_type: str, attrs: dict[str, Any] | None = None,
                    entity_id: str | None = None,
                    pheromone_base: float | None = None,
                    half_life_sec: int | None = None) -> Entity:
        """Create or merge an entity. Idempotent on entity_id.

        If pheromone_base / half_life_sec are not given, defaults are
        looked up from PHEROMONE_DEFAULTS by entity_type.
        """
        with self._lock:
            eid = entity_id or self.new_entity_id(entity_type)
            if eid in self._entities:
                self._entities[eid].attrs.update(attrs or {})
                # Refresh pheromone if explicitly provided on merge
                if pheromone_base is not None:
                    self._entities[eid].pheromone_base = pheromone_base
                if half_life_sec is not None:
                    self._entities[eid].half_life_sec = half_life_sec
                return self._entities[eid]

            defaults = PHEROMONE_DEFAULTS.get(entity_type, (0.5, 3600))
            e = Entity(
                id=eid,
                type=entity_type,
                attrs=attrs or {},
                pheromone_base=pheromone_base if pheromone_base is not None else defaults[0],
                half_life_sec=half_life_sec if half_life_sec is not None else defaults[1],
            )
            self._entities[eid] = e
            return e

    def get_entity(self, entity_id: str) -> Entity | None:
        with self._lock:
            return self._entities.get(entity_id)

    def query(self, entity_type: str | None = None, **attr_filters) -> list[Entity]:
        """Query entities by type and/or attribute equality."""
        with self._lock:
            out: list[Entity] = []
            for e in self._entities.values():
                if entity_type and e.type != entity_type:
                    continue
                if all(e.attrs.get(k) == v for k, v in attr_filters.items()):
                    out.append(e)
            return out

    def ranked_query(self, entity_type: str | None = None,
                     min_pheromone: float = 0.0,
                     **attr_filters) -> list[Entity]:
        """Query entities sorted by decayed pheromone weight (descending).

        This is the core coordination primitive: agents call this to get
        findings ordered by urgency — hot leads first, stale ones last.
        Findings below min_pheromone are excluded entirely.
        """
        with self._lock:
            candidates = self.query(entity_type, **attr_filters)
            alive = [e for e in candidates if e.pheromone_weight() >= min_pheromone]
            alive.sort(key=lambda e: e.pheromone_weight(), reverse=True)
            return alive

    def boost_entity(self, entity_id: str, new_base: float | None = None) -> None:
        """Boost an entity's pheromone weight (e.g. after a successful PoC).

        Also resets the created_ts so the decay starts fresh.
        """
        with self._lock:
            e = self._entities.get(entity_id)
            if not e:
                return
            if new_base is not None:
                e.pheromone_base = min(new_base, 1.0)
            e._created_ts = _time.monotonic()

    # =====================================================================
    # KG: relationships
    # =====================================================================

    def add_relationship(self, from_id: str, rel_type: str, to_id: str,
                          attrs: dict | None = None) -> Relationship:
        with self._lock:
            if from_id not in self._entities or to_id not in self._entities:
                raise KeyError(f"add_relationship: missing entity ({from_id} or {to_id})")
            rel = Relationship(from_id=from_id, to_id=to_id, rel_type=rel_type, attrs=attrs or {})
            self._relationships.append(rel)
            return rel

    def neighbors(self, entity_id: str, rel_type: str | None = None,
                  direction: str = "out") -> list[Entity]:
        """Walk the graph. direction in ('out', 'in', 'both')."""
        with self._lock:
            out: list[Entity] = []
            for r in self._relationships:
                if rel_type and r.rel_type != rel_type:
                    continue
                if direction in ("out", "both") and r.from_id == entity_id:
                    e = self._entities.get(r.to_id)
                    if e:
                        out.append(e)
                if direction in ("in", "both") and r.to_id == entity_id:
                    e = self._entities.get(r.from_id)
                    if e:
                        out.append(e)
            return out

    # =====================================================================
    # Facts (global or entity-scoped)
    # =====================================================================

    def add_fact(self, key: str, value: Any, confidence: str = "confirmed",
                 source: str = "", iteration: int = 0,
                 entity_id: str | None = None) -> str:
        """Add or update a fact. If entity_id is given, scope to that entity.

        Refuses to silently downgrade a `confirmed` fact to a weaker
        confidence — returns a warning string instead.
        """
        with self._lock:
            target = (self._entities[entity_id].facts
                      if entity_id and entity_id in self._entities
                      else self.facts)
            if key in target:
                old = target[key]
                if old.value == value:
                    return f"Fact '{key}' unchanged."
                if old.confidence == "confirmed" and confidence != "confirmed":
                    return f"WARNING: refusing to downgrade '{key}' (was {old.value})."
                msg = f"UPDATED '{key}': {old.value} -> {value}"
            else:
                msg = f"NEW '{key}': {value}"
            target[key] = Fact(
                key=key, value=value, confidence=confidence,
                source=source, iteration=iteration,
            )
            return msg

    def get_fact(self, key: str, default: Any = None,
                 entity_id: str | None = None) -> Any:
        with self._lock:
            target = (self._entities[entity_id].facts
                      if entity_id and entity_id in self._entities else self.facts)
            return target[key].value if key in target else default

    def get_all_facts(self, entity_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            target = (self._entities[entity_id].facts
                      if entity_id and entity_id in self._entities else self.facts)
            return {k: f.value for k, f in target.items()}

    # =====================================================================
    # Payload history & dedup (global, shared across agents)
    # =====================================================================

    def _hash_payload(self, payload: str) -> str:
        return payload.strip().lower()

    def is_duplicate(self, payload: str) -> bool:
        with self._lock:
            return self._hash_payload(payload) in self._payload_hashes

    def add_payload(self, payload: str, hypothesis: str, phase: str,
                    result: str, signals: dict, iteration: int) -> str:
        with self._lock:
            h = self._hash_payload(payload)
            if h in self._payload_hashes:
                return f"DUPLICATE skipped: {payload[:80]}"
            self._payload_hashes.add(h)
            self.payload_history.append(PayloadRecord(
                payload=payload, hypothesis=hypothesis, phase=phase,
                result=result, signals=signals, iteration=iteration,
            ))
            return f"Payload #{len(self.payload_history)} recorded"

    def get_recent_payloads(self, n: int = 10) -> list[dict]:
        with self._lock:
            return [
                {"payload": p.payload[:120], "hypothesis": p.hypothesis,
                 "result": p.result, "phase": p.phase}
                for p in self.payload_history[-n:]
            ]

    def get_payload_count(self) -> int:
        with self._lock:
            return len(self.payload_history)

    # =====================================================================
    # Failed-attempt memory (prevents repeating known-bad paths)
    # =====================================================================

    def tool_attempt_fingerprint(self, tool: str, args: dict[str, Any]) -> str:
        """Stable hash for an exact tool call."""
        canonical = json.dumps(args or {}, sort_keys=True, default=str)
        return hashlib.sha256(f"{tool}:{canonical}".encode("utf-8")).hexdigest()

    def is_known_failed_attempt(self, tool: str, args: dict[str, Any]) -> bool:
        with self._lock:
            return self.tool_attempt_fingerprint(tool, args) in self._failed_attempt_hashes

    def add_failed_attempt(
        self,
        tool: str,
        args: dict[str, Any],
        phase: str,
        reason: str,
        lesson: str,
        iteration: int,
    ) -> str:
        with self._lock:
            fingerprint = self.tool_attempt_fingerprint(tool, args)
            if fingerprint in self._failed_attempt_hashes:
                return f"Known failed attempt already recorded: {tool}"
            self._failed_attempt_hashes.add(fingerprint)
            args_summary = json.dumps(args or {}, sort_keys=True, default=str)[:300]
            self.failed_attempts.append(FailureRecord(
                fingerprint=fingerprint,
                tool=tool,
                args_summary=args_summary,
                phase=phase,
                reason=reason[:300],
                lesson=lesson[:300],
                iteration=iteration,
            ))
            return f"Failed attempt #{len(self.failed_attempts)} recorded"

    def get_recent_failures(self, n: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "tool": f.tool,
                    "phase": f.phase,
                    "reason": f.reason,
                    "lesson": f.lesson,
                    "args": f.args_summary,
                    "iteration": f.iteration,
                }
                for f in self.failed_attempts[-n:]
            ]

    def failure_summary(self, n: int = 10) -> str:
        with self._lock:
            recent = self.get_recent_failures(n)
            if not recent:
                return "## FAILED ATTEMPTS\n(none recorded)"
            lines = [f"## FAILED ATTEMPTS ({len(self.failed_attempts)} total, last {len(recent)})"]
            for i, item in enumerate(recent, 1):
                lines.append(
                    f"  {i}. [{item['phase']}/{item['tool']}] {item['reason']} "
                    f"-> lesson: {item['lesson']}"
                )
            return "\n".join(lines)

    # =====================================================================
    # Phase progress (legacy / strategy.py)
    # =====================================================================

    def update_progress(self, phase: str, status: str) -> str:
        with self._lock:
            if phase not in self.progress:
                return f"Unknown phase: {phase}"
            old = self.progress[phase]
            self.progress[phase] = status
            return f"Phase '{phase}': {old} -> {status}"

    def get_progress_string(self) -> str:
        icons = {"pending": "( )", "in_progress": "(*)",
                 "done": "(+)", "skipped": "(-)"}
        with self._lock:
            return "\n".join(
                f"  {icons.get(s, '[?]')} {p.upper()}: {s}"
                for p, s in self.progress.items()
            )

    def get_current_phase(self) -> str:
        with self._lock:
            for phase, status in self.progress.items():
                if status in ("pending", "in_progress"):
                    return phase
            return "exploit"

    # =====================================================================
    # Prompt-injection snapshots (read by every agent before each LLM call)
    # =====================================================================

    def kg_snapshot(self, max_per_type: int = 25) -> str:
        """Compact text rendering of the KG for prompt injection.

        Entities are sorted by pheromone weight within each type bucket,
        and each entity shows its current heat label so the Coordinator
        can see at a glance which findings are worth pursuing.
        """
        with self._lock:
            buckets: dict[str, list[Entity]] = {}
            for e in self._entities.values():
                buckets.setdefault(e.type, []).append(e)

            if not buckets:
                return "## KNOWLEDGE GRAPH\n(empty — recon has not started)"

            lines = ["## KNOWLEDGE GRAPH"]
            for etype in ("Target", "Endpoint", "Parameter", "Technology",
                           "Vulnerability", "PoC", "Credential"):
                ents = buckets.get(etype) or []
                if not ents:
                    continue
                # Sort by pheromone weight — hottest first
                ents.sort(key=lambda e: e.pheromone_weight(), reverse=True)
                lines.append(f"\n### {etype} ({len(ents)})")
                for e in ents[:max_per_type]:
                    heat = e.heat_label()
                    weight = f"{e.pheromone_weight():.2f}"
                    attrs = ", ".join(
                        f"{k}={str(v)[:80]}" for k, v in e.attrs.items()
                    )
                    lines.append(f"  - {e.id} [{heat} w={weight}]: {attrs}")
                    for fk, f in list(e.facts.items())[:5]:
                        lines.append(f"      • {fk}={f.value} ({f.confidence})")
                if len(ents) > max_per_type:
                    lines.append(f"  ... ({len(ents) - max_per_type} more)")

            if self._relationships:
                lines.append(f"\n### RELATIONSHIPS ({len(self._relationships)})")
                for r in self._relationships[-40:]:
                    lines.append(f"  - {r.from_id} --[{r.rel_type}]--> {r.to_id}")

            return "\n".join(lines)

    def get_context_injection(self) -> str:
        """Legacy single-agent prompt context (used by agent.py)."""
        with self._lock:
            sections = ["## EXPLOITATION PROGRESS",
                         self.get_progress_string(),
                         f"  Current Phase: {self.get_current_phase().upper()}"]
            if self.facts:
                sections.append("\n## KNOWN FACTS (do NOT re-derive these)")
                for key, fact in self.facts.items():
                    conf = "CONFIRMED" if fact.confidence == "confirmed" else "SUSPECTED"
                    sections.append(f"  {conf} | {key}: {fact.value}")
            recent = self.get_recent_payloads(10)
            if recent:
                sections.append(f"\n## PAYLOAD HISTORY ({self.get_payload_count()} total, last 10)")
                for i, p in enumerate(recent, 1):
                    sections.append(
                        f"  {i}. ({p['result']}) {p['payload'][:80]} — {p['hypothesis'][:60]}"
                    )
            if self.failed_attempts:
                sections.append("\n" + self.failure_summary(10))
            if self.current_hypothesis:
                sections.append(f"\n## CURRENT HYPOTHESIS\n  {self.current_hypothesis}")
            if self._entities:
                sections.append("\n" + self.kg_snapshot())
            return "\n".join(sections)

    # =====================================================================
    # Serialization (session logs)
    # =====================================================================

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "facts": {k: {"value": f.value, "confidence": f.confidence}
                          for k, f in self.facts.items()},
                "payload_count": len(self.payload_history),
                "failed_attempt_count": len(self.failed_attempts),
                "recent_failures": self.get_recent_failures(20),
                "progress": dict(self.progress),
                "current_hypothesis": self.current_hypothesis,
                "kg_entities": [
                    {"id": e.id, "type": e.type, "attrs": e.attrs,
                     "facts": {k: {"value": f.value, "confidence": f.confidence}
                               for k, f in e.facts.items()}}
                    for e in self._entities.values()
                ],
                "kg_relationships": [
                    {"from": r.from_id, "to": r.to_id, "rel": r.rel_type, "attrs": r.attrs}
                    for r in self._relationships
                ],
            }
