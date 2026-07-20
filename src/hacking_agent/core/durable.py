"""
=============================================================================
Reynard — Durable cross-run memory (SQLite)
=============================================================================
Fresh-per-run memory throws away everything the swarm learned. This module is
the persistence substrate that lets a run rehydrate prior knowledge for the
same target/lab-class and record which techniques succeeded or dead-ended so
future runs can prime the good and skip the bad.

Design constraints:
  - OPT-IN-SAFE: if the DB can't be opened, `open_durable_store()` returns None
    and every call site degrades to the existing in-memory behaviour.
  - Path is configurable via REYNARD_MEMORY_DB (default logs/reynard_memory.db).
  - The DB layer knows nothing about AgentMemory/EvidenceStore internals; it
    exchanges plain serializable rows. Serialization lives in those classes.

Schema (all rows are additive; no migration needed for a fresh file):
  kg_entities(target, lab_class, entity_id, entity_type, attrs, facts,
              pheromone_base, half_life_sec, created_at, updated_at)
  kg_relationships(target, lab_class, from_id, to_id, rel_type, attrs)
  global_facts(target, lab_class, key, value, confidence, source, updated_at)
  pocs(target, lab_class, vuln_id, payload, request_summary, response_excerpt,
       verdict, agent_name, timestamp, poc_id)
  techniques(lab_class, technique, tool, outcome, count, last_seen, detail)
=============================================================================
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from hacking_agent.core.paths import LOG_DIR, ensure_runtime_dirs

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kg_entities (
    target        TEXT NOT NULL,
    lab_class     TEXT NOT NULL,
    entity_id     TEXT NOT NULL,
    entity_type   TEXT NOT NULL,
    attrs         TEXT NOT NULL,
    facts         TEXT NOT NULL,
    pheromone_base REAL NOT NULL,
    half_life_sec INTEGER NOT NULL,
    created_at    TEXT,
    updated_at    TEXT,
    PRIMARY KEY (target, lab_class, entity_id)
);
CREATE TABLE IF NOT EXISTS kg_relationships (
    target    TEXT NOT NULL,
    lab_class TEXT NOT NULL,
    from_id   TEXT NOT NULL,
    to_id     TEXT NOT NULL,
    rel_type  TEXT NOT NULL,
    attrs     TEXT NOT NULL,
    PRIMARY KEY (target, lab_class, from_id, to_id, rel_type)
);
CREATE TABLE IF NOT EXISTS global_facts (
    target     TEXT NOT NULL,
    lab_class  TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    confidence TEXT NOT NULL,
    source     TEXT,
    updated_at TEXT,
    PRIMARY KEY (target, lab_class, key)
);
CREATE TABLE IF NOT EXISTS pocs (
    target          TEXT NOT NULL,
    lab_class       TEXT NOT NULL,
    poc_id          TEXT NOT NULL,
    vuln_id         TEXT NOT NULL,
    payload         TEXT,
    request_summary TEXT,
    response_excerpt TEXT,
    verdict         TEXT,
    agent_name      TEXT,
    timestamp       TEXT,
    PRIMARY KEY (target, lab_class, poc_id)
);
CREATE TABLE IF NOT EXISTS techniques (
    lab_class TEXT NOT NULL,
    technique TEXT NOT NULL,
    tool      TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    count     INTEGER NOT NULL DEFAULT 1,
    last_seen TEXT,
    detail    TEXT,
    PRIMARY KEY (lab_class, technique, tool, outcome)
);
"""


def _now() -> str:
    return datetime.utcnow().isoformat()


class DurableStore:
    """Thread-safe SQLite wrapper for cross-run persistence."""

    def __init__(self, conn: sqlite3.Connection, path: Path):
        self._conn = conn
        self._lock = threading.RLock()
        self.path = path
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ---- knowledge graph -----------------------------------------------

    def save_entities(self, target: str, lab_class: str,
                      rows: list[dict[str, Any]]) -> None:
        with self._lock:
            for r in rows:
                self._conn.execute(
                    """INSERT INTO kg_entities
                       (target, lab_class, entity_id, entity_type, attrs, facts,
                        pheromone_base, half_life_sec, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(target, lab_class, entity_id) DO UPDATE SET
                        entity_type=excluded.entity_type,
                        attrs=excluded.attrs,
                        facts=excluded.facts,
                        pheromone_base=excluded.pheromone_base,
                        half_life_sec=excluded.half_life_sec,
                        updated_at=excluded.updated_at""",
                    (target, lab_class, r["id"], r["type"],
                     json.dumps(r.get("attrs", {}), default=str),
                     json.dumps(r.get("facts", {}), default=str),
                     float(r.get("pheromone_base", 0.5)),
                     int(r.get("half_life_sec", 3600)),
                     r.get("created_at") or _now(), _now()),
                )
            self._conn.commit()

    def load_entities(self, target: str, lab_class: str) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT entity_id, entity_type, attrs, facts,
                          pheromone_base, half_life_sec, created_at
                   FROM kg_entities WHERE target=? AND lab_class=?""",
                (target, lab_class),
            )
            out = []
            for row in cur.fetchall():
                out.append({
                    "id": row[0], "type": row[1],
                    "attrs": json.loads(row[2] or "{}"),
                    "facts": json.loads(row[3] or "{}"),
                    "pheromone_base": row[4], "half_life_sec": row[5],
                    "created_at": row[6],
                })
            return out

    def save_relationships(self, target: str, lab_class: str,
                           rows: list[dict[str, Any]]) -> None:
        with self._lock:
            for r in rows:
                self._conn.execute(
                    """INSERT OR REPLACE INTO kg_relationships
                       (target, lab_class, from_id, to_id, rel_type, attrs)
                       VALUES (?,?,?,?,?,?)""",
                    (target, lab_class, r["from"], r["to"], r["rel"],
                     json.dumps(r.get("attrs", {}), default=str)),
                )
            self._conn.commit()

    def load_relationships(self, target: str, lab_class: str) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT from_id, to_id, rel_type, attrs
                   FROM kg_relationships WHERE target=? AND lab_class=?""",
                (target, lab_class),
            )
            return [
                {"from": r[0], "to": r[1], "rel": r[2],
                 "attrs": json.loads(r[3] or "{}")}
                for r in cur.fetchall()
            ]

    def save_facts(self, target: str, lab_class: str,
                   rows: list[dict[str, Any]]) -> None:
        with self._lock:
            for r in rows:
                self._conn.execute(
                    """INSERT OR REPLACE INTO global_facts
                       (target, lab_class, key, value, confidence, source, updated_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    (target, lab_class, r["key"],
                     json.dumps(r.get("value"), default=str),
                     r.get("confidence", "confirmed"),
                     r.get("source", ""), _now()),
                )
            self._conn.commit()

    def load_facts(self, target: str, lab_class: str) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT key, value, confidence, source
                   FROM global_facts WHERE target=? AND lab_class=?""",
                (target, lab_class),
            )
            out = []
            for r in cur.fetchall():
                try:
                    value = json.loads(r[1])
                except (json.JSONDecodeError, TypeError):
                    value = r[1]
                out.append({"key": r[0], "value": value,
                            "confidence": r[2], "source": r[3]})
            return out

    # ---- evidence -------------------------------------------------------

    def save_pocs(self, target: str, lab_class: str,
                  rows: list[dict[str, Any]]) -> None:
        with self._lock:
            for r in rows:
                self._conn.execute(
                    """INSERT OR REPLACE INTO pocs
                       (target, lab_class, poc_id, vuln_id, payload,
                        request_summary, response_excerpt, verdict,
                        agent_name, timestamp)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (target, lab_class, r.get("id", ""), r.get("vuln_id", ""),
                     r.get("payload", ""), r.get("request_summary", ""),
                     r.get("response_excerpt", ""), r.get("verdict", ""),
                     r.get("agent_name", ""), r.get("timestamp", _now())),
                )
            self._conn.commit()

    def load_pocs(self, target: str, lab_class: str) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT poc_id, vuln_id, payload, request_summary,
                          response_excerpt, verdict, agent_name, timestamp
                   FROM pocs WHERE target=? AND lab_class=?""",
                (target, lab_class),
            )
            return [
                {"id": r[0], "vuln_id": r[1], "payload": r[2],
                 "request_summary": r[3], "response_excerpt": r[4],
                 "verdict": r[5], "agent_name": r[6], "timestamp": r[7]}
                for r in cur.fetchall()
            ]

    # ---- learned techniques / failure patterns -------------------------

    def record_technique(self, lab_class: str, technique: str, tool: str,
                         outcome: str, detail: str = "") -> None:
        """Upsert a (lab_class, technique, tool, outcome) observation.

        outcome is normalized to 'success' or 'deadend'.
        """
        outcome = "success" if outcome == "success" else "deadend"
        lab_class = lab_class or "unknown"
        technique = (technique or "unknown")[:200]
        tool = (tool or "unknown")[:120]
        with self._lock:
            self._conn.execute(
                """INSERT INTO techniques
                   (lab_class, technique, tool, outcome, count, last_seen, detail)
                   VALUES (?,?,?,?,1,?,?)
                   ON CONFLICT(lab_class, technique, tool, outcome) DO UPDATE SET
                    count = count + 1,
                    last_seen = excluded.last_seen,
                    detail = excluded.detail""",
                (lab_class, technique, tool, outcome, _now(), detail[:300]),
            )
            self._conn.commit()

    def successful_techniques(self, lab_class: str,
                              limit: int = 20) -> list[dict[str, Any]]:
        return self._query_techniques(lab_class, "success", limit)

    def known_deadends(self, lab_class: str,
                       limit: int = 20) -> list[dict[str, Any]]:
        return self._query_techniques(lab_class, "deadend", limit)

    def _query_techniques(self, lab_class: str, outcome: str,
                          limit: int) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT technique, tool, count, last_seen, detail
                   FROM techniques WHERE lab_class=? AND outcome=?
                   ORDER BY count DESC, last_seen DESC LIMIT ?""",
                (lab_class or "unknown", outcome, limit),
            )
            return [
                {"technique": r[0], "tool": r[1], "count": r[2],
                 "last_seen": r[3], "detail": r[4]}
                for r in cur.fetchall()
            ]

    # ---- housekeeping ---------------------------------------------------

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
                self._conn.close()
            except Exception:
                pass


def resolve_db_path(db_path: str | os.PathLike | None = None) -> Path:
    """Resolve the durable-memory DB path from arg or REYNARD_MEMORY_DB."""
    raw = db_path or os.getenv("REYNARD_MEMORY_DB") or (LOG_DIR / "reynard_memory.db")
    return Path(raw)


def open_durable_store(db_path: str | os.PathLike | None = None) -> DurableStore | None:
    """Open (or create) the durable store. Returns None on any failure so
    callers degrade to in-memory behaviour."""
    try:
        path = resolve_db_path(db_path)
        ensure_runtime_dirs()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10.0)
        return DurableStore(conn, path)
    except Exception:
        return None


# Rehydrated pheromones must be "warm, not hot": a stale finding should nudge
# the swarm, not dominate a fresh run. Clamp the base and reset decay so the
# fresh weight lands in the WARM band (>=0.5, <0.8) regardless of the original.
REHYDRATE_WARM_CAP = 0.6


def warm_pheromone_base(original_base: float) -> float:
    try:
        return min(float(original_base), REHYDRATE_WARM_CAP)
    except (TypeError, ValueError):
        return REHYDRATE_WARM_CAP


def monotonic_now() -> float:
    return time.monotonic()
