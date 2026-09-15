"""Run store: per-run directories + a small SQLite status index.

Layout (under logs/runs/):
  runs.db                         status index (this module)
  <run_id>/config.json           the submitted RunRequest (NO secrets)
  <run_id>/events.jsonl          event stream (written by the worker's sink)
  <run_id>/report.md / .json     generated report
  <run_id>/evidence.json         evidence bundles snapshot
  <run_id>/worker.log            worker stdout/stderr
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from hacking_agent.core.paths import LOG_DIR, ensure_runtime_dirs
from hacking_agent.harness.models import RunRecord, RunRequest, RunStatus

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id              TEXT PRIMARY KEY,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    targets         TEXT NOT NULL,
    description     TEXT,
    findings_count  INTEGER NOT NULL DEFAULT 0,
    verified_count  INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    pid             INTEGER,
    exit_code       INTEGER
);
"""


def _now() -> str:
    return datetime.utcnow().isoformat()


class RunStore:
    """Thread-safe registry of runs backed by SQLite + per-run directories."""

    def __init__(self, root: str | os.PathLike | None = None):
        ensure_runtime_dirs()
        self.root = Path(root) if root else (LOG_DIR / "runs")
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.root / "runs.db"),
                                     check_same_thread=False, timeout=10.0)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ---- paths ----------------------------------------------------------

    def run_dir(self, run_id: str) -> Path:
        d = self.root / run_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def config_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "config.json"

    def events_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "events.jsonl"

    def report_paths(self, run_id: str) -> tuple[Path, Path]:
        d = self.run_dir(run_id)
        return d / "report.md", d / "report.json"

    def evidence_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "evidence.json"

    def worker_log_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "worker.log"

    # ---- lifecycle ------------------------------------------------------

    def create(self, request: RunRequest) -> RunRecord:
        run_id = uuid.uuid4().hex[:12]
        rec = RunRecord(
            id=run_id, status=RunStatus.queued,
            targets=request.resolved_targets(),
            description=(request.description or "")[:500],
        )
        # Persist the submitted config (no secrets) for the worker to read.
        self.config_path(run_id).write_text(
            request.model_dump_json(indent=2), encoding="utf-8")
        with self._lock:
            self._conn.execute(
                """INSERT INTO runs (id, status, created_at, updated_at, targets,
                       description, findings_count, verified_count, error, pid, exit_code)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (rec.id, rec.status.value, rec.created_at, rec.updated_at,
                 json.dumps(rec.targets), rec.description, 0, 0, "", None, None),
            )
            self._conn.commit()
        return rec

    def update(self, run_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = _now()
        if isinstance(fields.get("status"), RunStatus):
            fields["status"] = fields["status"].value
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._lock:
            self._conn.execute(
                f"UPDATE runs SET {cols} WHERE id=?",
                (*fields.values(), run_id),
            )
            self._conn.commit()

    def get(self, run_id: str) -> Optional[RunRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._row_to_record(row) if row else None

    def list(self, limit: int = 100) -> list[RunRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()
        return [self._row_to_record(r) for r in rows]

    def load_request(self, run_id: str) -> Optional[RunRequest]:
        p = self.config_path(run_id)
        if not p.exists():
            return None
        try:
            return RunRequest.model_validate_json(p.read_text(encoding="utf-8"))
        except Exception:
            return None

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> RunRecord:
        return RunRecord(
            id=row["id"], status=RunStatus(row["status"]),
            created_at=row["created_at"], updated_at=row["updated_at"],
            targets=json.loads(row["targets"] or "[]"),
            description=row["description"] or "",
            findings_count=row["findings_count"] or 0,
            verified_count=row["verified_count"] or 0,
            error=row["error"] or "", pid=row["pid"], exit_code=row["exit_code"],
        )

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
