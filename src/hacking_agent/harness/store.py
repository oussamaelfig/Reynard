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
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
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
    suppressed_count INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    pid             INTEGER,
    exit_code       INTEGER
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunPathError(ValueError):
    """An invalid run identifier must never become a filesystem path."""


class RunStore:
    """Thread-safe registry of runs backed by SQLite + per-run directories."""

    def __init__(self, root: str | os.PathLike | None = None):
        ensure_runtime_dirs()
        self.root = Path(root) if root else (LOG_DIR / "runs")
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._auth_sessions: dict[str, list[dict[str, Any]]] = {}
        self._research_inputs: dict[str, dict[str, Any]] = {}
        self._conn = sqlite3.connect(str(self.root / "runs.db"),
                                     check_same_thread=False, timeout=10.0)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            columns = {
                row[1] for row in self._conn.execute("PRAGMA table_info(runs)")
            }
            if "suppressed_count" not in columns:
                self._conn.execute(
                    "ALTER TABLE runs ADD COLUMN suppressed_count "
                    "INTEGER NOT NULL DEFAULT 0"
                )
            self._conn.commit()

    # ---- paths ----------------------------------------------------------

    def run_dir(self, run_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
            raise RunPathError("invalid run identifier")
        d = (self.root / run_id).resolve()
        if d.parent != self.root.resolve():
            raise RunPathError("run directory escapes the run store")
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
        self.run_dir(run_id).mkdir(mode=0o700)
        # Credentials are ephemeral: only the worker's stdin receives them.
        public_config = request.model_dump(mode="json")
        public_config["auth_sessions"] = []
        public_config["authenticated_research"] = None
        public_config["business_rules"] = []
        self.config_path(run_id).write_text(
            json.dumps(public_config, indent=2), encoding="utf-8")
        with self._lock:
            self._auth_sessions[run_id] = [s.model_dump(mode="json") for s in request.auth_sessions]
            if request.authenticated_research is not None:
                self._research_inputs[run_id] = {
                    "authenticated_research": request.authenticated_research.model_dump(mode="json"),
                    "business_rules": [rule.model_dump(mode="json") for rule in request.business_rules],
                }
            self._conn.execute(
                """INSERT INTO runs (id, status, created_at, updated_at, targets,
                       description, findings_count, verified_count,
                       suppressed_count, error, pid, exit_code)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rec.id, rec.status.value, rec.created_at, rec.updated_at,
                 json.dumps(rec.targets), rec.description, 0, 0, 0, "",
                 None, None),
            )
            self._conn.commit()
        return rec

    def take_auth_sessions(self, run_id: str) -> list[dict[str, Any]]:
        """Consume credentials once; do not retain them after launch/cancel."""
        with self._lock:
            return self._auth_sessions.pop(run_id, [])

    def take_worker_inputs(self, run_id: str) -> dict[str, Any] | list[dict[str, Any]]:
        """Consume all private inputs once; preserve legacy session-list IPC."""
        with self._lock:
            sessions = self._auth_sessions.pop(run_id, [])
            research = self._research_inputs.pop(run_id, None)
            return {"auth_sessions": sessions, **research} if research is not None else sessions

    def recover_interrupted(self) -> int:
        """Stale queued/running records require a fresh authorized submission.

        Never kill stored PIDs: after restart a PID may belong to another app.
        """
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE runs SET status=?, updated_at=?, error=? WHERE status IN (?, ?)",
                (RunStatus.failed.value, _now(),
                 "Harness restarted; execution state unknown. Check previous worker before resubmitting.",
                 RunStatus.queued.value, RunStatus.running.value),
            )
            self._conn.commit()
            self._auth_sessions.clear()
            self._research_inputs.clear()
            return cursor.rowcount

    def update(self, run_id: str, **fields: Any) -> None:
        if not fields:
            return
        allowed = {"status", "findings_count", "verified_count", "suppressed_count",
                   "error", "pid", "exit_code"}
        if fields.keys() - allowed:
            raise ValueError("unsupported run update field")
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
        return self._reconcile_record(self._row_to_record(row)) if row else None

    def list(self, limit: int = 100) -> list[RunRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()
        return [
            self._reconcile_record(self._row_to_record(row))
            for row in rows
        ]

    def _reconcile_record(self, record: RunRecord) -> RunRecord:
        """Backfill customer counts from the authenticated structured report.

        SQLite and worker summaries are cache fields only.  Missing, legacy, or
        unverifiable reports fail closed to zero confirmed findings.
        """
        report_path = self.root / record.id / "report.json"
        confirmed = 0
        suppressed = 0
        if report_path.exists():
            try:
                from hacking_agent.harness.submission import sanitize_report_json
                raw = json.loads(report_path.read_text(encoding="utf-8"))
                safe = sanitize_report_json(
                    raw,
                    expected_run_id=record.id,
                )
                confirmed = max(
                    0, int(safe.get("confirmed_count", 0) or 0),
                )
                suppressed = max(
                    0, int(safe.get("suppressed_count", 0) or 0),
                )
            except Exception:
                confirmed = 0
                suppressed = 0
        if (
            record.findings_count == confirmed
            and record.verified_count == confirmed
            and record.suppressed_count == suppressed
        ):
            return record
        updated_at = _now()
        with self._lock:
            self._conn.execute(
                """UPDATE runs
                   SET findings_count=?, verified_count=?,
                       suppressed_count=?, updated_at=?
                   WHERE id=?""",
                (confirmed, confirmed, suppressed, updated_at, record.id),
            )
            self._conn.commit()
        return record.model_copy(update={
            "findings_count": confirmed,
            "verified_count": confirmed,
            "suppressed_count": suppressed,
            "updated_at": updated_at,
        })

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
            suppressed_count=row["suppressed_count"] or 0,
            error=row["error"] or "", pid=row["pid"], exit_code=row["exit_code"],
        )

    def close(self) -> None:
        with self._lock:
            self._auth_sessions.clear()
            self._research_inputs.clear()
            try:
                self._conn.close()
            except Exception:
                pass
