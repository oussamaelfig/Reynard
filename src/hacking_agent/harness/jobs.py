"""JobManager: launch + monitor per-run worker subprocesses.

Single-operator MVP: runs are SERIALIZED (max_concurrency defaults to 1) because
they share one Kali container + cookie jar. Each run executes as its own process
(isolated globals). The manager tracks status in the RunStore, streams worker
stdout/stderr to worker.log, reads result.json on exit, and supports cancel.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
from collections import deque
from typing import Any, Callable, Optional

from hacking_agent.core.paths import PROJECT_ROOT
from hacking_agent.harness.models import RunStatus
from hacking_agent.harness.store import RunStore

# A worker command factory: given a run_dir, return the argv to execute.
WorkerCmd = Callable[[str], list]


def _default_worker_cmd(run_dir: str) -> list:
    return [sys.executable, "-m", "hacking_agent.harness.run_job", run_dir]


def _terminate(proc: subprocess.Popen) -> None:
    """Signal the worker AND its children (it spawns docker exec / tools).

    The worker is started in its own session (start_new_session=True), so on
    POSIX we can signal the whole process group; otherwise fall back to
    terminating the direct child."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        return
    except Exception:
        pass
    try:
        proc.terminate()
    except Exception:
        pass


class JobManager:
    def __init__(self, store: RunStore, *, max_concurrency: int = 1,
                 worker_cmd: Optional[WorkerCmd] = None,
                 env_extra: Optional[dict[str, str]] = None):
        self.store = store
        self.max_concurrency = max(1, int(max_concurrency))
        self._worker_cmd = worker_cmd or _default_worker_cmd
        self._env_extra = dict(env_extra or {})
        self._lock = threading.RLock()
        self._queue: deque[str] = deque()
        self._running: dict[str, subprocess.Popen] = {}
        self._cancelled: set[str] = set()

    # ---- submission ------------------------------------------------------

    def submit(self, run_id: str) -> None:
        with self._lock:
            self._queue.append(run_id)
        self._drain()

    def _drain(self) -> None:
        """Start queued runs up to the concurrency limit."""
        with self._lock:
            while self._queue and len(self._running) < self.max_concurrency:
                run_id = self._queue.popleft()
                if run_id in self._cancelled:
                    self.store.update(run_id, status=RunStatus.cancelled)
                    continue
                self._start(run_id)

    def _start(self, run_id: str) -> None:
        run_dir = str(self.store.run_dir(run_id))
        env = dict(os.environ)
        env.update(self._env_extra)
        log_fh = open(self.store.worker_log_path(run_id), "w", encoding="utf-8")
        try:
            proc = subprocess.Popen(
                self._worker_cmd(run_dir),
                cwd=str(PROJECT_ROOT), env=env,
                stdout=log_fh, stderr=subprocess.STDOUT,
                start_new_session=True,  # own process group so cancel kills children
            )
        except Exception as exc:
            log_fh.close()
            self.store.update(run_id, status=RunStatus.failed,
                              error=f"failed to launch worker: {exc}")
            return
        self._running[run_id] = proc
        self.store.update(run_id, status=RunStatus.running, pid=proc.pid, error="")
        threading.Thread(target=self._monitor, args=(run_id, proc, log_fh),
                         daemon=True).start()

    # ---- monitoring ------------------------------------------------------

    def _monitor(self, run_id: str, proc: subprocess.Popen, log_fh: Any) -> None:
        rc = proc.wait()
        try:
            log_fh.close()
        except Exception:
            pass
        result = self._read_result(run_id)
        with self._lock:
            self._running.pop(run_id, None)
            was_cancelled = run_id in self._cancelled
            self._cancelled.discard(run_id)
        if was_cancelled:
            status = RunStatus.cancelled
        elif rc == 0 and not result.get("error"):
            status = RunStatus.completed
        else:
            status = RunStatus.failed
        findings_count, verified_count = self._strict_report_counts(run_id)
        self.store.update(
            run_id, status=status, exit_code=rc,
            findings_count=findings_count,
            verified_count=verified_count,
            error=str(result.get("error", ""))[:500],
        )
        self._drain()

    def _read_result(self, run_id: str) -> dict[str, Any]:
        p = self.store.run_dir(run_id) / "result.json"
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _strict_report_counts(self, run_id: str) -> tuple[int, int]:
        """Recompute customer counts from re-gated report evidence."""
        _md, path = self.store.report_paths(run_id)
        if not path.exists():
            return 0, 0
        try:
            from hacking_agent.harness.submission import sanitize_report_json
            raw = json.loads(path.read_text(encoding="utf-8"))
            safe = sanitize_report_json(raw)
            count = int(safe.get("confirmed_count", 0) or 0)
            return count, count
        except Exception:
            return 0, 0

    # ---- cancellation ----------------------------------------------------

    def cancel(self, run_id: str) -> bool:
        with self._lock:
            self._cancelled.add(run_id)
            proc = self._running.get(run_id)
            if run_id in self._queue:
                # queued but not started -> drop + mark cancelled
                try:
                    self._queue.remove(run_id)
                except ValueError:
                    pass
                self.store.update(run_id, status=RunStatus.cancelled)
                self._cancelled.discard(run_id)
                return True
        if proc is not None and proc.poll() is None:
            _terminate(proc)
            return True
        return False

    def is_running(self, run_id: str) -> bool:
        with self._lock:
            return run_id in self._running

    def shutdown(self) -> None:
        with self._lock:
            procs = list(self._running.values())
        for p in procs:
            if p.poll() is None:
                _terminate(p)
