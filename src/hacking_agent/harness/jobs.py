"""JobManager: launch + monitor per-run worker subprocesses.

Single-operator MVP: runs are SERIALIZED (max_concurrency defaults to 1) because
they share one Kali container + cookie jar. Each run executes as its own process
(isolated globals). The manager tracks status in the RunStore, streams worker
stdout/stderr to worker.log, reads result.json on exit, and supports cancel.
"""
from __future__ import annotations

import json
import os
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
    from hacking_agent.core.process_control import stop_process_tree
    stop_process_tree(proc)


class JobManager:
    def __init__(self, store: RunStore, *, max_concurrency: int = 1,
                 worker_cmd: Optional[WorkerCmd] = None,
                 env_extra: Optional[dict[str, str]] = None):
        self.store = store
        if max_concurrency != 1:
            raise ValueError("Only max_concurrency=1 is supported while runs share a tool container")
        self.max_concurrency = 1
        self._worker_cmd = worker_cmd or _default_worker_cmd
        self._env_extra = dict(env_extra or {})
        self._lock = threading.RLock()
        self._queue: deque[str] = deque()
        self._running: dict[str, subprocess.Popen] = {}
        self._cancelled: set[str] = set()
        self._closed = False
        self.store.recover_interrupted()

    # ---- submission ------------------------------------------------------

    def submit(self, run_id: str) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("job manager is shut down")
            record = self.store.get(run_id)
            if record is None or record.status != RunStatus.queued:
                return
            if run_id in self._queue or run_id in self._running:
                return
            self._queue.append(run_id)
        self._drain()

    def _drain(self) -> None:
        """Start queued runs up to the concurrency limit."""
        with self._lock:
            while not self._closed and self._queue and len(self._running) < self.max_concurrency:
                run_id = self._queue.popleft()
                if run_id in self._cancelled:
                    self.store.update(run_id, status=RunStatus.cancelled)
                    continue
                self._start(run_id)

    def _start(self, run_id: str) -> None:
        run_dir = str(self.store.run_dir(run_id))
        env = dict(os.environ)
        env.update(self._env_extra)
        env["REYNARD_AUTH_SESSIONS_STDIN"] = "1"
        sessions = self.store.take_auth_sessions(run_id)
        log_fh = open(self.store.worker_log_path(run_id), "w", encoding="utf-8")
        try:
            proc = subprocess.Popen(
                self._worker_cmd(run_dir),
                cwd=str(PROJECT_ROOT), env=env,
                stdout=log_fh, stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                start_new_session=True,  # own process group so cancel kills children
            )
            if proc.stdin is not None:
                try:
                    proc.stdin.write(json.dumps(sessions).encode("utf-8"))
                    proc.stdin.close()
                except BrokenPipeError:
                    pass  # failed/custom worker; monitor records its outcome
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
        findings_count, verified_count, suppressed_count = (
            self._strict_report_counts(run_id)
        )
        self.store.update(
            run_id, status=status, exit_code=rc,
            findings_count=findings_count,
            verified_count=verified_count,
            suppressed_count=suppressed_count,
            error="" if was_cancelled else str(result.get("error", ""))[:500],
        )
        self._drain()

    def _read_result(self, run_id: str) -> dict[str, Any]:
        p = self.store.run_dir(run_id) / "result.json"
        if not p.exists():
            return {"error": "worker exited without result.json"}
        try:
            result = json.loads(p.read_text(encoding="utf-8"))
            return result if isinstance(result, dict) else {"error": "invalid worker result"}
        except Exception:
            return {"error": "worker result.json is unreadable"}

    def _strict_report_counts(self, run_id: str) -> tuple[int, int, int]:
        """Recompute customer counts from re-gated report evidence."""
        _md, path = self.store.report_paths(run_id)
        if not path.exists():
            return 0, 0, 0
        try:
            from hacking_agent.harness.submission import sanitize_report_json
            raw = json.loads(path.read_text(encoding="utf-8"))
            safe = sanitize_report_json(raw)
            count = int(safe.get("confirmed_count", 0) or 0)
            suppressed = int(safe.get("suppressed_count", 0) or 0)
            return count, count, max(0, suppressed)
        except Exception:
            return 0, 0, 0

    # ---- cancellation ----------------------------------------------------

    def cancel(self, run_id: str) -> bool:
        with self._lock:
            proc = self._running.get(run_id)
            if run_id in self._queue:
                # queued but not started -> drop + mark cancelled
                try:
                    self._queue.remove(run_id)
                except ValueError:
                    pass
                self.store.update(run_id, status=RunStatus.cancelled)
                self.store.take_auth_sessions(run_id)
                return True
            if proc is not None and proc.poll() is None:
                self._cancelled.add(run_id)
        if proc is not None and proc.poll() is None:
            _terminate(proc)
            return True
        return False

    def is_running(self, run_id: str) -> bool:
        with self._lock:
            return run_id in self._running

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            for run_id in self._queue:
                self.store.update(run_id, status=RunStatus.cancelled)
                self.store.take_auth_sessions(run_id)
            self._queue.clear()
            procs = list(self._running.items())
            self._cancelled.update(self._running)
        for _run_id, p in procs:
            if p.poll() is None:
                _terminate(p)
