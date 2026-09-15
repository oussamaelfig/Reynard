"""JobManager: subprocess launch, status recording, cancel, serialization."""
from __future__ import annotations

import json
import sys
import time

from hacking_agent.harness.jobs import JobManager
from hacking_agent.harness.models import RunRequest, RunStatus
from hacking_agent.harness.store import RunStore

# Fake workers (hermetic: no LLM, no Docker) invoked as `python -c <script> <run_dir>`.
_OK = (
    "import sys,json,pathlib;p=pathlib.Path(sys.argv[1]);"
    "(p/'result.json').write_text(json.dumps({'findings_count':2,'verified_count':1}))"
)
_SLOW = "import time;time.sleep(30)"
_TIMED = (
    "import sys,json,pathlib,time;p=pathlib.Path(sys.argv[1]);s=time.time();"
    "time.sleep(0.5);e=time.time();"
    "(p/'result.json').write_text(json.dumps({'start':s,'end':e}))"
)


def _cmd(script):
    return lambda rd: [sys.executable, "-c", script, rd]


def _wait_terminal(store, run_id, timeout=20.0):
    end = time.time() + timeout
    while time.time() < end:
        rec = store.get(run_id)
        if rec and rec.status.is_terminal:
            return rec
        time.sleep(0.05)
    return store.get(run_id)


def _req():
    return RunRequest(authorized_domains=["example.com"], authorized=True)


def test_run_completes_and_records_counts(tmp_path):
    store = RunStore(root=tmp_path)
    jm = JobManager(store, worker_cmd=_cmd(_OK))
    rec = store.create(_req())
    jm.submit(rec.id)
    final = _wait_terminal(store, rec.id)
    assert final.status is RunStatus.completed
    assert final.findings_count == 2 and final.verified_count == 1
    assert final.exit_code == 0


def test_cancel_running_marks_cancelled(tmp_path):
    store = RunStore(root=tmp_path)
    jm = JobManager(store, worker_cmd=_cmd(_SLOW))
    rec = store.create(_req())
    jm.submit(rec.id)
    # wait until it is actually running
    end = time.time() + 5
    while time.time() < end and not jm.is_running(rec.id):
        time.sleep(0.05)
    assert jm.is_running(rec.id)
    assert jm.cancel(rec.id) is True
    final = _wait_terminal(store, rec.id)
    assert final.status is RunStatus.cancelled


def test_cancel_queued_before_start(tmp_path):
    store = RunStore(root=tmp_path)
    # Occupy the single slot with a slow run, then queue + cancel a second.
    jm = JobManager(store, worker_cmd=_cmd(_SLOW), max_concurrency=1)
    blocker = store.create(_req())
    jm.submit(blocker.id)
    while not jm.is_running(blocker.id):
        time.sleep(0.02)
    queued = store.create(_req())
    jm.submit(queued.id)
    assert jm.cancel(queued.id) is True
    assert store.get(queued.id).status is RunStatus.cancelled
    jm.cancel(blocker.id)  # cleanup


def test_runs_are_serialized(tmp_path):
    store = RunStore(root=tmp_path)
    jm = JobManager(store, worker_cmd=_cmd(_TIMED), max_concurrency=1)
    a = store.create(_req())
    b = store.create(_req())
    jm.submit(a.id)
    jm.submit(b.id)
    _wait_terminal(store, a.id)
    _wait_terminal(store, b.id)
    ta = json.loads((store.run_dir(a.id) / "result.json").read_text())
    tb = json.loads((store.run_dir(b.id) / "result.json").read_text())
    first, second = sorted([ta, tb], key=lambda r: r["start"])
    # With one slot, the second run cannot start until the first has finished.
    assert second["start"] >= first["end"] - 0.05
