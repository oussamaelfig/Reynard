"""JobManager: subprocess launch, status recording, cancel, serialization."""
from __future__ import annotations

import json
import sys
import time
import pytest

from hacking_agent.harness.jobs import JobManager
from hacking_agent.harness.models import RunRequest, RunStatus
from hacking_agent.harness.store import RunStore

# Fake workers (hermetic: no LLM, no Docker) invoked as `python -c <script> <run_dir>`.
_OK = (
    "import sys,json,pathlib;p=pathlib.Path(sys.argv[1]);"
    "(p/'result.json').write_text(json.dumps({'findings_count':2,'verified_count':1}))"
)
_SLOW = "import time;time.sleep(30)"
_SUPPRESSED = (
    "import sys,json,pathlib;p=pathlib.Path(sys.argv[1]);"
    "(p/'report.json').write_text(json.dumps({"
    "'finding_count':9,'verified_count':9,'suppressed_count':2,"
    "'targets_assessed':[]}));"
    "(p/'result.json').write_text(json.dumps({"
    "'findings_count':9,'verified_count':9,'suppressed_count':99}))"
)
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


def test_result_json_counts_cannot_bypass_report_gate(tmp_path):
    store = RunStore(root=tmp_path)
    jm = JobManager(store, worker_cmd=_cmd(_OK))
    rec = store.create(_req())
    jm.submit(rec.id)
    final = _wait_terminal(store, rec.id)
    assert final.status is RunStatus.completed
    assert final.findings_count == 0 and final.verified_count == 0
    assert final.exit_code == 0


def test_run_record_exposes_regated_suppressed_count(tmp_path):
    store = RunStore(root=tmp_path)
    jm = JobManager(store, worker_cmd=_cmd(_SUPPRESSED))
    rec = store.create(_req())
    jm.submit(rec.id)
    final = _wait_terminal(store, rec.id)
    assert final.status is RunStatus.completed
    assert final.findings_count == final.verified_count == 0
    assert final.suppressed_count == 2


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


def test_unsafe_shared_container_concurrency_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="max_concurrency=1"):
        JobManager(RunStore(root=tmp_path), max_concurrency=2)


def test_duplicate_submission_cannot_launch_worker_twice(tmp_path):
    store = RunStore(root=tmp_path)
    jm = JobManager(store, worker_cmd=_cmd(_TIMED))
    rec = store.create(_req())
    jm.submit(rec.id)
    pid = store.get(rec.id).pid
    jm.submit(rec.id)
    assert store.get(rec.id).pid == pid
    _wait_terminal(store, rec.id)
    jm.submit(rec.id)
    assert not jm.is_running(rec.id)


def test_credentials_reach_worker_over_stdin_only(tmp_path):
    store = RunStore(root=tmp_path)
    script = (
        "import sys,json,pathlib,os;p=pathlib.Path(sys.argv[1]);"
        "s=json.load(sys.stdin);"
        "assert s[0]['cookie_header']=='session=ephemeral-secret';"
        "assert 'ephemeral-secret' not in str(os.environ);"
        "assert 'ephemeral-secret' not in (p/'config.json').read_text();"
        "(p/'result.json').write_text('{}')"
    )
    jm = JobManager(store, worker_cmd=_cmd(script))
    req = RunRequest(authorized=True, authorized_domains=["example.com"],
                     auth_sessions=[{"name": "user", "cookie_header": "session=ephemeral-secret"}])
    rec = store.create(req)
    jm.submit(rec.id)
    assert _wait_terminal(store, rec.id).status is RunStatus.completed
    assert store.take_auth_sessions(rec.id) == []


def test_shutdown_cancels_queue_and_prevents_later_launch(tmp_path):
    store = RunStore(root=tmp_path)
    jm = JobManager(store, worker_cmd=_cmd(_SLOW))
    first, second = store.create(_req()), store.create(_req())
    jm.submit(first.id)
    jm.submit(second.id)
    jm.shutdown()
    assert _wait_terminal(store, first.id).status is RunStatus.cancelled
    assert store.get(second.id).status is RunStatus.cancelled
    with pytest.raises(RuntimeError):
        jm.submit(store.create(_req()).id)


@pytest.mark.parametrize("script", ["pass", "import sys,pathlib;pathlib.Path(sys.argv[1],'result.json').write_text('[]')"])
def test_zero_exit_without_valid_worker_result_is_not_completed(tmp_path, script):
    store = RunStore(root=tmp_path)
    jm = JobManager(store, worker_cmd=_cmd(script))
    rec = store.create(_req())
    jm.submit(rec.id)
    final = _wait_terminal(store, rec.id)
    assert final.status is RunStatus.failed and final.error
