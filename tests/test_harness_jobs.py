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
    "'targets_assessed':[{'findings':["
    "{'title':'legacy one'},{'title':'legacy two'}]}]}));"
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
    assert final.error == ""


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


def test_research_secrets_use_private_stdin_and_windows_logs_are_utf8(tmp_path):
    from test_research_pipeline import research_request
    store = RunStore(root=tmp_path)
    script = (
        "import sys,json,pathlib,os;p=pathlib.Path(sys.argv[1]);"
        "s=json.load(sys.stdin);"
        "assert s['authenticated_research']['identities'][0]['cookie_header']=='sid=private-test-cookie';"
        "assert s['business_rules'][0]['expected_value']=='private-object-42';"
        "assert 'private-test-cookie' not in str(os.environ);"
        "print(chr(0x25b6));"
        "(p/'result.json').write_text('{}')"
    )
    jobs = JobManager(store, worker_cmd=_cmd(script),
                      env_extra={"PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"})
    rec = store.create(research_request())
    jobs.submit(rec.id)
    assert _wait_terminal(store, rec.id).status is RunStatus.completed
    assert "\u25b6" in store.worker_log_path(rec.id).read_text(encoding="utf-8")
    assert store.take_worker_inputs(rec.id) == []


def test_cancel_queued_research_discards_all_private_inputs(tmp_path):
    from test_research_pipeline import research_request
    store = RunStore(root=tmp_path)
    jobs = JobManager(store, worker_cmd=_cmd(_SLOW))
    blocker = store.create(_req())
    jobs.submit(blocker.id)
    try:
        rec = store.create(research_request())
        jobs.submit(rec.id)
        assert jobs.cancel(rec.id)
        assert store.take_worker_inputs(rec.id) == []
    finally:
        jobs.shutdown()


def test_large_unicode_plan_uses_consistent_utf8_byte_bound(tmp_path):
    from test_research_pipeline import research_request, research_plan
    plan = research_plan()
    plan["allowed_mutations"] = [{"url": "https://fixture.invalid/setup", "purpose": "workflow"}]
    plan["identities"][0]["setup"] = [
        {"method": "POST", "url": "https://fixture.invalid/setup", "purpose": "workflow",
         "fields": {f"field{index}": "é" * 3000 for index in range(32)}} for _ in range(2)
    ]
    store = RunStore(root=tmp_path)
    script = (
        "import sys,json,pathlib;p=pathlib.Path(sys.argv[1]);raw=sys.stdin.buffer.read(1048577);"
        "assert len(raw)<=1048576;s=json.loads(raw);"
        "assert s['authenticated_research']['identities'][0]['setup'][0]['fields']['field0']==chr(233)*3000;"
        "(p/'result.json').write_text('{}')"
    )
    jobs = JobManager(store, worker_cmd=_cmd(script))
    rec = store.create(research_request(authenticated_research=plan))
    jobs.submit(rec.id)
    assert _wait_terminal(store, rec.id).status is RunStatus.completed


@pytest.mark.parametrize("cancel", [True, False])
def test_worker_not_reading_large_private_pipe_remains_cancellable_and_bounded(tmp_path, monkeypatch, cancel):
    from hacking_agent.harness import jobs as jobs_module
    from test_research_pipeline import research_request, research_plan
    plan = research_plan()
    plan["allowed_mutations"] = [{"url": "https://fixture.invalid/setup", "purpose": "workflow"}]
    plan["identities"][0]["setup"] = [{
        "method": "POST", "url": "https://fixture.invalid/setup", "purpose": "workflow",
        "fields": {str(index): "x" * 4000 for index in range(32)},
    }]
    monkeypatch.setattr(jobs_module, "_INPUT_DELIVERY_TIMEOUT", 0.4)
    store = RunStore(root=tmp_path)
    jobs = JobManager(store, worker_cmd=_cmd(_SLOW))
    rec = store.create(research_request(authenticated_research=plan))
    started = time.monotonic()
    jobs.submit(rec.id)
    assert time.monotonic() - started < 3
    if cancel:
        assert jobs.cancel(rec.id)
    final = _wait_terminal(store, rec.id, timeout=10)
    assert final.status is (RunStatus.cancelled if cancel else RunStatus.failed)
    if not cancel:
        assert "input delivery timed out" in final.error
    assert not jobs.is_running(rec.id)
    assert store.take_worker_inputs(rec.id) == []


def test_input_write_failure_closes_pipe_and_omits_secret_exception_text():
    import threading
    from types import SimpleNamespace
    from unittest.mock import Mock
    from hacking_agent.harness.jobs import _deliver_inputs
    stream = Mock()
    stream.write.side_effect = OSError("private-test-cookie")
    delivered = threading.Event()
    errors = []
    _deliver_inputs(SimpleNamespace(stdin=stream), b"private-test-cookie", delivered, errors)
    assert delivered.is_set()
    stream.close.assert_called_once()
    assert errors == ["private worker input delivery failed"]


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
