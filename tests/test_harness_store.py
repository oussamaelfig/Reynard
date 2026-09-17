"""RunStore lifecycle + per-run directory layout (run harness)."""
from __future__ import annotations

import json
import pytest

from hacking_agent.harness.models import RunRequest, RunStatus
from hacking_agent.harness.store import RunPathError, RunStore


def _req(**kw):
    base = dict(authorized_domains=["example.com"], authorized=True,
                description="find idor")
    base.update(kw)
    return RunRequest(**base)


def test_create_get_update_list(tmp_path):
    store = RunStore(root=tmp_path)
    rec = store.create(_req())
    assert rec.status is RunStatus.queued

    got = store.get(rec.id)
    assert got is not None and got.id == rec.id
    assert got.targets == ["https://example.com/"]

    store.update(rec.id, status=RunStatus.running, pid=4321)
    got = store.get(rec.id)
    assert got.status is RunStatus.running and got.pid == 4321

    store.update(rec.id, status=RunStatus.completed, findings_count=3,
                 verified_count=2, suppressed_count=4, exit_code=0)
    got = store.get(rec.id)
    assert got.status is RunStatus.completed
    # Worker/SQLite counters are caches; no authenticated report means zero.
    assert got.findings_count == 0 and got.verified_count == 0
    assert got.suppressed_count == 0

    # newest-first listing
    rec2 = store.create(_req(description="second"))
    ids = [r.id for r in store.list()]
    assert ids[0] == rec2.id and rec.id in ids


def test_per_run_dirs_and_paths(tmp_path):
    store = RunStore(root=tmp_path)
    rec = store.create(_req())
    d = store.run_dir(rec.id)
    assert d.is_dir()
    assert store.config_path(rec.id).exists()
    md, js = store.report_paths(rec.id)
    assert md.name == "report.md" and js.name == "report.json"
    assert store.events_path(rec.id).name == "events.jsonl"
    assert store.worker_log_path(rec.id).name == "worker.log"


def test_config_roundtrip_has_no_secret_fields(tmp_path):
    store = RunStore(root=tmp_path)
    rec = store.create(_req())
    loaded = store.load_request(rec.id)
    assert loaded is not None and loaded.description == "find idor"
    raw = store.config_path(rec.id).read_text(encoding="utf-8")
    # The persisted config carries scope/options only, never credentials.
    lowered = raw.lower()
    for secret in ("api_key", "apikey", "deepseek", "authorization", "password"):
        assert secret not in lowered


def test_get_missing_returns_none(tmp_path):
    store = RunStore(root=tmp_path)
    assert store.get("does-not-exist") is None
    assert store.load_request("does-not-exist") is None
    assert not (tmp_path / "does-not-exist").exists()


def test_auth_credentials_are_ephemeral_and_consumed_once(tmp_path):
    store = RunStore(root=tmp_path)
    rec = store.create(_req(auth_sessions=[{
        "name": "user", "cookie_header": "session=secret-cookie-marker",
        "headers": {"Authorization": "Bearer secret-auth-marker"},
    }]))
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert b"secret-cookie-marker" not in path.read_bytes()
            assert b"secret-auth-marker" not in path.read_bytes()
    sessions = store.take_auth_sessions(rec.id)
    assert sessions[0]["cookie_header"] == "session=secret-cookie-marker"
    assert store.take_auth_sessions(rec.id) == []
    assert store.load_request(rec.id).auth_sessions == []


@pytest.mark.parametrize("run_id", ["..", "../escape", "C:\\escape", "a/b", "a\\b", ""])
def test_store_paths_cannot_escape_root(tmp_path, run_id):
    store = RunStore(root=tmp_path)
    with pytest.raises(RunPathError):
        store.report_paths(run_id)


def test_restart_marks_interrupted_runs_failed_without_pid_signals(tmp_path):
    store = RunStore(root=tmp_path)
    running = store.create(_req())
    queued = store.create(_req(auth_sessions=[{"name": "user", "cookie_header": "x=secret"}]))
    done = store.create(_req())
    store.update(running.id, status=RunStatus.running, pid=42)
    store.update(done.id, status=RunStatus.completed)
    assert store.recover_interrupted() == 2
    assert store.get(running.id).status is RunStatus.failed
    assert store.get(queued.id).status is RunStatus.failed
    assert store.get(done.id).status is RunStatus.completed
    assert "execution state unknown" in store.get(running.id).error
    assert store.take_auth_sessions(queued.id) == []
    with pytest.raises(ValueError):
        store.update(running.id, **{"pid = 0 --": 1})


def test_get_and_list_backfill_legacy_count_mismatch(tmp_path):
    store = RunStore(root=tmp_path)
    rec = store.create(_req())
    _, report_path = store.report_paths(rec.id)
    report_path.write_text(json.dumps({
        "finding_count": 99,
        "verified_count": 99,
        "suppressed_count": 0,
        "targets_assessed": [{
            "findings": [
                {"title": "legacy candidate one"},
                {"title": "legacy candidate two"},
            ],
        }],
    }), encoding="utf-8")
    store.update(
        rec.id,
        findings_count=99,
        verified_count=99,
        suppressed_count=0,
    )

    reconciled = store.get(rec.id)
    assert reconciled.findings_count == reconciled.verified_count == 0
    assert reconciled.suppressed_count == 2
    listed = next(item for item in store.list() if item.id == rec.id)
    assert listed.suppressed_count == 2
    row = store._conn.execute(
        "SELECT findings_count, verified_count, suppressed_count "
        "FROM runs WHERE id=?",
        (rec.id,),
    ).fetchone()
    assert tuple(row) == (0, 0, 2)
