"""Hermetic target subprocess, cancellation, IPC and failure-contract regressions."""
from __future__ import annotations

import io
import json
import os
import signal
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hacking_agent.cli import assess, assess_worker
from hacking_agent.core import process_control, sessions
from hacking_agent.core.engagement import Engagement, EngagementError


@pytest.fixture(autouse=True)
def no_real_runtime(monkeypatch):
    monkeypatch.setattr(sessions, "_REGISTRY", None)
    monkeypatch.setattr(sessions, "_docker_exec", Mock(side_effect=AssertionError("Docker forbidden")))
    monkeypatch.setattr("dotenv.load_dotenv", Mock(return_value=False))
    # CLI/worker entrypoints set runtime feature flags directly. Restore every
    # environment key, including keys not routed through monkeypatch.setenv.
    with patch.dict(os.environ, {}, clear=False):
        yield


def engagement():
    return Engagement(authorized_domains=["fixture.invalid"])


def run(**kwargs):
    return assess.run_target(engagement(), "https://fixture.invalid/", max_iterations=2,
                             per_target_timeout=kwargs.pop("timeout", 5), **kwargs)


def stub_worker(monkeypatch, script):
    original = subprocess.Popen
    processes = []
    def launch(argv, **kwargs):
        if len(argv) < 3 or argv[1:3] != ["-m", "hacking_agent.cli.assess_worker"]:
            return original(argv, **kwargs)
        proc = original([sys.executable, "-c", script, argv[-1]], **kwargs)
        processes.append(proc)
        return proc
    monkeypatch.setattr(assess.subprocess, "Popen", launch)
    return processes


@pytest.mark.parametrize("timeout", [-1, float("nan"), float("inf"), -float("inf")])
def test_invalid_timeout_rejected_before_process_creation(monkeypatch, timeout):
    launch = Mock(side_effect=AssertionError("must not spawn"))
    monkeypatch.setattr(assess.subprocess, "Popen", launch)
    with pytest.raises(ValueError):
        run(timeout=timeout)
    launch.assert_not_called()


@pytest.mark.parametrize("option", [["--per-target-timeout", "nan"],
                                   ["--per-target-timeout", "-1"], ["--max-iterations", "0"]])
def test_cli_rejects_invalid_execution_limits(option):
    with pytest.raises(SystemExit) as error:
        assess.parse_args(option)
    assert error.value.code == 2


def test_target_scope_rejected_before_process_creation(monkeypatch):
    launch = Mock(side_effect=AssertionError("must not spawn"))
    monkeypatch.setattr(assess.subprocess, "Popen", launch)
    with pytest.raises(EngagementError):
        assess.run_target(engagement(), "https://outside.invalid/", max_iterations=2,
                          per_target_timeout=5)
    launch.assert_not_called()


@pytest.mark.parametrize("output", ["[]", "null", "not-json", "{}",
    '{"verdict":1,"findings":[]}', '{"verdict":"assessed","findings":{}}',
    '{"verdict":"assessed","findings":[{"unexpected":true}]}'])
def test_malformed_worker_output_fails_closed(monkeypatch, output):
    script = ("import sys,pathlib;sys.stdin.read();"
              f"pathlib.Path(sys.argv[1]).write_text({output!r},encoding='utf-8')")
    processes = stub_worker(monkeypatch, script)
    result = run()
    assert result["verdict"].startswith("error:") and result["findings"] == []
    assert processes[0].poll() is not None


@pytest.mark.parametrize("script", ["import sys;sys.stdin.read();sys.exit(3)",
                                   "import sys;sys.stdin.read()"])
def test_nonzero_or_missing_result_fails_closed(monkeypatch, script):
    stub_worker(monkeypatch, script)
    result = run()
    assert result["verdict"].startswith("error:") and result["findings"] == []


def test_timeout_reaps_worker_discards_partial_result_and_cleans_workspace(monkeypatch):
    script = (
        "import sys,pathlib,time;sys.stdin.read();"
        "pathlib.Path(sys.argv[1]).write_text('{\"verdict\":\"assessed\",\"findings\":[]}');"
        "time.sleep(30)"
    )
    processes = stub_worker(monkeypatch, script)
    result = run(timeout=0.2)
    assert result["timed_out"] is True and result["findings"] == []
    assert processes[0].poll() is not None
    assert not Path(processes[0].args[-1]).parent.exists()


def test_success_and_zero_legacy_timeout_use_stdin_not_argv_or_disk(monkeypatch):
    secret = "ephemeral-auth-value"
    identity = sessions.AuthSession("user", static_headers={"Authorization": "Bearer " + secret})
    registry = SimpleNamespace(names=lambda: ["user"], get=lambda name: identity,
                               active=lambda: identity)
    monkeypatch.setattr(sessions, "_REGISTRY", registry)
    captured = {}
    def launch(argv, **kwargs):
        captured["argv"] = argv
        assert secret not in str(argv) and secret not in str(kwargs)
        path = Path(argv[-1])
        assert list(path.parent.iterdir()) == []
        proc = SimpleNamespace(returncode=0, stdin=io.StringIO())
        def communicate(*, input, timeout):
            config = json.loads(input)
            assert config["session_snapshot"]["sessions"][0]["static_headers"]["Authorization"] == "Bearer " + secret
            assert config["session_snapshot"]["active"] == "user"
            assert config["run_id"] == "test-run"
            assert config["engagement_id"].startswith("engagement:")
            assert timeout is None
            assert list(path.parent.iterdir()) == []
            path.write_text('{"verdict":"assessed","findings":[]}', encoding="utf-8")
        proc.communicate = communicate
        return proc
    monkeypatch.delenv("REYNARD_ENGAGEMENT_ID", raising=False)
    monkeypatch.setattr(assess.subprocess, "Popen", launch)
    result = run(timeout=0, run_id="test-run")
    assert result["verdict"] == "assessed"
    assert not Path(captured["argv"][-1]).parent.exists()


@pytest.mark.parametrize("outcome", [None, SimpleNamespace(success=False)])
def test_missing_or_failed_orchestrator_report_is_not_assessed(monkeypatch, outcome):
    fake = SimpleNamespace(run=lambda: outcome,
                           _assemble_evidence_bundles=Mock(side_effect=AssertionError("no evidence on failure")))
    factory = Mock(return_value=fake)
    monkeypatch.setattr("hacking_agent.cli.orchestrator.Orchestrator", factory)
    result = assess._run_target_worker({"engagement": asdict(engagement()),
        "target_url": "https://fixture.invalid/", "max_iterations": 2,
        "run_id": "run-one", "engagement_id": "engagement-one"})
    assert result["verdict"].startswith("error:") and result["findings"] == []
    assert factory.call_args.kwargs["mission_mode"] == "production"
    assert factory.call_args.kwargs["run_id"] == "run-one"
    assert factory.call_args.kwargs["engagement_id"] == "engagement-one"


def test_worker_restores_authenticated_identity_and_passes_bindings(monkeypatch):
    identity = sessions.AuthSession("user", static_headers={"Cookie": "session=private"})
    registry = SimpleNamespace(register=Mock(), set_active=Mock())
    monkeypatch.setattr(sessions, "get_registry", lambda: registry)
    fake = SimpleNamespace(run=lambda: SimpleNamespace(success=True),
                           _assemble_evidence_bundles=Mock(), memory=None, evidence=None, bundles=None)
    monkeypatch.setattr("hacking_agent.cli.orchestrator.Orchestrator", lambda **_: fake)
    monkeypatch.setattr(assess, "extract_findings", lambda *_: [])
    result = assess._run_target_worker({"engagement": asdict(engagement()),
        "target_url": "https://fixture.invalid/", "max_iterations": 2,
        "session_snapshot": {"sessions": [identity.to_transfer_dict()], "active": "user"}})
    assert result == {"verdict": "assessed", "findings": []}
    assert registry.register.call_args.args[0].static_headers == {"Cookie": "session=private"}
    registry.set_active.assert_called_once_with("user")


def test_worker_entrypoint_sanitizes_failure_and_returns_nonzero(tmp_path, monkeypatch):
    path = tmp_path / "result.json"
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"secret":"do-not-persist"}'))
    monkeypatch.setattr(assess_worker, "_run_target_worker",
                        Mock(side_effect=RuntimeError("do-not-persist")))
    assert assess_worker.main([str(path)]) == 1
    assert "do-not-persist" not in path.read_text()
    assert json.loads(path.read_text())["findings"] == []
    assert assess_worker.main([]) == 2


@pytest.mark.parametrize("value", ["[]", "bad-json"])
def test_worker_entrypoint_rejects_malformed_input(tmp_path, monkeypatch, value):
    monkeypatch.setattr(sys, "stdin", io.StringIO(value))
    target = Mock(side_effect=AssertionError("do not execute"))
    monkeypatch.setattr(assess_worker, "_run_target_worker", target)
    assert assess_worker.main([str(tmp_path / "result.json")]) == 1
    target.assert_not_called()


def test_assessment_stops_after_timeout_and_reports_failed_exit(tmp_path, monkeypatch):
    config = tmp_path / "engagement.json"
    config.write_text(json.dumps(asdict(engagement())), encoding="utf-8")
    args = assess.parse_args(["--engagement", str(config), "--out", str(tmp_path),
                             "--target", "https://a.fixture.invalid/", "--target", "https://b.fixture.invalid/"])
    calls = []
    def timeout(_engagement, target, **_):
        calls.append(target)
        return {"target": target, "verdict": "timeout after 1s", "timed_out": True,
                "wall_clock_seconds": 1, "findings": []}
    monkeypatch.setattr(assess, "run_target", timeout)
    monkeypatch.setattr(assess, "build_consolidated_report", lambda *_a, **_kw: ("report", {}))
    writer = Mock(return_value=(tmp_path / "report.md", tmp_path / "report.json"))
    monkeypatch.setattr(assess, "write_reports", writer)
    assert assess.run_assessment(args) == 1
    assert calls == ["https://a.fixture.invalid/"]
    writer.assert_called_once()


def test_cleanup_failure_does_not_allow_assessment_to_schedule_next_target(tmp_path, monkeypatch):
    script = "import sys,time;sys.stdin.read();time.sleep(30)"
    processes = stub_worker(monkeypatch, script)
    def failed_cleanup(proc):
        proc.kill(); proc.wait(timeout=5)
        raise process_control.ProcessCleanupError("fixture cleanup failure")
    monkeypatch.setattr(assess, "stop_process_tree", failed_cleanup)
    with pytest.raises(process_control.ProcessCleanupError):
        run(timeout=0.1)
    assert processes[0].poll() is not None


def test_harness_stops_remaining_targets_after_unconfirmed_cleanup(tmp_path, monkeypatch):
    from hacking_agent.harness.models import RunRequest
    from hacking_agent.harness import run_job
    request = RunRequest(authorized=True, authorized_domains=["fixture.invalid"],
                         targets=["https://a.fixture.invalid/", "https://b.fixture.invalid/"])
    (tmp_path / "config.json").write_text(request.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr("hacking_agent.harness.envload.load_operator_env", lambda: None)
    monkeypatch.setattr("hacking_agent.harness.envload.llm_key_present", lambda: True)
    target = Mock(side_effect=process_control.ProcessCleanupError("fixture failed cleanup"))
    monkeypatch.setattr(assess, "run_target", target)
    monkeypatch.setattr(assess, "build_consolidated_report", lambda *_a, **_kw: ("empty", {}))
    monkeypatch.setattr("hacking_agent.harness.submission.render_stored_report_markdown", lambda *_a, **_kw: "empty")
    for name in ("REYNARD_RUN_ID", "REYNARD_ENGAGEMENT_ID", "REYNARD_EVENT_LOG", "REYNARD_MEMORY_DB"):
        monkeypatch.setenv(name, "")
    assert run_job.main([str(tmp_path)]) == 1
    target.assert_called_once()
    assert "cleanup could not be confirmed" in (tmp_path / "result.json").read_text()


def test_posix_sigterm_forwards_to_nested_target_session(monkeypatch):
    captured = {}
    previous = object()
    def fake_signal(sig, handler):
        captured.setdefault("handlers", []).append(handler)
        return previous
    proc = SimpleNamespace(stdin=io.StringIO(), returncode=None)
    def communicate(**kwargs):
        captured["handlers"][0](signal.SIGTERM, None)
    proc.communicate = communicate
    monkeypatch.setattr(assess, "os", SimpleNamespace(name="posix", getenv=lambda *_: ""))
    monkeypatch.setattr(assess.signal, "signal", fake_signal)
    monkeypatch.setattr(assess.subprocess, "Popen", lambda *_a, **_k: proc)
    cleanup = Mock()
    monkeypatch.setattr(assess, "stop_process_tree", cleanup)
    with pytest.raises(SystemExit):
        run()
    cleanup.assert_called_once_with(proc)
    assert captured["handlers"][-1] is previous
    assert proc.stdin.closed


def test_windows_failed_tree_command_still_reaps_and_fails_closed(monkeypatch):
    monkeypatch.setattr(process_control, "os", SimpleNamespace(name="nt"))
    command = Mock(side_effect=subprocess.TimeoutExpired("taskkill", 1))
    monkeypatch.setattr(process_control.subprocess, "run", command)
    proc = Mock(pid=1234)
    proc.poll.return_value = None
    proc.wait.side_effect = [subprocess.TimeoutExpired("worker", 0.1), 1]
    with pytest.raises(process_control.ProcessCleanupError):
        process_control.stop_process_tree(proc, grace_seconds=0.1)
    proc.kill.assert_called_once()
    assert proc.wait.call_count == 2
    assert command.call_args.args[0] == ["taskkill", "/PID", "1234", "/T", "/F"]


def test_posix_cleanup_signals_group_even_when_direct_child_exited(monkeypatch):
    killpg = Mock()
    monkeypatch.setattr(process_control, "os", SimpleNamespace(name="posix", killpg=killpg))
    monkeypatch.setattr(process_control, "signal", SimpleNamespace(SIGTERM=15, SIGKILL=9))
    proc = Mock(pid=1234)
    process_control.stop_process_tree(proc)
    assert [call.args for call in killpg.call_args_list] == [(1234, 15), (1234, 9)]
    assert proc.wait.call_count == 2


@pytest.mark.parametrize("grace", [-1, float("inf"), float("nan")])
def test_cleanup_rejects_nonfinite_wait_bounds(grace):
    with pytest.raises(ValueError):
        process_control.stop_process_tree(Mock(), grace_seconds=grace)
