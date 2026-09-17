"""Opt-in host execution fallback for _docker_exec (no Kali container)."""
from __future__ import annotations

import json
import subprocess

from hacking_agent.core import tools as tools_mod


def test_host_exec_runs_echo(monkeypatch):
    monkeypatch.setenv("REYNARD_HOST_EXEC", "1")
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "host-exec-ok\n", "")

    monkeypatch.setattr(tools_mod.subprocess, "run", run)
    raw = tools_mod.run_shell("echo host-exec-ok")
    result = json.loads(raw)
    assert result["exit_code"] == 0
    assert "host-exec-ok" in result["stdout"]
    assert calls == [["bash", "-c", "echo host-exec-ok"]]


def test_host_exec_default_off_does_not_use_host_when_docker_missing(monkeypatch):
    monkeypatch.delenv("REYNARD_HOST_EXEC", raising=False)
    monkeypatch.setattr(tools_mod, "CONTAINER_NAME", "fixture-missing-container")
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        raise FileNotFoundError("fixture: Docker is unavailable")

    monkeypatch.setattr(tools_mod.subprocess, "run", run)
    # Without the opt-in flag, a missing docker/container must not silently
    # run the command on the host.
    raw = tools_mod.run_shell("echo should-not-run")
    result = json.loads(raw)
    assert "should-not-run" not in (result.get("stdout") or "")
    assert result["exit_code"] == -1
    assert calls == [["docker", "exec", "fixture-missing-container", "bash", "-c", "echo should-not-run"]]
