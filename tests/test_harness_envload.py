"""Harness .env loading + instant-fail when the worker has no LLM key."""
from __future__ import annotations

import json
import os

from hacking_agent.harness.envload import (
    load_operator_env, llm_key_present, missing_llm_key_error,
)
from hacking_agent.harness.models import RunRequest
from hacking_agent.harness.run_job import main as run_job_main


def test_fills_blank_key_from_dotenv(tmp_path, monkeypatch):
    envfile = tmp_path / ".env"
    envfile.write_text("DEEPSEEK_API_KEY=sk-from-file\n", encoding="utf-8")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("LLM_DEFAULT_API_KEY", raising=False)
    monkeypatch.setattr(
        "hacking_agent.harness.envload.env_candidates", lambda: [envfile])
    assert load_operator_env() == envfile
    assert os.environ["DEEPSEEK_API_KEY"] == "sk-from-file"
    assert llm_key_present() is True


def test_does_not_clobber_existing_key(tmp_path, monkeypatch):
    envfile = tmp_path / ".env"
    envfile.write_text("DEEPSEEK_API_KEY=sk-from-file\n", encoding="utf-8")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-already-set")
    monkeypatch.setattr(
        "hacking_agent.harness.envload.env_candidates", lambda: [envfile])
    load_operator_env()
    assert os.environ["DEEPSEEK_API_KEY"] == "sk-already-set"


def test_run_job_fails_immediately_without_key(tmp_path, monkeypatch):
    for k in ("DEEPSEEK_API_KEY", "LLM_DEFAULT_API_KEY",
              "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("hacking_agent.harness.envload.load_operator_env",
                        lambda: None)
    monkeypatch.setattr("hacking_agent.harness.envload.llm_key_present",
                        lambda: False)
    req = RunRequest(authorized_domains=["example.com"], authorized=True)
    (tmp_path / "config.json").write_text(req.model_dump_json(), encoding="utf-8")
    rc = run_job_main([str(tmp_path)])
    assert rc == 1
    result = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert "No LLM API key" in result["error"]
    events = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    assert "error" in events and "run_end" in events
    # Must NOT have started an Orchestrator (no memory_fact spam).
    assert "memory_fact" not in events


def test_run_job_target_error_is_failed(tmp_path, monkeypatch):
    monkeypatch.setattr("hacking_agent.harness.envload.load_operator_env",
                        lambda: None)
    monkeypatch.setattr("hacking_agent.harness.envload.llm_key_present",
                        lambda: True)
    req = RunRequest(authorized_domains=["example.com"], authorized=True)
    (tmp_path / "config.json").write_text(req.model_dump_json(), encoding="utf-8")

    def _boom(*_a, **_k):
        return {"target": "https://example.com/",
                "verdict": "error: No API key found.",
                "timed_out": False, "wall_clock_seconds": 0, "findings": []}

    monkeypatch.setattr("hacking_agent.cli.assess.run_target", _boom)
    monkeypatch.setattr(
        "hacking_agent.cli.assess.build_consolidated_report",
        lambda *_a, **_k: ("# empty", {"finding_count": 0, "verified_count": 0}),
    )
    # run_job imports assess after preflight; patch via the module it binds.
    import hacking_agent.harness.run_job as rj
    monkeypatch.setattr(rj, "run_target", _boom, raising=False)

    # Import happens inside main, so patch assess before calling.
    import hacking_agent.cli.assess as assess
    monkeypatch.setattr(assess, "run_target", _boom)
    monkeypatch.setattr(
        assess, "build_consolidated_report",
        lambda *_a, **_k: ("# empty", {"finding_count": 0, "verified_count": 0}),
    )

    rc = run_job_main([str(tmp_path)])
    assert rc == 1
    result = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert result["error"].startswith("error:")


def test_timeout_stops_remaining_targets_and_marks_run_failed(tmp_path, monkeypatch):
    monkeypatch.setattr("hacking_agent.harness.envload.load_operator_env", lambda: None)
    monkeypatch.setattr("hacking_agent.harness.envload.llm_key_present", lambda: True)
    monkeypatch.setenv("REYNARD_MEMORY_DB", "shared-should-not-be-used.db")
    req = RunRequest(authorized_domains=["example.com"], authorized=True,
                     targets=["https://a.example.com/", "https://b.example.com/"])
    (tmp_path / "config.json").write_text(req.model_dump_json(), encoding="utf-8")
    calls = []
    def timeout(_engagement, target, **_kwargs):
        calls.append(target)
        return {"target": target, "timed_out": True, "findings": [], "verdict": "timeout"}
    monkeypatch.setattr("hacking_agent.cli.assess.run_target", timeout)
    monkeypatch.setattr("hacking_agent.cli.assess.build_consolidated_report",
                        lambda *_a: ("# empty", {"finding_count": 0, "verified_count": 0}))
    assert run_job_main([str(tmp_path)]) == 1
    assert calls == ["https://a.example.com/"]
    assert "timed out" in json.loads((tmp_path / "result.json").read_text())["error"]
    assert os.environ["REYNARD_MEMORY_DB"] == str(tmp_path / "memory.db")


def test_auth_session_failure_does_not_silently_run_anonymous(tmp_path, monkeypatch):
    monkeypatch.setattr("hacking_agent.harness.envload.load_operator_env", lambda: None)
    monkeypatch.setattr("hacking_agent.harness.envload.llm_key_present", lambda: True)
    req = RunRequest(authorized_domains=["example.com"], authorized=True,
                     auth_sessions=[{"name": "user", "cookie_header": "x=secret"}])
    (tmp_path / "config.json").write_text(req.model_dump_json(), encoding="utf-8")
    def fail_registry():
        raise RuntimeError("message might contain a credential")
    monkeypatch.setattr("hacking_agent.core.sessions.get_registry", fail_registry)
    monkeypatch.setattr("hacking_agent.cli.assess.run_target",
                        lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("must not start")))
    assert run_job_main([str(tmp_path)]) == 1
    result = (tmp_path / "result.json").read_text()
    assert "auth session load failed" in result
    assert "message might contain" not in result
