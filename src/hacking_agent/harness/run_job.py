"""Per-run worker: executes ONE harness run in its own process.

Reynard uses process-global singletons (event bus, session registry, OOB, the
single Kali container + cookie jar), so each run must execute in a fresh process.
The JobManager launches this module as a subprocess:

    python -m hacking_agent.harness.run_job <run_dir>

It sets env sinks BEFORE importing the heavy agent stack, builds an Engagement
from the submitted scope, runs each authorized target via the existing
assess.run_target (production, evidence-gated), and writes the consolidated
report + a result.json the JobManager reads on exit.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


def _write_result(run_dir: Path, **fields: Any) -> None:
    payload = {
        "findings_count": 0,
        "verified_count": 0,
        "suppressed_count": 0,
        "error": "",
    }
    payload.update(fields)
    try:
        (run_dir / "result.json").write_text(
            json.dumps(payload, default=str), encoding="utf-8")
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m hacking_agent.harness.run_job <run_dir>",
              file=sys.stderr)
        return 2
    run_dir = Path(argv[0]).resolve()
    try:
        config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"failed to read config.json: {exc}", file=sys.stderr)
        return 2

    # ---- env sinks + toggles MUST be set before importing the agent stack ----
    os.environ["REYNARD_EVENT_LOG"] = str(run_dir / "events.jsonl")
    os.environ["REYNARD_MEMORY_DB"] = str(run_dir / "memory.db")
    from hacking_agent.harness.envload import (
        load_operator_env, llm_key_present, missing_llm_key_error,
    )
    load_operator_env()
    browser = bool(config.get("enable_browser_use"))
    hexstrike = bool(config.get("enable_hexstrike"))
    os.environ["BROWSER_USE_ENABLED"] = "1" if browser else "0"
    os.environ["HEXSTRIKE_ENABLED"] = "1" if hexstrike else "0"
    if not (browser or hexstrike):
        os.environ.setdefault("REYNARD_EXTERNAL_ENABLED", "0")

    from hacking_agent.harness.models import RunRequest
    try:
        if os.environ.pop("REYNARD_AUTH_SESSIONS_STDIN", "") == "1":
            # Credentials never enter config files, argv, or the child environment.
            config["auth_sessions"] = json.loads(sys.stdin.buffer.read(1048577))
        req = RunRequest.model_validate(config)
    except (ValueError, TypeError) as exc:
        _write_result(run_dir, error=f"invalid run configuration: {type(exc).__name__}")
        return 1

    err = req.authorization_error()
    if err:
        _write_result(run_dir, error=err)
        return 1

    if not llm_key_present():
        from hacking_agent.core.events import emit
        msg = missing_llm_key_error()
        emit("error", {"message": msg})
        emit("run_end", {"findings": 0, "error": msg})
        _write_result(run_dir, error=msg)
        print(msg, file=sys.stderr)
        return 1

    from hacking_agent.core.events import emit
    from hacking_agent.core.engagement import engagement_from_dict
    from hacking_agent.cli.assess import build_consolidated_report, run_target

    # ---- controlled identities for authenticated / authorization testing ----
    if req.auth_sessions:
        try:
            from hacking_agent.core import sessions as session_mod
            reg = session_mod.get_registry()
            for s in req.auth_sessions:
                reg.register_session(
                    name=s.name, role_hint=s.role_hint,
                    static_headers=dict(s.headers or {}),
                    cookie_header=s.cookie_header or "",
                    overwrite=True)
        except Exception as exc:
            # A failed controlled identity cannot silently become anonymous.
            msg = f"auth session load failed: {type(exc).__name__}"
            emit("error", {"message": msg})
            emit("run_end", {"error": msg})
            _write_result(run_dir, error=msg)
            return 1

    engagement = engagement_from_dict(req.to_engagement_dict())
    targets = req.resolved_targets()
    emit("run_start", {"targets": targets,
                       "description": (req.description or "")[:200]})

    results: list[dict[str, Any]] = []
    for target in targets:
        try:
            row = run_target(
                engagement, target,
                max_iterations=req.max_iterations,
                per_target_timeout=req.per_target_timeout,
                objective=req.description or None,
            )
        except Exception as exc:  # never abort the whole run on one target
            row = {"target": target, "verdict": f"error: {exc}",
                   "timed_out": False, "wall_clock_seconds": 0, "findings": []}
            emit("error", {"target": target, "message": str(exc)[:300]})
        results.append(row)
        if row.get("timed_out"):
            # Container-side commands may outlive their client; stop this run.
            emit("error", {"target": target, "message": "Target timed out; remaining targets skipped."})
            break

    try:
        report_md, report_json = build_consolidated_report(engagement, targets, results)
        (run_dir / "report.md").write_text(report_md, encoding="utf-8")
        (run_dir / "report.json").write_text(
            json.dumps(report_json, indent=2, default=str), encoding="utf-8")
        findings_count = int(report_json.get("finding_count", 0) or 0)
        verified_count = int(report_json.get("verified_count", 0) or 0)
        suppressed_count = int(report_json.get("suppressed_count", 0) or 0)
    except Exception as exc:
        _write_result(run_dir, error=f"report generation failed: {exc}")
        emit("run_end", {"error": str(exc)[:300]})
        return 1

    fatal = [str(r.get("verdict") or "") for r in results
             if str(r.get("verdict") or "").startswith("error:")]
    if any(row.get("timed_out") for row in results):
        fatal.append("error: target timed out; remaining targets skipped")
    if fatal:
        err = " | ".join(fatal)[:500]
        _write_result(run_dir, findings_count=findings_count,
                      verified_count=verified_count,
                      suppressed_count=suppressed_count, error=err)
        emit("run_end", {"findings": findings_count, "verified": verified_count,
                         "suppressed": suppressed_count, "error": err})
        return 1

    _write_result(run_dir, findings_count=findings_count,
                  verified_count=verified_count,
                  suppressed_count=suppressed_count)
    emit("run_end", {
        "findings": findings_count,
        "verified": verified_count,
        "suppressed": suppressed_count,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
