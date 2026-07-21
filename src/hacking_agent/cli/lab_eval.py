"""Offline lab-readiness evaluator.

This command does not attack a target. It checks whether the agent can parse a
lab objective into a target, expert profile, playbook, tool plan, and obvious
run-time prerequisites. Use it as a fast regression harness before spending LLM
and lab time.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console

from hacking_agent.core.expert_playbooks import get_playbook, render_playbook_context
from hacking_agent.core.lab_corpus import (
    class_to_playbook,
    classify_url,
    is_placeholder_target,
    normalize_lab_level,
)
from hacking_agent.core.lab_intel import detect_lab_profile, normalize_target_input
from hacking_agent.core.paths import LOG_DIR, ensure_runtime_dirs


console = Console()

AUTH_HEAVY_PLAYBOOKS = {
    "authentication",
    "oauth",
    "jwt",
    "access_control_idor",
    "csrf",
    "cors",
    "graphql_api",
    "race_condition",
    "business_logic",
    "api_testing",
    "web_llm_attacks",
}

BROWSER_HEAVY_PLAYBOOKS = {
    "xss",
    "clickjacking",
    "dom_based",
    "dom_xss",
    "csrf",
    "websocket",
    "prototype_pollution",
    "oauth",
    "web_llm_attacks",
}

DEFAULT_CASES: list[dict[str, str]] = [
    {
        "name": "SQL injection",
        "objective": "PortSwigger SQL injection lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "sqli",
    },
    {
        "name": "Cross-site scripting",
        "objective": "Reflected XSS lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "xss",
    },
    {
        "name": "CSRF",
        "objective": "Cross-site request forgery CSRF lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "csrf",
    },
    {
        "name": "Clickjacking",
        "objective": "Clickjacking lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "clickjacking",
    },
    {
        "name": "DOM-based vulnerabilities",
        "objective": "DOM-based vulnerabilities lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "dom_based",
    },
    {
        "name": "CORS",
        "objective": "CORS cross-origin resource sharing lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "cors",
    },
    {
        "name": "XXE",
        "objective": "XML external entity XXE injection lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "xxe",
    },
    {
        "name": "SSRF",
        "objective": "Server-side request forgery SSRF lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "ssrf",
    },
    {
        "name": "HTTP request smuggling",
        "objective": "HTTP request smuggling CL.TE lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "request_smuggling",
    },
    {
        "name": "OS command injection",
        "objective": "OS command injection lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "os_command_injection",
    },
    {
        "name": "SSTI",
        "objective": "Server-side template injection SSTI lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "ssti",
    },
    {
        "name": "Path traversal",
        "objective": "Path traversal lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "path_traversal",
    },
    {
        "name": "Access control",
        "objective": "Access control IDOR lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "access_control_idor",
    },
    {
        "name": "Authentication",
        "objective": "Authentication password reset lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "authentication",
    },
    {
        "name": "WebSockets",
        "objective": "WebSocket security flaw lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "websocket",
    },
    {
        "name": "Web cache poisoning",
        "objective": "Web cache poisoning with an unkeyed header. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "web_cache_poisoning",
    },
    {
        "name": "Insecure deserialization",
        "objective": "Insecure deserialization lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "deserialization",
    },
    {
        "name": "Information disclosure",
        "objective": "Information disclosure debug page lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "information_disclosure",
    },
    {
        "name": "Business logic",
        "objective": "Business logic flaw lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "business_logic",
    },
    {
        "name": "HTTP Host header",
        "objective": "HTTP Host header password reset poisoning lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "host_header",
    },
    {
        "name": "OAuth authentication",
        "objective": "OAuth authentication lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "oauth",
    },
    {
        "name": "File upload",
        "objective": "File upload vulnerability lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "file_upload",
    },
    {
        "name": "JWT",
        "objective": "JWT authentication bypass lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "jwt",
    },
    {
        "name": "Essential skills",
        "objective": "Essential skills mystery lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "essential_skills",
    },
    {
        "name": "Prototype pollution",
        "objective": "Client-side prototype pollution lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "prototype_pollution",
    },
    {
        "name": "GraphQL API vulnerabilities",
        "objective": "GraphQL introspection authorization lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "graphql_api",
    },
    {
        "name": "Race conditions",
        "objective": "Race condition limit-overrun lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "race_condition",
    },
    {
        "name": "NoSQL injection",
        "objective": "NoSQL injection operator injection lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "nosql_injection",
    },
    {
        "name": "API testing",
        "objective": "API testing OpenAPI lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "api_testing",
    },
    {
        "name": "Web LLM attacks",
        "objective": "Web LLM attacks prompt injection lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "web_llm_attacks",
    },
    {
        "name": "Web cache deception",
        "objective": "Web cache deception lab. Target: https://0abc.web-security-academy.net/",
        "expected_playbook": "web_cache_deception",
    },
    {
        "name": "OIDC dynamic registration SSRF",
        "objective": (
            "SSRF via OpenID dynamic client registration. You can log in using "
            "wiener:peter. Target: https://0abc.web-security-academy.net/"
        ),
        "expected_playbook": "oauth_ssrf_dynamic_registration",
    },
]


def _case_text(case: str | dict[str, Any]) -> str:
    if isinstance(case, str):
        return case
    parts = [
        str(case.get(key, ""))
        for key in ("name", "objective", "description", "target")
        if case.get(key)
    ]
    return " ".join(parts)


def evaluate_case(case: str | dict[str, Any]) -> dict[str, Any]:
    """Evaluate one lab objective for deterministic readiness."""
    text = _case_text(case)
    target_url, objective = normalize_target_input(text)
    profile = detect_lab_profile(text, target_url)
    playbook = get_playbook(profile)
    playbook_id = playbook.get("id") if playbook else ""
    expected = case.get("expected_playbook") if isinstance(case, dict) else None

    gaps: list[str] = []
    if not target_url or " " in target_url.strip():
        gaps.append("target_not_parsed")
    if not profile:
        gaps.append("lab_profile_not_detected")
    if not playbook:
        gaps.append("expert_playbook_missing")
    if expected and playbook_id != expected:
        gaps.append(f"expected_{expected}_got_{playbook_id or 'none'}")

    credentials = profile.get("credentials", []) if profile else []
    primary_tools = playbook.get("primary_tools", []) if playbook else []
    requires_auth = bool(playbook_id in AUTH_HEAVY_PLAYBOOKS or credentials)
    requires_browser = bool(playbook_id in BROWSER_HEAVY_PLAYBOOKS)
    requires_oob = any(str(tool).startswith("oob_") for tool in primary_tools)
    prefers_caido = "caido_local_api" in primary_tools

    if requires_auth and not credentials:
        gaps.append("auth_session_or_credentials_missing")
    if requires_oob:
        gaps.append("verify_oob_interactsh_available_before_run")
    if prefers_caido:
        gaps.append("verify_caido_local_bridge_before_run")

    # Gaps that are prerequisites, not parser failures, should not destroy the
    # score as harshly. The goal is to show whether the agent has a good plan.
    hard_gaps = [
        gap for gap in gaps
        if not gap.startswith("verify_") and gap != "auth_session_or_credentials_missing"
    ]
    soft_gaps = [gap for gap in gaps if gap not in hard_gaps]
    readiness_score = max(0, 10 - (3 * len(hard_gaps)) - len(soft_gaps))

    return {
        "name": case.get("name", "") if isinstance(case, dict) else "",
        "target_url": target_url,
        "objective": objective,
        "profile_id": profile.get("id", "") if profile else "",
        "playbook_id": playbook_id,
        "vulnerability": playbook.get("vulnerability", "") if playbook else "",
        "primary_tools": primary_tools,
        "required_artifacts": playbook.get("required_artifacts", []) if playbook else [],
        "credentials_detected": credentials,
        "requires_auth": requires_auth,
        "requires_browser": requires_browser,
        "requires_oob": requires_oob,
        "prefers_caido": prefers_caido,
        "readiness_score": readiness_score,
        "gaps": gaps,
        "playbook_context_preview": render_playbook_context(profile)[:1500],
    }


def load_suite(path: str | None) -> list[str | dict[str, Any]]:
    if not path:
        return DEFAULT_CASES
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and isinstance(raw.get("cases"), list):
        return raw["cases"]
    raise ValueError("Suite must be a JSON list or an object with a 'cases' list.")


def write_report(results: list[dict[str, Any]]) -> Path:
    ensure_runtime_dirs()
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = LOG_DIR / f"lab_eval_{ts}.json"
    payload = {
        "generated_at": datetime.utcnow().isoformat(),
        "case_count": len(results),
        "average_readiness": (
            round(sum(item["readiness_score"] for item in results) / len(results), 2)
            if results else 0
        ),
        "results": results,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


# =============================================================================
# Live solve-rate eval harness
# =============================================================================
# `--live` runs the real multi-agent Orchestrator against a config-listed set of
# labs and records a solve-rate scorecard. This is the 0%-to-100% ruler.

_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: Any) -> Any:
    """Expand ${ENV_VAR} placeholders in strings so configs never hardcode secrets."""
    if not isinstance(value, str):
        return value
    return _ENV_PLACEHOLDER.sub(lambda m: os.getenv(m.group(1), ""), value)


def load_live_config(path: str) -> list[dict[str, Any]]:
    """Load a live lab config (JSON or YAML). Accepts a top-level list or a
    mapping with a `labs` (or `cases`) list."""
    text = Path(path).read_text(encoding="utf-8")
    suffix = Path(path).suffix.lower()
    if suffix in (".yaml", ".yml"):
        import yaml
        raw = yaml.safe_load(text)
    else:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            import yaml
            raw = yaml.safe_load(text)

    if isinstance(raw, list):
        labs = raw
    elif isinstance(raw, dict):
        labs = raw.get("labs") or raw.get("cases") or []
    else:
        labs = []
    if not labs:
        raise ValueError(
            "Live config must be a list of labs or a mapping with a 'labs' list."
        )
    return [dict(lab) for lab in labs]


def _scoring_class(lab: dict[str, Any], detected_playbook: str) -> str:
    """Resolve the coverage class (internal playbook_id) used for scoring.

    Prefers the config's expected_vuln, then the detected playbook, then the
    class derived from the documentation lab_url via the corpus classifier.
    """
    expected = str(lab.get("expected_vuln") or lab.get("expected_playbook") or "")
    if expected:
        return expected
    if detected_playbook:
        return detected_playbook
    lab_url = str(lab.get("lab_url") or "")
    if lab_url:
        vuln_class, _ = classify_url(lab_url)
        return class_to_playbook(vuln_class) or vuln_class
    return ""


def run_live_lab(
    lab: dict[str, Any],
    per_lab_timeout: float,
    default_max_iterations: int,
    *,
    force_strong: bool = False,
    capture_transcript: bool = False,
) -> dict[str, Any]:
    """Run the Orchestrator against a single lab and return a scorecard row.

    Reuses the orchestrator entry point programmatically. The run executes in a
    daemon thread so a per-lab wall-clock timeout can be enforced; the shared
    token meter is reset before the run so tokens are attributed per lab.

    When ``force_strong`` is set the strong tier is pinned for the whole run
    (used by the training re-run pass); when ``capture_transcript`` is set an
    unsolved run writes a compact failure transcript under ``logs/``.
    """
    # Imported lazily: the offline readiness path must not require the full
    # orchestrator/agent stack (and its optional runtime deps) to be importable.
    from hacking_agent.cli.orchestrator import Orchestrator
    from hacking_agent.core.metering import get_token_meter
    from hacking_agent.core import sessions as session_mod

    name = str(lab.get("name") or lab.get("objective") or lab.get("target") or "lab")
    target = str(lab.get("target") or lab.get("target_url") or "")
    objective = str(lab.get("objective") or lab.get("name") or "")
    text = " ".join(x for x in (lab.get("name"), objective, target) if x)

    target_url, parsed_objective = normalize_target_input(text)
    objective_final = objective or parsed_objective
    lab_profile = detect_lab_profile(text, target_url) or {}
    playbook = get_playbook(lab_profile) if lab_profile else None
    playbook_id = playbook.get("id") if playbook else ""
    expected_vuln = lab.get("expected_vuln") or lab.get("expected_playbook") or ""

    lab_level = normalize_lab_level(lab.get("level") or lab.get("lab_level"))
    if lab_level and isinstance(lab_profile, dict):
        lab_profile["lab_level"] = lab_level
    scoring_class = _scoring_class(lab, playbook_id)

    creds = lab.get("creds") or {}
    username = _expand_env(creds.get("username"))
    password = _expand_env(creds.get("password"))
    if username and password:
        lab_profile.setdefault("credentials", []).append(
            {"username": username, "password": password}
        )

    auth_file = _expand_env(lab.get("auth_file"))
    if auth_file:
        try:
            session_mod.load_from_file(auth_file)
        except Exception as exc:  # noqa: BLE001 - best effort, recorded below
            console.print(f"[yellow]auth_file load failed for {name}: {exc}[/]")

    max_iterations = int(lab.get("max_iterations", default_max_iterations))

    meter = get_token_meter()
    meter.reset()

    console.print(f"[bold cyan]▶ Running lab:[/] {name} → {target_url}")

    holder: dict[str, Any] = {}

    def _run() -> None:
        try:
            orch = Orchestrator(
                target_url=target_url,
                max_iterations=max_iterations,
                objective=objective_final,
                lab_profile=lab_profile,
                subagents_enabled=bool(lab.get("subagents", True)),
            )
            holder["orch"] = orch
            holder["result"] = orch.run()
        except Exception as exc:  # noqa: BLE001 - surfaced in verdict
            holder["error"] = exc

    # Pin the strong tier for the whole run during the escalated re-run pass.
    # The Orchestrator reads this env flag at construction (inside the thread),
    # so it must be set before the thread starts and restored afterwards.
    prev_force_strong = os.environ.get("REYNARD_FORCE_STRONG_TIER")
    if force_strong:
        os.environ["REYNARD_FORCE_STRONG_TIER"] = "1"

    thread = threading.Thread(target=_run, daemon=True)
    started = time.time()
    thread.start()
    thread.join(per_lab_timeout if per_lab_timeout > 0 else None)
    elapsed = round(time.time() - started, 1)
    timed_out = thread.is_alive()

    if force_strong:
        if prev_force_strong is None:
            os.environ.pop("REYNARD_FORCE_STRONG_TIER", None)
        else:
            os.environ["REYNARD_FORCE_STRONG_TIER"] = prev_force_strong

    orch = holder.get("orch")
    result = holder.get("result")
    error = holder.get("error")

    solved = False
    iterations = 0
    verified_pocs = 0
    if orch is not None:
        try:
            solved = bool(orch.memory.get_fact("lab_solved"))
            verified_pocs = sum(
                1 for p in orch.evidence.all_pocs() if p.verdict == "success"
            )
            solved = solved or verified_pocs > 0
            iterations = orch.sm.iteration
        except Exception:  # noqa: BLE001 - defensive snapshot
            pass

    if timed_out:
        verdict = f"timeout after {per_lab_timeout}s"
    elif error is not None:
        verdict = f"error: {str(error)[:200]}"
    elif result is not None:
        verdict = (result.summary or "reported")[:200]
    else:
        verdict = "no_report"

    transcript_path = ""
    if capture_transcript and not solved and orch is not None:
        transcript_path = _write_failure_transcript(
            name, orch, scoring_class, lab_level, verdict, force_strong
        )

    tokens = meter.totals()
    return {
        "name": name,
        "target_url": target_url,
        "objective": objective_final,
        "playbook_id": playbook_id,
        "class": scoring_class,
        "level": lab_level,
        "expected_vuln": expected_vuln,
        "expected_match": (not expected_vuln) or (playbook_id == expected_vuln),
        "solved": solved,
        "escalated": force_strong,
        "verified_pocs": verified_pocs,
        "iterations": iterations,
        "prompt_tokens": tokens["prompt_tokens"],
        "completion_tokens": tokens["completion_tokens"],
        "total_tokens": tokens["total_tokens"],
        "llm_calls": tokens["calls"],
        "estimated_cost_usd": meter.estimated_cost(),
        "wall_clock_seconds": elapsed,
        "timed_out": timed_out,
        "transcript_path": transcript_path,
        "verdict": verdict,
    }


def _md_table(results: list[dict[str, Any]]) -> str:
    header = (
        "| Lab | Solved | Iters | Tokens | Cost (USD) | Seconds | Verdict |\n"
        "| --- | :---: | ---: | ---: | ---: | ---: | --- |\n"
    )
    rows = []
    for r in results:
        rows.append(
            "| {name} | {solved} | {iters} | {tokens} | {cost} | {secs} | {verdict} |".format(
                name=str(r["name"]).replace("|", "\\|")[:60],
                solved="✅" if r["solved"] else "❌",
                iters=r["iterations"],
                tokens=r["total_tokens"],
                cost=f"{r['estimated_cost_usd']:.4f}",
                secs=r["wall_clock_seconds"],
                verdict=str(r["verdict"]).replace("|", "\\|")[:80],
            )
        )
    return header + "\n".join(rows) + "\n"


def write_live_scorecard(results: list[dict[str, Any]]) -> tuple[Path, Path]:
    """Write the live scorecard as JSON and a human-readable markdown table."""
    ensure_runtime_dirs()
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    solved = sum(1 for r in results if r["solved"])
    total = len(results)
    totals = {
        "labs": total,
        "solved": solved,
        "solve_rate": round(solved / total, 3) if total else 0.0,
        "total_tokens": sum(r["total_tokens"] for r in results),
        "estimated_cost_usd": round(sum(r["estimated_cost_usd"] for r in results), 6),
        "wall_clock_seconds": round(sum(r["wall_clock_seconds"] for r in results), 1),
    }
    payload = {
        "generated_at": datetime.utcnow().isoformat(),
        "summary": totals,
        "results": results,
    }

    json_path = LOG_DIR / f"live_scorecard_{ts}.json"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md = [
        "# Reynard Live Solve-Rate Scorecard",
        "",
        f"- Generated: {payload['generated_at']}",
        f"- Labs: {totals['labs']}",
        f"- Solved: {totals['solved']} ({totals['solve_rate'] * 100:.1f}%)",
        f"- Total tokens: {totals['total_tokens']}",
        f"- Estimated cost: ${totals['estimated_cost_usd']}",
        f"- Wall-clock: {totals['wall_clock_seconds']}s",
        "",
        _md_table(results),
    ]
    md_path = LOG_DIR / f"live_scorecard_{ts}.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    return json_path, md_path


def _write_failure_transcript(
    name: str,
    orch: Any,
    lab_class: str,
    lab_level: str,
    verdict: str,
    escalated: bool,
) -> str:
    """Write a compact failure transcript (hypotheses / failed attempts /
    final summary) for an unsolved lab. Best-effort; returns "" on failure."""
    try:
        ensure_runtime_dirs()
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48] or "lab"
        path = LOG_DIR / f"failure_{slug}_{ts}.md"

        hypotheses: list[str] = []
        try:
            for h in orch.agenda.all()[:12]:
                hypotheses.append(
                    f"- [{h.status}] {h.vuln_type or '?'}@{h.vector or '?'} "
                    f"(phase={h.phase}, heat={h.heat:.2f}, fails={h.fail_count}): "
                    f"{(h.text or '')[:160]}"
                )
        except Exception:  # noqa: BLE001 - transcript is best-effort
            pass

        failures: list[str] = []
        try:
            for f in orch.memory.get_recent_failures(12):
                failures.append(
                    f"- [{f.get('phase')}/{f.get('tool')}] {f.get('reason')} "
                    f"-> {f.get('lesson')}"
                )
        except Exception:  # noqa: BLE001
            pass

        lines = [
            f"# Failure transcript: {name}",
            "",
            f"- Class: `{lab_class or 'unknown'}`",
            f"- Level: {lab_level or 'unknown'}",
            f"- Tier: {'strong (escalated re-run)' if escalated else 'default'}",
            f"- Target: {orch.target_url}",
            f"- Iterations: {getattr(orch.sm, 'iteration', 0)}",
            f"- Final verdict: {verdict}",
            "",
            "## Hypothesis agenda (last state)",
            *(hypotheses or ["- (none recorded)"]),
            "",
            "## Failed attempts",
            *(failures or ["- (none recorded)"]),
            "",
        ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)
    except Exception:  # noqa: BLE001 - never let transcript IO break a run
        return ""


def _record_solved_technique(lab_class: str, name: str) -> None:
    """Belt-and-suspenders durable write: record a solved technique for the
    class so later runs surface it as a primed win (durable.py feed-back)."""
    if not lab_class:
        return
    try:
        from hacking_agent.core.durable import open_durable_store

        store = open_durable_store()
        if store is None:
            return
        try:
            store.record_technique(
                lab_class,
                technique=lab_class,
                tool="training_loop",
                outcome="success",
                detail=f"solved: {name}"[:200],
            )
        finally:
            store.close()
    except Exception:  # noqa: BLE001 - durable memory is opt-in-safe
        pass


def _not_run_row(lab: dict[str, Any], reason: str) -> dict[str, Any]:
    """Scorecard row for a lab that was intentionally not run (placeholder
    target / total-budget exhausted). Counted separately, not as a failure."""
    playbook_id = ""
    lab_url = str(lab.get("lab_url") or "")
    if lab_url:
        vuln_class, _ = classify_url(lab_url)
        playbook_id = class_to_playbook(vuln_class) or vuln_class
    return {
        "name": str(lab.get("name") or lab.get("target") or "lab"),
        "target_url": str(lab.get("target") or lab.get("target_url") or ""),
        "objective": str(lab.get("objective") or ""),
        "playbook_id": playbook_id,
        "class": _scoring_class(lab, playbook_id),
        "level": normalize_lab_level(lab.get("level") or lab.get("lab_level")),
        "expected_vuln": lab.get("expected_vuln") or "",
        "expected_match": True,
        "solved": False,
        "escalated": False,
        "not_run": True,
        "verified_pocs": 0,
        "iterations": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "llm_calls": 0,
        "estimated_cost_usd": 0.0,
        "wall_clock_seconds": 0.0,
        "timed_out": False,
        "transcript_path": "",
        "verdict": reason,
    }


def _aggregate(results: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    """Aggregate solve stats by a row key (``class`` or ``level``)."""
    out: dict[str, dict[str, Any]] = {}
    for r in results:
        bucket = str(r.get(key) or "unknown")
        row = out.setdefault(bucket, {"labs": 0, "run": 0, "solved": 0})
        row["labs"] += 1
        if r.get("not_run"):
            continue
        row["run"] += 1
        if r.get("solved"):
            row["solved"] += 1
    for row in out.values():
        row["solve_rate"] = round(row["solved"] / row["run"], 3) if row["run"] else 0.0
    return out


def write_training_scorecard(
    results: list[dict[str, Any]],
) -> tuple[Path, Path]:
    """Write the training scorecard (JSON + markdown) with per-class and
    per-level breakdowns, plus a stable ``training_scorecard_latest.json`` that
    the coverage-matrix generator reads."""
    ensure_runtime_dirs()
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_rows = [r for r in results if not r.get("not_run")]
    solved = sum(1 for r in run_rows if r["solved"])
    total = len(results)
    run = len(run_rows)
    skipped = total - run
    by_class = _aggregate(results, "class")
    by_level = _aggregate(results, "level")
    summary = {
        "labs": total,
        "run": run,
        "skipped": skipped,
        "solved": solved,
        "solve_rate": round(solved / run, 3) if run else 0.0,
        "escalated_reruns": sum(1 for r in run_rows if r.get("escalated")),
        "total_tokens": sum(r["total_tokens"] for r in results),
        "estimated_cost_usd": round(sum(r["estimated_cost_usd"] for r in results), 6),
        "wall_clock_seconds": round(sum(r["wall_clock_seconds"] for r in results), 1),
    }
    payload = {
        "generated_at": datetime.utcnow().isoformat(),
        "summary": summary,
        "by_class": by_class,
        "by_level": by_level,
        "results": results,
    }

    json_path = LOG_DIR / f"training_scorecard_{ts}.json"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (LOG_DIR / "training_scorecard_latest.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )

    md = [
        "# Reynard Training Scorecard",
        "",
        f"- Generated: {payload['generated_at']}",
        f"- Labs: {summary['labs']} (run {summary['run']}, skipped {summary['skipped']})",
        f"- Solved: {summary['solved']} ({summary['solve_rate'] * 100:.1f}% of run)",
        f"- Escalated re-runs: {summary['escalated_reruns']}",
        f"- Total tokens: {summary['total_tokens']}",
        f"- Estimated cost: ${summary['estimated_cost_usd']}",
        f"- Wall-clock: {summary['wall_clock_seconds']}s",
        "",
        "## Solve-rate by class",
        "",
        "| Class | Labs | Run | Solved | Solve-rate |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for cls in sorted(by_class, key=lambda k: (-by_class[k]["solved"], k)):
        row = by_class[cls]
        md.append(
            f"| `{cls}` | {row['labs']} | {row['run']} | {row['solved']} | "
            f"{row['solve_rate'] * 100:.0f}% |"
        )
    md += [
        "",
        "## Solve-rate by level",
        "",
        "| Level | Labs | Run | Solved | Solve-rate |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for lvl in sorted(by_level):
        row = by_level[lvl]
        md.append(
            f"| {lvl} | {row['labs']} | {row['run']} | {row['solved']} | "
            f"{row['solve_rate'] * 100:.0f}% |"
        )
    md += ["", _md_table(results), ""]
    md_path = LOG_DIR / f"training_scorecard_{ts}.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    return json_path, md_path


def run_train(args: argparse.Namespace) -> None:
    """Batch training/eval loop: run every lab, record techniques + failure
    transcripts, auto-re-run unsolved labs once at the escalated (strong) tier,
    emit per-class/per-level scorecards, and refresh the coverage matrix."""
    config_path = args.config or args.suite
    if not config_path:
        console.print(
            "[red]--train requires --config PATH (JSON/YAML list of labs).[/]"
        )
        raise SystemExit(2)

    rerun_strong = os.getenv(
        "REYNARD_TRAIN_RERUN_STRONG", "1"
    ).lower() not in ("0", "false", "no", "off")
    refresh_matrix = os.getenv(
        "REYNARD_TRAIN_REFRESH_MATRIX", "1"
    ).lower() not in ("0", "false", "no", "off")

    labs = load_live_config(config_path)
    results: list[dict[str, Any]] = []
    started = time.time()

    def _budget_left() -> bool:
        return (not args.max_total_seconds) or (
            (time.time() - started) < args.max_total_seconds
        )

    # ---- pass 1: run every lab at the default (cheap) tier ----
    for lab in labs:
        target = str(lab.get("target") or lab.get("target_url") or "")
        if is_placeholder_target(target):
            results.append(_not_run_row(lab, "not-run: target is a placeholder"))
            continue
        if not _budget_left():
            results.append(_not_run_row(lab, "not-run: total budget exhausted"))
            continue
        row = run_live_lab(
            lab, args.per_lab_timeout, args.max_iterations,
            capture_transcript=True,
        )
        if row["solved"]:
            _record_solved_technique(row.get("class", ""), row["name"])
        results.append(row)

    # ---- pass 2: re-run unsolved (that actually ran) once at strong tier ----
    if rerun_strong:
        by_name = {r["name"]: i for i, r in enumerate(results)}
        for lab in labs:
            name = str(lab.get("name") or lab.get("objective") or lab.get("target") or "lab")
            idx = by_name.get(name)
            if idx is None:
                continue
            prev = results[idx]
            if prev.get("not_run") or prev.get("solved"):
                continue
            if not _budget_left():
                break
            console.print(f"[magenta]↻ Escalated re-run (strong tier): {name}[/]")
            row = run_live_lab(
                lab, args.per_lab_timeout, args.max_iterations,
                force_strong=True, capture_transcript=True,
            )
            if row["solved"]:
                _record_solved_technique(row.get("class", ""), row["name"])
                results[idx] = row  # promote the successful escalated result

    json_path, md_path = write_training_scorecard(results)
    solved = sum(1 for r in results if r.get("solved"))
    run = sum(1 for r in results if not r.get("not_run"))
    console.print(
        f"[bold green]Training complete:[/] {solved}/{run} solved "
        f"({len(results) - run} not-run)"
    )
    console.print(f"[green]Scorecard JSON:[/] {json_path}")
    console.print(f"[green]Scorecard MD:[/]   {md_path}")

    if refresh_matrix:
        try:
            from hacking_agent.core.coverage import generate_coverage_matrix

            matrix_path = generate_coverage_matrix()
            console.print(f"[green]Coverage matrix:[/] {matrix_path}")
        except Exception as exc:  # noqa: BLE001 - matrix refresh is best-effort
            console.print(f"[yellow]Coverage matrix refresh failed: {exc}[/]")


def run_live(args: argparse.Namespace) -> None:
    config_path = args.config or args.suite
    if not config_path:
        console.print(
            "[red]--live requires --config PATH (JSON/YAML list of labs).[/]"
        )
        raise SystemExit(2)

    labs = load_live_config(config_path)
    results: list[dict[str, Any]] = []
    started = time.time()

    for lab in labs:
        if args.max_total_seconds and (time.time() - started) >= args.max_total_seconds:
            console.print(
                "[yellow]Max total wall-clock budget reached — "
                "skipping remaining labs.[/]"
            )
            results.append({
                "name": str(lab.get("name") or lab.get("target") or "lab"),
                "target_url": str(lab.get("target") or lab.get("target_url") or ""),
                "objective": str(lab.get("objective") or ""),
                "playbook_id": "",
                "expected_vuln": lab.get("expected_vuln") or "",
                "expected_match": True,
                "solved": False,
                "verified_pocs": 0,
                "iterations": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "llm_calls": 0,
                "estimated_cost_usd": 0.0,
                "wall_clock_seconds": 0.0,
                "timed_out": False,
                "verdict": "skipped: total budget exhausted",
            })
            continue
        results.append(
            run_live_lab(lab, args.per_lab_timeout, args.max_iterations)
        )

    json_path, md_path = write_live_scorecard(results)
    solved = sum(1 for r in results if r["solved"])
    console.print(
        f"[bold green]Live eval complete:[/] {solved}/{len(results)} solved"
    )
    console.print(f"[green]Scorecard JSON:[/] {json_path}")
    console.print(f"[green]Scorecard MD:[/]   {md_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="reynard-lab-eval",
        description=(
            "Lab evaluator. Default: offline readiness check. With --live: run "
            "the multi-agent Orchestrator against a config of labs and write a "
            "solve-rate scorecard."
        ),
    )
    parser.add_argument("case", nargs="?", help="Single lab objective to evaluate (offline).")
    parser.add_argument("--case", dest="case_text", help="Single lab objective to evaluate (offline).")
    parser.add_argument("--suite", help="JSON suite file: list of cases or {'cases': [...]}.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run the real Orchestrator against labs in --config and score solves.",
    )
    parser.add_argument(
        "--train",
        action="store_true",
        help=(
            "Batch training/eval loop: run all labs, record techniques + failure "
            "transcripts, auto-re-run unsolved labs once at the strong tier, and "
            "emit per-class/per-level scorecards + refresh the coverage matrix."
        ),
    )
    parser.add_argument(
        "--config",
        help="Live-mode lab config file (JSON or YAML). See eval/labs.sample.yaml.",
    )
    parser.add_argument(
        "--per-lab-timeout",
        type=float,
        default=float(os.getenv("EVAL_PER_LAB_TIMEOUT", "900")),
        help="Per-lab wall-clock timeout in seconds (default 900, 0 = no timeout).",
    )
    parser.add_argument(
        "--max-total-seconds",
        type=float,
        default=float(os.getenv("EVAL_MAX_TOTAL_SECONDS", "0")),
        help="Stop launching new labs after this total wall-clock budget (0 = unlimited).",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=int(os.getenv("MAX_ITERATIONS", "30")),
        help="Default per-lab max specialist dispatches (labs may override).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.live or args.train:
        from dotenv import load_dotenv

        from hacking_agent.core.paths import ENV_FILE
        if ENV_FILE.exists():
            load_dotenv(ENV_FILE)
        if args.train:
            run_train(args)
        else:
            run_live(args)
        return
    if args.case_text or args.case:
        cases: list[str | dict[str, Any]] = [args.case_text or args.case]
    else:
        cases = load_suite(args.suite)

    results = [evaluate_case(case) for case in cases]
    report_path = write_report(results)
    output = {
        "report_path": str(report_path),
        "average_readiness": (
            round(sum(item["readiness_score"] for item in results) / len(results), 2)
            if results else 0
        ),
        "results": results,
    }
    console.print_json(json.dumps(output, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
