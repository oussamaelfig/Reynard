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


def run_live_lab(
    lab: dict[str, Any],
    per_lab_timeout: float,
    default_max_iterations: int,
) -> dict[str, Any]:
    """Run the Orchestrator against a single lab and return a scorecard row.

    Reuses the orchestrator entry point programmatically. The run executes in a
    daemon thread so a per-lab wall-clock timeout can be enforced; the shared
    token meter is reset before the run so tokens are attributed per lab.
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

    thread = threading.Thread(target=_run, daemon=True)
    started = time.time()
    thread.start()
    thread.join(per_lab_timeout if per_lab_timeout > 0 else None)
    elapsed = round(time.time() - started, 1)
    timed_out = thread.is_alive()

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

    tokens = meter.totals()
    return {
        "name": name,
        "target_url": target_url,
        "objective": objective_final,
        "playbook_id": playbook_id,
        "expected_vuln": expected_vuln,
        "expected_match": (not expected_vuln) or (playbook_id == expected_vuln),
        "solved": solved,
        "verified_pocs": verified_pocs,
        "iterations": iterations,
        "prompt_tokens": tokens["prompt_tokens"],
        "completion_tokens": tokens["completion_tokens"],
        "total_tokens": tokens["total_tokens"],
        "llm_calls": tokens["calls"],
        "estimated_cost_usd": meter.estimated_cost(),
        "wall_clock_seconds": elapsed,
        "timed_out": timed_out,
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
    if args.live:
        from dotenv import load_dotenv

        from hacking_agent.core.paths import ENV_FILE
        if ENV_FILE.exists():
            load_dotenv(ENV_FILE)
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
