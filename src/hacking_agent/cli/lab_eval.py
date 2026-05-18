"""Offline lab-readiness evaluator.

This command does not attack a target. It checks whether the agent can parse a
lab objective into a target, expert profile, playbook, tool plan, and obvious
run-time prerequisites. Use it as a fast regression harness before spending LLM
and lab time.
"""
from __future__ import annotations

import argparse
import json
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="reynard-lab-eval",
        description="Offline readiness check for PortSwigger/CTF lab objectives.",
    )
    parser.add_argument("case", nargs="?", help="Single lab objective to evaluate.")
    parser.add_argument("--case", dest="case_text", help="Single lab objective to evaluate.")
    parser.add_argument("--suite", help="JSON suite file: list of cases or {'cases': [...]}.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
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
