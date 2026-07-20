"""
=============================================================================
Reynard — Automatic Tool-Selection Layer
=============================================================================
A deterministic scorer that maps (vulnerability class + attack phase +
observed technology) to a ranked list of recommended tools. Weak/cheap models
guess badly at tool choice; this hands them a justified shortlist instead.

Signal sources (all deterministic, no LLM):
  1. Expert playbooks (`expert_playbooks.py`, `primary_tools`) — the strongest
     prior. Tools listed for the matched vuln class get an order-weighted boost.
  2. Attack phase — recon vs. exploit vs. validate favours different tools.
  3. Observed technology — e.g. AngularJS -> browser tools, GraphQL ->
     discover_apis, a SQL DBMS banner -> sqlmap.
  4. A curated per-tool profile (phases + tech keywords) for tools that are
     not necessarily in a playbook's primary_tools.

Public API:
    rank_tools(vuln_class, phase, tech, available_tools) -> list of
        {"tool", "score", "justification"} sorted by score (desc).
    render_recommendations(...) -> compact text block for prompt injection.

CONSUMPTION
-----------
A specialist consumes the ranking in one of two non-invasive ways:
  * Call the `recommend_tools` tool (registered in tools.py) with the current
    vuln class / phase / tech; the JSON result lists ordered tools + reasons.
  * The tool catalog / playbook context already injected into prompts pairs
    naturally with this ranking, so an agent can call `recommend_tools` at the
    start of a phase and prefer the top entry unless it justifies an override.
No agent prompt strings need editing to use this.
=============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field

from hacking_agent.core.expert_playbooks import EXPERT_PLAYBOOKS, normalize_vuln_key


# =============================================================================
# Phase normalization
# =============================================================================

_PHASE_ALIASES = {
    "recon": "recon",
    "reconnaissance": "recon",
    "discovery": "recon",
    "injection": "exploit",
    "context": "exploit",
    "capability": "exploit",
    "escape": "exploit",
    "exploit": "exploit",
    "exploitation": "exploit",
    "validate": "validate",
    "validation": "validate",
    "verify": "validate",
}


def normalize_phase(phase: str | None) -> str:
    return _PHASE_ALIASES.get((phase or "").strip().lower(), "recon")


# =============================================================================
# Per-tool profiles
# =============================================================================

@dataclass(frozen=True)
class ToolProfile:
    name: str
    phases: frozenset[str] = field(default_factory=frozenset)
    tech: frozenset[str] = field(default_factory=frozenset)
    note: str = ""


TOOL_PROFILES: dict[str, ToolProfile] = {
    "http_request": ToolProfile(
        "http_request", frozenset({"recon", "exploit", "validate"}),
        frozenset(), "Precise HTTP with cookie jar + auto analysis."),
    "browser_navigate": ToolProfile(
        "browser_navigate", frozenset({"recon", "exploit", "validate"}),
        frozenset({"angular", "react", "vue", "javascript", "spa"}),
        "Real Chromium render for JS-driven pages."),
    "browser_execute_js": ToolProfile(
        "browser_execute_js", frozenset({"exploit", "validate"}),
        frozenset({"angular", "react", "vue", "javascript", "spa"}),
        "Runs JS and captures alert() dialogs — XSS proof."),
    "browser_interact": ToolProfile(
        "browser_interact", frozenset({"exploit", "validate"}),
        frozenset({"angular", "react", "vue", "javascript", "spa"}),
        "Clicks/types/submits via real selectors."),
    "discover_apis": ToolProfile(
        "discover_apis", frozenset({"recon"}),
        frozenset({"graphql", "swagger", "openapi", "rest", "api"}),
        "Probes swagger/openapi/graphql/.well-known."),
    "extract_js_endpoints": ToolProfile(
        "extract_js_endpoints", frozenset({"recon"}),
        frozenset({"angular", "react", "vue", "javascript", "spa"}),
        "Mines JS bundles for hidden endpoints/params."),
    "nuclei_scan": ToolProfile(
        "nuclei_scan", frozenset({"recon"}),
        frozenset(), "Known-CVE/misconfig template pass."),
    "nmap_scan": ToolProfile(
        "nmap_scan", frozenset({"recon"}),
        frozenset({"network", "host", "service"}),
        "Service/version mapping for hosts."),
    "ffuf_fuzz": ToolProfile(
        "ffuf_fuzz", frozenset({"recon"}),
        frozenset(), "Content/parameter/vhost fuzzing."),
    "sqlmap_run": ToolProfile(
        "sqlmap_run", frozenset({"exploit"}),
        frozenset({"mysql", "postgresql", "postgres", "mssql", "oracle",
                   "sqlite", "sql", "mariadb"}),
        "Automated SQLi detection + extraction."),
    "request_smuggling_probe": ToolProfile(
        "request_smuggling_probe", frozenset({"exploit", "validate"}),
        frozenset({"nginx", "apache", "cloudfront", "haproxy", "varnish",
                   "cdn", "proxy"}),
        "Raw HTTP/1.1 desync probes."),
    "capture_baseline": ToolProfile(
        "capture_baseline", frozenset({"recon", "exploit"}),
        frozenset(), "Record a clean baseline for diffing."),
    "diff_against_baseline": ToolProfile(
        "diff_against_baseline", frozenset({"exploit", "validate"}),
        frozenset(), "Diff responses — boolean-blind/IDOR/cache signal."),
    "oob_get_domain": ToolProfile(
        "oob_get_domain", frozenset({"exploit"}),
        frozenset(), "Mint OOB callback domain for blind vulns."),
    "oob_poll": ToolProfile(
        "oob_poll", frozenset({"exploit", "validate"}),
        frozenset(), "Poll OOB listener for blind-vuln callbacks."),
    "swap_session": ToolProfile(
        "swap_session", frozenset({"exploit", "validate"}),
        frozenset(), "Switch identity for IDOR/authz testing."),
    "list_sessions": ToolProfile(
        "list_sessions", frozenset({"recon", "exploit"}),
        frozenset(), "Enumerate configured auth identities."),
    "register_session": ToolProfile(
        "register_session", frozenset({"recon", "exploit"}),
        frozenset(), "Create a named session mid-run for multi-user labs."),
    "caido_local_api": ToolProfile(
        "caido_local_api", frozenset({"recon", "exploit", "validate"}),
        frozenset(), "Caido Replay/history bridge for raw requests."),
    "burp_get_proxy_history": ToolProfile(
        "burp_get_proxy_history", frozenset({"recon"}),
        frozenset(), "Read Burp proxy history for observed traffic."),
    "burp_get_proxy_history_regex": ToolProfile(
        "burp_get_proxy_history_regex", frozenset({"recon"}),
        frozenset(), "Regex-filter Burp proxy history."),
    "web_search": ToolProfile(
        "web_search", frozenset({"recon", "exploit"}),
        frozenset(), "Research writeups/CVEs when stuck."),
}


# Vuln-class -> extra tool bonuses beyond playbook primary_tools.
_VULN_TOOL_BONUS: dict[str, dict[str, float]] = {
    "sqli": {"sqlmap_run": 3.0, "ffuf_fuzz": 0.5},
    "xss": {"browser_execute_js": 2.5, "browser_navigate": 1.5},
    "dom_xss": {"browser_execute_js": 3.0, "browser_navigate": 2.0},
    "dom_based": {"browser_execute_js": 2.5, "browser_navigate": 1.5},
    "request_smuggling": {"request_smuggling_probe": 3.0},
    "access_control_idor": {"swap_session": 2.5, "register_session": 1.5,
                            "diff_against_baseline": 1.5},
    "graphql_api": {"discover_apis": 2.0, "extract_js_endpoints": 1.0},
    "api_testing": {"discover_apis": 2.0, "extract_js_endpoints": 1.5,
                    "swap_session": 1.0},
    "information_disclosure": {"ffuf_fuzz": 1.5, "extract_js_endpoints": 1.5,
                               "discover_apis": 1.0},
}


def _playbook_primary_tools(vuln_key: str) -> list[str]:
    pb = EXPERT_PLAYBOOKS.get(vuln_key)
    if not pb:
        return []
    return list(pb.get("primary_tools", []) or [])


def _all_known_tools() -> list[str]:
    names = set(TOOL_PROFILES.keys())
    for pb in EXPERT_PLAYBOOKS.values():
        names.update(pb.get("primary_tools", []) or [])
    return sorted(names)


# Score deltas applied from durable cross-run signals. A prior success for the
# lab class nudges a tool up; a known dead-end nudges it down (never below the
# other signals' reach, so a strong playbook prior can still surface it).
DURABLE_WIN_BONUS = 2.5
DURABLE_DEADEND_PENALTY = 2.0


def rank_tools(
    vuln_class: str | None = None,
    phase: str | None = None,
    tech: str | list[str] | None = None,
    available_tools: list[str] | None = None,
    boost_tools: list[str] | set[str] | None = None,
    demote_tools: list[str] | set[str] | None = None,
) -> list[dict[str, object]]:
    """Return tools ranked for the given (vuln_class, phase, tech) context.

    Each entry: {"tool", "score", "justification"}. Higher score = better fit.
    Only tools in `available_tools` (if provided) are returned.

    `boost_tools` / `demote_tools` fold durable cross-run signals into the
    ranking: tools that previously SUCCEEDED for this lab class are boosted and
    known DEAD-END tools are demoted, so learned experience steers selection.
    """
    norm_phase = normalize_phase(phase)
    vuln_key = normalize_vuln_key(vuln_class) if vuln_class else ""
    boost_set = {str(t) for t in (boost_tools or [])}
    demote_set = {str(t) for t in (demote_tools or [])}

    if isinstance(tech, str):
        tech_tokens = {tech.lower()}
    elif isinstance(tech, list):
        tech_tokens = {str(t).lower() for t in tech}
    else:
        tech_tokens = set()
    tech_blob = " ".join(tech_tokens)

    universe = list(available_tools) if available_tools else _all_known_tools()
    universe_set = set(universe)

    primary = _playbook_primary_tools(vuln_key)
    vuln_bonus = _VULN_TOOL_BONUS.get(vuln_key, {})

    scored: list[dict[str, object]] = []
    for tool in universe:
        score = 0.0
        reasons: list[str] = []
        profile = TOOL_PROFILES.get(tool)

        if tool in primary:
            rank = primary.index(tool)
            boost = 4.0 - min(rank, 3) * 0.7
            score += boost
            reasons.append(f"playbook '{vuln_key}' primary tool #{rank + 1}")

        if tool in vuln_bonus:
            score += vuln_bonus[tool]
            reasons.append(f"high-yield for {vuln_key}")

        if profile:
            if norm_phase in profile.phases:
                score += 1.5
                reasons.append(f"fits {norm_phase} phase")
            elif profile.phases:
                score -= 0.5
            if tech_tokens and profile.tech:
                overlap = profile.tech.intersection(tech_tokens) or {
                    t for t in profile.tech if t in tech_blob
                }
                if overlap:
                    score += 1.5
                    reasons.append(f"matches tech {sorted(overlap)}")
            if profile.note and not reasons:
                reasons.append(profile.note)

        if tool in boost_set:
            score += DURABLE_WIN_BONUS
            reasons.append("prior win (durable memory)")
        if tool in demote_set:
            score -= DURABLE_DEADEND_PENALTY
            reasons.append("known dead-end (durable memory)")

        if score <= 0 and tool not in primary and tool not in boost_set:
            continue

        scored.append({
            "tool": tool,
            "score": round(score, 2),
            "justification": "; ".join(reasons) or "general-purpose fit",
            "available": tool in universe_set,
        })

    scored.sort(key=lambda item: (item["score"], item["tool"]), reverse=True)
    return scored


def render_recommendations(
    vuln_class: str | None = None,
    phase: str | None = None,
    tech: str | list[str] | None = None,
    available_tools: list[str] | None = None,
    limit: int = 6,
    boost_tools: list[str] | set[str] | None = None,
    demote_tools: list[str] | set[str] | None = None,
) -> str:
    """Compact text block for prompt/console injection."""
    ranked = rank_tools(
        vuln_class, phase, tech, available_tools,
        boost_tools=boost_tools, demote_tools=demote_tools,
    )[:limit]
    if not ranked:
        return "# RECOMMENDED TOOLS\n(no deterministic recommendation)"
    lines = [
        "# RECOMMENDED TOOLS "
        f"(vuln={vuln_class or '?'}, phase={normalize_phase(phase)}, "
        f"tech={tech or '?'})",
    ]
    for i, item in enumerate(ranked, 1):
        lines.append(
            f"{i}. {item['tool']} (score={item['score']}) — {item['justification']}"
        )
    return "\n".join(lines)
