"""Operator-controlled authenticated discovery before the agent reasoning loop.

Only safe observations enter shared agent memory. The private runner's identity
state is deliberately NOT installed in the legacy, origin-unbound tool registry.
Business-rule observations cannot bypass the independent finding export gate.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from hacking_agent.core.authenticated_research import AuthenticatedResearchPlan, ResearchRunner
from hacking_agent.core.business_logic import BusinessRuleSpec, evaluate_business_rules
from hacking_agent.core.events import emit
from hacking_agent.core.scope import ScopeGuard


def validate_research_inputs(
    plan: AuthenticatedResearchPlan, rules: list[BusinessRuleSpec],
    guard: ScopeGuard, target_url: str,
) -> None:
    """Admission checks without requests, registry mutation, or credential logs."""
    plan.validate_scope(guard, target_url)
    names = {identity.name for identity in plan.identities}
    if len(rules) > 20 or len({rule.name for rule in rules}) != len(rules):
        raise ValueError("business rules must have unique names and at most 20 entries")
    origin = urlsplit(plan.origin)
    origin_key = (origin.scheme, origin.hostname, origin.port or (443 if origin.scheme == "https" else 80))
    reads = ScopeGuard(authorized_url_prefixes=list(plan.read_prefixes), ALLOWLIST=set())
    for rule in rules:
        url = urlsplit(rule.url)
        key = (url.scheme, url.hostname, url.port or (443 if url.scheme == "https" else 80))
        if url.query or key != origin_key or not guard.is_in_scope(rule.url) or not reads.is_in_scope(rule.url):
            raise ValueError("business rule URL must be inside the plan's origin, read paths and scope")
        if rule.owner_identity not in names or rule.denied_identity not in names | {"anonymous"}:
            raise ValueError("business rule identities must be declared in the research plan")
        if rule.owner_identity == rule.denied_identity:
            raise ValueError("business rule requires distinct owner and denied identities")


def parse_research_inputs(
    raw_plan: dict[str, Any] | None, raw_rules: list[dict[str, Any]],
    guard: ScopeGuard, target_url: str,
) -> tuple[AuthenticatedResearchPlan, list[BusinessRuleSpec]]:
    """Use on both sides of IPC; never echo Pydantic inputs in public errors."""
    try:
        plan = AuthenticatedResearchPlan.model_validate(raw_plan)
        rules = [BusinessRuleSpec.model_validate(rule) for rule in raw_rules]
        validate_research_inputs(plan, rules, guard, target_url)
        return plan, rules
    except (ValueError, TypeError):
        raise ValueError("invalid authenticated research configuration") from None


def prepare_authenticated_research(
    orchestrator: Any, raw_plan: dict[str, Any] | None,
    raw_rules: list[dict[str, Any]], target_url: str,
) -> dict[str, Any]:
    """Share the target's scope/rate budget, then hand observations to agents."""
    plan, rules = parse_research_inputs(raw_plan, raw_rules, orchestrator.scope_guard, target_url)
    emit("research_summary", {"message": "Starting scoped authenticated research."})
    try:
        runner = ResearchRunner(plan, orchestrator.scope_guard)
        research = runner.run()
        if any(identity.name not in runner.verified_identities for identity in plan.identities):
            raise RuntimeError("identity setup incomplete")
        checks = evaluate_business_rules(runner, rules)
        research["total_request_count"] = runner.request_count
    except Exception:
        # Passwords, CSRF fields and private object identifiers must not escape
        # through exception reprs or provider/HTTP error strings.
        emit("error", {"message": "Authenticated research failed; agent execution was not started. Check the plan, login verification and budgets."})
        raise RuntimeError("authenticated research failed; verify the plan, authentication and budgets") from None
    summary = {"research": research, "business_rules": checks,
               "reportable": False, "verification_status": "observation"}
    orchestrator.memory.add_fact("authenticated_research", summary, source="authenticated_research")
    # The module exposes only a sanitized inventory here, never response bodies
    # or credential-bearing private sessions. This is discovery, not proof.
    for page in research.get("observations", []):
        if isinstance(page, dict) and page.get("url") and page.get("kind") == "page":
            orchestrator.surface.add_endpoint(
                page["url"], source="authenticated_research",
                attrs={"identity": page.get("identity", ""), "discovery_only": True},
            )
    orchestrator.surface.project_to_memory(orchestrator.memory)
    message = ("Authenticated discovery stopped at a configured limit; coverage is partial."
               if research.get("partial") else "Authenticated discovery and declared business-rule checks finished.")
    emit("research_summary", {"message": message + " Observations are not confirmed findings.", **summary})
    return summary
