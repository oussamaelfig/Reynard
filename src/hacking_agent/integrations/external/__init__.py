"""
Reynard external capability adapters.

Browser Use (semantic workflow discovery) and HexStrike AI (on-demand specialist
tools) are integrated here as OPTIONAL, UNTRUSTED capability providers. They are
never the brain: their output is data (structured observations), never
instructions, and it flows into Reynard's AttackSurface as Observations — never
directly into Findings. Reynard's own reasoning, ScopeGuard, BudgetedToolExecutor,
Validator and EvidenceBundle remain the sole authorities for what becomes a
reportable finding.
"""
from hacking_agent.integrations.external.base import (  # noqa: F401
    ExternalCapability,
    ExternalObservation,
    ExternalProvider,
    ExternalTriggerDecision,
    TriggerSignals,
    PROVIDER_BROWSER_USE,
    PROVIDER_HEXSTRIKE,
    evaluate_triggers,
    ingest_external_capability,
    spill_raw,
    summarize_raw,
)
