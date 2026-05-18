"""
=============================================================================
Reynard — Pydantic Schemas (Strict Typed LLM I/O)
=============================================================================
Every cross-agent communication is a Pydantic model. The orchestrator
forces specialist LLMs to emit JSON that validates against these schemas;
non-conforming outputs are retried with the validator error attached.

This eliminates the "free-form ReAct rabbit hole" failure mode: the model
cannot accidentally invent fields, skip required ones, or produce free
prose where structured data is expected.
=============================================================================
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

# =============================================================================
# Enumerations (closed sets — model can only pick from these)
# =============================================================================

ConfidenceLevel = Literal["confirmed", "suspected", "disproven"]

AgentName = Literal["recon", "analyst", "exploitation", "reporter", "validator"]

VulnStatus = Literal[
    "theoretical",     # Hypothesised, no PoC yet
    "verified",        # Reproducible PoC succeeded
    "informational",   # Real but not exploitable in this context
    "false_positive",  # Disproven on attempt
]

Severity = Literal["critical", "high", "medium", "low", "info"]

ExploitVerdict = Literal[
    "success",         # PoC works, vuln is real
    "failure",         # Payload had no effect / was blocked
    "partial",         # Reflected/triggered but not full impact
    "unverifiable",    # Could not test (network, auth, timing)
]

EntityType = Literal[
    "Target", "Endpoint", "Parameter", "Technology",
    "Vulnerability", "PoC", "Credential",
]

ToolName = Literal[
    "run_shell", "request_smuggling_probe",
    "tool_inventory", "read_file", "write_file", "list_dir",
    "http_request", "browser_navigate", "browser_execute_js",
    "browser_interact", "analyze_response",
    # Out-of-band interaction (interactsh)
    "oob_get_domain", "oob_poll",
    # Multi-session auth
    "swap_session", "list_sessions",
    # Differential analysis
    "capture_baseline", "diff_against_baseline",
    # Recon expansions
    "nuclei_scan", "extract_js_endpoints", "discover_apis",
    # Caido Cloud API
    "caido_cloud_api", "caido_cloud_request",
    # Caido local Replay/history bridge
    "caido_local_api",
    # Web research
    "web_search", "web_fetch",
    # Burp Suite MCP
    "burp_send_http1_request", "burp_get_scanner_issues",
    "burp_generate_collaborator_payload", "burp_get_collaborator_interactions",
    "burp_create_repeater_tab", "burp_send_to_intruder",
]


# =============================================================================
# Atomic records (used inside larger schemas)
# =============================================================================

class FactClaim(BaseModel):
    """A single fact an agent wants written to memory."""
    entity_id: Optional[str] = Field(
        None, description="KG entity id this fact attaches to. None = global fact."
    )
    key: str = Field(..., min_length=1)
    value: Any
    confidence: ConfidenceLevel = "suspected"
    source: str = Field(..., description="Tool/agent/iteration that produced the claim.")


class ToolDecision(BaseModel):
    """One concrete tool call request from a specialist agent."""
    tool: ToolName
    args: dict[str, Any] = Field(default_factory=dict)
    reasoning: str = Field(..., min_length=1,
                            description="Why this tool, why these args, what hypothesis.")
    expected_signal: str = Field(
        ..., description="What signal in the response will confirm/refute the hypothesis."
    )


class Hypothesis(BaseModel):
    text: str
    phase: str


# =============================================================================
# Knowledge-graph projections
# =============================================================================

class EndpointSpec(BaseModel):
    url: str
    method: str = "GET"
    parameters: list[str] = Field(default_factory=list)
    notes: str = ""


class Vulnerability(BaseModel):
    id: str = Field("", description="Filled by orchestrator on creation.")
    vuln_type: str = Field(..., description="XSS / SQLi / SSRF / IDOR / CSRF / etc.")
    severity: Severity = "medium"
    target_entity_id: str = Field(..., description="KG id of the affected target/endpoint.")
    parameter: Optional[str] = None
    hypothesis: str = Field(..., min_length=1)
    status: VulnStatus = "theoretical"
    notes: Optional[str] = None


class PoC(BaseModel):
    """A proof-of-concept artifact. Recorded in the EvidenceStore."""
    id: str = Field("", description="Filled by EvidenceStore on record.")
    vuln_id: str
    payload: str
    request_summary: str = Field(..., description="HTTP request or shell cmd that delivered the PoC.")
    response_excerpt: str = Field("", description="Up to ~500 chars of the relevant response.")
    verdict: ExploitVerdict
    agent_name: AgentName
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# =============================================================================
# Cross-agent task / result envelopes
# =============================================================================

class AgentTask(BaseModel):
    """Routed work item handed to a specialist by the Coordinator."""
    task_description: str = Field(..., min_length=1)
    context: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(
        default_factory=dict,
        description="e.g. max_iterations, target_entity_id, tool_whitelist.",
    )
    target_vulnerability_id: Optional[str] = None


class AgentResult(BaseModel):
    """Result returned by every specialist run."""
    success: bool
    summary: str
    facts_added: list[FactClaim] = Field(default_factory=list)
    vulnerabilities_found: list[Vulnerability] = Field(default_factory=list)
    pocs_recorded: list[PoC] = Field(default_factory=list)
    next_recommendation: Optional[str] = None
    artifact: Optional[str] = Field(
        None, description="Long-form output (e.g. final report markdown)."
    )


class CoordinatorDecision(BaseModel):
    """Routing decision from the Coordinator. Either dispatch a specialist
    or terminate (done=True)."""
    done: bool = Field(False, description="If True, no more specialists; produce final report.")
    next_agent: Optional[AgentName] = None
    task: Optional[AgentTask] = None
    reasoning: str = Field(..., min_length=1)


# =============================================================================
# Specialist-specific output shapes
# =============================================================================

class ReconFinding(BaseModel):
    """Per-iteration output of the recon agent."""
    technologies_detected: list[str] = Field(default_factory=list)
    endpoints_discovered: list[EndpointSpec] = Field(default_factory=list)
    interesting_responses: list[str] = Field(default_factory=list)
    next_action: Optional[ToolDecision] = None
    recon_complete: bool = False


class AnalystOutput(BaseModel):
    """Full output of one analyst run."""
    vulnerabilities: list[Vulnerability]
    reasoning: str


class ExploitAttempt(BaseModel):
    """One exploit attempt with structured outcome."""
    payload: str
    request_summary: str
    response_excerpt: str = ""
    verdict: ExploitVerdict
    notes: str = ""


class ExploitationOutput(BaseModel):
    """Full output of one exploitation run against a single Vulnerability."""
    vuln_id: str
    final_verdict: ExploitVerdict
    poc: Optional[PoC] = None
    attempts: list[ExploitAttempt] = Field(default_factory=list)
    next_action: Optional[ToolDecision] = None
    reasoning: str


class ValidationProbe(BaseModel):
    """One re-test probe the validator runs against a claimed PoC."""
    description: str
    next_action: Optional[ToolDecision] = None


class ValidationOutput(BaseModel):
    """Output of one validator iteration.

    The validator's job: confirm or refute a PoC the exploitation agent
    flagged success/partial. It re-runs the PoC, varies it, and decides
    whether it survives. `confirmed=False` means the orchestrator should
    demote the vuln to false_positive (or informational if signal exists).
    """
    poc_id: str
    confirmed: bool = Field(
        ..., description="True only if the PoC is reproducible and causally tied to the payload."
    )
    reproducibility: Literal["reproducible", "flaky", "non_reproducible", "ambiguous"] = "ambiguous"
    causal_signal: str = Field(
        "", description="What concrete observation links payload -> effect."
    )
    fp_reason: str = Field(
        "", description="If confirmed=False, why this looks like a false positive."
    )
    next_probe: Optional[ToolDecision] = Field(
        None,
        description="Optional next probe to run. None = stop iterating.",
    )
    final: bool = Field(
        False, description="True when the validator is done iterating."
    )
    reasoning: str


class ReporterOutput(BaseModel):
    """Structured metadata companion for the free-form Markdown report.
    Used by the orchestrator to log session results programmatically."""
    title: str = Field("Penetration Test Report", description="Report title.")
    target_url: str
    generated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    verified_count: int = 0
    informational_count: int = 0
    false_positive_count: int = 0
    total_pocs: int = 0
    total_iterations: int = 0
    total_tool_calls: int = 0
    report_path: str = ""


# =============================================================================
# Provider configuration
# =============================================================================

class ProviderConfig(BaseModel):
    """Configuration for one LLM provider/model binding (per agent role)."""
    role: str = "default"
    kind: Literal["openai-compatible", "anthropic"] = "openai-compatible"
    model: str
    api_key: str
    base_url: Optional[str] = None
    extra_headers: dict[str, str] = Field(default_factory=dict)
    max_tokens: int = 4096
    temperature: float = 0.0
    supports_json_mode: bool = Field(
        True,
        description="Set False for local models (some Ollama/llama.cpp builds) "
                    "that reject response_format={'type':'json_object'}.",
    )

    # ---- Reasoning / extended thinking controls ----
    # OpenAI o-series / GPT-5 style: reasoning_effort
    reasoning_effort: Optional[Literal["none", "minimal", "low", "medium", "high", "xhigh"]] = Field(
        None,
        description="OpenAI-compatible reasoning_effort. None = don't send the param.",
    )
    # Anthropic / Claude extended thinking
    thinking_enabled: bool = Field(
        False,
        description="Enable Anthropic extended thinking (Claude reasoning models).",
    )
    thinking_budget_tokens: int = Field(
        8000,
        description="Token budget for Anthropic extended thinking (only used when thinking_enabled).",
    )
    # DeepSeek-R1 / Qwen-thinking style toggle (some providers expose `enable_thinking`)
    enable_thinking_param: bool = Field(
        False,
        description="Send `enable_thinking=true` in extra_body for providers that support it (Qwen, DeepSeek-R1 family).",
    )
