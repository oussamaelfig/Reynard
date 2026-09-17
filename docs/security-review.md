# Reynard security and reliability review

Review date: **2026-09-16**. Scope: repository code, local tests, fixtures,
configuration, and documentation. Public research was read from primary sources.
No live third-party exploitation or end-to-end target benchmark was performed.

## Audit summary

Reynard already separates research, validation, and reporting and has useful
scope, evidence, and persistent-state abstractions. The largest gaps were at
their boundaries: inferred scope could survive an engagement, tools could make
requests beyond the destination checked by their caller, timeout threads could
continue working, and model-authored metadata could look like independent proof.

This revision tightens those boundaries and incorporates reportability schema v2
with locally authenticated executor provenance. It also adds reproducible tool
inventory and evidence-policy measurements. These improvements reduce specific
promotion and authorization failure paths. They do not establish general
discovery accuracy or comprehensive production readiness.

The most significant remaining product limitation is **trusted detector
coverage**. The executor currently derives browser-dialog execution and a narrow
template-evaluation signal. Several schema-supported effects have no complete
runtime adapter. Browser execution is also restricted under production scope.
The engine can therefore investigate candidates that it cannot independently
promote. Expanding tested adapters is a higher priority than adding scanners.

## Architecture and trust boundaries

| Layer | Main code | Responsibility and boundary |
| --- | --- | --- |
| Entry points | `cli/assess.py`, `cli/orchestrator.py`, `cli/agent.py`, `cli/lab_eval.py` | Explicit mode and target selection; engagement assessment forces production. |
| Orchestration | `cli/orchestrator.py`, `core/strategy.py`, `core/subagents.py` | Ranked hypotheses, bounded dispatches, stalls, retries, escalation, independent parallel lanes. |
| Agents | `agents/` | Coordinator, recon, analyst, exploitation, independent validator, and report assembly. |
| Typed messages | `core/schemas.py` | Structured task/result/tool contracts; schema validity alone is not evidence validity. |
| Tool execution | `agents/base.py`, `core/tools.py` | Admission, budgeting, deduplication, captured observations, and ingestion. |
| Authorization | `core/scope.py`, `core/engagement.py`, `core/target_address.py`, `core/http_transport.py` | Canonical targets, explicit engagement scope, timing/rate limits, production restrictions, per-hop HTTP checks. |
| State | `core/memory.py`, `core/attack_surface.py`, `core/durable.py`, `core/evidence.py` | Knowledge, provenance, candidate state, cross-run memory, and PoC history. |
| Evidence authority | `core/validation_provenance.py`, `core/evidence_bundle.py`, `core/finding_validation.py` | Signed captures, matched protocol, artifact verification, projection binding, deterministic reportability. |
| Export | `agents/reporter.py`, `harness/submission.py` | Recheck findings, report signatures, metadata, and aggregate counts at outward boundaries. |
| Local control plane | `harness/`, Caido bridge backend | Authenticated loopback APIs, input limits, run isolation, and control-plane credentials. |

Paths in this table are relative to `src/hacking_agent/` unless otherwise noted.
The [README diagram](../README.md#architecture) shows the execution flow.

## Prioritized findings

Severity describes the engineering risk of the original weakness or remaining
gap, not a CVSS rating for a deployed customer application. Effort estimates are
relative. Change risk means compatibility or regression risk when applying the
recommendation.

| Priority / severity | Weakness and impact | Effort | Change risk | Recommendation and current state |
| --- | --- | --- | --- | --- |
| P0 / High | Lab/localhost exceptions, ambiguous target forms, or stale inferred allowlists could widen production authorization. | Medium | Medium | Explicit engagement scope replaces inferred scope; canonical parsing, deny precedence, URL-prefix boundaries, and target pre-rejection are implemented. Keep adversarial scope regressions. |
| P0 / High | Shell, browser, scanner, and broker calls can contact destinations not represented by their initial tool arguments. | Large | High | Restrict unbounded production tools. Re-enable each capability only with enforceable downstream destination controls and tests. Restrictions intentionally reduce production breadth. |
| P0 / High | Automatic redirects can leave scope, forward identity material, or avoid request accounting. | Medium | Medium | Production HTTP now validates and charges additional hops, bounds body/redirect counts, isolates identity cookies, and drops sensitive headers across origins. DNS/IP enforcement remains a separate defense. |
| P0 / High | Self-attested replay context, notes, or proof metadata can promote unsupported claims; an unkeyed hash proves no authority. | Large | High | Schema v2 binds executor observations, independent protocol, artifacts, customer projection, and report to local HMAC receipts. Model prose cannot sign its own result. See the local trust limitations below. |
| P0 / High | A daemon-thread timeout leaves research running after the caller returns and risks inconsistent evidence snapshots. | Medium | Medium | Assessment targets now run in owned subprocesses with termination/reaping and incomplete result rejection. Subsequent targets run only after confirmed cleanup; unconfirmed cleanup stops scheduling. Submitted container/remote jobs may outlive host termination. |
| P0 / High | Exposing the harness token in bootstrap HTML undermines API authentication; browser-origin and run-path trust increase exposure. | Medium | Medium | Token entry creates an HttpOnly session; Host/origin checks, guarded run identifiers, body limits, and protected API/SSE routes are implemented. Keep the service private to loopback. |
| P0 / High | Optional Caido authentication and permissive browser access expose Replay/history operations; ambiguous raw HTTP parsing risks duplicate dispatch. | Medium | Medium | Mandatory shared token, loopback Host checks, no browser Origin/CORS access, strict framing limits, and single dispatch are implemented. Live Caido Desktop interoperability still needs a separate local check. |
| P0 / High | Loading a modified pickle methodology cache can execute code as the Reynard host account. | Medium | Low | Replace pickle with bounded, schema-validated JSON, content fingerprints, and atomic writes. Old pickle files are ignored and retained, not migrated or executed. |
| P1 / High | Trusted effect adapters cover fewer classes than the tool catalog or proof schema suggests, producing false negatives. | Large | Medium | Publish the gap; add positive and patched-negative local fixtures per adapter before enabling it. Generic SQL, authz, timing, and independently bound OOB proof remain follow-up work. |
| P1 / High | The separate live lab evaluator retains daemon-thread deadlines and can score candidate PoC success as solved. | Medium | Medium | Remaining: isolate `cli/lab_eval.py` live/train workers and grade independent outcomes. Do not use its current scores for trustworthy time-bounded solve-rate claims; this review ran offline readiness only. |
| P1 / Medium | Shared identities, repeated calls, partial validation, and parallel work can exhaust budgets or corrupt attribution. | Medium | Medium | Serialize identity-bearing execution and shared tool state; keep exploitation/validation lanes serial, stabilize subagent result ordering, and advance stalls per hypothesis. Stress recovery under cancellation. |
| P1 / Medium | Model retries can bypass initial budget checks; request caps are not shared across assessment targets. | Medium | Medium | Check provider admission before every call/retry and require prices for cost caps. Remaining: aggregate request budget across target processes; in-flight/model-usage uncertainty prevents exact billing guarantees. |
| P1 / High | Host networking, elevated container capabilities, and unconfined seccomp mean the supplied runtime is not a containment boundary. | Medium | Medium | Remaining: reduce default privileges and add per-engagement egress controls in an isolated runtime profile. Do not claim regex scope checks provide sandboxing. |
| P1 / Medium | Missing pytest dependency, narrow test evidence, and legacy typing errors undermine reproducible quality claims. | Medium | Low | Development extras and collection configuration are added; local regression checks and scripts are documented. Repository-wide mypy debt remains; make touched-module checks ratchets. |
| P2 / Medium | A large dynamic registry invites untested capabilities and misleading dead-code removal. | Medium | Medium | Exact name alignment and static/runtime inventory added. No registered tool was proven dead; retain public APIs, restrict production exposure, and collect representative usage before removal. |
| P2 / Low | Deprecated UTC constructors and an unclosed test file add noise and can hide future regressions. | Small | Low | Replace deprecated constructors while preserving legacy naive UTC fields; add compatibility regression and close the test file explicitly. New provenance timestamps retain their own aware UTC format. |

## Phased plan and implementation rationale

### 1. Correctness and authorization

**Delivered:** explicit target pre-rejection, normalized scope rules, removal of
production lab exceptions, bounded HTTP redirects, restrictive production tool
availability, subprocess assessment deadlines, and local control-plane hardening.

These changes stop work from silently expanding or continuing after failure.
They also make test results interpretable: evidence from an unauthorized
destination or an abandoned process should never be mistaken for a valid run.

**Next:** enforce DNS resolution/connection destinations at the network boundary,
reduce container privileges, and cancel already submitted external jobs through
their own lifecycle APIs.
Apply process isolation and independent outcome grading separately to the legacy
live/train lab evaluator; assessment-worker fixes do not cover that code path.

### 2. Validation and evidence

**Delivered:** authenticated executor captures, two positive captures plus a
separate matched control, verified artifact manifests, complete projection/report
binding, and deterministic checks at export and count boundaries. The fixture
benchmark measures expected acceptance and rejection in both directions.

**Next:** implement one trusted effect adapter at a time with independently
labeled vulnerable and patched fixtures. Cover reflected-but-not-executed
content, noisy latency, login/cache confounders, identity ownership, stale OOB
events, and failed cleanup. A schema entry or a signed synthetic fixture does
not establish an implemented detector.

### 3. Coordination and budgets

**Delivered:** serialize identity-bearing tool execution and shared state while
allowing independent reasoning; treat exploitation and validation lanes as
serial even when a task omits its mutation flag. Preserve result ordering, move
stalls forward per hypothesis, and publish durable events in order. Check token
and priced cost budgets before provider calls and retries.

**Next:** compare one-agent and bounded multi-agent runs on the same held-out
local tasks, model versions, budgets, and trial count. Measure cost per confirmed
finding before raising concurrency. Add cancellation and recovery tests for
session ownership and durable state; avoid uncontrolled parallel mutation.
Aggregate engagement request caps across workers: `max_total_requests` currently
resets per target, so a multi-target assessment can exceed that value in total.

### 4. Tool cleanup and integration admission

The registry contains 75 dynamically dispatched tools. Function, schema, and
typed-name alignment is checked exactly, including duplicates and callability.
All registered tools can be selected through dynamic dispatch; a missing static
call is not proof of dead code. No registered tool was removed on that basis.

Production restrictions are a compatibility-conscious alternative to deleting
lab capabilities. Before adding or enabling a capability, require:

1. A demonstrated gap on a representative local fixture.
2. Typed inputs, explicit destinations, bounded runtime/output, cancellation,
   and predictable failure behavior.
3. An observation format with provenance and a tested path into validation.
4. Positive, negative, scope, and failure tests.
5. Usage/cost evidence and ownership for future maintenance.

HTTPX and Playwright were already dependencies; Nuclei and other tool wrappers
already existed. Bandit is added to development dependencies for reviewing
Reynard's own Python. No additional offensive scanner, Semgrep service, or Trivy
runtime was added. Those integrations require a demonstrated benefit before
increasing the operational and dependency surface.

### 5. Tests and documentation

**Delivered:** pytest/dev dependencies, registry and policy measurements, focused
scope/validation/control-plane regressions, deprecation cleanup, and a rewritten
README with current capability restrictions and trust boundaries.

The methodology cache now uses validated bounded JSON with atomic replacement
and SHA-256 content fingerprints. Old pickle caches remain on disk but are never
loaded. This removes a local deserialization execution path without adding a
runtime dependency.

**Next:** make the local checks a CI gate, expand typing coverage incrementally,
and maintain per-class adapter coverage alongside fixture outcomes. Preserve
negative fixtures when improving recall.

## Public research: facts and engineering implications

### XBOW's public benchmark is no longer a differentiation target

XBOW's benchmark repository describes 104 CTF-style challenges. Its current
README explicitly warns that the set is outdated and saturated as of mid-2026,
and no longer distinguishes models or frameworks. This is the publisher's
assessment, not an independently reproduced finding from this review.
[XBOW validation benchmarks](https://github.com/xbow-engineering/validation-benchmarks).

**Implication for Reynard:** use historical public cases as regression material,
not evidence of competitive superiority. A meaningful comparison needs fresh,
held-out tasks, controlled budgets, repeated trials, patched negatives, and
independent grading. No head-to-head comparison was performed.

### Validation maturity differs by vulnerability class

XBOW's documentation distinguishes deterministic validators, AI-agent validation,
and informational findings. It describes different precision expectations for
release stages and notes possible false positives in AI-agent-validated classes.
These are vendor statements; the review did not verify their internal results.
[XBOW vulnerability classification](https://docs.xbow.com/console/reference/vulnerability-classification/).

**Implication for Reynard:** publish adapter maturity and tested evidence forms
per class. Avoid converting a class name, confidence score, or model consensus
into a blanket reliability claim.

### Measure detection separately from stored-policy acceptance

OWASP Benchmark provides runnable applications, labeled vulnerability cases,
and scoring tools for assessing detection accuracy, coverage, and speed.
[OWASP Benchmark](https://owasp.org/projects/benchmark).

Anthropic's agent-evaluation guidance distinguishes traces from actual outcomes,
recommends multiple trials, and emphasizes isolated trial state and both positive
and negative cases. [Demystifying evals for AI agents](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents).

**Implication for Reynard:** the current signed-record fixture score is only a
policy regression result. Future discovery grading must check the final local
application state and evidence independently, including patched targets and
environmental failures. Reusing a public corpus alone does not resolve training
contamination.

### More agents and more tools require stronger boundaries

Anthropic reports benefits from orchestrator-worker research systems on tasks
that support independent parallel work, alongside higher token use, duplicated
work, and coordination challenges. Its measurements concern its research
system, not security-agent performance.
[Multi-agent research system](https://www.anthropic.com/engineering/multi-agent-research-system).

OWASP describes excessive functionality, permissions, and autonomy as causes of
excessive agency and recommends limiting available tools and their authority.
[OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).

**Implication for Reynard:** partition independent hypotheses with explicit
budgets and provenance. Keep mutable sessions and validation captures under
deterministic control, and expose only capabilities whose destinations can be
enforced. Parallelism is a hypothesis to measure, not a quality guarantee.

## Success metrics

| Metric | Definition / acceptance criterion | Evidence status |
| --- | --- | --- |
| Test collection | All intended pytest modules collect; no missing development dependency. | 817 collected. |
| Regression pass rate | Passed collected tests / executed tests; failures must be fixed or explicitly retained as known gaps. | 817/817 passed, plus 56 subtests. |
| Statement coverage | Covered instrumented statements / measured source statements. | 11,483/18,812 = 61.04%; not branch coverage. |
| Scope containment fixtures | Zero unauthorized dispatches in the named redirect, alias, prefix, window, budget, and production-tool tests. | Local tests only; not a network isolation guarantee. |
| Evidence fixture precision | Accepted labeled-positive records / all accepted records. | Current corpus: 2/2. |
| Evidence fixture recall | Accepted labeled-positive records / all labeled-positive records. | Current corpus: 2/2. |
| Evidence fixture false-positive rate | Accepted labeled-negative records / all labeled-negative records. | Current corpus: 0/16. |
| Validator replay rate | Successful independent validator replay attempts / attempted replays, with environmental failures separate. | Not measured end to end. |
| Discovery precision / recall | Independently matched findings against known vulnerable and patched local fixtures, by class. | Not measured end to end. |
| Tool contract coverage | Exact implementation/schema/typed-name agreement. | 75 aligned entries; 75 source-reference and 35 test-reference matches. These are not executed coverage. |
| Observed tool usage | Distinct registered tools with `tool_result` events / registered tools in supplied distinct runs. | Unmeasured without representative logs. |
| Lint and typing | Configured Ruff passes; changed-module typing passes; no increase in documented legacy typing debt. | Repository-wide mypy remains non-clean. |
| Efficiency | Median/p95 runtime, tokens, tool calls, and cost per independently confirmed finding. | Requires repeated held-out local runs. |

The 18-case stored-policy corpus has **2 true positives, 16 true negatives,
0 false positives, and 0 false negatives**. Its positives are synthetic signed
SQL/browser records; no detector or browser runs. Most mutated negatives fail
integrity before semantic checks. No population-level confidence interval or
operational false-positive estimate follows from this deliberately small corpus.

## Validation record

The following commands were run from an activated environment with
`.[dev,harness]` installed. Results describe this repository state and local
environment; they do not establish live target performance.

| Command | Result |
| --- | --- |
| `python -m pytest --collect-only -q` | Passed: 817 tests collected. |
| `python -m pytest -q --cov=src/hacking_agent --cov-report=json:logs/security-review-coverage.json` | Passed: 817 tests, 56 subtests, 40.51 seconds; one upstream Starlette/AnyIO deprecation warning. Statement coverage: 11,483/18,812 (61.04%). |
| Strict full-suite deprecation check, command below | Passed: 817 tests, 56 subtests, 27.18 seconds; no warnings after excluding only the identified upstream Starlette/AnyIO message. |
| `python -m ruff check .` | Passed with the configured correctness rule set. |
| `python -m mypy src` | Not clean: 258 errors across 18 files; 89 source files checked. Legacy mixins and optional-import typing contribute to this debt. |
| Scoped mypy gate below | Passed: 17 files, no errors; transitive imports intentionally excluded. |
| `python -m bandit -r src -f json -o logs/security-review-bandit.json` | Exit 1: 118 diagnostics (0 high, 11 medium, 107 low). These require triage; they are not 118 confirmed vulnerabilities. The pickle-deserialization diagnostic is removed. |
| `python -m pip check` | Passed. |
| `python scripts/audit_tools.py --check` | Passed: 75 aligned tools; 75 with static source references, 35 with static test references, 40 without static test references. Runtime usage unmeasured. |
| `python scripts/quality_metrics.py --check` | Passed: 18/18 records; TP 2, TN 16, FP 0, FN 0. |
| `python -m pytest tests/test_quality_metrics.py -q -W error::DeprecationWarning` | Passed: 14 tests, no deprecation warnings. |
| `python -m mypy scripts/audit_tools.py scripts/quality_metrics.py tests/test_quality_metrics.py` | Passed: 3 files. |
| `reynard-lab-eval --pretty` | Passed: 32 offline cases; average readiness 8.97. This is routing/readiness, not detection or solve accuracy. |
| Caido `pnpm test`, `pnpm typecheck`, `pnpm build` | Passed: 5 tests, typecheck, and build. Live Desktop compatibility not verified. |

Strict warning command (the filter is specific to an upstream AnyIO alias used
by Starlette; it does not suppress project deprecations):

```bash
python -m pytest -q -W error::DeprecationWarning -W "ignore:The anyio.abc.BlockingPortal alias is deprecated:DeprecationWarning:starlette.testclient"
```

Reproduce the scoped typing gate in PowerShell:

```powershell
$typeTargets = @(
  'src/hacking_agent/core/scope.py',
  'src/hacking_agent/core/engagement.py',
  'src/hacking_agent/core/target_address.py',
  'src/hacking_agent/core/http_transport.py',
  'src/hacking_agent/core/sessions.py',
  'src/hacking_agent/core/process_control.py',
  'src/hacking_agent/core/events.py',
  'src/hacking_agent/core/subagents.py',
  'src/hacking_agent/core/strategy.py',
  'src/hacking_agent/core/tool_catalog.py',
  'src/hacking_agent/core/knowledge.py',
  'src/hacking_agent/core/finding_validation.py',
  'src/hacking_agent/core/validation_provenance.py',
  'src/hacking_agent/agents/validator.py',
  'src/hacking_agent/core/providers.py',
  'scripts/audit_tools.py',
  'scripts/quality_metrics.py'
)
python -m mypy --follow-imports=skip @typeTargets
```

The `--follow-imports=skip` gate checks these files in isolation; it is not a
clean whole-project typecheck. Full-source mypy and Bandit diagnostics are
retained as explicit follow-up work.

## Remaining risks and next steps

The local HMAC authority authenticates what Reynard's control plane issued; it
does not defend against the same OS account, a stolen signing key, compromised
Python code, or a detector that mistakes a response for an exploit effect.
Host-execution mode deliberately disables authenticated reporting. Key rotation,
key loss, or missing artifacts make old reports unverifiable. See
[validation trust](validation-trust.md).

Prioritize constrained production transports and trusted effect adapters,
container/egress isolation, live-evaluator isolation/grading, lifecycle cancellation for external jobs, and
per-class local discovery benchmarks. Keep exported findings and raw operator
logs under separate retention/access rules; sanitization is not a universal
secret detector. Treat public provider/model/tool versions as changing inputs.

The next defensible performance milestone is improved recall on fresh labeled
local cases at a fixed budget while keeping negative-case precision unchanged.
No evidence in this review supports claims of being unbeatable, fully reliable
under every environment, or incapable of false positives.
