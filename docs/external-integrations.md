# External capabilities: Browser Use + HexStrike AI

Reynard v3.1 adds two OPTIONAL, UNTRUSTED external capability providers behind a
single adapter layer in [`src/hacking_agent/integrations/external/`](../src/hacking_agent/integrations/external/).
They are specialized capabilities only — Reynard remains the autonomous brain
that decides WHAT to investigate, WHY, WHEN to call an external capability, WHAT
the result means, and HOW to independently prove a vulnerability.

```
Browser Use  -> semantic workflow discovery ->
HexStrike    -> on-demand specialist tools  ->  Reynard (reason / test / validate)
Reynard Playwright (browser_map, unchanged) -> deterministic capture / proof
```

## Roles

- Browser Use = semantic navigation / workflow discovery (explores like a real
  user: signup, login, onboarding, invites, role changes, dashboards, checkout,
  uploads, multi-step forms, dynamic UI).
- Reynard Playwright (`browser_map`, unchanged) = deterministic network capture,
  screenshots, and proof.
- Reynard = reasoning, testing, validation, evidence, reporting.

Neither external provider may declare a vulnerability. Their output becomes
`AttackSurface` Observations (and safe assets); only Reynard's hypothesis ->
test -> Validator -> EvidenceBundle pipeline produces a reportable finding.

## Security architecture (untrusted by design)

Every external action still flows through the same chokepoint:

```
ScopeGuard -> engagement / mutation policy -> BudgetedToolExecutor -> execution
```

Invariants (enforced + tested):

- An external tool can NEVER widen scope, authorize a new domain, override
  engagement policy, disable rate limits, or change Reynard's objective.
- Browser Use is hard-restricted to ScopeGuard's allowed domains
  (`allowed_domains`) with the out-of-scope denylist as `prohibited_domains`, and
  every returned URL is re-validated with `ScopeGuard.classify` (out-of-scope
  dropped).
- HexStrike targets are scope-checked before execution.
- External output is DATA, not instructions: only whitelisted structured fields
  are read; free text is sanitized/summarized and never executed. Raw output is
  spilled to `logs/external/` and referenced by path, never dumped into the LLM.
- External results become Observations only — `ingest_external_capability` never
  records a finding.

## Browser Use

`browser_use_explore(url, task, session)` wraps the optional `browser-use`
library. It builds a `BrowserProfile` from ScopeGuard (allowed/prohibited
domains), reuses a Reynard session's cookies (`storage_state`) for authenticated
exploration, records a HAR network trace, and returns a `WorkflowExploration`
(pages, actions, discovered API/network requests, auth state, workflow states).
These are converted into `ExternalObservation`s and folded into the attack
surface. It does NOT replace `browser_map`.

Install: `pip install "reynard[external]"`. Missing install -> `available=False`.

## HexStrike AI (capability broker)

HexStrike exposes 150+ tools via an HTTP server (default `http://127.0.0.1:8888`;
`GET /health`, `POST /api/tools/<tool>`). Exposing all of them to the LLM would
create tool-selection noise, so Reynard talks to it through a broker
([`hexstrike.py`](../src/hacking_agent/integrations/external/hexstrike.py)):

- `search_capability(requirement)` returns the smallest relevant subset (<=5),
  GAP-first so native Reynard tools (subfinder/httpx/nuclei/katana/ffuf/sqlmap/
  jwt/...) stay preferred; HexStrike fills gaps or adds a second technique.
- `execute_capability(capability, target, params)` runs exactly one, scope-checked.
- `list_capabilities()`, `health()`, `version()`.

The LLM only ever sees `hexstrike_search_capability` (<=5 candidates) and
`hexstrike_run_capability` — never the full catalogue. Run the server separately;
missing server -> `available=False`.

## Clever triggering + feedback loop

The orchestrator invokes these only when deterministic rules say the expected
information gain justifies the cost (`evaluate_triggers` in
[`base.py`](../src/hacking_agent/integrations/external/base.py)), and only in
production missions:

- Browser Use: SPA/JS-heavy app, authentication exists, complex workflow/forms,
  or incomplete crawler coverage.
- HexStrike: a strong hypothesis lacks a native tool, the run stalled after
  native attempts, or a niche protocol/technology is detected.

After each external result Reynard records observation/attempt/interpretation in
durable memory and re-syncs the agenda, so the next turn reasons about what
changed and picks the cheapest next experiment (does this strengthen/weaken the
hypothesis? can user A modify user B? can a normal user hit the admin endpoint?
can workflow states be skipped? can object IDs be changed? does the API expose
hidden functionality?).

## Combination flow

1. Browser Use discovers an undocumented API call in a privileged workflow.
2. Reynard adds the endpoint + parameters to the AttackSurface.
3. It compares the request across controlled identities (`authz_matrix`).
4. It forms an authorization hypothesis and tests simple mutations natively.
5. If the parameter structure is unclear, it asks
   `hexstrike_search_capability("hidden parameter discovery")` and runs one
   specialist.
6. It interprets the result, independently reproduces the issue, builds an
   EvidenceBundle, and only then creates a reportable finding.

## Configuration

See [`.env.example`](../.env.example): `REYNARD_EXTERNAL_ENABLED`,
`REYNARD_MAX_EXTERNAL_INVOCATIONS`, `BROWSER_USE_ENABLED`, `BROWSER_USE_LLM_*`,
`HEXSTRIKE_ENABLED`, `HEXSTRIKE_SERVER_URL`.
