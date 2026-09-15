# Reynard v3 — Production Autonomous Web Security Researcher

Reynard v3 evolves the CTF/PortSwigger solver into a production-grade autonomous
web security researcher for authorized pentests and bug-bounty assessments, while
keeping the labs as regression benchmarks. The design keeps **one strong
autonomous researcher/coordinator** with broad freedom; deterministic modules are
used only where they measurably improve reliability.

The engine is organized around a single research loop:

```
UNDERSTAND SCOPE -> MAP ATTACK SURFACE -> IDENTIFY INTERESTING BEHAVIOR ->
GENERATE HYPOTHESES -> TEST -> LEARN FROM RESPONSE -> PIVOT/CHAIN ->
INDEPENDENTLY VERIFY -> REPORT
```

## Mission modes (labs vs production)

`core/mission.py` is the single source of truth for whether a run is a
**benchmark** (intentionally-vulnerable lab/CTF) or a **production** assessment.
Lab-specific behaviour — PortSwigger profile seeding, the "Congratulations, you
solved the lab" banner short-circuit, deterministic lab fast-paths, exploit
servers — is confined to benchmark mode. The default decision path carries no lab
assumptions; production success is defined only by independently-verified
evidence.

- Auto-detected: a known lab host (or an explicit lab profile) selects benchmark;
  everything else defaults to production.
- Forced: `--production` / `--benchmark` CLI flags, or `REYNARD_MISSION_MODE`.
- `reynard-assess` always runs production; `reynard-lab-eval` always benchmark.

## Attack Surface model (`core/attack_surface.py`)

A persistent, structured, scope-annotated map of everything discovered:
domains, subdomains, hosts/IPs, URLs, endpoints, parameters, JS bundles, source
maps, APIs, websockets, technologies, identities, roles, workflows, cloud assets,
credentials — plus behavioural `Observation`s and `Finding`s.

- Every discovery carries **provenance** (multi-source corroboration),
  **confidence** (monotonic upgrade), **scope status** (`in_scope` /
  `out_of_scope` / `unknown`), and first/last-seen timestamps.
- Scope is annotated via a **read-only** `ScopeGuard.classify()` — the surface can
  never widen or narrow the authorization boundary.
- Persisted per scope in SQLite (`surface_snapshots`) and bridged to the
  knowledge graph so existing prompt injection keeps working.

## Structured recon (`core/recon_wrappers.py`)

Typed wrappers around the ProjectDiscovery toolchain (subfinder, dnsx, httpx,
naabu, katana, waybackurls) and passive OSINT (crt.sh, urlscan.io). Each parser is
a pure function of raw output -> structured records; each runner degrades
gracefully to a structured no-op when the binary/key is missing. Results are
auto-ingested into the attack surface (with provenance + scope) by the tool
executor — the researcher reasons over structured state, never raw dumps.

Exposed tools: `subfinder_scan`, `dnsx_resolve`, `httpx_probe`, `naabu_scan`,
`katana_crawl`, `waybackurls_fetch`, `crtsh_lookup`, `urlscan_lookup`.

## Playwright application mapper (`core/browser.py` + `browser_map`)

The in-container Chromium driver now captures the full network map a real
(optionally authenticated) browser generates — XHR/fetch/API calls, WebSockets,
JS bundles and source maps — plus DOM links and forms, and turns it into an
endpoint/parameter inventory on the attack surface. Use `browser_map` to discover
a SPA's real API surface and authenticated traffic a plain crawler misses.

## Authorization matrix (`core/authz_matrix.py` + `authz_matrix_scan`)

Authorization testing is a first-class capability. Given controlled identities
(anonymous / userA / userB / admin-test-role), Reynard replays equivalent
requests as every identity, compares results semantically, and builds a
roles x resources matrix that surfaces **IDOR / BOLA / BFLA / privilege
escalation**. Every anomaly carries control-vs-test evidence and becomes a
verified `EvidenceBundle` (an authorization difference is concrete proof).

## Evidence & validation (`core/evidence_bundle.py`)

Every suspected vulnerability must be backed by an `EvidenceBundle`: sanitized
request/response exchanges (secrets redacted), the identity each ran as, the
endpoint, timestamps, **control tests**, reproduction steps, screenshots, OOB
interactions, and a verification status. A `verified` bundle requires a concrete
behavioural signal (successful execution, data access, an authorization
difference, an OOB interaction, a browser proof, or a reproducible control-vs-test
response). Reports are generated **from** these bundles — the reporter appends a
verbatim, machine-generated evidence appendix.

## Continuous / delta hunting

The attack surface persists across runs. On a new run the prior surface is loaded
and diffed; assets that appeared since last time (new subdomains, APIs, admin
panels, JS bundles) are prioritized into the hypothesis agenda. The cumulative
surface is saved at the end so each run builds on the last.

## Bug-bounty scope import (`integrations/bounty.py`)

Import a program's scope into an `Engagement` that feeds `ScopeGuard`:
- Offline structured scope file (YAML/JSON): engagement format, a `scopes` list of
  `{asset_type, asset_identifier, eligible_for_submission}`, or simple
  `in_scope` / `out_of_scope` lists.
- Optional HackerOne API connector (read-only) activated only when
  `HACKERONE_API_USERNAME` + `HACKERONE_API_TOKEN` are set.

Use `reynard-assess --bounty-scope <file>` or `--bounty-scope hackerone:<handle>`.
The importer only *produces* an engagement at startup; ScopeGuard remains the sole
authority and no tool/web/MCP response can widen scope at runtime.

## Docker profiles

The default image is a lean **web** runtime (recon toolchain incl. dnsx/naabu/
katana, web scanners, JWT/deserialization/SSTI tools, headless Chromium). CTF/
binary, mobile, wireless, forensics, Metasploit, and the Z4nzu meta-toolkit are
opt-in build-arg profiles (`PROFILE_PWN`, `PROFILE_MOBILE`, `PROFILE_WIRELESS`,
`PROFILE_FORENSICS`, `PROFILE_METASPLOIT`, `PROFILE_HACKINGTOOL`).

## Code organization

- `agents/exploitation.py` was split behavior-preservingly into
  `agents/exploit_fastpaths_web.py` (injection + client-side) and
  `agents/exploit_fastpaths_authz.py` (authz + misc) mixins.
- The regression suite was split from one 3529-line file into per-subsystem files
  plus per-module test files for every new capability.
