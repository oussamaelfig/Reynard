<div align="center">

```
██████╗ ███████╗██╗   ██╗███╗   ██╗ █████╗ ██████╗ ██████╗
██╔══██╗██╔════╝╚██╗ ██╔╝████╗  ██║██╔══██╗██╔══██╗██╔══██╗
██████╔╝█████╗   ╚████╔╝ ██╔██╗ ██║███████║██████╔╝██║  ██║
██╔══██╗██╔══╝    ╚██╔╝  ██║╚██╗██║██╔══██║██╔══██╗██║  ██║
██║  ██║███████╗   ██║   ██║ ╚████║██║  ██║██║  ██║██████╔╝
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

# Reynard

**Autonomous web security researcher for authorized pentests, bug bounties, and CTF/lab benchmarks.**

Multi-agent LLM reasoning · persistent attack surface · structured recon · authenticated differential testing · evidence-gated reporting · a local web console with copy-paste bug-bounty submissions.

<br/>

[![Version](https://img.shields.io/badge/version-3.0.0-0ea5e9?style=for-the-badge)](./pyproject.toml)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](./pyproject.toml)
[![Docker](https://img.shields.io/badge/runtime-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](./Dockerfile)
[![Use](https://img.shields.io/badge/use-authorized%20only-ef4444?style=for-the-badge)](#scope--safety)

</div>

> **Authorized use only.** Run Reynard against systems you own, intentionally vulnerable labs, CTF infrastructure, or targets covered by explicit written authorization (e.g. an in-scope bug-bounty program). You are responsible for every target, technique, and tool invocation.

---

## What it is

Reynard is a **structured multi-agent penetration engine**, not a script runner with an LLM bolted on. A coordinator routes specialist agents through one research loop:

> understand scope → map attack surface → identify interesting behavior → hypothesize → test → learn → pivot/chain → **independently verify** → report

| Layer | What you get |
| --- | --- |
| **Agents** | Coordinator · Recon · Analyst · Exploitation · Validator · Reporter · Pivot |
| **Runtime** | Kali container with scanners + headless Chromium; every tool call gated by `ScopeGuard` |
| **Attack surface** | Persistent, scope-annotated map (domains, hosts, URLs, APIs, params, JS, identities, roles…) with provenance + confidence |
| **Memory** | Knowledge graph + SQLite cross-run store + methodology playbooks via RAG |
| **Proof** | PoC evidence store + validator replay; reports are generated from evidence, not model claims |
| **Console** | Local web harness: submit a target/scope, watch live model reasoning, export reports and bug-bounty submissions |

Two mission modes: **`production`** (default — real assessments, evidence-gated, no lab shortcuts) and **`benchmark`** (PortSwigger/CTF labs).

---

## How to run

### Prerequisites

- **Python 3.10+**
- **Docker** (Docker Desktop on macOS/Windows) — the agents execute tools inside a `reynard-kali` container
- An **LLM API key** (DeepSeek, OpenAI, Anthropic, or any OpenAI-compatible gateway)

### 1. Configure your key

```bash
cp .env.example .env
```

Edit `.env` and set a provider (DeepSeek example):

```env
LLM_DEFAULT_PROVIDER=deepseek
LLM_DEFAULT_MODEL=deepseek-chat
DEEPSEEK_API_KEY=sk-your-key
```

<details><summary>Other providers</summary>

```env
# OpenAI-compatible gateway
LLM_DEFAULT_PROVIDER=openai-compatible
LLM_DEFAULT_MODEL=your-model
LLM_DEFAULT_BASE_URL=https://your-gateway/v1
LLM_DEFAULT_API_KEY=sk-your-key
```

`openai` / `gpt` → `OPENAI_API_KEY`, `anthropic` / `claude` → `ANTHROPIC_API_KEY`, `qwen` / `dashscope` → `QWEN_API_KEY`. Per-role overrides exist for every agent (`RECON_*`, `EXPLOITATION_*`, …); see [`.env.example`](./.env.example).

</details>

### 2. Install

```bash
python -m venv venv
source venv/bin/activate                 # Windows: .\venv\Scripts\Activate.ps1
pip install -e ".[harness]"              # base engine + the web console
# optional extras:  pip install -e ".[rag]"   (better embeddings)   /   ".[external]"   (Browser Use)
```

### 3. Start the Kali runtime

```bash
docker compose build      # first build is large (Kali + tools + Chromium)
docker compose up -d
docker ps --filter "name=reynard-kali"
```

### 4. Run — pick one

**A) Web console (recommended)** — a self-serve dashboard: submit a target + scope, watch live reasoning, export reports and submissions.

```bash
export REYNARD_HARNESS_TOKEN="$(openssl rand -hex 24)"   # optional; auto-generated + printed if unset
reynard-harness                                          # serves http://127.0.0.1:8787/
```

Open **http://127.0.0.1:8787/** and launch a run from the form. See [Starting a scan](#starting-a-scan).

> Windows / PATH note: if `reynard-harness` isn't found, run `python -m hacking_agent.harness.server` instead.

**B) CLI** — for scripted / headless use:

```bash
# Bug-bounty or client assessment (scope-gated, consolidated report)
reynard-assess --engagement eval/engagement.sample.yaml --out reports/acme

# Authorized pentest with the multi-agent orchestrator
python orchestrator.py --production --ui \
  "Authorized pentest for https://app.example.com. Scope: app.example.com only."
```

---

## Starting a scan

### From the web console

1. Open **http://127.0.0.1:8787/** and click **New run**.
2. Fill the drawer:
   - **Targets** — e.g. `https://app.example.com/`
   - **Authorized domains** — `app.example.com` (subdomains included). Use **Authorized URL prefixes** for path-scoped assets like `https://example.com/docs`.
   - **Out of scope** — hosts to never touch (overrides the allowlist).
   - **Objective** — free text; this drives the agents (e.g. "Focus on IDOR/BOLA across the account API").
   - Set rate limit / iterations, then tick **"I am authorized to test this scope"** and **Launch run**.
3. Watch the **Live** tab (streaming model reasoning + tool activity) and **Console** (raw worker log).
4. When it finishes, read the **Report** tab (Copy / Download `.md` / Export PDF), then open **Findings** to copy a ready-to-paste **bug-bounty submission** per finding.

### Headless (same backend, from a script)

```bash
TOKEN="$REYNARD_HARNESS_TOKEN"
# launch
curl -s -H "x-harness-token: $TOKEN" -H 'content-type: application/json' \
  -X POST http://127.0.0.1:8787/api/runs -d '{
    "targets": ["https://app.example.com/"],
    "authorized_domains": ["app.example.com"],
    "out_of_scope": ["blog.example.com"],
    "description": "Focus on IDOR/BOLA across the account API",
    "max_requests_per_second": 2,
    "max_iterations": 30,
    "authorized": true
  }'
# -> {"run_id":"...","status":"queued"}

curl -s -H "x-harness-token: $TOKEN" http://127.0.0.1:8787/api/runs                 # list runs
curl -N -s "http://127.0.0.1:8787/api/runs/<id>/events?token=$TOKEN"                # live SSE
curl -s -H "x-harness-token: $TOKEN" http://127.0.0.1:8787/api/runs/<id>/report.md  # report (markdown)
curl -s -H "x-harness-token: $TOKEN" http://127.0.0.1:8787/api/findings.md          # all submissions
```

### Pure CLI (no console)

```bash
# from a bug-bounty program scope (offline file or HackerOne handle)
reynard-assess --bounty-scope eval/bounty_scope.sample.json --out reports/acme
reynard-assess --bounty-scope hackerone:acme --target https://app.acme.com/

# from an engagement config (authorized domains/CIDRs, rate limits, window, destructive policy)
reynard-assess --engagement eval/engagement.sample.yaml --dry-run     # validate scope only
reynard-assess --engagement eval/engagement.sample.yaml --out reports/acme

# authenticated / IDOR testing with controlled identities
python orchestrator.py --production --ui --auth-file auth-sessions.json \
  "Authorized pentest for https://app.example.com. Scope: app.example.com only."
```

`auth-sessions.json`:

```json
{
  "sessions": {
    "user1": { "headers": { "Cookie": "session=USER1_COOKIE" } },
    "user2": { "headers": { "Cookie": "session=USER2_COOKIE" } }
  }
}
```

> **Reynard refuses to run without an authorized scope.** Every request is gated by the engagement's out-of-scope denylist, rate limit, request cap, destructive-action policy, and testing window.

---

## The web console (harness)

A single-operator local dashboard over the same engine — no change to the agent architecture. Each run executes in its own subprocess (isolated globals) and is serialized for the single-operator MVP.

- **New Run drawer** — target, scope (domains / CIDRs / URL prefixes), out-of-scope, objective, rate limits, and an explicit authorization ack.
- **Live** — model reasoning streamed and coalesced into readable "thinking"/"output" blocks, plus tool/finding events.
- **Console** — the raw worker log (exact model output as printed).
- **Report** — the consolidated report with **Copy Markdown / Download .md / Export PDF**.
- **Findings** — every finding across all runs, severity-filtered, each rendered as a complete **bug-bounty submission** (title, asset, severity, CVSS vector+score, CWE, summary, steps to reproduce, PoC request/response, impact, remediation, references) with **Copy submission / Download .md / Export PDF** and **Export all**.
- **⌘K** command palette, light/dark theme.

Security: binds `127.0.0.1` only and requires `REYNARD_HARNESS_TOKEN` on every call; the LLM key is read from the server env and never persisted. Full details: [`docs/harness.md`](./docs/harness.md).

---

## Production research capabilities

| Capability | What it does |
| --- | --- |
| **Attack Surface model** | Persistent, scope-annotated map (domains/subdomains/hosts/URLs/APIs/params/JS/source-maps/websockets/tech/identities/roles/workflows) with provenance, confidence, first/last-seen. |
| **Structured recon** | Typed wrappers for subfinder, dnsx, httpx, naabu, katana, waybackurls, crt.sh, urlscan → parsed into surface state (never raw dumps); graceful when tools/keys are absent. |
| **Application mapper** | `browser_map` drives authenticated Chromium and captures XHR/fetch/APIs, WebSockets, JS bundles + source maps, links and forms into an endpoint/param inventory. |
| **Authorization matrix** | `authz_matrix_scan` replays endpoints as anon/userA/userB/admin-test-role, compares semantically, and flags IDOR/BOLA/BFLA/privilege-escalation with control-vs-test evidence. |
| **EvidenceBundle** | Sanitized exchanges, identity, endpoint, control tests, reproduction steps, OOB, verification status — the basis for every report and submission. |
| **Delta hunting** | Prior attack surfaces persist across runs; newly-appeared subdomains/APIs/admin panels are prioritized next run. |
| **Bug-bounty scope import** | Load a program's scope (offline file or `hackerone:<handle>`) into an engagement behind `ScopeGuard` — never mutable by a connector/webpage/MCP response. |
| **Tiered escalation** | Stuck runs escalate to a high-reasoning `pivot`/`strong` role before concluding failure; token/cost budgets are enforced. |

Architecture deep-dive: [`docs/production-research-architecture.md`](./docs/production-research-architecture.md).

---

## Scope & safety

**In scope by design:** intentionally vulnerable labs (DVWA, Juice Shop, WebGoat), PortSwigger Academy, HTB/THM/CTF boxes you may attack, authorized pentest environments, and in-scope bug-bounty assets.

**Refused / out of scope:** targets without permission; DDoS, phishing, credential stuffing, social engineering; wireless deauth or disruptive testing unless explicitly authorized; production testing without rate limits, a test window, and written approval.

Follow the target program's rules of engagement (allowed test types, rate caps, excluded paths). The engagement config **is** the authorization boundary.

---

## Configuration

Authoritative, commented list: [`.env.example`](./.env.example).

| Area | Key knobs |
| --- | --- |
| Provider / models | `LLM_DEFAULT_PROVIDER`, `LLM_DEFAULT_MODEL`, `LLM_DEFAULT_API_KEY`/`DEEPSEEK_API_KEY`, per-role `RECON_*`/`EXPLOITATION_*`/… |
| Reasoning / budgets | `LLM_*_REASONING_EFFORT`, `LLM_*_THINKING`, `LLM_MAX_TOKENS_BUDGET`, `LLM_MAX_COST_BUDGET` |
| Harness | `REYNARD_HARNESS_TOKEN`, `REYNARD_HARNESS_HOST`, `REYNARD_HARNESS_PORT`, `REYNARD_HARNESS_MAX_CONCURRENCY`, `REYNARD_EVENT_LOG` |
| Runtime | `CONTAINER_NAME` (default `reynard-kali`), `REYNARD_HOST_EXEC` (run tools on the host when no container) |
| Memory / RAG | `REYNARD_DURABLE_MEMORY`, `REYNARD_MEMORY_DB`, `REYNARD_EMBEDDINGS`, `OLLAMA_BASE_URL` |
| Eval / assess | `ASSESS_PER_TARGET_TIMEOUT`, `EVAL_PER_LAB_TIMEOUT` |

---

## Integrations (optional)

- **Caido** — Local Bridge (replay, HTTP history, findings) + Cloud API. See [`docs/caido-local-bridge.md`](./docs/caido-local-bridge.md).
- **Burp MCP** — raw HTTP, scanner issues, Collaborator, Repeater/Intruder when the extension is online (`BURP_MCP_URL`).
- **Browser Use + HexStrike AI** — two optional, untrusted specialist providers behind one adapter; they return structured observations into the AttackSurface (never findings), and every action still passes through `ScopeGuard`. `pip install -e ".[external]"`; details in [`docs/external-integrations.md`](./docs/external-integrations.md).
- **OSINT** — Shodan / Censys / urlscan and web search when keys are set; graceful fallback otherwise.

---

## Benchmarks (PortSwigger / CTF)

Reynard keeps a deterministic lab layer for regression benchmarking (labs are **not** on the production path).

```bash
reynard-lab-eval --pretty                                   # offline readiness (no attack)
reynard-lab-eval --live --config eval/labs.sample.yaml      # live solve-rate scorecard
python orchestrator.py --benchmark --ui --no-oob \
  "Solve this authorized PortSwigger lab: <description>. Target: https://YOUR-LAB.web-security-academy.net/"
```

Coverage matrix: [`docs/portswigger-coverage-matrix.md`](./docs/portswigger-coverage-matrix.md).

---

## Project structure

```text
reynard/
├── orchestrator.py / agent.py    # multi-agent / single-agent launchers
├── Dockerfile · docker-compose.yml   # reynard-kali runtime
├── pyproject.toml                # package metadata (v3.0.0) + console scripts
├── .env.example                  # full, commented env template
├── methodologies/                # bug-class playbooks (RAG corpus)
├── eval/                         # lab corpus + sample engagement / bounty scope
├── docs/                         # harness, production architecture, Caido, coverage…
└── src/hacking_agent/
    ├── agents/                   # coordinator, recon, analyst, exploitation, validator, reporter, pivot
    ├── cli/                      # reynard, reynard-orchestrator, reynard-lab-eval, reynard-assess
    ├── core/                     # strategy, memory, RAG, tools, scope, metering, evidence…
    ├── harness/                  # web console: server, jobs, store, run worker, submission, UI
    └── integrations/             # Burp, Caido, Shodan, external providers
```

Console scripts: `reynard` · `reynard-orchestrator` · `reynard-lab-eval` · `reynard-assess` · `reynard-harness`.

---

## Common commands

```bash
docker compose up -d                       # start the Kali runtime
reynard-harness                            # web console at http://127.0.0.1:8787/
reynard-assess --engagement eval/engagement.sample.yaml --out reports/acme
python orchestrator.py --production --ui "Authorized target: https://TARGET"
docker compose down                        # stop the runtime
```

Reports, evidence, and per-run logs land under `logs/` (gitignored); harness runs live in `logs/runs/<id>/`.

---

## Docs

| Doc | Topic |
| --- | --- |
| [`docs/harness.md`](./docs/harness.md) | Web console: API, run lifecycle, security |
| [`docs/production-research-architecture.md`](./docs/production-research-architecture.md) | Production research loop + subsystems |
| [`docs/external-integrations.md`](./docs/external-integrations.md) | Browser Use + HexStrike adapters |
| [`docs/caido-local-bridge.md`](./docs/caido-local-bridge.md) | Caido local bridge contract |
| [`docs/portswigger-coverage-matrix.md`](./docs/portswigger-coverage-matrix.md) | Benchmark coverage |

---

## Legal

Reynard is for education, CTFs, research labs, and **authorized** security assessments only. Ensure every target, technique, and tool invocation is permitted by the applicable rules of engagement and law.

<div align="center">
<br/>

**Reynard** · think like a fox · prove like an engineer · `v3.0.0`

</div>
