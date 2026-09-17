# Reynard run harness (local web console)

A single-operator web console so you stop prompting the agents by hand: submit a
target + scope + objective in a form, the agents run in the background against
the Dockerized runtime, and you watch live progress and read the evidence-backed
report. It is a **thin control plane over the existing engine** — it does not
change the agent/reasoning architecture, and every tool call still goes through
`ScopeGuard`, the engagement rules of engagement, and the evidence-gated
validator.

## Why a process per run

Reynard is built for one run per process: the event bus, session registry, OOB
session, token meter, and the single `reynard-kali` container + cookie jar are
process/host-global. So each submitted run executes in its **own subprocess**
(isolated globals). For the single-operator MVP, runs are **serialized**
(`REYNARD_HARNESS_MAX_CONCURRENCY=1`); other values are rejected while optional
tools can share one Kali container. Run only one harness server per checkout.

## Install & run

```bash
pip install -e ".[harness]"        # adds fastapi + uvicorn only
docker compose up -d               # bring up the reynard-kali runtime + services
export REYNARD_HARNESS_TOKEN="$(openssl rand -hex 24)"   # optional; auto-generated if unset
reynard-harness                    # serves http://127.0.0.1:8787/
```

The LLM provider/model/key come from the same environment the CLIs use
(`LLM_DEFAULT_*`, `DEEPSEEK_API_KEY`, …). The console reads that env and passes
it to each run's subprocess **via env only** — it is never written to disk.

## Security model

- **Localhost + token.** Non-loopback binds and Host headers are rejected.
  Paste `REYNARD_HARNESS_TOKEN` into the login dialog; when unset, the CLI
  generates and prints one. The public HTML never contains the token.
  Login exchanges it for an HttpOnly, SameSite=Strict session cookie. API
  clients may continue using `x-harness-token`. SSE uses the cookie or header;
  URL query tokens are no longer accepted. Cross-origin requests are refused.
  Responses disable caching and framing; the UI uses a nonce-based script policy.
- **Authorization gate.** A run is refused unless it declares an authorized
  scope (domain or CIDR) **and** the operator checks "I am authorized to test
  this scope" — mirroring `reynard-assess`. Targets outside scope or inside
  exclusions are rejected before queueing. The worker rebuilds the `Engagement`
  and calls `ScopeGuard.attach_engagement`, so the UI can never widen scope
  beyond the submitted engagement.
- **Credentials are ephemeral.** Submitted cookie/header identities remain in
  server memory until worker launch, then travel once over stdin. They are
  excluded from `config.json`, argv, and environment variables. LLM API keys
  stay in the process environment. Existing old configs are not migrated or
  erased; review their retention. Operator descriptions, tool logs, responses,
  and evidence may contain sensitive data, so protect the entire run directory.
- **Bounded input.** Request bodies are limited to 1 MiB, target lists to 100,
  and auth-session payloads to 256 KiB. Timeouts and budgets reject negative,
  non-finite, and excessive values; header injection is refused.

## API surface

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`  | `/` | The console (single HTML page). |
| `GET`  | `/api/health` | Liveness + whether auth is required. |
| `POST` | `/api/session` | Exchange `x-harness-token` for a browser session cookie. |
| `POST` | `/api/runs` | Validate authorization + scope, persist, enqueue. Returns `run_id`. |
| `GET`  | `/api/runs` | List runs (newest first) with status + counts. |
| `GET`  | `/api/runs/{id}` | Run detail + status. |
| `GET`  | `/api/runs/{id}/events` | SSE live stream (tails `events.jsonl`; supports `Last-Event-ID`). |
| `GET`  | `/api/runs/{id}/report` | Consolidated report (`markdown` + `json`). |
| `GET`  | `/api/runs/{id}/evidence` | Findings/verification snapshot. |
| `POST` | `/api/runs/{id}/cancel` | Terminate the run subprocess. |

## Run lifecycle & storage

Runs are tracked in a small SQLite index plus a per-run directory under
`logs/runs/`:

```
logs/runs/
  runs.db                  status index
  <run_id>/config.json     submitted request (no secrets)
  <run_id>/events.jsonl    event stream (the SSE endpoint tails this)
  <run_id>/report.md/.json consolidated report
  <run_id>/memory.db       per-run durable memory
  <run_id>/worker.log      worker stdout/stderr
  <run_id>/result.json     findings/verified counts read on exit
```

Status flow: `queued → running → completed | failed | cancelled`.

Duplicate submissions cannot launch a second worker. Cancellation and shutdown
terminate the owned host process tree, cancel queued jobs, and clear pending
credentials. A timeout stops the remaining targets and marks the run failed;
an empty or malformed worker result cannot become a successful run. Startup
marks stale queued/running records failed without killing stored PIDs (PIDs
may have been reused). Inspect previous workers after an unclean shutdown
before resubmitting. Terminating a Docker client does not prove that every
container-side command ended.

SSE event IDs are durable file cursors, so reconnects work when target workers
restart their internal counters. Each harness run owns its memory database.

## The submission form

- **Targets** — explicit URLs (optional if authorized domains are given).
- **Authorized domains / CIDRs** — the engagement scope (at least one required).
- **Out of scope** — denylist enforced by `ScopeGuard`.
- **Objective / description** — free text that becomes the agents' objective.
- **Iterations / timeout / rate limits / max requests** — rules of engagement.
- **Advanced** — allow-destructive, Browser Use / HexStrike toggles, and
  optional auth sessions (JSON array of controlled identities for
  authenticated / authorization testing).

## Enabling the event log for a plain CLI run

The harness sets `REYNARD_EVENT_LOG` per run automatically. To persist/stream a
one-off CLI run, set it yourself:

```bash
REYNARD_EVENT_LOG=logs/manual.jsonl reynard-assess --engagement eng.yaml
```

Each `emit()` is then appended as one JSON line (default-off otherwise).

## Non-goals (MVP)

No multi-user accounts/RBAC, no concurrency > 1, no per-run containers, no cloud
hosting, and no changes to the agent/reasoning architecture.
