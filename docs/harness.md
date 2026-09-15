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
(`REYNARD_HARNESS_MAX_CONCURRENCY=1`) because they share one Kali container.

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

- **Localhost + token.** The server binds `127.0.0.1` and requires
  `REYNARD_HARNESS_TOKEN` on every API call (the SSE stream accepts it as a
  `?token=` query param because `EventSource` cannot set headers). If no token
  is set, one is generated and printed at startup. Binding to a non-loopback
  host prints a warning — don't expose this endpoint.
- **Authorization gate.** A run is refused unless it declares an authorized
  scope (domain or CIDR) **and** the operator checks "I am authorized to test
  this scope" — mirroring `reynard-assess`. The worker rebuilds the `Engagement`
  and calls `ScopeGuard.attach_engagement`, so the UI can never widen scope
  beyond the submitted engagement.
- **No secrets persisted.** The submitted `config.json` contains scope + options
  only; API keys stay in env.

## API surface

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`  | `/` | The console (single HTML page). |
| `GET`  | `/api/health` | Liveness + whether auth is required. |
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
