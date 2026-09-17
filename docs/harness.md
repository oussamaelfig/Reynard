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
  HTML, CSS, JavaScript, and the bundled font are served from the same origin;
  there are no external font, analytics, or UI runtime requests. Static assets
  use an explicit allowlist, not a general-purpose file server.
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
| `GET`  | `/` | Console HTML with a fresh script nonce. |
| `GET`  | `/assets/{name}` | Allowlisted local CSS, JavaScript, and font only. |
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

## Workspace interactions

| Area | Use |
| --- | --- |
| Runs | Search by objective, run ID, or target; filter by status. Selection stays stable while the list updates. |
| Activity | Follow the event stream and connection state. The visible stream retains at most 300 blocks/rows; grouped output retains its last 16,000 characters. Full records remain in run artifacts. |
| Console | Inspect raw worker output. Do not share it without checking for sensitive data. |
| Report / Evidence | Review the stored report and its confirmed-finding snapshot. Older responses cannot overwrite a newly selected run. |
| Findings | Review only independently confirmed findings and export submissions. Candidate counts are separate from confirmed results. |
| Quick switcher | Ctrl+K or Cmd+K opens commands and run search. Arrow keys navigate; Enter opens; Escape closes. |
| Appearance | Warm dark by default, with a light theme. Theme preference is local; storage failure falls back to a usable session-only theme. |

Use Tab to move between controls. Run tabs also support Left/Right, Home, and
End. The launch drawer and quick switcher contain keyboard focus and restore
it when closed. On narrow screens, lists and details become separate views;
**All runs** or **Findings** returns to the list. Motion respects
`prefers-reduced-motion` and does not animate every incoming event.

The console displays measured run state, not estimated agent productivity or
fabricated success metrics. A completed run is not a guarantee of coverage.

## UI development and testing

The frontend is plain HTML/CSS/JavaScript: no bundler or npm runtime dependency.

| File | Responsibility |
| --- | --- |
| `src/hacking_agent/harness/ui/index.html` | Accessible landmarks, forms, tabs, and view structure. |
| `src/hacking_agent/harness/ui/console.css` | Warm neutral tokens, responsive layouts, and restrained motion. |
| `src/hacking_agent/harness/ui/console.js` | API/session state, keyed lists, stream bounds, keyboard interaction, and safe report rendering. |
| `src/hacking_agent/harness/ui/FONT-LICENSE.txt` | Geist font license, pinned upstream revision, and asset checksum. |

The bundled [Geist font](https://github.com/vercel/geist-font) is unmodified and
distributed with its SIL Open Font License. The visual reference informed the
palette and pane hierarchy; no Conductor application code, trackers, or branding
are bundled.

Run regression checks from the repository root:

```bash
pip install -e ".[dev,harness]"
python -m pytest tests/test_harness_server.py tests/test_harness_ui.py
node --test tests/ui/*.test.cjs
node --check src/hacking_agent/harness/ui/console.js
```

Node is needed only for the dependency-free JavaScript regression tests, not to
run the harness. For visual checks without Docker, model keys, or assessments:

```bash
python scripts/preview_harness_ui.py --port 8891
# Optional: start with no runs
python scripts/preview_harness_ui.py --port 8892 --empty
```

The helper is checkout-only and reuses test signing fixtures. It binds only to
`127.0.0.1`, creates a temporary store and signing authority, and prints a
**fixture-only** token. Every displayed finding is synthetic and labeled DEMO.
Launch/cancel actions change fixture state only: no worker, model, tool, or
assessment process starts. The real authentication, scope admission, and
report-validation gates remain enabled. Temporary state is cleaned on shutdown;
never use this known preview token for real research.

With the seeded preview on port 8891, an optional real-browser smoke check uses
the [Playwright CLI](https://github.com/microsoft/playwright-cli):

```bash
npx --yes --package @playwright/cli playwright-cli -s=reynard-ui open http://127.0.0.1:8891
npx --yes --package @playwright/cli playwright-cli -s=reynard-ui snapshot
npx --yes --package @playwright/cli playwright-cli -s=reynard-ui run-code --filename scripts/harness_ui_smoke.js
```

The smoke script refuses non-fixture servers, blocks unexpected remote or
mutating requests, and checks keyboard interaction, five viewport widths,
Markdown download, reduced motion, offline recovery, and expired-session cache
clearing. It never launches or cancels research, touches the clipboard, or opens
a print dialog. This optional browser check downloads CLI tooling; the console
itself has no JavaScript runtime dependency.

Verify dark/light appearances, desktop/tablet/mobile layouts, keyboard-only
navigation, reduced motion, empty states, offline recovery, and report exports.
Keep local screenshots in ignored `output/playwright/`. Restart the server after
asset changes to refresh the all-asset fingerprint returned by `/api/health`.

If native imports fail after a Python upgrade, verify that the virtual
environment's interpreter version matches its installed native wheels. Recreate
the environment for the intended Python version; do not interpret skipped
optional-import tests as a successful harness validation.

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
