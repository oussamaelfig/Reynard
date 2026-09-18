# Authenticated research: validation record

Validated locally on Windows, Python 3.12, 2026-09-17. No live third-party
assessment, exploitation or model call was performed. The HTTP integration
fixtures use an in-process mock transport or a temporary loopback application.

## Environment

This checkout's existing `.venv` points at Python 3.11 but contains CPython 3.12
native wheels. The tests used the installed Python 3.12 interpreter with its
package path explicitly set; the virtual environment was not rewritten.
An unrelated globally installed `libtmux` pytest plugin fails during startup,
so third-party plugin auto-loading was disabled for the regression run.

```powershell
$env:PYTHONPATH = "$PWD\.venv\Lib\site-packages;$PWD\src"
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
```

A normally installed, version-consistent virtual environment should not need
the `PYTHONPATH` workaround. Do not interpret environment workarounds as evidence
that all installations are supported.

## Commands and results

| Command | Observed result |
| --- | --- |
| `py -3.12 -m pytest -q` | 1,027 passed; 56 subtests passed; one upstream Starlette/AnyIO deprecation warning. |
| `node --test tests/ui/*.test.cjs` | 41 passed. |
| Playwright CLI `run-code --filename scripts/harness_ui_smoke.js` against the verified port-8891 fixture | 10 browser check groups passed; zero research runs launched. |
| `py -3.12 -m ruff check .` | Passed the repository's configured lint rules. |
| Scoped mypy command below | Passed eight source files. This is not full-repository type coverage. |
| `py -3.12 scripts/audit_tools.py --check` | Passed; 75 functions, schemas and typed tool names aligned. No extra general-purpose tools added. |
| `py -3.12 scripts/quality_metrics.py --check` | All 18 stored-evidence fixtures passed: two positives and 16 negatives. Not a live false-positive rate. |
| `py -3.12 -m hacking_agent.cli.lab_eval --pretty` | Completed 32 offline routing/readiness cases, average readiness 8.97. Not a solve-rate benchmark. |
| Scoped Bandit command below | Exit 1: four low-severity warnings, no medium/high warnings; review notes below. |
| `git diff --check` | Passed; Git emitted line-ending conversion notices for this Windows checkout. |

```powershell
py -3.12 -m mypy src/hacking_agent/core/authenticated_research.py src/hacking_agent/core/business_logic.py src/hacking_agent/core/research_pipeline.py src/hacking_agent/harness/models.py src/hacking_agent/harness/jobs.py src/hacking_agent/harness/run_job.py src/hacking_agent/harness/store.py src/hacking_agent/harness/server.py

py -3.12 -m bandit -q src/hacking_agent/core/authenticated_research.py src/hacking_agent/core/business_logic.py src/hacking_agent/core/research_pipeline.py src/hacking_agent/harness/jobs.py src/hacking_agent/harness/models.py src/hacking_agent/harness/run_job.py
```

Bandit warnings concern the existing subprocess import/launch and two
best-effort exception handlers (log close and result writing). The default
launcher uses fixed interpreter/module arguments, no shell, with a validated
run-directory identifier; custom worker factories are trusted Python injection
points, not HTTP input. These warnings were reviewed, not suppressed or presented
as a clean Bandit result.

## New fixture coverage

- Loopback registration → hidden-CSRF login → persistent authenticated cookies
  → links only present behind login.
- Anonymous and cross-identity negative controls; distinct account assertions;
  pre/post verification around independently cloned rule requests.
- Cookie rotation, host-only cookies, same-origin redirects and blocked mutation
  replays; no inherited proxies or Docker cookie files in the new runner.
- Scope, read-prefix, request, page, depth and deadline boundaries; explicit
  partial coverage and failed setup stopping the agent handoff.
- Missing/ambiguous markers, public/shared resources, generic success pages,
  expired identities, truncation and inconsistent replay.
- Private plan/rule data excluded from disk, argv and environment; safe API
  validation errors and Unicode IPC byte bounds.
- Large unread worker input does not hold the manager lock: cancellation remains
  possible, and input delivery times out after 30 seconds.
- UI opt-in, conflicting legacy sessions, clearing private fields, bounded
  research-outcome rendering and candidate/confirmed separation.

The new form was visually inspected in Chromium at desktop and 390px mobile
widths using synthetic preview data. No research was launched from the browser.
Screenshots remain in ignored `output/playwright/`.
The standard smoke helper first refused port 8893 as designed, then passed on
its expected, identity-verified port-8891 fixture. Initial unauthenticated and
deliberate offline/session-expiry HTTP errors are expected parts of these checks.

## Known limits

The fixture results validate implementation behavior, not arbitrary application
coverage. The runner is HTTP/server-rendered, not JavaScript-browser automation.
Business contracts remain unverified candidates; no trusted authorization or
state-transition effect adapter was added. See
[the usage and safety guide](authenticated-research.md).

## Follow-up from the real run log

Read-only inspection of stored run `781d1293c5d3` confirmed zero findings and a
target timeout. Its worker log contains 12 routing/framing-error occurrences,
21 duplicate-payload occurrences and 11 tool-budget-exhausted occurrences.
These are text occurrence counts, not counts of unique vulnerabilities or
requests actually sent.

Code review identified the next priorities; they are **not fixed by the new
authenticated research feature**:

1. Propagate structured execution errors. `execute_tool()` can return an `error`
   object that exploitation's `_summarize_result()` ignores, producing an empty
   observation and repeated unproductive attempts.
2. Build one capability set from production policy, connector readiness, tool
   budgets and implemented validation adapters. Use it in tool exposure, prompts,
   recommendations, fallbacks and hypothesis admission. An empty available-tools
   list must not expand back to the whole registry.
3. Circuit-break terminal policy/budget failures inside the specialist loop;
   preserve repeated-failure counts separately from unique failure records.
4. Authorize without charging, deduplicate with explicit identity/header/body
   context, then reserve the actual request budget immediately before dispatch.
   Reserve capacity for validation replay and negative controls.
5. Add trusted deterministic validation adapters, starting with controlled
   authorization effects. Existing trusted derivation covers only a browser
   dialog effect and a specific template-evaluation signal, despite a wider proof
   vocabulary. Do not solve missing adapters by accepting weaker evidence.

`X-Forwarded-Host` alone is not in the production header denylist. `Host`, framing,
connection and proxy-routing overrides are blocked. A mixed request can fail
because of `Host`. Caido availability would not authorize production-blocked raw
replay or bypass the engagement request cap.

Acceptance targets for that follow-up: no policy-disabled tool recommendations
in capability fixtures, no repeated terminal-failure probes, rejected duplicates
charge no request units, identity/header variants remain distinct, and every
advertised reportable class has both positive and negative end-to-end fixtures.
