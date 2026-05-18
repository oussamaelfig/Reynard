# Expert Lab Upgrade Notes

This repo now has a deterministic expert layer for authorized labs and CTF
targets. The intent is to move the agent away from broad, repeated probing and
toward a repeatable workflow:

1. Parse the user's objective into target URL, lab profile, credentials, and
   vulnerability class.
2. Attach a compact expert playbook with primary tools, required artifacts,
   exploit strategy, validation criteria, and pivot hints.
3. Inject that playbook into the coordinator, recon, analyst, exploitation, and
   single-agent prompts.
4. Classify failures so the next step changes primitive or tooling instead of
   repeating the same request.
5. Use `reynard-lab-eval` as a fast offline readiness check before running an
   expensive live lab attempt.

## New Commands

```powershell
reynard-lab-eval --pretty
reynard-lab-eval --case "JWT authentication bypass lab. Target: https://0abc.web-security-academy.net/" --pretty
```

The evaluator does not attack the target. It reports:

- parsed target URL
- detected lab profile
- matched expert playbook
- preferred tools
- required evidence artifacts
- prerequisite gaps such as missing credentials, OOB setup, or Caido bridge
- readiness score out of 10

## Current Expert Coverage

The playbook layer covers every Web Security Academy topic listed in
`docs/portswigger-coverage-matrix.md`, plus the specific OAuth/OIDC dynamic
client registration SSRF expert case. The default `reynard-lab-eval --pretty`
suite asserts that all mapped topics detect a playbook and score at least
`8/10` before live execution.

## What Still Matters During Live Runs

Expert-level labs usually fail for environmental reasons before methodology:

- Caido local bridge is not running when Replay/history artifacts are needed.
- OOB/interactsh is unavailable for blind SSRF, XXE, CMDi, or deserialization.
- Auth sessions are missing for access-control, JWT, GraphQL, CSRF, or business
  logic labs.
- The model is allowed to keep probing after weak evidence instead of requiring
  control requests.

The new failure classifier records these causes in memory as
`last_failure_class` and `last_failure_guidance`, which the coordinator sees on
the next routing turn.
