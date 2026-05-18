# Bounded Subagents Architecture

Reynard now uses bounded subagents for work that benefits from parallelism while
keeping target-mutating exploitation controlled.

## Principle

Parallelism is useful for independent information gathering. It is dangerous
for state-changing exploitation. The scheduler therefore splits work into lanes:

- `profile`: lab profile and playbook reasoning
- `readiness`: local tooling, Caido bridge, OOB, and session checks
- `recon`: read-only discovery lanes
- `research`: public methodology/writeup/documentation sidecars
- `analysis`: hypothesis generation
- `exploitation`: state-changing proof attempts
- `validation`: replay and refutation

Only read-only/profile/readiness/research/analysis lanes run in parallel by
default. Exploitation lanes run serially. Parallel state-changing exploitation
is only allowed when explicitly enabled by policy and the playbook is
`race_condition`.

## Startup Flow

On orchestrator startup, before the first coordinator decision, Reynard runs a
bounded bootstrap group:

1. `profile-analyst`: turns a detected expert lab profile into one focused
   theoretical finding.
2. `caido-readiness`: checks the Caido local bridge when the playbook prefers
   Caido Replay/history.
3. `session-readiness`: inventories configured sessions for auth-heavy labs.
4. `oob-readiness`: records OOB dependency when blind proof is expected.

The coordinator then sees these facts in shared memory and can route directly
to the highest-value next step.

## Safety Controls

- One shared `ScopeGuard` still gates all tool calls.
- One shared payload history still blocks duplicates.
- One shared `EvidenceStore` still controls verified findings.
- The `StateMachine` is now lock-protected for concurrent budget/counter use.
- State-changing subagents do not run in the parallel pool by default.

## CLI Controls

```powershell
python orchestrator.py --max-subagents 4 "Authorized lab: https://TARGET"
python orchestrator.py --no-subagents "Authorized lab: https://TARGET"
```

`--max-subagents` controls safe bootstrap parallelism. It does not make
exploitation fan out across the target.

## Why This Helps Expert Labs

Expert PortSwigger labs usually fail because the agent spends too much time on
generic recon or repeats weak probes. The bootstrap subagents front-load the
important context:

- known lab class
- exact evidence artifacts required
- auth/session prerequisites
- Caido/OOB readiness
- one focused theoretical finding for exploitation

This gets the system to the right exploit lane faster while preserving control
over lab state.
