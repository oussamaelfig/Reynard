# Offline quality measurements

These checks run inside the repository. They do not execute registered security
tools, contact targets, start browsers, or require a running Kali container.
Install the development dependencies first:

```bash
python -m pip install -e ".[dev,harness]"
python -m pytest tests/test_quality_metrics.py -q
```

## Tool registry and maintenance evidence

```bash
python scripts/audit_tools.py --check
```

The JSON report compares the exact names in `TOOL_FUNCTIONS`, `TOOL_SCHEMAS`, and
the `ToolName` type. Equal counts alone cannot detect a renamed or missing tool.
Duplicate schemas, missing declarations, noncallable implementations, and source
files that cannot be parsed cause `--check` to fail.

Each tool also gets a list of Python source and test files containing its exact
name as a string token or a symbol. Registry declaration files are excluded.
These references can be prompts, mocks, or names shared with unrelated objects;
they are **not executed test coverage or proof of a call**. Aliases, constructed
names, comments, and non-Python files are outside this heuristic.

Models select tools dynamically. A missing static reference is a maintenance
review cue, not proof that the tool is unused. Remove a registered tool only after
checking its supported modes, public API, dispatcher selection, integration
dependencies, and representative run usage.

Analyze existing runtime event logs when available:

```bash
python scripts/audit_tools.py --check --events logs/runs/RUN_ID/events.jsonl
```

Repeat `--events` for distinct runs. The report counts EventBus `tool_result`
records, including results with reported failures. It does not expose request or
response payloads. Unknown tool names and malformed records are reported;
malformed records fail `--check`. Supplying the same file twice does not double
count it, but overlapping copies of a run must not be supplied separately.

Without logs, observed usage is `null` (unmeasured), not evidence of zero usage.
With logs, the observed tool fraction is:

```text
distinct registered tools with at least one tool_result / registered tool count
```

The result describes only those supplied runs. It does not establish successful
execution, vulnerability discovery, or safe removal of unobserved tools.

## Stored-evidence policy fixture benchmark

```bash
python scripts/quality_metrics.py --check
```

This command evaluates 18 stored records using the v2 reportability fixtures:
two positive synthetic signed SQL/browser records and 16 negative records.
The synthetic executor mints the positive receipts; no actual detector or browser
runs. The standalone command uses a temporary authority/artifact directory and
restores the operator's environment afterward, so fixture receipts are not
signed with the operator's key.

Negative cases cover bare confidence/verified flags, missing receipts, legacy
schemas, validator failures, changed projections, missing controls/transcripts,
reused context claims, substituted proof metadata, mismatched run/key bindings,
and removed artifact manifests. Mutation occurs only after fixture finalization;
the helper cannot repair or re-attest corrupted records. Most tampering cases
fail integrity before semantic proof checks, so these results do not establish
that a real detector rejects reflection, latency noise, or stale callbacks.

The JSON includes per-fixture decisions, the confusion matrix, and each metric's
numerator and denominator:

| Metric | Definition |
| --- | --- |
| Fixture precision | Accepted positive fixtures / all accepted fixtures |
| Fixture recall | Accepted positive fixtures / evaluated positive fixtures |
| Fixture false-positive rate | Accepted negative fixtures / evaluated negative fixtures |

An undefined metric is `null`, not zero or one. Evaluation exceptions are counted
separately, excluded from the confusion matrix, and fail the benchmark. Duplicate
fixture names and nonboolean labels are rejected. An empty corpus cannot pass.

`--check` returns a failing exit code for any unexpected acceptance, unexpected
rejection, or evaluation error. This guards against reducing fixture false
positives by rejecting everything.

The corpus tests the **stored-evidence acceptance policy only**. Its two
synthetic positive forms do not establish detector coverage. It does
not measure agent discovery, actual validator replay execution, tool execution,
or real-world false positives. The fixtures are constructed regression cases,
not an independent assessment corpus or evidence of competitor performance.

## Measuring the next layer

Use a separate, versioned local benchmark with vulnerable and patched fixtures
before making claims about finding quality. Keep the target definitions,
authorization boundaries, model/provider versions, budgets, tool versions,
repetitions, and expected outcomes in the result artifact. Report:

- Confirmed findings matched to the known vulnerability labels, with false
  positives and false negatives reported separately.
- Successful independent validator replay attempts divided by all attempted
  validator replays; report environmental failures separately.
- Median and tail cost, runtime, and tool calls per confirmed finding.
- Tool usage and failure counts per capability and benchmark family.
- Coverage gaps and every excluded or failed run.

Passing the policy fixture benchmark is a prerequisite for that measurement,
not a substitute for it.
