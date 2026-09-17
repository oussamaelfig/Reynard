"""Benchmark the stored-evidence reportability policy entirely offline.

This small regression corpus measures acceptance of synthetic stored evidence,
not vulnerability discovery, validator execution, live replay success or an
operational false-positive rate. Run from a checkout with the dev dependencies.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "src", ROOT / "tests"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))


@dataclass(frozen=True)
class PolicyFixture:
    name: str
    expected_reportable: bool
    finding: Any


def policy_fixtures() -> list[PolicyFixture]:
    # Reuse the exact positive regression fixture as the production policy
    # evolves. Importing it performs no tests or network requests.
    from test_finding_validation import finding_for, valid_bundle

    fixtures = [PolicyFixture("complete_independent_sql_oracle", True, finding_for(valid_bundle()))]

    def reject(name: str, mutate: Callable[[Any], None]) -> None:
        bundle = valid_bundle()
        mutate(bundle)
        bundle.seal()
        fixtures.append(PolicyFixture(name, False, finding_for(bundle)))

    fixtures.append(PolicyFixture("bare_verified_flag", False, {
        "title": "Synthetic scanner assertion", "vuln_type": "SQL injection",
        "severity": "critical", "confidence": 1.0, "verified": True,
        "verification_status": "verified",
    }))
    tampered = finding_for(valid_bundle())
    tampered.evidence_bundle["causal_signal"] = "Changed after sealing the evidence"
    fixtures.append(PolicyFixture("tampered_seal", False, tampered))
    mismatch = finding_for(valid_bundle())
    mismatch.title = "Unrelated assertion outside the sealed projection"
    fixtures.append(PolicyFixture("projection_mismatch", False, mismatch))
    reject("legacy_schema", lambda bundle: setattr(bundle, "validation_schema_version", 0))
    reject("validator_failure", lambda bundle: setattr(bundle, "validation_error", "fixture: replay unavailable"))
    reject("self_validation", lambda bundle: setattr(bundle, "discovered_by", "validator"))
    reject("missing_negative_control", lambda bundle: setattr(bundle, "control_tests", []))
    reject("one_replay", lambda bundle: setattr(bundle, "replay_count", 1))
    reject("incomplete_response", lambda bundle: setattr(bundle.test_exchanges[0], "response", ""))
    reject("uncorrelated_signal", lambda bundle: bundle.replay_results[0].update(
        behavioral_signal="This claimed effect never appears in either transcript"))
    reject("same_replay_context", lambda bundle: bundle.replay_results[1].update(
        context_id=bundle.replay_results[0]["context_id"]))
    reject("control_also_has_effect", lambda bundle: bundle.proof_metadata.update(
        control_effect_observed=True))
    reject("unsupported_vulnerability_class", lambda bundle: setattr(bundle, "vuln_type", "Unknown synthetic class"))

    reflected = valid_bundle("Reflected XSS", proof_type="browser_execution", proof_metadata={
        "canary": "fixture-xss-canary", "executed": False,
        "execution_context": "script", "browser_artifact": "trace/fixture.zip",
    })
    fixtures.append(PolicyFixture("reflection_without_execution", False, finding_for(reflected)))
    timing = valid_bundle(proof_type="time_oracle", proof_metadata={
        "baseline_ms": [100, 110, 95], "payload_ms": [5100], "control_ms": [105, 100],
    })
    fixtures.append(PolicyFixture("one_off_latency", False, finding_for(timing)))
    dns = valid_bundle("SSRF", proof_type="oob_callback", proof_metadata={
        "correlation_id": "fixture-correlation-id", "attributable": True,
        "fresh_interaction": True, "interaction_protocol": "dns",
        "interaction_timestamp": "2026-01-01T00:00:00+00:00",
    })
    dns.oob_interactions = ["fixture-correlation-id DNS lookup"]
    dns.seal()
    fixtures.append(PolicyFixture("dns_only_callback", False, finding_for(dns)))
    return fixtures


def _ratio(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def score_fixtures(
    fixtures: Iterable[PolicyFixture], evaluator: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    from hacking_agent.core.finding_validation import evaluate_reportability

    evaluator = evaluator or evaluate_reportability
    cases = list(fixtures)
    if len({fixture.name for fixture in cases}) != len(cases):
        raise ValueError("Fixture names must be unique")
    if any(type(fixture.expected_reportable) is not bool for fixture in cases):
        raise ValueError("Fixture labels must be explicit booleans")
    counts = {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0}
    results = []
    errors = 0
    for fixture in cases:
        try:
            decision = evaluator(fixture.finding)
            predicted = decision.reportable
            if type(predicted) is not bool:
                raise ValueError("Policy prediction must be a boolean")
            reason = str(decision.reason_code)
            evaluation_error = False
        except Exception:
            predicted = None
            reason = "benchmark_evaluation_error"
            evaluation_error = True
            errors += 1
        if predicted is not None:
            correct = predicted == fixture.expected_reportable
            key = ("true_" if correct else "false_") + ("positive" if predicted else "negative")
            counts[key] += 1
        results.append({
            "fixture": fixture.name, "expected_reportable": fixture.expected_reportable,
            "actual_reportable": predicted, "reason_code": reason,
            "passed": not evaluation_error and predicted == fixture.expected_reportable,
        })
    tp, fp = counts["true_positive"], counts["false_positive"]
    tn, fn = counts["true_negative"], counts["false_negative"]
    return {
        "schema_version": 1,
        "measurement": "stored_evidence_policy_fixture_benchmark",
        "limitations": [
            "Synthetic regression fixtures test only the deterministic stored-evidence acceptance policy.",
            "The built-in positive corpus covers a SQL boolean oracle; other classes need positive fixtures.",
            "This is not end-to-end discovery, an independent benchmark, a live validator replay rate, or an operational false-positive estimate.",
            "Fixture precision/recall depend on this small constructed corpus; no population confidence or competitor comparison is implied.",
            "Evaluation errors are excluded from the confusion matrix, counted separately, and always fail the benchmark.",
        ],
        "fixture_count": len(cases),
        "expected_positive_count": sum(f.expected_reportable for f in cases),
        "expected_negative_count": sum(not f.expected_reportable for f in cases),
        "evaluated_count": sum(counts.values()),
        "evaluation_errors": errors,
        "confusion_matrix": counts,
        "metrics": {"precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
                    "false_positive_rate": _ratio(fp, fp + tn)},
        "passed": bool(cases) and all(result["passed"] for result in results),
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Exit 1 on any fixture mismatch/error or an empty corpus.")
    args = parser.parse_args(argv)
    report = score_fixtures(policy_fixtures())
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not args.check or report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
