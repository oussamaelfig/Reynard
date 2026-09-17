"""Benchmark the stored-evidence reportability policy entirely offline.

This small regression corpus measures acceptance of synthetic stored evidence,
not vulnerability discovery, validator execution, live replay success or an
operational false-positive rate. Run from a checkout with the dev dependencies.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Callable, Iterable, Iterator

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
    # The helper mints synthetic executor receipts, not actual detector output.
    # Mutate only AFTER finalizing: helper calls can repair or re-attest a bundle.
    from test_finding_validation import finding_for, valid_bundle
    from hacking_agent.core.finding_validation import evidence_integrity_digest

    sql = finding_for(valid_bundle())
    browser = finding_for(valid_bundle("Reflected XSS", proof_type="browser_execution"))
    fixtures = [
        PolicyFixture("authenticated_synthetic_sql_oracle", True, sql),
        PolicyFixture("authenticated_synthetic_browser_artifact", True, browser),
    ]

    def reject(name: str, mutate: Callable[[Any], None], base: Any = sql) -> None:
        finding = deepcopy(base)
        mutate(finding)
        fixtures.append(PolicyFixture(name, False, finding))

    def change_bundle(**changes: Any) -> Callable[[Any], None]:
        return lambda finding: finding.evidence_bundle.update(changes)

    fixtures.append(PolicyFixture("bare_verified_flag", False, {
        "title": "Synthetic scanner assertion", "vuln_type": "SQL injection",
        "severity": "critical", "confidence": 1.0, "verified": True,
        "verification_status": "verified",
    }))
    reject("tampered_seal", change_bundle(causal_signal="Changed after signing the evidence"))
    reject("missing_bundle_receipt", change_bundle(authenticity={}))

    def public_reseal(finding: Any) -> None:
        finding.evidence_bundle["authenticity"] = {}
        finding.evidence_bundle["causal_signal"] = "A public hash cannot authenticate this claim"
        finding.evidence_bundle["integrity_sha256"] = evidence_integrity_digest(finding.evidence_bundle)

    reject("unkeyed_reseal_cannot_authenticate", public_reseal)
    reject("projection_mismatch", lambda finding: setattr(finding, "title", "Unrelated unsigned assertion"))
    reject("legacy_schema", change_bundle(validation_schema_version=1))
    reject("validator_failure", change_bundle(validation_error="fixture: replay unavailable"))
    reject("missing_negative_control", change_bundle(control_tests=[]))
    reject("one_replay", change_bundle(replay_count=1))
    reject("incomplete_response", lambda finding: finding.evidence_bundle["test_exchanges"][0].update(response=""))
    reject("reused_context_claim", lambda finding: finding.evidence_bundle["replay_results"][1].update(
        context_id=finding.evidence_bundle["replay_results"][0]["context_id"]))
    reject("model_proof_metadata_substitution", change_bundle(proof_metadata={
        "effect_observed": True, "control_effect_observed": False, "oracle": "model-authored claim",
    }))
    reject("missing_protocol_receipt", change_bundle(validation_protocol={}))
    reject("cross_run_binding", lambda finding: finding.evidence_bundle["authenticity"].update(run_id="other-run"))
    reject("unknown_authority_key", lambda finding: finding.evidence_bundle["authenticity"].update(key_id="unknown-key"))
    reject("removed_browser_artifact_manifest", change_bundle(artifacts=[]), base=browser)
    return fixtures


@contextmanager
def isolated_fixture_authority() -> Iterator[None]:
    """Standalone offline checks must never mint fixture receipts with operator keys."""
    keys = ("REYNARD_VALIDATION_STATE_DIR", "REYNARD_VALIDATION_HMAC_KEY", "REYNARD_HOST_EXEC")
    previous = {key: os.environ.get(key) for key in keys}
    with tempfile.TemporaryDirectory(prefix="reynard-policy-benchmark-") as directory:
        os.environ["REYNARD_VALIDATION_STATE_DIR"] = directory
        os.environ.pop("REYNARD_VALIDATION_HMAC_KEY", None)
        os.environ.pop("REYNARD_HOST_EXEC", None)
        try:
            yield
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


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
            "Positive records use synthetic signed SQL/browser effects; no real detector or browser is executed.",
            "Negative records test missing receipts and post-signing tampering; many fail integrity before semantic proof checks.",
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
    with isolated_fixture_authority():
        report = score_fixtures(policy_fixtures())
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not args.check or report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
