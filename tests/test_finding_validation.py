"""Adversarial regression tests for the customer finding report gate."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime

import pytest

from hacking_agent.agents.reporter import (
    Finding,
    finding_to_report_dict,
    render_assessment_report,
)
from hacking_agent.core.evidence_bundle import (
    ControlTest,
    EvidenceBundle,
    SanitizedExchange,
    V_UNVERIFIED,
    V_VERIFIED,
)
from hacking_agent.core.finding_validation import (
    SuppressionReason,
    emit_suppression,
    evaluate_reportability,
    is_reportable,
)
from hacking_agent.harness.submission import (
    UnreportableFindingError,
    build_submission_markdown,
    iter_report_findings,
    render_stored_report_markdown,
    sanitize_report_json,
)


def _now() -> str:
    return datetime.utcnow().isoformat()


def valid_bundle(
    vuln_type: str = "SQL injection",
    *,
    proof_type: str = "boolean_oracle",
    proof_metadata: dict | None = None,
) -> EvidenceBundle:
    now = _now()
    proof = proof_metadata or {
        "effect_observed": True,
        "control_effect_observed": False,
        "oracle": "row-count canary",
        "payload_effect": "controlled rows marker present",
        "control_effect": "controlled rows marker absent",
    }
    bundle = EvidenceBundle(
        id="bundle:strict-1",
        finding_id="vuln:1",
        vuln_id="vuln:1",
        title=vuln_type,
        vuln_type=vuln_type,
        severity="high",
        target="https://app.example.test/",
        endpoint="https://app.example.test/items?id=1",
        identity="anonymous",
        created_at=now,
        updated_at=now,
        causal_signal="payload-specific row-count canary reproduced twice",
        verification_status=V_VERIFIED,
        verified_by="validator",
        validation_schema_version=1,
        discovered_by="exploitation",
        validator_identity="validator",
        validator_version="reynard-validator/1",
        validation_method="two independent replays plus matched negative control",
        validation_context="controlled_replay",
        validated_at=now,
        replay_count=2,
        replay_results=[
            {
                "attempt_index": 1,
                "probe_kind": "replay",
                "outcome": "vulnerable_effect",
                "behavioral_signal": "rows marker present",
                "context_id": "ctx-replay-a",
                "timestamp": now,
            },
            {
                "attempt_index": 2,
                "probe_kind": "fresh_context_replay",
                "outcome": "vulnerable_effect",
                "behavioral_signal": "rows marker present",
                "context_id": "ctx-replay-b",
                "timestamp": now,
            },
            {
                "attempt_index": 3,
                "probe_kind": "control",
                "outcome": "control_no_effect",
                "behavioral_signal": "rows marker absent",
                "context_id": "ctx-control-a",
                "timestamp": now,
            },
        ],
        proof_type=proof_type,
        proof_metadata=proof,
        reproduction_steps=[
            "Send the recorded payload request to the affected endpoint.",
            "Repeat it in the controlled replay context and observe the marker.",
            "Send the matched false-condition control and observe no marker.",
        ],
    )
    for index, (label, context_id) in enumerate(
        (("replay", "ctx-replay-a"), ("fresh_context_replay", "ctx-replay-b")),
        1,
    ):
        bundle.add_test(SanitizedExchange.build(
            label=label,
            identity="anonymous",
            method="GET",
            url=bundle.endpoint,
            request="GET /items?id=1%27%20OR%201=1 HTTP/1.1\nHost: app.example.test",
            response="HTTP/1.1 200 OK\ncontrolled rows marker present",
            status_code=200,
            source="validator",
            context_id=context_id,
            attempt_index=index,
        ))
    bundle.add_control(ControlTest(
        description="Matched false-condition payload under the same route",
        exchange=SanitizedExchange.build(
            label="control",
            identity="anonymous",
            method="GET",
            url=bundle.endpoint,
            request="GET /items?id=1%27%20OR%201=2 HTTP/1.1\nHost: app.example.test",
            response="HTTP/1.1 200 OK\ncontrolled rows marker absent",
            status_code=200,
            source="validator",
            context_id="ctx-control-a",
            attempt_index=3,
        ),
        result="payload-specific rows marker was absent",
    ))
    bundle.seal()
    return bundle


def finding_for(bundle: EvidenceBundle, *, title: str | None = None) -> Finding:
    if title is not None and title != bundle.title:
        bundle.title = title
        bundle.seal()
    finding = Finding(
        finding_id="vuln:1",
        vuln_id="vuln:1",
        title=title or bundle.title,
        vuln_type=bundle.vuln_type,
        severity=bundle.severity,
        endpoint=bundle.endpoint,
        parameter="id",
        description="A payload-specific behavioral oracle was reproduced.",
        impact="An attacker can alter backend query behavior.",
        remediation="Use parameterized queries.",
        verification_status=bundle.verification_status,
        evidence_bundle=bundle.to_dict(),
        evidence=[
            {
                "verdict": "success",
                "request": bundle.test_exchanges[0].request,
                "response": bundle.test_exchanges[0].response,
            },
        ],
        verified=True,
    )
    finding.ensure_scored()
    return finding


def reseal(bundle: EvidenceBundle) -> EvidenceBundle:
    bundle.seal()
    return bundle


def test_high_confidence_scanner_or_llm_candidate_cannot_be_reported():
    candidate = {
        "title": "Critical scanner claim",
        "vuln_type": "SQL injection",
        "severity": "critical",
        "confidence": 1.0,
        "verified": True,
        "verification_status": "verified",
    }
    decision = evaluate_reportability(candidate)
    assert not decision.reportable
    assert decision.reason_code == SuppressionReason.MISSING_EVIDENCE_BUNDLE.value


def test_reflection_without_browser_execution_is_suppressed_as_xss():
    bundle = valid_bundle(
        "Reflected XSS",
        proof_type="browser_execution",
        proof_metadata={
            "canary": "xss-canary-93af",
            "executed": False,
            "execution_context": "script",
            "browser_artifact": "trace/browser-proof.zip",
        },
    )
    bundle.causal_signal = "xss-canary-93af reflected into HTML only"
    reseal(bundle)
    decision = evaluate_reportability(finding_for(bundle))
    assert decision.reason_code == SuppressionReason.XSS_EXECUTION_NOT_PROVEN.value


def test_generic_500_is_not_an_injection_oracle():
    bundle = valid_bundle(
        proof_metadata={
            "effect_observed": True,
            "control_effect_observed": True,
            "oracle": "generic HTTP 500",
            "payload_effect": "HTTP 500",
            "control_effect": "HTTP 500",
        },
    )
    decision = evaluate_reportability(finding_for(reseal(bundle)))
    assert decision.reason_code == SuppressionReason.INJECTION_ORACLE_NOT_PROVEN.value


def test_one_off_latency_and_dns_only_ssrf_are_suppressed():
    timing = valid_bundle(
        proof_type="time_oracle",
        proof_metadata={
            "baseline_ms": [100, 110, 95],
            "payload_ms": [5100],
            "control_ms": [105, 100],
        },
    )
    assert evaluate_reportability(finding_for(reseal(timing))).reason_code == (
        SuppressionReason.TIME_ORACLE_INSUFFICIENT.value
    )

    ssrf = valid_bundle(
        "SSRF",
        proof_type="oob_callback",
        proof_metadata={
            "correlation_id": "corr-12345678",
            "attributable": True,
            "fresh_interaction": True,
            "interaction_protocol": "dns",
            "interaction_timestamp": _now(),
        },
    )
    ssrf.oob_interactions = ["corr-12345678 DNS lookup"]
    assert evaluate_reportability(finding_for(reseal(ssrf))).reason_code == (
        SuppressionReason.OOB_ATTRIBUTION_NOT_PROVEN.value
    )


def test_auth_status_or_size_difference_without_semantic_proof_is_suppressed():
    bundle = valid_bundle(
        "IDOR",
        proof_type="unauthorized_access",
        proof_metadata={
            "attacker_identity": "user-a",
            "owner_identity": "user-b",
            "resource_id": "invoice-42",
            "unauthorized_effect": "HTTP response length changed",
            "ownership_control_passed": False,
            "login_confounder": False,
            "cache_confounder": False,
        },
    )
    for exchange in bundle.test_exchanges:
        exchange.identity = "user-a"
    bundle.control_tests[0].exchange.identity = "user-b"
    decision = evaluate_reportability(finding_for(reseal(bundle)))
    assert decision.reason_code == (
        SuppressionReason.AUTHORIZATION_IMPACT_NOT_PROVEN.value
    )


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (
            lambda bundle: setattr(bundle, "control_tests", []),
            SuppressionReason.MISSING_MATCHED_CONTROL.value,
        ),
        (
            lambda bundle: setattr(bundle, "replay_count", 1),
            SuppressionReason.INSUFFICIENT_REPLAY.value,
        ),
        (
            lambda bundle: setattr(bundle, "validation_schema_version", 0),
            SuppressionReason.LEGACY_OR_MISSING_STATUS.value,
        ),
        (
            lambda bundle: setattr(bundle.test_exchanges[0], "response", ""),
            SuppressionReason.INCOMPLETE_EVIDENCE.value,
        ),
    ],
)
def test_missing_control_replay_status_or_bundle_content_fails_closed(
    mutate, reason,
):
    bundle = valid_bundle()
    mutate(bundle)
    reseal(bundle)
    assert evaluate_reportability(finding_for(bundle)).reason_code == reason


def test_missing_independence_status_or_bundle_fails_closed():
    no_independence = valid_bundle()
    no_independence.discovered_by = ""
    finding = finding_for(reseal(no_independence))
    assert evaluate_reportability(finding).reason_code == (
        SuppressionReason.NOT_INDEPENDENTLY_VALIDATED.value
    )

    missing_status = finding_for(valid_bundle())
    missing_status.verification_status = ""
    assert evaluate_reportability(missing_status).reason_code == (
        SuppressionReason.LEGACY_OR_MISSING_STATUS.value
    )

    missing_bundle = finding_for(valid_bundle())
    missing_bundle.evidence_bundle = {}
    assert evaluate_reportability(missing_bundle).reason_code == (
        SuppressionReason.MISSING_EVIDENCE_BUNDLE.value
    )


def test_validator_exception_fails_closed_with_structured_reason():
    bundle = valid_bundle()
    bundle.verification_status = V_UNVERIFIED
    bundle.validation_error = "validator_exception: browser crashed"
    reseal(bundle)
    finding = finding_for(bundle)
    finding.verification_status = V_UNVERIFIED
    decision = evaluate_reportability(finding)
    assert not decision.reportable
    assert decision.reason_code == SuppressionReason.VALIDATOR_ERROR.value


def test_complete_independent_payload_oracle_is_reportable():
    finding = finding_for(valid_bundle())
    assert is_reportable(finding)
    assert evaluate_reportability(finding).reason_code == "reportable"


def test_integrity_tampering_fails_closed():
    finding = finding_for(valid_bundle())
    finding.evidence_bundle["causal_signal"] = "tampered after validation"
    decision = evaluate_reportability(finding)
    assert decision.reason_code == SuppressionReason.EVIDENCE_INTEGRITY_FAILED.value


def test_finding_projection_must_match_sealed_evidence():
    finding = finding_for(valid_bundle())
    finding.title = "Unrelated critical claim"
    decision = evaluate_reportability(finding)
    assert decision.reason_code == SuppressionReason.EVIDENCE_MISMATCH.value


def test_malformed_policy_input_returns_a_structured_decision():
    bundle = valid_bundle().to_dict()
    bundle["replay_results"][0]["attempt_index"] = {"not": "an integer"}
    bundle["integrity_sha256"] = ""
    # Recompute the seal after introducing a JSON-valid but malformed field.
    from hacking_agent.core.finding_validation import evidence_integrity_digest
    bundle["integrity_sha256"] = evidence_integrity_digest(bundle)
    decision = evaluate_reportability(evidence_bundle=bundle)
    assert not decision.reportable
    assert decision.reason_code in {
        SuppressionReason.INSUFFICIENT_REPLAY.value,
        SuppressionReason.MALFORMED_EVIDENCE.value,
    }


def test_suppression_event_contains_only_sanitized_identity_title_and_reason():
    from hacking_agent.core.events import get_event_bus

    before = len(get_event_bus().snapshot())
    candidate = {
        "finding_id": "password=hunter2",
        "title": "Authorization: Bearer customer-secret",
    }
    decision = evaluate_reportability(candidate)
    emit_suppression(candidate, decision)
    events = get_event_bus().snapshot()[before:]
    event = next(event for event in events if event["type"] == "finding_suppressed")
    assert set(event["payload"]) == {"finding_id", "title", "reason_code"}
    assert event["payload"]["reason_code"] == "missing_evidence_bundle"
    assert "hunter2" not in str(event["payload"])
    assert "customer-secret" not in str(event["payload"])


def test_reports_json_harness_iterator_and_submissions_share_gate():
    confirmed = finding_for(valid_bundle(), title="Confirmed SQL injection")
    suppressed = Finding(
        title="NOISY SECRET CANDIDATE",
        vuln_type="SQL injection",
        severity="critical",
        verified=True,
        verification_status="verified",
    )
    report_md = render_assessment_report(
        {"targets": ["https://app.example.test/"]},
        [confirmed, suppressed],
    )
    assert "Confirmed SQL injection" in report_md
    assert "NOISY SECRET CANDIDATE" not in report_md
    assert "1 internal candidate observation(s) were suppressed" in report_md

    confirmed_dict = finding_to_report_dict(confirmed)
    raw_report = {
        "target_count": 1,
        "targets_assessed": [{
            "target": "https://app.example.test/",
            "findings": [
                confirmed_dict,
                {
                    "title": "NOISY SECRET CANDIDATE",
                    "vuln_type": "SQL injection",
                    "verified": True,
                    "verification_status": "verified",
                },
            ],
        }],
    }
    safe = sanitize_report_json(deepcopy(raw_report))
    assert safe["confirmed_count"] == safe["finding_count"] == 1
    assert safe["suppressed_count"] == 1
    assert [item["title"] for item in iter_report_findings(raw_report)] == [
        "Confirmed SQL injection"
    ]
    assert "NOISY SECRET CANDIDATE" not in str(safe)
    assert "NOISY SECRET CANDIDATE" not in render_stored_report_markdown(raw_report)
    assert "Confirmed SQL injection" in build_submission_markdown(confirmed_dict)
    with pytest.raises(UnreportableFindingError):
        build_submission_markdown(raw_report["targets_assessed"][0]["findings"][1])

    # Unsealed parallel evidence cannot replace or augment the accepted bundle.
    tampered = deepcopy(confirmed_dict)
    tampered["evidence"] = [{
        "request": "Authorization: Bearer customer-secret",
        "response": "forged proof",
    }]
    submission = build_submission_markdown(tampered)
    assert "customer-secret" not in submission
    assert "forged proof" not in submission
