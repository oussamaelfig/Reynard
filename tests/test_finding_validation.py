"""Adversarial regressions for evidence provenance and customer report gates."""
from __future__ import annotations

import json
import os
import tempfile
from copy import deepcopy
from pathlib import Path

import pytest

# Receipts and artifacts are isolated from the operator's real key/store. A
# subprocess inherits and reuses the parent's test authority.
if not os.getenv("REYNARD_VALIDATION_STATE_DIR"):
    _TRUST_STATE = tempfile.TemporaryDirectory(
        prefix="reynard-validation-tests-",
    )
    os.environ["REYNARD_VALIDATION_STATE_DIR"] = _TRUST_STATE.name
else:
    _TRUST_STATE = None

from hacking_agent.agents.reporter import (  # noqa: E402
    Finding,
    finalize_bundle_for_reporting,
    finding_to_report_dict,
    render_assessment_report,
)
from hacking_agent.core.evidence_bundle import (  # noqa: E402
    ControlTest,
    EvidenceBundle,
    SanitizedExchange,
    V_UNVERIFIED,
    V_VERIFIED,
)
from hacking_agent.core.finding_validation import (  # noqa: E402
    SuppressionReason,
    emit_suppression,
    evaluate_reportability,
    is_reportable,
)
from hacking_agent.core.validation_provenance import (  # noqa: E402
    ARTIFACT_PRODUCER,
    EXECUTOR_SOURCE,
    artifact_root,
    attest_report,
    capture_observation,
    issue_protocol_receipt,
    sha256_bytes,
    sha256_text,
    sign_payload,
    utc_now,
    verify_artifact,
)
from hacking_agent.harness.submission import (  # noqa: E402
    UnreportableFindingError,
    build_submission_markdown,
    finding_from_dict,
    iter_report_findings,
    render_stored_report_markdown,
    sanitize_report_json,
)


RUN_ID = "test-run"
ENGAGEMENT_ID = "engagement:test"
VALIDATOR_ID = "validator:test-instance"
VALIDATOR_VERSION = "reynard-validator/test"


def _exchange(observation: dict) -> SanitizedExchange:
    return SanitizedExchange(
        label=observation["probe_kind"],
        identity=observation["identity"],
        method=observation["method"],
        url=observation["url"],
        request=observation["request"],
        response=observation["response"],
        status_code=observation["status_code"],
        timestamp=observation["captured_at"],
        source=observation["source"],
        context_id=observation["context_id"],
        attempt_index=observation["attempt_index"],
        capture_id=observation["capture_id"],
        request_sha256=observation["request_sha256"],
        response_sha256=observation["response_sha256"],
    )


def _trusted_effect(
    effect_kind: str,
    *,
    fingerprint: str,
    with_artifact: bool,
) -> dict:
    effect = {
        "kind": effect_kind,
        "fingerprint": fingerprint,
        "details": {"detector": "synthetic_executor_fixture"},
    }
    if with_artifact:
        effect.update({
            "artifact_content": json.dumps({
                "effect_kind": effect_kind,
                "fingerprint": fingerprint,
                "captured_by": "synthetic_executor_fixture",
            }, sort_keys=True).encode(),
            "artifact_kind": (
                "browser_execution_trace"
                if effect_kind == "browser_execution"
                else "validation_trace"
            ),
            "artifact_media_type": "application/json",
        })
    return effect


def valid_bundle(
    vuln_type: str = "SQL injection",
    *,
    proof_type: str = "boolean_oracle",
    proof_metadata: dict | None = None,
    run_id: str = RUN_ID,
    with_artifact: bool | None = None,
) -> EvidenceBundle:
    """Build a fully trusted synthetic record from executor observations.

    ``proof_metadata`` remains accepted for compatibility with older test
    imports, but it is intentionally ignored: model-authored proof metadata has
    no authority in the v2 protocol.
    """
    del proof_metadata
    if with_artifact is None:
        with_artifact = proof_type in {
            "browser_execution", "concrete_exploit_effect",
        }
    now = utc_now()
    endpoint = "https://app.example.test/items?id=1"
    fingerprint = sha256_text(f"trusted:{vuln_type}:{proof_type}")
    effect = _trusted_effect(
        proof_type,
        fingerprint=fingerprint,
        with_artifact=with_artifact,
    )
    observations = [
        capture_observation(
            attempt_index=1,
            probe_kind="replay",
            tool="synthetic_executor",
            request="GET /items?id=payload HTTP/1.1\nHost: app.example.test",
            response="HTTP/1.1 200 OK\ntrusted effect marker",
            status_code=200,
            identity="anonymous",
            url=endpoint,
            method="GET",
            captured_at=now,
            run_id=run_id,
            engagement_id=ENGAGEMENT_ID,
            validator_instance_id=VALIDATOR_ID,
            trusted_effect=effect,
        ),
        capture_observation(
            attempt_index=2,
            probe_kind="fresh_context_replay",
            tool="synthetic_executor",
            request="GET /items?id=payload HTTP/1.1\nHost: app.example.test",
            response="HTTP/1.1 200 OK\ntrusted effect marker",
            status_code=200,
            identity="anonymous",
            url=endpoint,
            method="GET",
            captured_at=utc_now(),
            run_id=run_id,
            engagement_id=ENGAGEMENT_ID,
            validator_instance_id=VALIDATOR_ID,
            trusted_effect=effect,
        ),
        capture_observation(
            attempt_index=3,
            probe_kind="control",
            tool="synthetic_executor",
            request="GET /items?id=control HTTP/1.1\nHost: app.example.test",
            response="HTTP/1.1 200 OK\ncontrol response without effect",
            status_code=200,
            identity="anonymous",
            url=endpoint,
            method="GET",
            captured_at=utc_now(),
            run_id=run_id,
            engagement_id=ENGAGEMENT_ID,
            validator_instance_id=VALIDATOR_ID,
            trusted_effect={},
        ),
    ]
    protocol, reason = issue_protocol_receipt(
        observations,
        run_id=run_id,
        engagement_id=ENGAGEMENT_ID,
        validator_instance_id=VALIDATOR_ID,
        validator_version=VALIDATOR_VERSION,
    )
    assert protocol is not None, reason
    replay_a, replay_b, control = observations
    bundle = EvidenceBundle(
        id="bundle:strict-1",
        finding_id="vuln:1",
        vuln_id="vuln:1",
        title=vuln_type,
        vuln_type=vuln_type,
        severity="high",
        target="https://app.example.test/",
        endpoint=endpoint,
        identity="anonymous",
        created_at=now,
        updated_at=now,
        test_exchanges=[_exchange(replay_a), _exchange(replay_b)],
        control_tests=[ControlTest(
            description="Matched negative control captured by trusted executor",
            exchange=_exchange(control),
            result=f"control_no_effect in {control['capture_id']}",
        )],
        reproduction_steps=list(protocol["reproduction_steps"]),
        causal_signal=protocol["causal_signal"],
        verification_status=V_VERIFIED,
        verified_by="validator",
        validation_schema_version=2,
        discovered_by="exploitation",
        validator_identity=dict(protocol["validator_identity"]),
        validator_version=VALIDATOR_VERSION,
        validation_method=protocol["validation_method"],
        validation_context=protocol["validation_context"],
        validated_at=protocol["validated_at"],
        replay_count=protocol["replay_count"],
        replay_results=list(protocol["replay_results"]),
        proof_type=protocol["proof_type"],
        proof_metadata=dict(protocol["proof_metadata"]),
        validation_protocol=protocol,
        artifacts=list(protocol["artifacts"]),
    )
    assert finalize_bundle_for_reporting(bundle, parameter="id")
    return bundle


def finding_for(bundle: EvidenceBundle, *, title: str | None = None) -> Finding:
    if title is not None and title != bundle.title:
        bundle.title = title
        bundle.customer_projection["title"] = title
        bundle.attest()
    projection = bundle.customer_projection
    return Finding(
        title=projection["title"],
        finding_id=projection["finding_id"],
        vuln_id=projection["vuln_id"],
        vuln_type=projection["vuln_type"],
        severity=projection["severity"],
        target=projection["target"],
        endpoint=projection["endpoint"],
        parameter=projection["parameter"],
        description=projection["description"],
        impact=projection["impact"],
        remediation=projection["remediation"],
        cwe=projection["cwe"],
        cvss_vector=projection["cvss_vector"],
        cvss_score=projection["cvss_score"],
        reproduction_steps=list(projection["reproduction_steps"]),
        references=list(projection["references"]),
        engagement_id=projection["engagement_id"],
        evidence=deepcopy(projection["evidence"]),
        verification_status="verified",
        evidence_bundle=bundle.to_dict(),
        verified=True,
    )


def signed_report(
    finding: Finding,
    *,
    run_id: str = RUN_ID,
    suppressed_count: int = 0,
) -> dict:
    item = finding_to_report_dict(finding)
    report = {
        "engagement_name": "Synthetic assessment",
        "client": "Test client",
        "tester": "Test operator",
        "generated_at": utc_now(),
        "targets": [finding.target],
        "authorized_domains": ["app.example.test"],
        "authorized_cidrs": [],
        "out_of_scope": [],
        "testing_window": "",
        "reportability_policy_version": 2,
        "target_count": 1,
        "finding_count": 1,
        "verified_count": 1,
        "confirmed_count": 1,
        "suppressed_count": suppressed_count,
        "suppression_semantics": (
            "report candidates rejected by the customer export gate"
        ),
        "targets_assessed": [{
            "target": finding.target,
            "verdict": "assessed",
            "wall_clock_seconds": 1.0,
            "findings": [item],
            "confirmed_count": 1,
            "suppressed_count": suppressed_count,
        }],
    }
    report["report_authenticity"] = attest_report(
        report,
        run_id=run_id,
        engagement_id=ENGAGEMENT_ID,
        validator_instance_id="reporter:test-instance",
    )
    return report


def _resign_artifact(record: dict, **changes) -> dict:
    payload = deepcopy(record)
    envelope = payload.pop("authenticity")
    payload.update(changes)
    payload["authenticity"] = sign_payload(
        "artifact",
        payload,
        run_id=envelope["run_id"],
        engagement_id=envelope["engagement_id"],
        validator_instance_id=envelope["validator_instance_id"],
    )
    return payload


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


def test_self_attested_responses_notes_and_claimed_contexts_are_rejected():
    now = utc_now()
    legacy = EvidenceBundle(
        id="bundle:self-attested",
        finding_id="vuln:1",
        vuln_id="vuln:1",
        title="SQL injection",
        vuln_type="SQL injection",
        severity="high",
        target="https://app.example.test/",
        endpoint="https://app.example.test/items?id=1",
        identity="anonymous",
        verification_status=V_VERIFIED,
        verified_by="validator",
        validation_schema_version=2,
        discovered_by="exploitation",
        validator_version="claimed",
        validation_method="claimed replays and control",
        validation_context="controlled_replay",
        validated_at=now,
        replay_count=2,
        causal_signal="ordinary 200 response allegedly proves rows marker",
        reproduction_steps=[
            "Send an ordinary request and claim a positive outcome.",
            "Repeat the same claim and write it into model notes.",
        ],
    )
    for index, label in enumerate(("replay", "fresh_context_replay"), 1):
        legacy.add_test(SanitizedExchange.build(
            label=label,
            identity="anonymous",
            method="GET",
            url=legacy.endpoint,
            request="GET /items HTTP/1.1",
            response="HTTP/1.1 200 OK\nordinary page",
            status_code=200,
            notes="MODEL CLAIM: rows marker present",
            source="validator",
            context_id=f"model-ctx-{index}",
            attempt_index=index,
        ))
    legacy.add_control(ControlTest(
        description="Model-authored matched control claim",
        exchange=SanitizedExchange.build(
            label="control",
            identity="anonymous",
            method="GET",
            url=legacy.endpoint,
            request="GET /items HTTP/1.1",
            response="HTTP/1.1 200 OK\nordinary page",
            status_code=200,
            notes="MODEL CLAIM: rows marker absent",
            source="validator",
            context_id="model-control",
            attempt_index=3,
        ),
        result="MODEL CLAIM: control_no_effect",
    ))
    legacy.seal()
    decision = evaluate_reportability(evidence_bundle=legacy)
    assert not decision.reportable
    assert decision.reason_code == (
        SuppressionReason.UNTRUSTED_EXECUTOR_PROVENANCE.value
    )


def test_legitimate_trusted_record_without_semantic_artifact_is_reportable():
    finding = finding_for(valid_bundle())
    assert finding.evidence_bundle["artifacts"] == []
    assert is_reportable(finding)
    assert evaluate_reportability(finding).reason_code == "reportable"


def test_legitimate_browser_record_uses_real_verified_artifact():
    bundle = valid_bundle(
        "Reflected XSS",
        proof_type="browser_execution",
    )
    assert bundle.artifacts
    record = bundle.artifacts[0]
    path = artifact_root().joinpath(*Path(record["path"]).parts)
    assert path.is_file()
    assert path.stat().st_size == record["size"]
    assert is_reportable(finding_for(bundle))


def test_nonexistent_required_artifact_fails_closed():
    bundle = valid_bundle(
        "Reflected XSS",
        proof_type="browser_execution",
    )
    record = bundle.artifacts[0]
    artifact_root().joinpath(*Path(record["path"]).parts).unlink()
    decision = evaluate_reportability(finding_for(bundle))
    assert not decision.reportable
    assert decision.reason_code == (
        SuppressionReason.UNTRUSTED_EXECUTOR_PROVENANCE.value
    )


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"size": 999999}, "artifact_size_mismatch"),
        ({"sha256": "0" * 64, "artifact_id": f"sha256:{'0' * 64}"},
         "artifact_hash_mismatch"),
        ({"source": "model", "producer": "model"}, "untrusted_artifact_provenance"),
    ],
)
def test_wrong_artifact_size_hash_or_source_is_rejected(changes, reason):
    bundle = valid_bundle(
        "Reflected XSS",
        proof_type="browser_execution",
    )
    record = _resign_artifact(bundle.artifacts[0], **changes)
    ok, actual_reason = verify_artifact(
        record,
        expected_run_id=RUN_ID,
        expected_engagement_id=ENGAGEMENT_ID,
        expected_validator_instance_id=VALIDATOR_ID,
    )
    assert not ok
    assert actual_reason == reason


def test_artifact_traversal_and_symlink_escape_are_rejected(tmp_path):
    bundle = valid_bundle(
        "Reflected XSS",
        proof_type="browser_execution",
    )
    original = bundle.artifacts[0]
    traversal = _resign_artifact(original, path="../outside.json")
    ok, reason = verify_artifact(
        traversal,
        expected_run_id=RUN_ID,
        expected_engagement_id=ENGAGEMENT_ID,
        expected_validator_instance_id=VALIDATOR_ID,
    )
    assert not ok and reason == "artifact_path_escape"

    outside = tmp_path / "outside.json"
    outside.write_bytes(b"outside")
    link = artifact_root() / RUN_ID / "escape.json"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside)
    digest = sha256_bytes(outside.read_bytes())
    symlink = _resign_artifact(
        original,
        path=f"{RUN_ID}/escape.json",
        sha256=digest,
        artifact_id=f"sha256:{digest}",
        size=outside.stat().st_size,
    )
    ok, reason = verify_artifact(
        symlink,
        expected_run_id=RUN_ID,
        expected_engagement_id=ENGAGEMENT_ID,
        expected_validator_instance_id=VALIDATOR_ID,
    )
    assert not ok and reason == "artifact_symlink_rejected"


def test_duplicate_replay_or_control_provenance_is_rejected():
    protocol = valid_bundle().validation_protocol
    observations = deepcopy(protocol["observations"])
    duplicated_control = deepcopy(observations[0])
    duplicated_control["probe_kind"] = "control"
    duplicated_control.pop("authenticity")
    duplicated_control["authenticity"] = sign_payload(
        "executor_observation",
        duplicated_control,
        run_id=RUN_ID,
        engagement_id=ENGAGEMENT_ID,
        validator_instance_id=VALIDATOR_ID,
    )
    receipt, reason = issue_protocol_receipt(
        [observations[0], observations[1], duplicated_control],
        run_id=RUN_ID,
        engagement_id=ENGAGEMENT_ID,
        validator_instance_id=VALIDATOR_ID,
        validator_version=VALIDATOR_VERSION,
    )
    assert receipt is None
    assert reason == "duplicate_executor_provenance"

    same_text_control = capture_observation(
        attempt_index=3,
        probe_kind="control",
        tool="synthetic_executor",
        request=observations[0]["request"],
        response=observations[0]["response"],
        status_code=200,
        identity="anonymous",
        url=observations[0]["url"],
        method="GET",
        captured_at=utc_now(),
        run_id=RUN_ID,
        engagement_id=ENGAGEMENT_ID,
        validator_instance_id=VALIDATOR_ID,
        trusted_effect={},
    )
    receipt, reason = issue_protocol_receipt(
        [observations[0], observations[1], same_text_control],
        run_id=RUN_ID,
        engagement_id=ENGAGEMENT_ID,
        validator_instance_id=VALIDATOR_ID,
        validator_version=VALIDATOR_VERSION,
    )
    assert receipt is None
    assert reason == "duplicated_control_capture"


@pytest.mark.parametrize(
    "field",
    [
        "title", "vuln_type", "endpoint", "severity", "description",
        "impact", "remediation", "parameter", "cwe", "cvss_vector",
        "cvss_score", "target", "engagement_id", "reproduction_steps",
        "references", "evidence",
    ],
)
def test_every_customer_visible_finding_field_is_bound(field):
    finding = finding_for(valid_bundle())
    if field in {"reproduction_steps", "references", "evidence"}:
        getattr(finding, field).append(
            {"request": "forged"} if field == "evidence" else "forged"
        )
    elif field == "cvss_score":
        setattr(finding, field, 10.0)
    elif field == "severity":
        setattr(finding, field, "critical")
    else:
        setattr(finding, field, f"mutated-{field}")
    decision = evaluate_reportability(finding)
    assert not decision.reportable
    assert decision.reason_code == SuppressionReason.EVIDENCE_MISMATCH.value


@pytest.mark.parametrize(
    "field",
    [
        "title", "vuln_type", "endpoint", "severity", "description",
        "impact", "remediation", "parameter", "cwe", "cvss_vector",
        "cvss_score", "target", "engagement_id", "reproduction_steps",
        "references", "evidence",
    ],
)
def test_mutated_content_is_rejected_from_every_outward_path(field, tmp_path):
    original = finding_for(valid_bundle())
    report = signed_report(original)
    item = report["targets_assessed"][0]["findings"][0]
    marker = f"OUTWARD-MUTATION-{field}"
    if field in {"reproduction_steps", "references", "evidence"}:
        item[field] = [marker]
    elif field == "cvss_score":
        item[field] = 10.0
    else:
        item[field] = marker

    safe = sanitize_report_json(report)
    assert safe["confirmed_count"] == 0
    assert marker not in str(safe)
    assert iter_report_findings(report) == []
    assert marker not in render_stored_report_markdown(report)
    assert marker not in render_assessment_report(
        {},
        [finding_from_dict(item)],
    )
    with pytest.raises(UnreportableFindingError):
        build_submission_markdown(item)

    from hacking_agent.cli.assess import write_reports
    md_path, json_path = write_reports(marker, report, str(tmp_path))
    assert marker not in md_path.read_text(encoding="utf-8")
    assert marker not in json_path.read_text(encoding="utf-8")


def test_unknown_signature_key_and_run_binding_fail_closed():
    finding = finding_for(valid_bundle())
    finding.evidence_bundle["authenticity"]["key_id"] = "unknown-key"
    assert evaluate_reportability(finding).reason_code == (
        SuppressionReason.EVIDENCE_AUTHENTICITY_FAILED.value
    )

    bound = finding_for(valid_bundle())
    decision = evaluate_reportability(bound, expected_run_id="other-run")
    assert not decision.reportable
    assert decision.reason_code == (
        SuppressionReason.EVIDENCE_AUTHENTICITY_FAILED.value
    )


def test_report_engagement_binding_cannot_mix_valid_findings():
    finding = finding_for(valid_bundle())
    report = signed_report(finding)
    report["report_authenticity"] = attest_report(
        report,
        run_id=RUN_ID,
        engagement_id="engagement:other",
        validator_instance_id="reporter:test-instance",
    )
    safe = sanitize_report_json(report)
    assert safe["confirmed_count"] == 0
    assert iter_report_findings(report) == []


def test_model_proof_metadata_and_notes_cannot_change_trusted_outcome():
    finding = finding_for(valid_bundle())
    finding.evidence_bundle["proof_metadata"] = {
        "effect_observed": True,
        "control_effect_observed": False,
        "oracle": "model-authored",
    }
    finding.evidence_bundle["test_exchanges"][0]["notes"] = (
        "model says this is definitely exploitable"
    )
    decision = evaluate_reportability(finding)
    assert not decision.reportable
    assert decision.reason_code == (
        SuppressionReason.EVIDENCE_INTEGRITY_FAILED.value
    )


def test_legacy_unkeyed_digest_no_longer_authenticates_evidence():
    bundle = valid_bundle()
    bundle.authenticity = {}
    bundle.seal()
    decision = evaluate_reportability(evidence_bundle=bundle)
    assert not decision.reportable
    assert decision.reason_code == (
        SuppressionReason.EVIDENCE_AUTHENTICITY_FAILED.value
    )


def test_validator_exception_fails_closed_with_structured_reason():
    bundle = valid_bundle()
    bundle.verification_status = V_UNVERIFIED
    bundle.validation_error = "validator_exception: browser crashed"
    bundle.seal()
    finding = finding_for(bundle)
    finding.verification_status = V_UNVERIFIED
    decision = evaluate_reportability(finding)
    assert not decision.reportable
    assert decision.reason_code == SuppressionReason.VALIDATOR_ERROR.value


def test_report_authenticity_rejects_mutated_engagement_metadata():
    finding = finding_for(valid_bundle())
    report = signed_report(finding)
    report["engagement_name"] = "MUTATED REPORT METADATA"
    safe = sanitize_report_json(report)
    assert safe["confirmed_count"] == 0
    assert "MUTATED REPORT METADATA" not in str(safe)
    assert "MUTATED REPORT METADATA" not in render_stored_report_markdown(report)


def test_arbitrary_suppression_reason_keys_never_cross_customer_boundary():
    report = signed_report(finding_for(valid_bundle()), suppressed_count=2)
    report["suppression_reasons"] = {
        "candidate prose Authorization: Bearer secret": 99,
    }
    safe = sanitize_report_json(report)
    assert safe["confirmed_count"] == 1
    assert safe["suppressed_count"] == 2
    assert "suppression_reasons" not in safe
    assert "Bearer secret" not in render_stored_report_markdown(report)


def test_internal_bundle_diagnostics_and_unknown_prose_are_not_serialized():
    finding = finding_for(valid_bundle())
    finding.evidence_bundle["suppression_reason_code"] = "arbitrary-key"
    finding.evidence_bundle["suppression_rationale"] = "INTERNAL PROSE"
    finding.evidence_bundle["unknown_candidate_prose"] = "UNRELATED PROSE"
    assert is_reportable(finding)
    exported = finding_to_report_dict(finding)
    serialized = exported["evidence_bundle"]
    assert "suppression_reason_code" not in serialized
    assert "suppression_rationale" not in serialized
    assert "unknown_candidate_prose" not in serialized
    assert "INTERNAL PROSE" not in str(exported)


def test_reports_json_markdown_iterator_and_submission_share_gate():
    confirmed = finding_for(
        valid_bundle(),
        title="Confirmed SQL injection",
    )
    report = signed_report(confirmed, suppressed_count=1)
    safe = sanitize_report_json(report)
    assert safe["confirmed_count"] == safe["finding_count"] == 1
    assert safe["suppressed_count"] == 1
    assert [item["title"] for item in iter_report_findings(report)] == [
        "Confirmed SQL injection"
    ]
    markdown = render_stored_report_markdown(report)
    assert "Confirmed SQL injection" in markdown
    submission = build_submission_markdown(finding_to_report_dict(confirmed))
    assert "Confirmed SQL injection" in submission


def test_unsigned_or_legacy_report_is_empty_and_counts_raw_candidates():
    raw = {
        "engagement_name": "UNTRUSTED REPORT PROSE",
        "targets_assessed": [{
            "target": "https://app.example.test/",
            "findings": [
                finding_to_report_dict(finding_for(valid_bundle())),
                {"title": "legacy candidate"},
            ],
        }],
    }
    safe = sanitize_report_json(raw)
    assert safe["confirmed_count"] == 0
    assert safe["suppressed_count"] == 2
    assert safe["targets_assessed"] == []
    assert "UNTRUSTED REPORT PROSE" not in str(safe)


def test_empty_customer_report_excludes_unverified_candidate_prose():
    candidate = Finding(
        title="Unverified candidate",
        vuln_type="SQL injection",
        severity="critical",
        verified=True,
    )
    markdown = render_assessment_report({}, [candidate])
    assert "No independently confirmed findings were found." in markdown
    assert "Unverified candidate" not in markdown
    assert "not mean that zero hypotheses" not in markdown


def test_integrity_tampering_fails_closed():
    finding = finding_for(valid_bundle())
    finding.evidence_bundle["causal_signal"] = "tampered after validation"
    decision = evaluate_reportability(finding)
    assert decision.reason_code == SuppressionReason.EVIDENCE_INTEGRITY_FAILED.value


def test_malformed_policy_input_returns_a_structured_decision():
    bundle = valid_bundle().to_dict()
    bundle["replay_results"][0]["attempt_index"] = {"not": "an integer"}
    decision = evaluate_reportability(evidence_bundle=bundle)
    assert not decision.reportable
    assert decision.reason_code in {
        SuppressionReason.EVIDENCE_INTEGRITY_FAILED.value,
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


def test_report_file_writer_regates_and_ignores_caller_markdown(tmp_path):
    from hacking_agent.cli.assess import write_reports

    report = signed_report(finding_for(valid_bundle()))
    md_path, json_path = write_reports(
        "# stale\nUNSEALED CUSTOMER PROSE",
        report,
        str(tmp_path),
    )
    markdown = md_path.read_text(encoding="utf-8")
    safe = json.loads(json_path.read_text(encoding="utf-8"))
    assert "UNSEALED CUSTOMER PROSE" not in markdown
    assert safe["confirmed_count"] == 1
    assert "suppression_reasons" not in safe
