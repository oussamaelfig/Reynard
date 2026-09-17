"""Regression tests for offline quality measurements and their denominators."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


def _script(name: str):
    path = Path(__file__).resolve().parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


inventory = _script("audit_tools")
metrics = _script("quality_metrics")


def _schema(name):
    return {"type": "function", "function": {"name": name}}


def test_inventory_rejects_equal_counts_with_different_names():
    report = inventory.registry_alignment({"one": lambda args: None}, [_schema("two")], ["one"])
    assert report["function_count"] == report["schema_count"] == 1
    assert not report["ok"]
    assert report["functions_missing_schemas"] == ["one"]
    assert report["schemas_missing_functions"] == ["two"]


def test_inventory_rejects_duplicates_noncallables_malformed_and_typed_drift():
    report = inventory.registry_alignment(
        {"one": None}, [_schema("one"), _schema("one"), None, {"function": {}}], ["ghost"],
    )
    assert not report["ok"]
    assert report["duplicate_schema_names"] == ["one"]
    assert report["noncallable_functions"] == ["one"]
    assert report["malformed_schema_indexes"] == [2, 3]
    assert report["typed_names_missing_functions"] == ["ghost"]


def test_static_reference_heuristic_excludes_registry_and_matches_complete_names(tmp_path):
    core = tmp_path / "src" / "hacking_agent" / "core"
    core.mkdir(parents=True)
    (core / "tools.py").write_text('registry = {"one": "two"}', encoding="utf-8")
    (core / "schemas.py").write_text('names = ["one", "two"]', encoding="utf-8")
    (core / "consumer.py").write_text(
        'tool = "one and prefix_two_suffix"\nclient.one()\n# two is a comment\n', encoding="utf-8",
    )
    (core / "broken.py").write_text("def broken(", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_sample.py").write_text('fake("two")\n', encoding="utf-8")
    refs, skipped = inventory.static_references(tmp_path, ["one", "two"])
    assert refs["one"]["source"] == [{"file": "src/hacking_agent/core/consumer.py", "lines": [1, 2]}]
    assert refs["two"]["source"] == []
    assert refs["two"]["tests"] == [{"file": "tests/test_sample.py", "lines": [1]}]
    assert skipped == ["src/hacking_agent/core/broken.py"]


def test_observed_usage_counts_failed_results_once_per_file_and_reports_bad_input(tmp_path):
    path = tmp_path / "events.jsonl"
    records = [
        {"type": "tool_result", "payload": {"tool": "one", "failure_reason": "timeout", "secret": "never_export"}},
        {"type": "tool_result", "payload": {"tool": "one"}},
        {"type": "tool_result", "payload": {"tool": "unknown_tool"}},
        {"type": "tool_result", "payload": []},
        {"type": "tool_result", "payload": {"tool": "Authorization: Bearer never_export"}},
        {"type": "status", "payload": {}},
        [],
    ]
    path.write_text("\n".join(json.dumps(record) for record in records) + "\ninvalid JSON\n", encoding="utf-8")
    report = inventory.observed_usage([path, path], ["one", "two"])
    assert report["files_analyzed"] == 1
    assert report["counts"] == {"one": 2}
    assert report["unknown_tool_counts"] == {"unknown_tool": 1}
    assert report["malformed_records"] == 4
    assert report["ignored_non_tool_records"] == 1
    assert report["observed_tool_fraction"] == 0.5
    assert "never_export" not in json.dumps(report)


def test_no_runtime_logs_means_unmeasured_instead_of_zero_usage():
    assert inventory.observed_usage([], ["one"])["observed_tool_fraction"] is None


def test_real_inventory_is_aligned_without_executing_registered_functions(monkeypatch):
    from hacking_agent.core import tools

    def forbidden(_args):
        pytest.fail("Inventory must not execute registered tools")

    monkeypatch.setattr(tools, "TOOL_FUNCTIONS", {name: forbidden for name in tools.TOOL_FUNCTIONS})
    report = inventory.build_inventory()
    assert report["alignment"]["ok"]
    assert not report["static_summary"]["unparsed_python_files"]
    assert len(report["tools"]) == len(tools.TOOL_FUNCTIONS)
    assert all(tool["observed_tool_results"] is None for tool in report["tools"])


def test_inventory_check_fails_on_registry_drift(monkeypatch, capsys):
    monkeypatch.setattr(inventory, "build_inventory", lambda **_: {
        "alignment": {"ok": False}, "static_summary": {"unparsed_python_files": []},
        "observed_usage": {"malformed_records": 0},
    })
    assert inventory.main(["--check"]) == 1
    assert not json.loads(capsys.readouterr().out)["alignment"]["ok"]


def _decision(value):
    return SimpleNamespace(reportable=value, reason_code="fixture")


def test_confusion_matrix_and_metric_denominators_include_both_error_directions():
    cases = [
        metrics.PolicyFixture("tp", True, True),
        metrics.PolicyFixture("fp", False, True),
        metrics.PolicyFixture("tn", False, False),
        metrics.PolicyFixture("fn", True, False),
    ]
    report = metrics.score_fixtures(cases, _decision)
    assert report["confusion_matrix"] == {
        "true_positive": 1, "false_positive": 1, "true_negative": 1, "false_negative": 1,
    }
    assert report["expected_positive_count"] == report["expected_negative_count"] == 2
    assert report["evaluated_count"] == 4
    for metric in report["metrics"].values():
        assert metric == {"numerator": 1, "denominator": 2, "value": 0.5}
    assert not report["passed"]


def test_undefined_metrics_are_null_and_empty_corpus_cannot_pass():
    report = metrics.score_fixtures([], _decision)
    assert not report["passed"]
    assert all(metric == {"numerator": 0, "denominator": 0, "value": None}
               for metric in report["metrics"].values())


def test_evaluator_errors_do_not_masquerade_as_correct_rejections():
    def fail(_finding):
        raise RuntimeError("fixture exception")

    report = metrics.score_fixtures([metrics.PolicyFixture("negative", False, {})], fail)
    assert not report["passed"]
    assert report["evaluation_errors"] == 1
    assert report["evaluated_count"] == 0
    assert report["confusion_matrix"]["true_negative"] == 0
    assert report["results"][0]["actual_reportable"] is None


def test_duplicate_fixture_ids_and_nonboolean_labels_are_rejected():
    case = metrics.PolicyFixture("repeated", False, {})
    with pytest.raises(ValueError, match="unique"):
        metrics.score_fixtures([case, case])
    with pytest.raises(ValueError, match="booleans"):
        metrics.score_fixtures([metrics.PolicyFixture("bad_label", "false", {})])


def test_builtin_stored_evidence_corpus_passes_and_has_positive_and_negative_cases():
    report = metrics.score_fixtures(metrics.policy_fixtures())
    assert report["passed"], report["results"]
    assert report["expected_positive_count"] >= 1
    assert report["expected_negative_count"] >= 10
    assert report["confusion_matrix"]["false_positive"] == 0
    assert report["confusion_matrix"]["false_negative"] == 0
    assert report["metrics"]["false_positive_rate"]["denominator"] == report["expected_negative_count"]


def test_benchmark_check_fails_on_mismatched_fixture(monkeypatch, capsys):
    monkeypatch.setattr(metrics, "policy_fixtures", lambda: [metrics.PolicyFixture("bad_claim", True, {})])
    assert metrics.main(["--check"]) == 1
    assert not json.loads(capsys.readouterr().out)["passed"]
