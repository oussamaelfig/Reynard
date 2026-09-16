"""FastAPI control plane: token gate, authorization refusal, runs, SSE, report."""
from __future__ import annotations

import json
import sys
import time
from copy import deepcopy

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from hacking_agent.agents.reporter import finding_to_report_dict  # noqa: E402
from hacking_agent.harness.jobs import JobManager  # noqa: E402
from hacking_agent.harness.models import RunRequest, RunStatus  # noqa: E402
from hacking_agent.harness.server import create_app  # noqa: E402
from hacking_agent.harness.store import RunStore  # noqa: E402
from test_finding_validation import finding_for, valid_bundle  # noqa: E402

TOKEN = "secret-token"
AUTH = {"x-harness-token": TOKEN}

_STRICT_FINDING = finding_to_report_dict(
    finding_for(valid_bundle(), title="SQL injection via `id`")
)
_STRICT_REPORT = {
    "engagement_name": "worker-test",
    "targets": ["https://x/"],
    "target_count": 1,
    "finding_count": 1,
    "verified_count": 1,
    "confirmed_count": 1,
    "suppressed_count": 0,
    "targets_assessed": [{
        "target": "https://x/",
        "verdict": "assessed",
        "findings": [_STRICT_FINDING],
    }],
}

# Fake worker: emits events, a strict report, and result.json, then exits 0.
_WORKER = (
    "import sys,json,pathlib;p=pathlib.Path(sys.argv[1]);"
    "(p/'events.jsonl').write_text("
    "json.dumps({'id':1,'type':'run_start','payload':{},'ts':1})+chr(10)+"
    "json.dumps({'id':2,'type':'finding','payload':{'summary':'sqli'},'ts':2})+chr(10));"
    "(p/'report.md').write_text('# Report\\n\\n## Findings\\n- SQLi in id');"
    f"(p/'report.json').write_text({json.dumps(json.dumps(_STRICT_REPORT))});"
    "(p/'result.json').write_text(json.dumps({'findings_count':1,'verified_count':1}))"
)


def _client(tmp_path, worker=_WORKER):
    store = RunStore(root=tmp_path)
    cmd = (lambda rd: [sys.executable, "-c", worker, rd])
    jobs = JobManager(store, worker_cmd=cmd)
    app = create_app(store=store, jobs=jobs, token=TOKEN)
    return store, TestClient(app)


def _wait_status(client, run_id, timeout=20.0):
    end = time.time() + timeout
    while time.time() < end:
        rec = client.get(f"/api/runs/{run_id}", headers=AUTH).json()
        if rec["status"] in ("completed", "failed", "cancelled"):
            return rec
        time.sleep(0.05)
    return client.get(f"/api/runs/{run_id}", headers=AUTH).json()


def test_health_is_public(tmp_path):
    _, c = _client(tmp_path)
    r = c.get("/api/health")
    assert r.status_code == 200 and r.json()["auth_required"] is True


def test_token_gate(tmp_path):
    _, c = _client(tmp_path)
    assert c.get("/api/runs").status_code == 401
    assert c.get("/api/runs", headers=AUTH).status_code == 200


def test_create_refuses_without_ack(tmp_path):
    _, c = _client(tmp_path)
    r = c.post("/api/runs", headers=AUTH,
               json={"authorized_domains": ["x.com"], "authorized": False})
    assert r.status_code == 400 and "authorized" in r.json()["detail"].lower()


def test_create_refuses_without_scope(tmp_path):
    _, c = _client(tmp_path)
    r = c.post("/api/runs", headers=AUTH, json={"authorized": True})
    assert r.status_code == 400 and "scope" in r.json()["detail"].lower()


def test_create_run_completes_report_and_evidence(tmp_path):
    _, c = _client(tmp_path)
    r = c.post("/api/runs", headers=AUTH,
               json={"authorized_domains": ["x.com"], "authorized": True,
                     "description": "find idor"})
    assert r.status_code == 201
    run_id = r.json()["run_id"]

    rec = _wait_status(c, run_id)
    assert rec["status"] == "completed" and rec["findings_count"] == 1

    rep = c.get(f"/api/runs/{run_id}/report", headers=AUTH).json()
    assert "SQL injection" in rep["markdown"] and rep["json"]["finding_count"] == 1

    ev = c.get(f"/api/runs/{run_id}/evidence", headers=AUTH).json()
    assert ev["finding_count"] == 1 and ev["target_count"] == 1


def test_log_endpoint_returns_worker_output(tmp_path):
    store, c = _client(tmp_path)
    rec = store.create(RunRequest(authorized_domains=["x.com"], authorized=True))
    store.worker_log_path(rec.id).write_text(
        "\U0001f914 Thinking...\nreasoning goes here\n", encoding="utf-8")
    r = c.get(f"/api/runs/{rec.id}/log", headers=AUTH)
    assert r.status_code == 200 and "Thinking" in r.text
    # token-gated
    assert c.get(f"/api/runs/{rec.id}/log").status_code == 401
    # empty (200) when no log yet
    rec2 = store.create(RunRequest(authorized_domains=["x.com"], authorized=True))
    r2 = c.get(f"/api/runs/{rec2.id}/log", headers=AUTH)
    assert r2.status_code == 200 and r2.text == ""
    # 404 for unknown run
    assert c.get("/api/runs/does-not-exist/log", headers=AUTH).status_code == 404


def test_report_404_before_ready(tmp_path):
    store, c = _client(tmp_path)
    rec = store.create(RunRequest(authorized_domains=["x.com"], authorized=True))
    assert c.get(f"/api/runs/{rec.id}/report", headers=AUTH).status_code == 404


def test_sse_stream_from_seeded_events(tmp_path):
    store, c = _client(tmp_path)
    rec = store.create(RunRequest(authorized_domains=["x.com"], authorized=True))
    store.events_path(rec.id).write_text(
        json.dumps({"id": 1, "type": "run_start", "payload": {}, "ts": 1}) + "\n" +
        json.dumps({"id": 2, "type": "finding", "payload": {"summary": "x"}, "ts": 2}) + "\n",
        encoding="utf-8")
    store.update(rec.id, status=RunStatus.completed)
    with c.stream("GET", f"/api/runs/{rec.id}/events?token={TOKEN}") as s:
        body = "".join(s.iter_text())
    assert body.count("data:") == 3           # 2 events + _done
    assert "run_start" in body and "finding" in body
    assert "_done" in body


def test_sse_requires_token(tmp_path):
    store, c = _client(tmp_path)
    rec = store.create(RunRequest(authorized_domains=["x.com"], authorized=True))
    assert c.get(f"/api/runs/{rec.id}/events?token=wrong").status_code == 401


def test_cancel_endpoint(tmp_path):
    store, c = _client(tmp_path, worker="import time;time.sleep(30)")
    r = c.post("/api/runs", headers=AUTH,
               json={"authorized_domains": ["x.com"], "authorized": True})
    run_id = r.json()["run_id"]
    # wait until running
    end = time.time() + 5
    while time.time() < end:
        if c.get(f"/api/runs/{run_id}", headers=AUTH).json()["status"] == "running":
            break
        time.sleep(0.05)
    assert c.post(f"/api/runs/{run_id}/cancel", headers=AUTH).json()["cancelled"] is True
    assert _wait_status(c, run_id)["status"] == "cancelled"


def _seed_report(store, run_id):
    md = "# Security Assessment Report\n\n## Findings\n\n- SQLi\n"
    js = dict(_STRICT_REPORT)
    js["engagement_name"] = "harness-run"
    md_path, json_path = store.report_paths(run_id)
    md_path.write_text(md, encoding="utf-8")
    json_path.write_text(json.dumps(js), encoding="utf-8")


def test_findings_endpoint_aggregates_submissions(tmp_path):
    store, c = _client(tmp_path)
    rec = store.create(RunRequest(authorized_domains=["x"], authorized=True))
    _seed_report(store, rec.id)
    r = c.get("/api/findings", headers=AUTH)
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    f = data["findings"][0]
    assert f["run_id"] == rec.id and f["severity"] == "high"
    assert f["finding_id"].startswith(rec.id)
    assert "## Steps to Reproduce" in f["submission"]
    assert "CWE-89" in f["submission"]
    # token gate
    assert c.get("/api/findings").status_code == 401


def test_findings_markdown_download(tmp_path):
    store, c = _client(tmp_path)
    rec = store.create(RunRequest(authorized_domains=["x"], authorized=True))
    _seed_report(store, rec.id)
    r = c.get("/api/findings.md", headers=AUTH)
    assert r.status_code == 200
    assert "attachment" in r.headers.get("content-disposition", "")
    assert "SQL injection" in r.text and "## Proof of Concept" in r.text


def test_every_report_api_and_export_suppresses_raw_candidate_details(tmp_path):
    store, c = _client(tmp_path)
    rec = store.create(RunRequest(authorized_domains=["x"], authorized=True))
    raw = deepcopy(_STRICT_REPORT)
    raw["targets_assessed"][0]["findings"].append({
        "title": "SUPPRESSED CUSTOMER SECRET",
        "description": "prose-only anomaly detail",
        "vuln_type": "SQL injection",
        "severity": "critical",
        "confidence": 1.0,
        "verified": True,
        "verification_status": "verified",
    })
    md_path, json_path = store.report_paths(rec.id)
    md_path.write_text(
        "# stale report\nSUPPRESSED CUSTOMER SECRET\nprose-only anomaly detail",
        encoding="utf-8",
    )
    json_path.write_text(json.dumps(raw), encoding="utf-8")

    responses = [
        c.get(f"/api/runs/{rec.id}/report", headers=AUTH),
        c.get(f"/api/runs/{rec.id}/report.md", headers=AUTH),
        c.get(f"/api/runs/{rec.id}/evidence", headers=AUTH),
        c.get("/api/findings", headers=AUTH),
        c.get("/api/findings.md", headers=AUTH),
    ]
    assert all(response.status_code == 200 for response in responses)
    for response in responses:
        assert "SUPPRESSED CUSTOMER SECRET" not in response.text
        assert "prose-only anomaly detail" not in response.text

    report = responses[0].json()
    assert report["json"]["confirmed_count"] == 1
    assert report["json"]["suppressed_count"] == 1
    aggregate = responses[3].json()
    assert aggregate["confirmed_count"] == aggregate["count"] == 1
    assert aggregate["suppressed_count"] == 1
    assert "Suppressed internal candidates: 1." in responses[4].text


def test_report_md_download(tmp_path):
    store, c = _client(tmp_path)
    rec = store.create(RunRequest(authorized_domains=["x"], authorized=True))
    assert c.get(f"/api/runs/{rec.id}/report.md", headers=AUTH).status_code == 404
    _seed_report(store, rec.id)
    r = c.get(f"/api/runs/{rec.id}/report.md", headers=AUTH)
    assert r.status_code == 200
    assert "attachment" in r.headers.get("content-disposition", "")
    assert "Security Assessment Report" in r.text


def test_index_injects_token(tmp_path):
    _, c = _client(tmp_path)
    html = c.get("/").text
    assert 'const TOKEN = "secret-token"' in html
    assert "__HARNESS_TOKEN__" not in html
    assert "Launch run" in html
    assert "confirmed ·" in html and "suppressed" in html
