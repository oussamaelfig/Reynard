"""Loopback-only harness preview with synthetic data and no research workers.

Run from a checkout with the dev/harness dependencies installed. All run data,
signing keys and artifacts live in a temporary directory. The actual harness
authentication and reportability gates remain enabled. Creating or cancelling a
run only changes fixture state; no tool, model or assessment process is called.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Iterator, cast
from unittest.mock import patch

if TYPE_CHECKING:
    from hacking_agent.harness.jobs import JobManager

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "src", ROOT / "tests"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

PREVIEW_TOKEN = "reynard-local-ui-preview-only"
PREVIEW_HOST = "127.0.0.1"
SEED_IDS = {
    "running": "demo00000001",
    "completed": "demo00000002",
    "clean": "demo00000003",
    "failed": "demo00000004",
}
DEMO_TIME = datetime(2026, 9, 17, 0, 30, tzinfo=timezone.utc)


def _event(index: int, kind: str, **payload: Any) -> dict[str, Any]:
    return {
        "id": index, "type": kind,
        "ts": DEMO_TIME.timestamp() + index * 3,
        "payload": {"demo": True, **payload},
    }


def _write_events(store: Any, run_id: str, events: list[dict[str, Any]]) -> None:
    store.events_path(run_id).write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8",
    )


class PreviewJobs:
    """Fixture job sink: deliberately has no worker command or process launcher."""

    def __init__(self, store: Any):
        self.store = store
        self.submitted: list[str] = []
        self.closed = False

    def submit(self, run_id: str) -> None:
        from hacking_agent.harness.models import RunStatus

        self.submitted.append(run_id)
        self.store.take_auth_sessions(run_id)
        self.store.update(run_id, status=RunStatus.running)
        record = self.store.get(run_id)
        with self.store._lock:
            self.store._conn.execute(
                "UPDATE runs SET description=? WHERE id=?",
                (("[DEMO] " + (record.description if record else "Simulated run"))[:500], run_id),
            )
            self.store._conn.commit()
        self.store.worker_log_path(run_id).write_text(
            "[DEMO PREVIEW] Launch was simulated. No worker, model or network request was started.\n",
            encoding="utf-8",
        )
        request = self.store.load_request(run_id)
        _write_events(self.store, run_id, [
            _event(1, "run_start", targets=request.resolved_targets() if request else []),
            _event(2, "reasoning_note", agent="coordinator", text=(
                "DEMO PREVIEW: request accepted by the real authorization gate; "
                "execution is replaced by this local fixture. No scans are performed."
            )),
        ])

    def cancel(self, run_id: str) -> bool:
        from hacking_agent.harness.models import RunStatus

        record = self.store.get(run_id)
        if record is None or record.status.is_terminal:
            return False
        self.store.take_auth_sessions(run_id)
        self.store.update(run_id, status=RunStatus.cancelled)
        with self.store.events_path(run_id).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(_event(999, "run_end", findings=0,
                                          summary="DEMO preview cancelled; no worker existed.")) + "\n")
        return True

    def shutdown(self) -> None:
        self.closed = True


def _seed(store: Any) -> None:
    from hacking_agent.core.validation_provenance import attest_report
    from hacking_agent.harness.models import RunRequest, RunStatus
    from hacking_agent.harness.submission import render_stored_report_markdown
    from test_finding_validation import ENGAGEMENT_ID, finding_for, signed_report, valid_bundle

    records = [
        ("running", RunStatus.running, "[DEMO] Account API · controlled identity review"),
        ("completed", RunStatus.completed, "[DEMO] Catalog API · one independently confirmed fixture"),
        ("clean", RunStatus.completed, "[DEMO] Public application · no confirmed findings"),
        ("failed", RunStatus.failed, "[DEMO] Partner portal · interrupted fixture"),
    ]
    for offset, (key, status, description) in enumerate(records):
        run_id = SEED_IDS[key]
        request = RunRequest(
            targets=["https://app.example.test/"],
            authorized_domains=["app.example.test"],
            description=description, authorized=True,
            max_requests_per_second=2, max_total_requests=200,
        )
        with patch("hacking_agent.harness.store.uuid.uuid4", return_value=SimpleNamespace(hex=run_id)):
            record = store.create(request)
        assert record.id == run_id
        store.take_auth_sessions(run_id)
        store.update(run_id, status=status, error=(
            "DEMO: local fixture stopped after its mocked deadline. No worker was started."
            if status == RunStatus.failed else ""
        ))
        timestamp = (DEMO_TIME - timedelta(minutes=offset * 18)).isoformat()
        with store._lock:
            store._conn.execute("UPDATE runs SET created_at=?, updated_at=? WHERE id=?",
                                (timestamp, timestamp, run_id))
            store._conn.commit()

        events = [
            _event(1, "run_start", targets=request.targets),
            _event(2, "agent_start", agent="coordinator", phase="recon"),
            _event(3, "reasoning_note", agent="coordinator", text=(
                "DEMO: Reviewing the supplied request fixtures and declared scope. "
                "These records are synthetic; no requests are sent."
            )),
            _event(4, "tool_start", tool="http_request", args="GET /api/catalog — fixture only"),
            _event(5, "tool_result", tool="http_request", agent="recon", summary=(
                "DEMO response fixture: 200 OK · 1.8 KiB · two candidate parameters"
            ), result_length=1840),
            _event(6, "token_usage", prompt=4200, completion=960, total=5160,
                   estimated_cost_usd=0.012),
            _event(7, "agent_start", agent="validator", phase="validation"),
            _event(8, "reasoning_note", agent="validator", text=(
                "DEMO: Comparing two independently signed synthetic captures "
                "with a matched negative control. No finding is promoted from a model claim."
            )),
        ]
        if key in {"completed", "clean"}:
            finding = finding_for(valid_bundle(run_id=run_id),
                                  title="[DEMO] SQL query behavior confirmed by controlled replay")
            report = signed_report(finding, run_id=run_id, suppressed_count=3 if key == "completed" else 2)
            report.update(engagement_name="DEMO · Local UI fixture", client="Demo workspace",
                          tester="Synthetic fixture generator", generated_at=timestamp)
            if key == "clean":
                report.update(finding_count=0, verified_count=0, confirmed_count=0)
                report["targets_assessed"][0].update(findings=[], confirmed_count=0)
            report["report_authenticity"] = attest_report(
                report, run_id=run_id, engagement_id=ENGAGEMENT_ID,
                validator_instance_id="reporter:ui-preview",
            )
            markdown_path, json_path = store.report_paths(run_id)
            json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            markdown_path.write_text(render_stored_report_markdown(report, expected_run_id=run_id),
                                     encoding="utf-8")
            if key == "completed":
                events.append(_event(9, "finding", title=finding.title, severity="high"))
            events.append(_event(10, "run_end", findings=1 if key == "completed" else 0,
                                 summary="DEMO fixture complete"))
        elif key == "failed":
            events.append(_event(9, "error", message="DEMO fixture deadline reached; no worker ran."))
        _write_events(store, run_id, events)
        store.worker_log_path(run_id).write_text(
            "[DEMO PREVIEW] Synthetic activity only. No model, worker or security tool was invoked.\n"
            "00:30:03 Coordinator: scope accepted for app.example.test\n"
            "00:30:12 Recon: request fixture parsed; candidate observations recorded\n"
            "00:30:24 Validator: comparing signed fixture captures and matched control\n",
            encoding="utf-8",
        )


@contextmanager
def preview_app(*, empty: bool = False) -> Iterator[Any]:
    """Keep the isolated authority alive for as long as the ASGI app is used."""
    with tempfile.TemporaryDirectory(prefix="reynard-ui-preview-") as directory:
        root = Path(directory)
        environment = {
            "REYNARD_VALIDATION_STATE_DIR": str(root / "authority"),
            "REYNARD_VALIDATION_HMAC_KEY": "",
            "REYNARD_HOST_EXEC": "0",
            "REYNARD_EVENT_LOG": "",
            "REYNARD_BUILD_REVISION": "demo-local-preview",
        }
        with patch.dict(os.environ, environment):
            from hacking_agent.harness.server import create_app
            from hacking_agent.harness.store import RunStore

            # RunStore otherwise creates the repository's default log directory
            # even with an explicit root. The preview needs only its temporary store.
            with patch("hacking_agent.harness.store.ensure_runtime_dirs"):
                store = RunStore(root=root / "runs")
            jobs = PreviewJobs(store)
            try:
                if not empty:
                    _seed(store)
                # Fixture-only structural substitute for submit/cancel/shutdown;
                # never construct the production JobManager or its worker pool.
                app = create_app(store=store, jobs=cast("JobManager", jobs), token=PREVIEW_TOKEN)
                app.state.preview = True
                app.state.preview_root = root
                yield app
            finally:
                jobs.shutdown()
                store.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8891)
    parser.add_argument("--empty", action="store_true", help="Start with no runs or findings.")
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("preview port must be between 1024 and 65535")
    import uvicorn

    with preview_app(empty=args.empty) as app:
        print("[DEMO PREVIEW] Temporary synthetic data. Launch/cancel actions never run scans.", flush=True)
        print(f"Preview: http://{PREVIEW_HOST}:{args.port}/", flush=True)
        print(f"Preview-only login token: {PREVIEW_TOKEN}", flush=True)
        print("Press Ctrl+C to stop and remove the temporary fixture data.", flush=True)
        uvicorn.run(app, host=PREVIEW_HOST, port=args.port, log_level="warning",
                    timeout_graceful_shutdown=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
