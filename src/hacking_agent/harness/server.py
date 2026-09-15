"""FastAPI control plane for the run harness.

Bound to 127.0.0.1 and gated by a shared token (offensive tooling must not be an
open local endpoint). Serves the single-page console + a small REST API, and
streams a run's events over SSE by tailing its events.jsonl. It does not run any
agent logic itself — it validates authorization, persists the request, and hands
off to the JobManager (subprocess per run).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Iterator, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    StreamingResponse,
)

from hacking_agent.harness.jobs import JobManager
from hacking_agent.harness.models import RunRequest
from hacking_agent.harness.store import RunStore

UI_DIR = Path(__file__).parent / "ui"
INDEX_HTML = UI_DIR / "index.html"


def _sse(event: dict[str, Any]) -> str:
    # No `event:` line: every frame arrives on the client's single onmessage
    # handler; the event kind travels inside the JSON payload as `type`.
    ev_id = event.get("id", "")
    data = json.dumps(event, ensure_ascii=False, default=str)
    return f"id: {ev_id}\ndata: {data}\n\n"


def _tail_events(store: RunStore, run_id: str, last_id: int) -> Iterator[str]:
    """Yield SSE frames for a run: existing events (id>last_id) then live tail.

    The event sink writes complete, flushed JSON lines, so we advance by byte
    offset and de-dupe by the event ``id`` for reconnects (Last-Event-ID)."""
    path = store.events_path(run_id)
    pos = 0
    sent = last_id
    drain_passes = 0
    while True:
        if path.exists():
            with open(path, "r", encoding="utf-8") as fh:
                fh.seek(pos)
                while True:
                    line = fh.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        # Partial line: the worker is mid-write. Leave pos before
                        # it and re-read on the next pass once it's flushed.
                        break
                    pos = fh.tell()
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        ev = json.loads(stripped)
                    except Exception:
                        continue
                    if int(ev.get("id", 0)) <= sent:
                        continue
                    sent = int(ev.get("id", sent))
                    yield _sse(ev)
        rec = store.get(run_id)
        if rec is not None and rec.status.is_terminal:
            # Give the file one more drain pass, then close the stream.
            drain_passes += 1
            if drain_passes >= 2:
                yield ("data: " + json.dumps(
                    {"type": "_done", "status": rec.status.value}) + "\n\n")
                return
        time.sleep(0.5)
        yield ": keep-alive\n\n"


def create_app(store: Optional[RunStore] = None,
               jobs: Optional[JobManager] = None,
               token: Optional[str] = None) -> FastAPI:
    store = store or RunStore()
    token = token if token is not None else (os.getenv("REYNARD_HARNESS_TOKEN") or "")
    jobs = jobs or JobManager(store, max_concurrency=int(
        os.getenv("REYNARD_HARNESS_MAX_CONCURRENCY", "1") or "1"))

    app = FastAPI(title="Reynard Run Harness", docs_url=None, redoc_url=None)
    app.state.store = store
    app.state.jobs = jobs
    app.state.token = token

    def _check(supplied: str) -> None:
        if token and supplied != token:
            raise HTTPException(status_code=401, detail="invalid or missing token")

    def require_token(request: Request) -> None:
        _check(request.headers.get("x-harness-token", ""))

    # ---- UI ------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        if not INDEX_HTML.exists():
            return HTMLResponse("<h1>Reynard harness</h1><p>UI missing.</p>")
        html = INDEX_HTML.read_text(encoding="utf-8")
        # Inject the token so the localhost operator's browser can call the API.
        html = html.replace("__HARNESS_TOKEN__", token)
        return HTMLResponse(html)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "auth_required": bool(token)}

    # ---- runs ----------------------------------------------------------
    @app.post("/api/runs")
    def create_run(req: RunRequest, _: None = Depends(require_token)) -> JSONResponse:
        err = req.authorization_error()
        if err:
            raise HTTPException(status_code=400, detail=err)
        rec = store.create(req)
        jobs.submit(rec.id)
        return JSONResponse({"run_id": rec.id, "status": rec.status.value},
                            status_code=201)

    @app.get("/api/runs")
    def list_runs(_: None = Depends(require_token)) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in store.list()]

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str, _: None = Depends(require_token)) -> dict[str, Any]:
        rec = store.get(run_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="run not found")
        return rec.model_dump(mode="json")

    @app.get("/api/runs/{run_id}/events")
    def run_events(run_id: str, request: Request,
                   token_q: str = Query("", alias="token")) -> StreamingResponse:
        # EventSource can't set headers, so accept the token via query param too.
        _check(request.headers.get("x-harness-token", "") or token_q)
        if store.get(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        last_id = 0
        hdr = request.headers.get("last-event-id", "")
        if hdr.isdigit():
            last_id = int(hdr)
        return StreamingResponse(
            _tail_events(store, run_id, last_id),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/runs/{run_id}/report")
    def run_report(run_id: str, _: None = Depends(require_token)) -> dict[str, Any]:
        md_path, json_path = store.report_paths(run_id)
        if not md_path.exists():
            raise HTTPException(status_code=404, detail="report not ready")
        report_json: Any = {}
        if json_path.exists():
            try:
                report_json = json.loads(json_path.read_text(encoding="utf-8"))
            except Exception:
                report_json = {}
        return {"markdown": md_path.read_text(encoding="utf-8"),
                "json": report_json}

    @app.get("/api/runs/{run_id}/evidence")
    def run_evidence(run_id: str, _: None = Depends(require_token)) -> Any:
        _, json_path = store.report_paths(run_id)
        if not json_path.exists():
            raise HTTPException(status_code=404, detail="evidence not ready")
        try:
            return json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            raise HTTPException(status_code=500, detail="evidence unreadable")

    @app.post("/api/runs/{run_id}/cancel")
    def cancel_run(run_id: str, _: None = Depends(require_token)) -> dict[str, Any]:
        if store.get(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        return {"cancelled": jobs.cancel(run_id)}

    return app


def main(argv: Optional[list[str]] = None) -> int:
    """Console entry (``reynard-harness``): serve the app via uvicorn."""
    import argparse

    import uvicorn
    from dotenv import load_dotenv

    from hacking_agent.core.paths import ENV_FILE

    # Load .env like the other CLIs so the operator's LLM provider/model/key
    # (LLM_DEFAULT_*, DEEPSEEK_API_KEY, …) and REYNARD_HARNESS_* are available;
    # these are then inherited by each run's worker subprocess via the env.
    if ENV_FILE.exists():
        load_dotenv(ENV_FILE)

    parser = argparse.ArgumentParser(description="Reynard run harness console")
    parser.add_argument("--host", default=os.getenv("REYNARD_HARNESS_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int,
                        default=int(os.getenv("REYNARD_HARNESS_PORT", "8787")))
    args = parser.parse_args(argv)

    token = os.getenv("REYNARD_HARNESS_TOKEN") or ""
    if not token:
        import secrets
        token = secrets.token_urlsafe(24)
        os.environ["REYNARD_HARNESS_TOKEN"] = token
        print("[reynard-harness] No REYNARD_HARNESS_TOKEN set; generated one for "
              "this session:")
        print(f"    {token}")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[reynard-harness] WARNING: binding to {args.host} exposes an "
              "offensive-tooling control plane beyond localhost.")

    app = create_app(token=token)
    print(f"[reynard-harness] console: http://{args.host}:{args.port}/")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
