"""FastAPI control plane for the run harness.

Bound to 127.0.0.1 and gated by a shared token (offensive tooling must not be an
open local endpoint). Serves the single-page console + a small REST API, and
streams a run's events over SSE by tailing its events.jsonl. It does not run any
agent logic itself — it validates authorization, persists the request, and hands
off to the JobManager (subprocess per run).
"""
from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import subprocess
import time
from contextlib import asynccontextmanager
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterator, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)

from hacking_agent.harness.jobs import JobManager
from hacking_agent.harness.models import RunRequest
from hacking_agent.harness.store import RunPathError, RunStore
from hacking_agent.core.finding_validation import REPORTABILITY_SCHEMA_VERSION
from hacking_agent.harness.submission import (
    UnreportableFindingError,
    build_submission_markdown,
    iter_report_findings,
    render_stored_report_markdown,
    report_meta,
    sanitize_report_json,
)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _build_revision() -> str:
    configured = os.getenv("REYNARD_BUILD_REVISION", "").strip()
    if configured:
        return configured[:80]
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=Path(__file__).resolve().parents[3],
            check=True,
            capture_output=True,
            text=True,
            timeout=1,
        )
        return completed.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _ui_fingerprint() -> str:
    """Fingerprint the complete console release, including independent assets."""
    digest = hashlib.sha256()
    try:
        paths = [("index.html", INDEX_HTML)] + [
            (name, UI_DIR / name) for name in sorted(CONSOLE_ASSETS)
        ]
        for name, path in paths:
            content = path.read_bytes()
            digest.update(name.encode("utf-8") + b"\0")
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
        return digest.hexdigest()[:16]
    except OSError:
        return "missing"


def _nonce_console_script(html: str, nonce: str) -> str:
    """Authorize only the known local script, preserving the HTML template.

    Parse attributes rather than treating data-src or text inside an attribute
    as a script destination. Inline scripts and other sources remain blocked.
    """
    offsets = [0] + [match.end() for match in re.finditer("\n", html)]
    insertions: list[int] = []

    class ConsoleScriptParser(HTMLParser):
        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            sources = [value for key, value in attrs if key == "src"]
            if (tag != "script" or sources != ["/assets/console.js"]
                    or any(key == "nonce" for key, _ in attrs)):
                return
            raw = self.get_starttag_text() or ""
            if not raw or raw.endswith("/>"):
                return
            line, column = self.getpos()
            insertions.append(offsets[line - 1] + column + len(raw) - 1)

    parser = ConsoleScriptParser()
    parser.feed(html)
    parser.close()
    for offset in reversed(insertions):
        html = html[:offset] + f' nonce="{nonce}"' + html[offset:]
    return html


def _read_report_json(store: RunStore, run_id: str) -> dict[str, Any]:
    _, json_path = store.report_paths(run_id)
    if not json_path.exists():
        return {}
    try:
        return json.loads(json_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _collect_findings(store: RunStore) -> list[dict[str, Any]]:
    """Flatten every run's findings into copy-paste submission records."""
    out: list[dict[str, Any]] = []
    for rec in store.list(limit=500):
        rj = _read_report_json(store, rec.id)
        if not rj:
            continue
        for idx, f in enumerate(iter_report_findings(
            rj,
            expected_run_id=rec.id,
        )):
            try:
                submission = build_submission_markdown(f)
            except (UnreportableFindingError, ValueError, TypeError):
                continue
            out.append({
                "finding_id": f"{rec.id}:{idx}",
                "run_id": rec.id,
                "created_at": rec.created_at,
                "target": f.get("target", ""),
                "title": f.get("title", ""),
                "vuln_type": f.get("vuln_type", ""),
                "severity": (f.get("severity") or "medium").lower(),
                "cwe": f.get("cwe", ""),
                "cvss_score": f.get("cvss_score", 0),
                "cvss_vector": f.get("cvss_vector", ""),
                "endpoint": f.get("endpoint", ""),
                "parameter": f.get("parameter", ""),
                "verification_status": "verified",
                "verified": True,
                "submission": submission,
            })
    out.sort(key=lambda r: (_SEVERITY_RANK.get(r["severity"], 5),
                            -float(r.get("cvss_score") or 0)))
    return out


def _suppressed_count(store: RunStore) -> int:
    total = 0
    for rec in store.list(limit=500):
        safe = sanitize_report_json(
            _read_report_json(store, rec.id),
            expected_run_id=rec.id,
        )
        total += max(0, int(safe.get("suppressed_count", 0) or 0))
    return total


UI_DIR = Path(__file__).parent / "ui"
INDEX_HTML = UI_DIR / "index.html"
CONSOLE_ASSETS = {
    "console.css": "text/css",
    "console.js": "text/javascript",
    "geist-latin.woff2": "font/woff2",
}


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
                    if not isinstance(ev, dict) or pos <= sent:
                        continue
                    # Workers each restart their event counters; the durable
                    # file cursor stays unique across every target subprocess.
                    ev["source_event_id"] = ev.get("id")
                    ev["id"] = pos
                    sent = pos
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
    token = (token if token is not None else os.getenv("REYNARD_HARNESS_TOKEN")) or secrets.token_urlsafe(32)
    session_token = secrets.token_urlsafe(32)
    jobs = jobs or JobManager(store, max_concurrency=int(
        os.getenv("REYNARD_HARNESS_MAX_CONCURRENCY", "1") or "1"))

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        jobs.shutdown()

    app = FastAPI(title="Reynard Run Harness", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.store = store
    app.state.jobs = jobs
    app.state.token = token
    app.state.revision = _build_revision()
    app.state.ui_fingerprint = _ui_fingerprint()

    def _check(supplied: str) -> None:
        if not secrets.compare_digest(supplied.encode(), token.encode()):
            raise HTTPException(status_code=401, detail="invalid or missing token")

    def require_token(request: Request) -> None:
        cookie = request.cookies.get("reynard_session", "")
        if cookie and secrets.compare_digest(cookie.encode(), session_token.encode()):
            return
        _check(request.headers.get("x-harness-token", ""))

    @app.exception_handler(RunPathError)
    async def invalid_run_path(_request: Request, _exc: RunPathError) -> JSONResponse:
        return JSONResponse({"detail": "invalid run identifier"}, status_code=400)

    @app.middleware("http")
    async def local_boundary(request: Request, call_next: Any) -> Any:
        # Host checking prevents browser DNS rebinding; Origin checking prevents
        # another local web app from using an operator's session cookie.
        if request.url.hostname not in {"127.0.0.1", "localhost", "::1"}:
            return JSONResponse({"detail": "loopback Host required"}, status_code=400)
        origin = request.headers.get("origin")
        if origin is not None and origin != str(request.base_url).rstrip("/"):
            return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "cross-site request refused"}, status_code=403)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 1048576:
                return JSONResponse({"detail": "request body exceeds 1 MiB"}, status_code=413)
        request._body = bytes(body)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    # ---- UI ------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        if not INDEX_HTML.exists():
            return HTMLResponse(
                "<h1>Reynard harness</h1><p>UI missing.</p>",
                headers={
                    "Cache-Control": "no-store, max-age=0",
                    "Pragma": "no-cache",
                    "X-Reynard-Revision": app.state.revision,
                    "X-Reynard-UI-SHA256": app.state.ui_fingerprint,
                },
            )
        html = INDEX_HTML.read_text(encoding="utf-8")
        nonce = secrets.token_urlsafe(24)
        html = _nonce_console_script(html, nonce)
        return HTMLResponse(html, headers={"Content-Security-Policy": (
            f"default-src 'self'; script-src 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        ), "Pragma": "no-cache",
            "X-Reynard-Revision": app.state.revision,
            "X-Reynard-UI-SHA256": app.state.ui_fingerprint,
        })

    @app.get("/assets/{asset_name:path}")
    def console_asset(asset_name: str) -> Response:
        # Public, secret-free bootstrap files only. Never mount the package,
        # report store, or an arbitrary user-provided filesystem path.
        media_type = CONSOLE_ASSETS.get(asset_name)
        if media_type is None:
            raise HTTPException(status_code=404, detail="asset not found")
        asset_path = UI_DIR / asset_name
        try:
            if asset_path.is_symlink() or asset_path.resolve().parent != UI_DIR.resolve():
                raise HTTPException(status_code=404, detail="asset not found")
            content = asset_path.read_bytes()
        except OSError:
            raise HTTPException(status_code=404, detail="asset not found")
        return Response(content, media_type=media_type, headers={
            "X-Reynard-UI-SHA256": app.state.ui_fingerprint,
        })

    @app.post("/api/session")
    def login(request: Request) -> JSONResponse:
        _check(request.headers.get("x-harness-token", ""))
        response = JSONResponse({"ok": True})
        response.set_cookie("reynard_session", session_token, httponly=True,
                            samesite="strict", secure=request.url.scheme == "https")
        return response

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "ok": True,
            "auth_required": bool(token),
            "revision": app.state.revision,
            "ui_sha256": app.state.ui_fingerprint,
            "reportability_policy_version": REPORTABILITY_SCHEMA_VERSION,
        }

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
                   _: None = Depends(require_token)) -> StreamingResponse:
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
        safe_json = sanitize_report_json(
            report_json,
            expected_run_id=run_id,
        )
        return {
            "markdown": render_stored_report_markdown(
                report_json,
                expected_run_id=run_id,
            ),
            "json": safe_json,
        }

    @app.get("/api/findings")
    def list_findings(_: None = Depends(require_token)) -> dict[str, Any]:
        items = _collect_findings(store)
        suppressed = _suppressed_count(store)
        return {
            "count": len(items),
            "confirmed_count": len(items),
            "suppressed_count": suppressed,
            "findings": items,
        }

    @app.get("/api/findings.md", response_class=PlainTextResponse)
    def findings_markdown(_: None = Depends(require_token)) -> PlainTextResponse:
        items = _collect_findings(store)
        suppressed = _suppressed_count(store)
        if not items:
            body = (
                "# Confirmed findings only\n\n"
                "No independently confirmed findings were found. No "
                "independently validated vulnerabilities met the strict "
                "evidence gate.\n\n"
                f"Report-candidate suppressions: {suppressed}. This is not a "
                "count of all hypotheses or reconnaissance observations.\n"
            )
        else:
            parts = [
                f"# Reynard confirmed findings — {len(items)} submission(s)\n\n"
                f"Report-candidate suppressions: {suppressed}.\n"
            ]
            parts += [it["submission"] for it in items]
            body = "\n\n---\n\n".join(parts)
        return PlainTextResponse(body, headers={
            "Content-Disposition": 'attachment; filename="reynard-findings.md"'})

    @app.get("/api/runs/{run_id}/report.md", response_class=PlainTextResponse)
    def download_report_md(run_id: str,
                           _: None = Depends(require_token)) -> PlainTextResponse:
        md_path, _j = store.report_paths(run_id)
        if not md_path.exists():
            raise HTTPException(status_code=404, detail="report not ready")
        report_json = _read_report_json(store, run_id)
        return PlainTextResponse(
            render_stored_report_markdown(
                report_json,
                expected_run_id=run_id,
            ),
            headers={"Content-Disposition":
                     f'attachment; filename="reynard-report-{run_id}.md"'})

    @app.get("/api/runs/{run_id}/log", response_class=PlainTextResponse)
    def run_log(run_id: str, _: None = Depends(require_token)) -> PlainTextResponse:
        """Tail the worker's stdout/stderr (the rich console output, including the
        live DeepSeek "Thinking…" stream). Returns the last ~256 KB as text."""
        if store.get(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        p = store.worker_log_path(run_id)
        if not p.exists():
            return PlainTextResponse("")
        try:
            data = p.read_bytes()[-262144:]
            return PlainTextResponse(data.decode("utf-8", errors="replace"))
        except Exception:
            return PlainTextResponse("")

    @app.get("/api/runs/{run_id}/evidence")
    def run_evidence(run_id: str, _: None = Depends(require_token)) -> Any:
        _md_path, json_path = store.report_paths(run_id)
        if not json_path.exists():
            raise HTTPException(status_code=404, detail="evidence not ready")
        try:
            return sanitize_report_json(
                json.loads(json_path.read_text(encoding="utf-8")),
                expected_run_id=run_id,
            )
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

    from hacking_agent.harness.envload import load_operator_env, llm_key_present

    loaded = load_operator_env()
    if loaded:
        print(f"[reynard-harness] loaded env from {loaded}")
    if not llm_key_present():
        print("[reynard-harness] WARNING: no LLM API key loaded. Runs will fail "
              "immediately. Put DEEPSEEK_API_KEY or LLM_DEFAULT_API_KEY in the "
              "repo .env and restart this process.")

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
        parser.error("the harness supports loopback binding only")

    app = create_app(token=token)
    print(f"[reynard-harness] console: http://{args.host}:{args.port}/")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
