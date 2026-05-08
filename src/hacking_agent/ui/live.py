"""Dependency-light live dashboard served over HTTP + Server-Sent Events."""
from __future__ import annotations

import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from hacking_agent.core.events import EventBus, get_event_bus


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Hacking Agent Live</title>
  <style>
    :root {
      --paper: #f5f1e8;
      --ink: #1d2320;
      --muted: #69736c;
      --line: #d7d0c2;
      --panel: #fffaf0;
      --green: #316b4f;
      --blue: #315f88;
      --red: #9a3e35;
      --amber: #956b2f;
      --violet: #6f568b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--paper);
      color: var(--ink);
      font: 14px/1.45 ui-sans-serif, "Segoe UI", system-ui, sans-serif;
      letter-spacing: 0;
    }
    header {
      display: grid;
      grid-template-columns: minmax(260px, 1fr) auto;
      gap: 16px;
      align-items: end;
      padding: 18px 22px 14px;
      border-bottom: 2px solid var(--ink);
      background: #eee5d6;
    }
    h1 { margin: 0; font-size: 24px; line-height: 1; font-weight: 800; }
    .sub { color: var(--muted); margin-top: 6px; }
    .status {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      justify-content: flex-end;
      align-items: center;
    }
    .pill {
      border: 1px solid var(--ink);
      padding: 5px 9px;
      background: var(--panel);
      font-weight: 700;
      min-height: 30px;
    }
    main {
      display: grid;
      grid-template-columns: minmax(280px, .95fr) minmax(360px, 1.45fr) minmax(260px, .8fr);
      min-height: calc(100vh - 82px);
    }
    section {
      border-right: 1px solid var(--line);
      min-width: 0;
      display: flex;
      flex-direction: column;
    }
    section:last-child { border-right: 0; }
    .section-head {
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      background: color-mix(in srgb, var(--panel) 70%, var(--paper));
      font-weight: 800;
      text-transform: uppercase;
      font-size: 12px;
    }
    .stream, .timeline, .side {
      overflow: auto;
      padding: 12px;
      flex: 1;
    }
    .reasoning {
      white-space: pre-wrap;
      font-family: "Cascadia Mono", Consolas, monospace;
      font-size: 12px;
      background: var(--ink);
      color: #efe9db;
      padding: 12px;
      min-height: 100%;
      border-left: 6px solid var(--amber);
    }
    .event {
      display: grid;
      grid-template-columns: 82px 1fr;
      gap: 10px;
      padding: 11px 0;
      border-bottom: 1px solid var(--line);
    }
    .time { color: var(--muted); font-size: 12px; font-family: "Cascadia Mono", Consolas, monospace; }
    .type { font-weight: 800; }
    .event.tool_start .type { color: var(--blue); }
    .event.tool_result .type { color: var(--green); }
    .event.tool_blocked .type, .event.error .type { color: var(--red); }
    .event.web_search .type, .event.web_fetch .type { color: var(--violet); }
    .event.agent_start .type { color: var(--amber); }
    .event.llm_start .type, .event.llm_end .type { color: var(--amber); }
    .payload {
      margin-top: 4px;
      color: var(--muted);
      overflow-wrap: anywhere;
      font-family: "Cascadia Mono", Consolas, monospace;
      font-size: 12px;
    }
    .metric {
      border-bottom: 1px solid var(--line);
      padding: 10px 0;
      display: grid;
      gap: 3px;
    }
    .metric strong { font-size: 20px; }
    .metric span { color: var(--muted); font-size: 12px; text-transform: uppercase; font-weight: 800; }
    .tool-row, .fact-row {
      padding: 8px 0;
      border-bottom: 1px solid var(--line);
      overflow-wrap: anywhere;
    }
    .tool-row b, .fact-row b { display: block; }
    .empty { color: var(--muted); padding: 16px 0; }
    @media (max-width: 980px) {
      main { grid-template-columns: 1fr; }
      section { min-height: 45vh; border-right: 0; border-bottom: 1px solid var(--line); }
      header { grid-template-columns: 1fr; }
      .status { justify-content: flex-start; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Hacking Agent Live</h1>
      <div class="sub" id="target">Waiting for session...</div>
    </div>
    <div class="status">
      <div class="pill" id="conn">connecting</div>
      <div class="pill" id="agent">agent: idle</div>
      <div class="pill" id="events">0 events</div>
    </div>
  </header>
  <main>
    <section>
      <div class="section-head"><span>Reasoning Stream</span><span id="reasoningMode">trace</span></div>
      <div class="stream"><div id="reasoning" class="reasoning"></div></div>
    </section>
    <section>
      <div class="section-head"><span>Execution Timeline</span><span id="lastEvent">idle</span></div>
      <div id="timeline" class="timeline"><div class="empty">Events will appear as the agent runs.</div></div>
    </section>
    <section>
      <div class="section-head"><span>Run State</span><span id="state">boot</span></div>
      <div class="side">
        <div class="metric"><span>Tool Calls</span><strong id="toolCount">0</strong></div>
        <div class="metric"><span>Searches</span><strong id="searchCount">0</strong></div>
        <div class="metric"><span>Findings</span><strong id="findingCount">0</strong></div>
        <h3>Tools</h3>
        <div id="tools"><div class="empty">No tool calls yet.</div></div>
        <h3>Facts</h3>
        <div id="facts"><div class="empty">No facts yet.</div></div>
      </div>
    </section>
  </main>
  <script>
    const state = { events: 0, tools: 0, searches: 0, findings: 0, toolCounts: new Map(), facts: new Map() };
    const el = (id) => document.getElementById(id);
    const timeline = el("timeline");
    const reasoning = el("reasoning");
    const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], {hour12:false});
    const brief = (payload) => {
      if (!payload) return "";
      const value = payload.summary || payload.reasoning || payload.message || payload.text || payload.query ||
        payload.url || payload.tool || payload.agent || payload.state || JSON.stringify(payload);
      return String(value).slice(0, 260);
    };
    const addLine = (event) => {
      if (timeline.querySelector(".empty")) timeline.innerHTML = "";
      const div = document.createElement("div");
      div.className = `event ${event.type}`;
      div.innerHTML = `<div class="time">${fmtTime(event.ts)}</div><div><div class="type">${event.type}</div><div class="payload"></div></div>`;
      div.querySelector(".payload").textContent = brief(event.payload);
      timeline.prepend(div);
      while (timeline.children.length > 160) timeline.removeChild(timeline.lastChild);
    };
    const renderSide = () => {
      el("events").textContent = `${state.events} events`;
      el("toolCount").textContent = state.tools;
      el("searchCount").textContent = state.searches;
      el("findingCount").textContent = state.findings;
      const tools = el("tools");
      tools.innerHTML = state.toolCounts.size ? "" : `<div class="empty">No tool calls yet.</div>`;
      [...state.toolCounts.entries()].sort((a,b)=>b[1]-a[1]).forEach(([name,count]) => {
        const row = document.createElement("div");
        row.className = "tool-row";
        row.innerHTML = `<b></b><span>${count} call${count === 1 ? "" : "s"}</span>`;
        row.querySelector("b").textContent = name;
        tools.appendChild(row);
      });
      const facts = el("facts");
      facts.innerHTML = state.facts.size ? "" : `<div class="empty">No facts yet.</div>`;
      [...state.facts.entries()].slice(-30).reverse().forEach(([key,val]) => {
        const row = document.createElement("div");
        row.className = "fact-row";
        row.innerHTML = `<b></b><span></span>`;
        row.querySelector("b").textContent = key;
        row.querySelector("span").textContent = String(val).slice(0, 180);
        facts.appendChild(row);
      });
    };
    const handle = (event) => {
      state.events++;
      el("lastEvent").textContent = event.type;
      if (event.payload?.target) el("target").textContent = event.payload.target;
      if (event.payload?.state) el("state").textContent = event.payload.state;
      if (event.type === "session_end") el("state").textContent = event.payload?.success ? "done" : "ended";
      if (event.payload?.agent) el("agent").textContent = `agent: ${event.payload.agent}`;
      if (event.type === "reasoning_delta") {
        reasoning.textContent += event.payload.text || "";
        reasoning.scrollTop = reasoning.scrollHeight;
        return renderSide();
      }
      if (event.type === "reasoning_note" && event.payload?.append_to_stream !== false) {
        reasoning.textContent += `\n[${fmtTime(event.ts)}] ${event.payload.text || event.payload.message || ""}\n`;
        reasoning.scrollTop = reasoning.scrollHeight;
      }
      if (event.type === "tool_start") {
        state.tools++;
        const name = event.payload.tool || "tool";
        state.toolCounts.set(name, (state.toolCounts.get(name) || 0) + 1);
      }
      if (event.type === "web_search" && event.payload?.stage !== "start") state.searches++;
      if (event.type === "memory_fact") state.facts.set(event.payload.key, event.payload.value);
      if (event.type === "finding") state.findings++;
      addLine(event);
      renderSide();
    };
    const source = new EventSource("/events");
    source.onopen = () => el("conn").textContent = "live";
    source.onerror = () => el("conn").textContent = "reconnecting";
    source.onmessage = (msg) => handle(JSON.parse(msg.data));
    ["session_start","session_end","agent_start","agent_result","llm_start","llm_end","llm_validation_error","tool_start","tool_result","tool_blocked","web_search","web_fetch","memory_fact","finding","state","error","reasoning_note","reasoning_delta"].forEach(type => {
      source.addEventListener(type, (msg) => handle(JSON.parse(msg.data)));
    });
  </script>
</body>
</html>
"""


class DashboardServer:
    def __init__(self, host: str, port: int, bus: EventBus | None = None):
        self.host = host
        self.port = port
        self.bus = bus or get_event_bus()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "DashboardServer":
        bus = self.bus

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def _send(self, status: int, body: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path == "/":
                    self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")
                    return
                if parsed.path == "/snapshot":
                    self._send(
                        200,
                        json.dumps(bus.snapshot()).encode("utf-8"),
                        "application/json; charset=utf-8",
                    )
                    return
                if parsed.path == "/events":
                    self._events(parsed.query)
                    return
                self._send(404, b"not found", "text/plain; charset=utf-8")

            def _events(self, query: str) -> None:
                params = parse_qs(query)
                last_id = int(
                    params.get("last_id", [self.headers.get("Last-Event-ID", "0")])[0]
                    or "0"
                )
                q = bus.subscribe(last_id)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                try:
                    while True:
                        try:
                            event = q.get(timeout=15)
                            self.wfile.write(event.to_sse())
                        except queue.Empty:
                            self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    bus.unsubscribe(q)

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = int(self._httpd.server_address[1])
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


def start_dashboard(host: str = "127.0.0.1", port: int = 8765) -> DashboardServer:
    last_error: OSError | None = None
    for candidate in [port, *range(port + 1, port + 20)]:
        try:
            return DashboardServer(host, candidate).start()
        except OSError as exc:
            last_error = exc
            if getattr(exc, "errno", None) not in (98, 10048):
                raise
    raise OSError(f"Could not start live dashboard near port {port}: {last_error}")
