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
  <title>Reynard Assessment Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg: oklch(97.5% 0.006 95);
      --bg-elev: oklch(99.2% 0.004 95);
      --bg-soft: oklch(95.2% 0.008 95);
      --ink: oklch(22% 0.02 250);
      --ink-soft: oklch(38% 0.018 250);
      --muted: oklch(52% 0.014 250);
      --line: oklch(88% 0.01 95);
      --line-strong: oklch(78% 0.012 95);
      --teal: oklch(48% 0.09 185);
      --teal-soft: oklch(94% 0.03 185);
      --amber: oklch(62% 0.12 75);
      --amber-soft: oklch(95% 0.04 85);
      --red: oklch(52% 0.15 25);
      --red-soft: oklch(95% 0.03 25);
      --green: oklch(48% 0.1 155);
      --green-soft: oklch(95% 0.035 155);
      --blue: oklch(48% 0.1 245);
      --blue-soft: oklch(95% 0.03 245);
      --shadow: 0 1px 0 oklch(22% 0.02 250 / 0.04), 0 12px 32px oklch(22% 0.02 250 / 0.05);
      --radius: 10px;
      --font: "DM Sans", "Segoe UI", sans-serif;
      --mono: "IBM Plex Mono", ui-monospace, monospace;
    }

    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      background:
        radial-gradient(1200px 500px at 8% -10%, oklch(94% 0.03 185 / 0.55), transparent 55%),
        radial-gradient(900px 420px at 100% 0%, oklch(96% 0.02 75 / 0.5), transparent 45%),
        var(--bg);
      color: var(--ink);
      font: 14px/1.45 var(--font);
      letter-spacing: -0.01em;
      -webkit-font-smoothing: antialiased;
    }

    .shell {
      min-height: 100%;
      display: grid;
      grid-template-rows: auto auto 1fr;
      gap: 14px;
      padding: 16px 18px 18px;
      max-width: 1680px;
      margin: 0 auto;
    }

    /* ── Top bar ── */
    .topbar {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 18px;
      align-items: center;
      padding: 14px 18px;
      background: var(--bg-elev);
      border: 1px solid var(--line);
      border-radius: calc(var(--radius) + 2px);
      box-shadow: var(--shadow);
      animation: rise 480ms cubic-bezier(0.16, 1, 0.3, 1) both;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
      min-width: 0;
    }
    .mark {
      width: 38px;
      height: 38px;
      border-radius: 9px;
      background:
        linear-gradient(145deg, oklch(52% 0.1 185), oklch(38% 0.08 210));
      display: grid;
      place-items: center;
      color: oklch(98% 0.01 185);
      font-weight: 700;
      font-size: 15px;
      letter-spacing: 0.04em;
      flex-shrink: 0;
    }
    .brand-copy { min-width: 0; }
    .brand-copy h1 {
      margin: 0;
      font-size: 17px;
      font-weight: 700;
      letter-spacing: -0.03em;
      line-height: 1.15;
    }
    .brand-copy .eyebrow {
      margin: 0 0 2px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--teal);
    }
    .target-line {
      margin-top: 4px;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: min(68vw, 720px);
    }
    .status-cluster {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      justify-content: flex-end;
      align-items: center;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      min-height: 32px;
      padding: 0 11px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: var(--bg-soft);
      color: var(--ink-soft);
      font-size: 12px;
      font-weight: 600;
      letter-spacing: -0.01em;
    }
    .chip .dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--muted);
      flex-shrink: 0;
    }
    .chip.live {
      background: var(--green-soft);
      border-color: color-mix(in oklch, var(--green) 28%, var(--line));
      color: var(--green);
    }
    .chip.live .dot {
      background: var(--green);
      box-shadow: 0 0 0 0 oklch(48% 0.1 155 / 0.45);
      animation: pulse 1.8s ease-out infinite;
    }
    .chip.warn {
      background: var(--amber-soft);
      border-color: color-mix(in oklch, var(--amber) 30%, var(--line));
      color: oklch(42% 0.1 75);
    }
    .chip.danger {
      background: var(--red-soft);
      border-color: color-mix(in oklch, var(--red) 28%, var(--line));
      color: var(--red);
    }
    .chip.accent {
      background: var(--teal-soft);
      border-color: color-mix(in oklch, var(--teal) 28%, var(--line));
      color: var(--teal);
    }

    /* ── KPI strip ── */
    .kpis {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 10px;
      animation: rise 560ms cubic-bezier(0.16, 1, 0.3, 1) 60ms both;
    }
    .kpi {
      background: var(--bg-elev);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 12px 14px 11px;
      min-height: 78px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 8px;
      box-shadow: 0 1px 0 oklch(22% 0.02 250 / 0.03);
    }
    .kpi .label {
      font-size: 11px;
      font-weight: 650;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--muted);
    }
    .kpi .value {
      font-size: 26px;
      font-weight: 700;
      letter-spacing: -0.04em;
      line-height: 1;
      font-variant-numeric: tabular-nums;
      color: var(--ink);
    }
    .kpi .hint {
      font-size: 11px;
      color: var(--muted);
      font-family: var(--mono);
    }
    .kpi.findings .value { color: var(--teal); }
    .kpi.phase .value {
      font-size: 15px;
      letter-spacing: -0.02em;
      text-transform: capitalize;
    }

    /* ── Workspace ── */
    .workspace {
      display: grid;
      grid-template-columns: minmax(320px, 1.15fr) minmax(280px, 0.9fr) minmax(300px, 1fr);
      gap: 12px;
      min-height: 0;
      animation: rise 640ms cubic-bezier(0.16, 1, 0.3, 1) 110ms both;
    }
    .panel {
      background: var(--bg-elev);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      min-height: 0;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .panel-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(180deg, var(--bg-elev), var(--bg-soft));
    }
    .panel-head h2 {
      margin: 0;
      font-size: 13px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .panel-head .meta {
      font-size: 11px;
      font-family: var(--mono);
      color: var(--muted);
      white-space: nowrap;
    }
    .panel-body {
      flex: 1;
      overflow: auto;
      min-height: 0;
    }

    /* Timeline */
    .timeline { padding: 6px 8px 12px; }
    .event {
      display: grid;
      grid-template-columns: 64px 10px 1fr;
      gap: 10px;
      padding: 11px 8px;
      border-bottom: 1px solid color-mix(in oklch, var(--line) 75%, transparent);
      transition: background 160ms ease;
    }
    .event:hover { background: var(--bg-soft); }
    .event .time {
      font-family: var(--mono);
      font-size: 11px;
      color: var(--muted);
      padding-top: 3px;
    }
    .event .rail {
      display: flex;
      justify-content: center;
      padding-top: 6px;
    }
    .event .rail span {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--line-strong);
      box-shadow: 0 0 0 3px var(--bg-soft);
    }
    .event.tool_start .rail span,
    .event.llm_start .rail span { background: var(--blue); }
    .event.tool_result .rail span,
    .event.llm_end .rail span { background: var(--green); }
    .event.tool_blocked .rail span,
    .event.error .rail span,
    .event.budget_exceeded .rail span { background: var(--red); }
    .event.finding .rail span { background: var(--teal); }
    .event.agent_start .rail span,
    .event.reasoning_note .rail span { background: var(--amber); }
    .event.web_search .rail span,
    .event.web_fetch .rail span { background: oklch(48% 0.12 300); }
    .event .type {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: var(--ink);
      text-transform: capitalize;
    }
    .event .payload {
      margin-top: 3px;
      color: var(--muted);
      font-size: 12px;
      font-family: var(--mono);
      line-height: 1.4;
      overflow-wrap: anywhere;
    }
    .sev {
      display: inline-flex;
      align-items: center;
      margin-left: 6px;
      padding: 1px 7px;
      border-radius: 999px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      vertical-align: 1px;
    }
    .sev.ok { background: var(--green-soft); color: var(--green); }
    .sev.warn { background: var(--amber-soft); color: oklch(42% 0.1 75); }
    .sev.crit { background: var(--red-soft); color: var(--red); }
    .sev.info { background: var(--blue-soft); color: var(--blue); }

    /* Findings */
    .findings { padding: 10px 12px 14px; display: grid; gap: 8px; }
    .finding {
      border: 1px solid var(--line);
      border-radius: 9px;
      padding: 11px 12px;
      background: var(--bg);
      display: grid;
      gap: 6px;
    }
    .finding.header-row {
      background: transparent;
      border: 0;
      padding: 0 2px 4px;
      color: var(--muted);
      font-size: 11px;
      font-weight: 650;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .finding .title {
      font-weight: 700;
      font-size: 13px;
      letter-spacing: -0.015em;
    }
    .finding .detail {
      color: var(--muted);
      font-size: 12px;
      font-family: var(--mono);
      overflow-wrap: anywhere;
    }
    .finding .tags {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    /* Intelligence / reasoning */
    .intel {
      display: grid;
      grid-template-rows: 1fr auto;
      min-height: 0;
    }
    .reasoning {
      margin: 0;
      padding: 14px 14px 18px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.55;
      color: oklch(93% 0.01 95);
      background:
        linear-gradient(180deg, oklch(24% 0.02 250), oklch(20% 0.018 250));
      min-height: 220px;
      max-height: none;
      overflow: auto;
    }
    .reasoning:empty::before {
      content: "Agent reasoning will stream here as specialists think and act.";
      color: oklch(70% 0.02 250);
    }
    .side-block {
      border-top: 1px solid var(--line);
      background: var(--bg-elev);
      max-height: 42%;
      overflow: auto;
      padding: 10px 12px 14px;
    }
    .side-block h3 {
      margin: 0 0 8px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--muted);
    }
    .tool-row, .fact-row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: baseline;
      padding: 7px 0;
      border-bottom: 1px solid color-mix(in oklch, var(--line) 70%, transparent);
      font-size: 12px;
    }
    .tool-row b, .fact-row b {
      font-weight: 650;
      overflow-wrap: anywhere;
      color: var(--ink);
    }
    .tool-row span, .fact-row span {
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      text-align: right;
    }
    .fact-row {
      grid-template-columns: 1fr;
      gap: 2px;
    }
    .fact-row span {
      text-align: left;
      overflow-wrap: anywhere;
    }

    .empty {
      color: var(--muted);
      padding: 22px 10px;
      font-size: 13px;
      text-align: left;
    }

    .filters {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .filter-btn {
      appearance: none;
      border: 1px solid var(--line);
      background: var(--bg);
      color: var(--muted);
      font: inherit;
      font-size: 11px;
      font-weight: 650;
      padding: 4px 9px;
      border-radius: 999px;
      cursor: pointer;
      transition: background 140ms ease, color 140ms ease, border-color 140ms ease;
    }
    .filter-btn:hover { color: var(--ink); border-color: var(--line-strong); }
    .filter-btn.active {
      background: var(--teal-soft);
      border-color: color-mix(in oklch, var(--teal) 35%, var(--line));
      color: var(--teal);
    }

    @keyframes rise {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: none; }
    }
    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 oklch(48% 0.1 155 / 0.45); }
      70% { box-shadow: 0 0 0 8px oklch(48% 0.1 155 / 0); }
      100% { box-shadow: 0 0 0 0 oklch(48% 0.1 155 / 0); }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
    }
    @media (max-width: 1180px) {
      .kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .workspace { grid-template-columns: 1fr 1fr; }
      .workspace .panel.intel { grid-column: 1 / -1; min-height: 320px; }
    }
    @media (max-width: 760px) {
      .shell { padding: 10px; gap: 10px; }
      .topbar { grid-template-columns: 1fr; }
      .status-cluster { justify-content: flex-start; }
      .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .workspace { grid-template-columns: 1fr; }
      .target-line { max-width: 100%; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="mark" aria-hidden="true">R</div>
        <div class="brand-copy">
          <p class="eyebrow">Reynard Security</p>
          <h1>Assessment Console</h1>
          <div class="target-line" id="target">Awaiting engagement session…</div>
        </div>
      </div>
      <div class="status-cluster">
        <div class="chip" id="connChip"><span class="dot"></span><span id="conn">Connecting</span></div>
        <div class="chip accent" id="agentChip"><span class="dot"></span><span id="agent">Agent idle</span></div>
        <div class="chip" id="phaseChip"><span id="phase">Boot</span></div>
        <div class="chip" id="eventsChip"><span id="events">0 events</span></div>
      </div>
    </header>

    <section class="kpis" aria-label="Run metrics">
      <div class="kpi findings">
        <div class="label">Findings</div>
        <div class="value" id="findingCount">0</div>
        <div class="hint" id="findingHint">verified evidence</div>
      </div>
      <div class="kpi">
        <div class="label">Tool calls</div>
        <div class="value" id="toolCount">0</div>
        <div class="hint" id="toolHint">actions executed</div>
      </div>
      <div class="kpi">
        <div class="label">Research</div>
        <div class="value" id="searchCount">0</div>
        <div class="hint">web lookups</div>
      </div>
      <div class="kpi">
        <div class="label">Tokens</div>
        <div class="value" id="tokenCount">0</div>
        <div class="hint">model usage</div>
      </div>
      <div class="kpi">
        <div class="label">Est. cost</div>
        <div class="value" id="costEstimate">$0</div>
        <div class="hint">USD running total</div>
      </div>
      <div class="kpi phase">
        <div class="label">Phase</div>
        <div class="value" id="state">Boot</div>
        <div class="hint" id="lastEvent">idle</div>
      </div>
    </section>

    <main class="workspace">
      <section class="panel">
        <div class="panel-head">
          <h2>Operations timeline</h2>
          <div class="filters" id="filters">
            <button type="button" class="filter-btn active" data-filter="all">All</button>
            <button type="button" class="filter-btn" data-filter="tools">Tools</button>
            <button type="button" class="filter-btn" data-filter="findings">Findings</button>
            <button type="button" class="filter-btn" data-filter="errors">Errors</button>
          </div>
        </div>
        <div class="panel-body">
          <div id="timeline" class="timeline"><div class="empty">Events appear here as the assessment progresses.</div></div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head">
          <h2>Findings &amp; evidence</h2>
          <span class="meta" id="findingsMeta">0 logged</span>
        </div>
        <div class="panel-body">
          <div id="findings" class="findings"><div class="empty">No findings yet. Confirmed issues will surface here with evidence.</div></div>
        </div>
      </section>

      <section class="panel intel">
        <div class="panel-head">
          <h2>Intelligence stream</h2>
          <span class="meta" id="reasoningMode">live trace</span>
        </div>
        <div class="panel-body intel">
          <pre id="reasoning" class="reasoning" aria-live="polite"></pre>
          <div class="side-block">
            <h3>Tool activity</h3>
            <div id="tools"><div class="empty">No tool calls yet.</div></div>
            <h3 style="margin-top:14px">Session facts</h3>
            <div id="facts"><div class="empty">No facts yet.</div></div>
          </div>
        </div>
      </section>
    </main>
  </div>

  <script>
    const state = {
      events: 0,
      tools: 0,
      searches: 0,
      findings: 0,
      tokens: 0,
      cost: 0,
      filter: "all",
      toolCounts: new Map(),
      facts: new Map(),
      findingItems: [],
      eventLog: [],
    };
    const el = (id) => document.getElementById(id);
    const timeline = el("timeline");
    const reasoning = el("reasoning");
    const findingsEl = el("findings");

    const TYPE_LABELS = {
      session_start: "Session start",
      session_end: "Session end",
      agent_start: "Agent start",
      agent_result: "Agent result",
      llm_start: "Model call",
      llm_end: "Model complete",
      llm_validation_error: "Schema retry",
      tool_start: "Tool start",
      tool_result: "Tool result",
      tool_blocked: "Tool blocked",
      web_search: "Web search",
      web_fetch: "Web fetch",
      memory_fact: "Memory fact",
      finding: "Finding",
      state: "State change",
      error: "Error",
      reasoning_note: "Note",
      reasoning_delta: "Reasoning",
      token_usage: "Token usage",
      budget_exceeded: "Budget exceeded",
    };

    const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], {
      hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
    const prettyType = (type) => TYPE_LABELS[type] || String(type || "").replace(/_/g, " ");
    const brief = (payload) => {
      if (!payload) return "";
      const value = payload.summary || payload.reasoning || payload.message || payload.text
        || payload.query || payload.url || payload.tool || payload.agent || payload.state
        || payload.key || payload.title || payload.vulnerability || JSON.stringify(payload);
      return String(value).slice(0, 280);
    };
    const eventBucket = (type) => {
      if (type === "finding") return "findings";
      if (type === "error" || type === "tool_blocked" || type === "budget_exceeded" || type === "llm_validation_error") return "errors";
      if (type.startsWith("tool_") || type === "web_search" || type === "web_fetch") return "tools";
      return "all";
    };
    const severityFor = (type) => {
      if (type === "finding") return ["ok", "Finding"];
      if (type === "error" || type === "tool_blocked" || type === "budget_exceeded") return ["crit", "Alert"];
      if (type === "llm_validation_error") return ["warn", "Retry"];
      if (type === "tool_result" || type === "session_end") return ["ok", "Done"];
      if (type === "agent_start" || type === "llm_start") return ["info", "Active"];
      return null;
    };

    const matchesFilter = (type) => {
      if (state.filter === "all") return true;
      return eventBucket(type) === state.filter;
    };

    const renderTimeline = () => {
      const visible = state.eventLog.filter((e) => matchesFilter(e.type));
      if (!visible.length) {
        timeline.innerHTML = `<div class="empty">${state.eventLog.length ? "No events in this filter." : "Events appear here as the assessment progresses."}</div>`;
        return;
      }
      timeline.innerHTML = "";
      visible.slice(0, 160).forEach((event) => {
        const div = document.createElement("div");
        div.className = `event ${event.type}`;
        const sev = severityFor(event.type);
        const sevHtml = sev ? `<span class="sev ${sev[0]}">${sev[1]}</span>` : "";
        div.innerHTML = `
          <div class="time">${fmtTime(event.ts)}</div>
          <div class="rail"><span></span></div>
          <div>
            <div class="type">${prettyType(event.type)}${sevHtml}</div>
            <div class="payload"></div>
          </div>`;
        div.querySelector(".payload").textContent = brief(event.payload);
        timeline.appendChild(div);
      });
    };

    const renderFindings = () => {
      el("findingsMeta").textContent = `${state.findingItems.length} logged`;
      if (!state.findingItems.length) {
        findingsEl.innerHTML = `<div class="empty">No findings yet. Confirmed issues will surface here with evidence.</div>`;
        return;
      }
      findingsEl.innerHTML = `<div class="finding header-row">Latest evidence-backed signals</div>`;
      state.findingItems.slice(0, 40).forEach((item) => {
        const card = document.createElement("div");
        card.className = "finding";
        const title = item.title || item.vulnerability || item.summary || item.type || "Finding";
        const detail = item.detail || item.summary || item.message || item.evidence || item.url || "";
        card.innerHTML = `
          <div class="title"></div>
          <div class="detail"></div>
          <div class="tags"><span class="sev ok">Evidence</span><span class="sev info"></span></div>`;
        card.querySelector(".title").textContent = title;
        card.querySelector(".detail").textContent = String(detail).slice(0, 320);
        card.querySelector(".sev.info").textContent = fmtTime(item.ts);
        findingsEl.appendChild(card);
      });
    };

    const renderSide = () => {
      el("events").textContent = `${state.events} events`;
      el("toolCount").textContent = state.tools.toLocaleString();
      el("searchCount").textContent = state.searches.toLocaleString();
      el("findingCount").textContent = state.findings.toLocaleString();
      el("tokenCount").textContent = state.tokens.toLocaleString();
      el("costEstimate").textContent = `$${Number(state.cost || 0).toFixed(4)}`;
      el("findingHint").textContent = state.findings === 1 ? "1 signal logged" : "verified evidence";
      el("toolHint").textContent = state.tools === 1 ? "1 action executed" : "actions executed";

      const tools = el("tools");
      tools.innerHTML = state.toolCounts.size ? "" : `<div class="empty">No tool calls yet.</div>`;
      [...state.toolCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 18).forEach(([name, count]) => {
        const row = document.createElement("div");
        row.className = "tool-row";
        row.innerHTML = `<b></b><span></span>`;
        row.querySelector("b").textContent = name;
        row.querySelector("span").textContent = `${count}×`;
        tools.appendChild(row);
      });

      const facts = el("facts");
      facts.innerHTML = state.facts.size ? "" : `<div class="empty">No facts yet.</div>`;
      [...state.facts.entries()].slice(-24).reverse().forEach(([key, val]) => {
        const row = document.createElement("div");
        row.className = "fact-row";
        row.innerHTML = `<b></b><span></span>`;
        row.querySelector("b").textContent = key;
        row.querySelector("span").textContent = String(val).slice(0, 180);
        facts.appendChild(row);
      });
    };

    const setConn = (mode) => {
      const chip = el("connChip");
      chip.classList.remove("live", "warn", "danger");
      if (mode === "live") {
        chip.classList.add("live");
        el("conn").textContent = "Live";
      } else if (mode === "reconnecting") {
        chip.classList.add("warn");
        el("conn").textContent = "Reconnecting";
      } else {
        el("conn").textContent = "Connecting";
      }
    };

    const handle = (event) => {
      if (!event || !event.type) return;
      if (event.type === "reasoning_delta") {
        reasoning.textContent += event.payload?.text || "";
        reasoning.scrollTop = reasoning.scrollHeight;
        return;
      }

      state.events++;
      el("lastEvent").textContent = prettyType(event.type).toLowerCase();
      if (event.payload?.target) el("target").textContent = event.payload.target;
      if (event.payload?.state) {
        el("state").textContent = String(event.payload.state).replace(/_/g, " ");
        el("phase").textContent = String(event.payload.state).replace(/_/g, " ");
      }
      if (event.type === "session_end") {
        const ok = !!event.payload?.success;
        el("state").textContent = ok ? "Complete" : "Ended";
        el("phase").textContent = ok ? "Complete" : "Ended";
        el("phaseChip").classList.toggle("danger", !ok);
        el("phaseChip").classList.toggle("accent", ok);
      }
      if (event.payload?.agent) {
        el("agent").textContent = String(event.payload.agent);
      }
      if (event.type === "reasoning_note" && event.payload?.append_to_stream !== false) {
        reasoning.textContent += `\n[${fmtTime(event.ts)}] ${event.payload.text || event.payload.message || ""}\n`;
        reasoning.scrollTop = reasoning.scrollHeight;
      }
      if (event.type === "tool_start") {
        state.tools++;
        const name = event.payload?.tool || "tool";
        state.toolCounts.set(name, (state.toolCounts.get(name) || 0) + 1);
      }
      if (event.type === "web_search" && event.payload?.stage !== "start") state.searches++;
      if (event.type === "token_usage") {
        if (typeof event.payload?.cumulative_total_tokens === "number") state.tokens = event.payload.cumulative_total_tokens;
        if (typeof event.payload?.estimated_cost_usd === "number") state.cost = event.payload.estimated_cost_usd;
      }
      if (event.type === "session_end" || event.type === "budget_exceeded") {
        if (typeof event.payload?.total_tokens === "number") state.tokens = event.payload.total_tokens;
        if (typeof event.payload?.estimated_cost_usd === "number") state.cost = event.payload.estimated_cost_usd;
        if (event.type === "budget_exceeded") {
          el("phaseChip").classList.add("danger");
          el("phase").textContent = "Budget exceeded";
        }
      }
      if (event.type === "memory_fact") state.facts.set(event.payload.key, event.payload.value);
      if (event.type === "finding") {
        state.findings++;
        state.findingItems.unshift({
          ts: event.ts,
          title: event.payload?.title || event.payload?.vulnerability || event.payload?.type,
          detail: event.payload?.summary || event.payload?.message || event.payload?.evidence || event.payload?.url,
          ...event.payload,
        });
        renderFindings();
      }

      state.eventLog.unshift(event);
      if (state.eventLog.length > 400) state.eventLog.length = 400;
      renderTimeline();
      renderSide();
    };

    document.getElementById("filters").addEventListener("click", (ev) => {
      const btn = ev.target.closest(".filter-btn");
      if (!btn) return;
      state.filter = btn.dataset.filter || "all";
      document.querySelectorAll(".filter-btn").forEach((b) => b.classList.toggle("active", b === btn));
      renderTimeline();
    });

    const source = new EventSource("/events");
    source.onopen = () => setConn("live");
    source.onerror = () => setConn("reconnecting");
    source.onmessage = (msg) => handle(JSON.parse(msg.data));
    [
      "session_start","session_end","agent_start","agent_result","llm_start","llm_end",
      "llm_validation_error","tool_start","tool_result","tool_blocked","web_search",
      "web_fetch","memory_fact","finding","state","error","reasoning_note",
      "reasoning_delta","token_usage","budget_exceeded",
    ].forEach((type) => {
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
