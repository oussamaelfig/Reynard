"use strict";

(function () {
const H = { "content-type": "application/json" };
let { selected, runsCache, reportMd, reportRun, findingsCache, fSel, curSubmission, curSubName } = emptyPrivateSession();
let es = null, logTimer = null, busy = 0, detailReady = false;
let lastBlock = null, lastBlockKind = null;
let authenticated = null, authEpoch = 0, offline = false, streamStatus = "idle", activeDialog = null;
let listLoading = false, findingsLoading = false, disposed = false;
const statuses = new Set(["queued", "running", "completed", "failed", "cancelled"]);
const severities = new Set(["critical", "high", "medium", "low", "info"]);
const STREAM_LIMIT = 300, BLOCK_LIMIT = 16000;

function emptyPrivateSession() {
  return { selected: null, runsCache: [], reportMd: "", reportRun: "", findingsCache: [],
    fSel: null, curSubmission: "", curSubName: "finding.md" };
}

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const splitList = (s) => (s || "").split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
const svg = (p, sw) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw||1.7}" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;

function count(value) { return Number.isFinite(Number(value)) ? Math.max(0, Math.floor(Number(value))) : 0; }
function statusName(value) { return statuses.has(value) ? value : "unknown"; }
function severityName(value) { return severities.has(value) ? value : "info"; }
function tabNavigationIndex(key, index, length) {
  if (!length) return null;
  return key === "Home" ? 0 : key === "End" ? length - 1 : key === "ArrowRight" ? (index + 1) % length : key === "ArrowLeft" ? (index + length - 1) % length : null;
}
function focusTrapTarget(items, active, backwards) {
  if (!items.length) return null;
  if (!items.includes(active)) return backwards ? items[items.length - 1] : items[0];
  if (backwards && active === items[0]) return items[items.length - 1];
  if (!backwards && active === items[items.length - 1]) return items[0];
  return null;
}
function confirmedFindings(items) {
  return items.filter((finding) => finding.verified === true && finding.verification_status === "verified");
}
function buildRunRequest(fields, sessions = []) {
  return {
    targets: splitList(fields["f-targets"]),
    authorized_domains: splitList(fields["f-domains"]),
    authorized_cidrs: splitList(fields["f-cidrs"]),
    authorized_url_prefixes: splitList(fields["f-prefixes"]),
    out_of_scope: splitList(fields["f-oos"]),
    description: (fields["f-desc"] || "").trim(),
    max_iterations: Number(fields["f-iter"]),
    per_target_timeout: Number(fields["f-timeout"]),
    max_requests_per_second: Number(fields["f-rps"]),
    max_total_requests: Number(fields["f-maxreq"]),
    allow_destructive: fields["f-destructive"] === true,
    enable_browser_use: fields["f-browser"] === true,
    enable_hexstrike: fields["f-hexstrike"] === true,
    auth_sessions: sessions,
    authorized: fields["f-authorized"] === true,
  };
}
function filterRuns(runs, query = "", status = "all") {
  const needle = query.trim().toLowerCase();
  return runs.filter((run) => (status === "all" || run.status === status) &&
    (!needle || [run.id, run.description, ...(run.targets || [])].join(" ").toLowerCase().includes(needle)));
}
function runSummary(runs) {
  const running = runs.filter((run) => run.status === "running").length;
  const queued = runs.filter((run) => run.status === "queued").length;
  const confirmed = runs.reduce((total, run) => total + count(run.findings_count), 0);
  return `${runs.length} ${runs.length === 1 ? "run" : "runs"} · ${running} running · ${queued} queued · ${confirmed} confirmed`;
}
function readTheme(storage) { try { return storage.getItem("reynard-theme") === "light" ? "light" : "dark"; } catch (_) { return "dark"; } }
function writeTheme(storage, value) { try { storage.setItem("reynard-theme", value); } catch (_) { /* Session-only theme is still usable. */ } }
function boundedText(current, addition, limit = BLOCK_LIMIT) { return (String(current) + String(addition)).slice(-limit); }
function createRequestGate() {
  let selection = null, epoch = 0;
  const versions = new Map();
  return {
    select(id) { selection = id; epoch += 1; },
    issue(key, scope) { const version = (versions.get(key) || 0) + 1; versions.set(key, version); return { key, scope, epoch, version }; },
    accepts(ticket) { return versions.get(ticket.key) === ticket.version &&
      (ticket.scope === undefined || (ticket.scope === selection && ticket.epoch === epoch)); },
  };
}
function createSeenWindow(limit = 1000) {
  const ids = new Set();
  return { add(id) { if (ids.has(id)) return false; ids.add(id); if (ids.size > limit) ids.delete(ids.values().next().value); return true; }, clear() { ids.clear(); }, get size() { return ids.size; } };
}
function reconcileKeyed(container, items, create, update) {
  const existing = new Map(Array.from(container.children).map((node) => [node.dataset.id, node]));
  items.forEach((item, index) => {
    let node = existing.get(String(item.id));
    if (node) existing.delete(String(item.id)); else node = create(item);
    update(node, item);
    if (container.children[index] !== node) container.insertBefore(node, container.children[index] || null);
  });
  existing.forEach((node) => node.remove());
}
const gate = createRequestGate(), seen = createSeenWindow();
if (typeof module !== "undefined" && module.exports) {
  module.exports = { esc, count, statusName, severityName, filterRuns, runSummary, readTheme, writeTheme,
    boundedText, createRequestGate, createSeenWindow, reconcileKeyed, mdToHtml, runRow, findingRow,
    badge, relTime, tabNavigationIndex, focusTrapTarget, confirmedFindings, buildRunRequest,
    emptyPrivateSession };
}
if (typeof document === "undefined") return;
const on = (id, event, callback) => $(id)?.addEventListener(event, callback);
const text = (id, value) => { if ($(id)) $(id).textContent = value; };

function setBusy(on) { busy += on ? 1 : -1; if (busy < 0) busy = 0; $("progress").classList.toggle("on", busy > 0 || anyRunning()); }
function anyRunning() { return runsCache.some((r) => r.status === "running" || r.status === "queued"); }

function relTime(iso) {
  if (!iso) return "";
  const d = new Date(/(?:Z|[+-]\d\d:\d\d)$/.test(iso) ? iso : iso + "Z");
  if (!Number.isFinite(d.getTime())) return "";
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return Math.floor(s) + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

async function api(path, opts = {}, responseType = "json") {
  setBusy(true);
  const requestEpoch = authEpoch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const r = await fetch(path, { headers: H, credentials: "same-origin", ...opts, signal: controller.signal });
    offline = false;
    if (requestEpoch !== authEpoch) { const error = new Error("Session changed. Refresh to retry."); error.status = 401; throw error; }
    if (!r.ok) {
      if (r.status === 401) authError();
      let detail = "";
      try { detail = (await r.json()).detail; } catch (_) {}
      if (Array.isArray(detail)) detail = detail.map((item) => `${(item.loc || []).slice(1).join(".")}: ${item.msg}`).join("; ");
      const error = new Error(typeof detail === "string" && detail ? detail : `Request failed (${r.status})`);
      error.status = r.status; throw error;
    }
    const value = r.status === 204 ? null : responseType === "text" ? await r.text() : await r.json();
    if (requestEpoch !== authEpoch) { const error = new Error("Session changed. Refresh to retry."); error.status = 401; throw error; }
    authenticated = true; updateConnection();
    return value;
  } catch (error) {
    if (!error.status) { offline = true; updateConnection(); }
    if (error.name === "AbortError") throw new Error("The console did not respond in time. Try again.");
    throw error;
  } finally { clearTimeout(timer); setBusy(false); }
}

// A 401 means this page's token no longer matches the server (usually a
// stale tab from a previous session, or the server restarted with a new
// token). Surface it clearly once instead of silently failing every poll.
function authError() {
  if (authenticated !== false) authEpoch += 1;
  authenticated = false;
  closeStream(); stopLogTimer(); updateConnection();
  ({ selected, runsCache, reportMd, reportRun, findingsCache, fSel, curSubmission, curSubName } = emptyPrivateSession());
  gate.select(null); detailReady = false; seen.clear(); lastBlock = null; lastBlockKind = null;
  setReportActions(false); setFindingActions(false); $("f-export").disabled = true;
  ["runs", "report", "evidence", "stream-wrap", "f-items", "f-doc"].forEach((id) => {
    $(id).innerHTML = emptyState("Session locked", "Connect with your operator token to load this workspace.");
  });
  delete $("runs").dataset.emptyKey; delete $("f-items").dataset.emptyKey;
  text("log", "Session locked."); text("d-title", "Workspace overview"); text("d-meta", ""); text("d-err", "");
  text("f-sel-title", "Select a finding"); text("f-count", "Sign in to load findings");
  text("runs-count", "—"); text("workspace-count", "Sign in to load runs");
  $("d-cancel").style.display = "none";
  $("f-sessions").value = ""; $("toasts").innerHTML = "";
  cmdkItems = []; $("cmdk-list").innerHTML = ""; $("cmdk-input").value = "";
  if ($("workspace-welcome")) $("workspace-welcome").hidden = false;
  if ($("detail-content")) $("detail-content").hidden = true;
  document.body.classList.remove("detail-open", "finding-open");
  if (activeDialog) closeOverlay(activeDialog, false);
  if (!$("login-dialog").open) $("login-dialog").showModal();
}

let loginPending = false;
$("login-dialog").addEventListener("cancel", (event) => { if (authenticated !== true) event.preventDefault(); });
$("login-form").onsubmit = async (event) => {
  event.preventDefault();
  if (loginPending) return;
  const input = $("login-token");
  const supplied = input.value; input.value = "";
  const button = $("login-form").querySelector('button[type="submit"]');
  loginPending = true; button.disabled = true; button.textContent = "Connecting…";
  $("login-form").setAttribute("aria-busy", "true"); text("login-error", "");
  try {
    const response = await fetch("/api/session", {
      method: "POST", credentials: "same-origin", headers: { "x-harness-token": supplied },
      signal: AbortSignal.timeout(12000),
    });
    if (!response.ok) throw new Error(response.status === 401 ? "Invalid token. Check the harness terminal." : `Connection failed (${response.status}). Try again.`);
    authEpoch += 1; authenticated = true; offline = false; $("login-dialog").close(); $("f-export").disabled = false; updateConnection();
    refreshRuns(); health(); if (document.body.classList.contains("mode-findings")) loadFindings();
  } catch (error) { text("login-error", error.name === "TimeoutError" ? "Connection timed out. Check the harness process." : error.message); input.focus(); }
  finally { loginPending = false; button.disabled = false; button.textContent = "Connect"; $("login-form").setAttribute("aria-busy", "false"); }
};

// ---------- toasts ----------
function toast(title, msg, type = "info") {
  const el = document.createElement("div");
  el.className = "toast " + type;
  el.setAttribute("role", type === "err" ? "alert" : "status");
  const ic = type === "ok" ? svg('<path d="M20 6L9 17l-5-5"/>', 2)
    : type === "err" ? svg('<circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/>', 1.8)
    : svg('<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>', 1.8);
  el.innerHTML = `<span class="ic">${ic}</span><div class="body"><strong>${esc(title)}</strong>${msg ? `<span>${esc(msg)}</span>` : ""}</div>`;
  $("toasts").appendChild(el);
  while ($("toasts").children.length > 4) $("toasts").firstElementChild.remove();
  setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 220); }, 4200);
}

// ---------- health ----------
function updateConnection() {
  const state = offline ? "offline" : authenticated === false ? "auth" : authenticated === null ? "connecting" : streamStatus === "reconnecting" ? "reconnecting" : "connected";
  $("conn").className = "conn " + (state === "connected" ? "ok" : "off");
  text("conn-text", { offline: "Offline · retrying", auth: "Sign in required", connecting: "Connecting…", reconnecting: "Reconnecting stream…", connected: "Connected" }[state]);
}
async function health() {
  try {
    const response = await fetch("/api/health", { signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error("Health unavailable");
    await response.json(); offline = false;
  } catch (_) { offline = true; }
  updateConnection();
}

// ---------- theme ----------
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { writeTheme(window.localStorage, t); } catch (_) {}
  $("theme-label").textContent = t === "dark" ? "Dark" : "Light";
  $("theme-icon").innerHTML = t === "dark"
    ? '<path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" stroke-linejoin="round"/>'
    : '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19"/>';
}
$("theme-toggle").onclick = () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");

// ---------- modal focus ----------
const dialogReturn = new Map();
function openOverlay(id, focusId) {
  if (activeDialog === id) return;
  if (activeDialog) closeOverlay(activeDialog);
  dialogReturn.set(id, document.activeElement);
  activeDialog = id;
  const dialog = $(id); dialog.inert = false; dialog.classList.add("open");
  dialog.setAttribute("aria-hidden", "false"); dialog.setAttribute("aria-modal", "true");
  const shell = $("app-shell") || document.querySelector(".shell"); if (shell && !shell.contains(dialog)) shell.inert = true;
  if (id === "drawer") $("drawer-scrim").classList.add("open");
  // The drawer becomes visible through CSS. Wait for that style to reach a
  // painted frame before focusing; a closed/replaced dialog must not steal it.
  requestAnimationFrame(() => requestAnimationFrame(() => {
    if (activeDialog === id && !$("login-dialog").open) $(focusId)?.focus();
  }));
}
function closeOverlay(id, restore = true) {
  if (activeDialog !== id) return;
  const dialog = $(id); activeDialog = null;
  dialog.classList.remove("open"); dialog.setAttribute("aria-hidden", "true"); dialog.inert = true;
  if (id === "drawer") $("drawer-scrim").classList.remove("open");
  const shell = $("app-shell") || document.querySelector(".shell"); if (shell) shell.inert = false;
  const previous = dialogReturn.get(id); dialogReturn.delete(id);
  if (restore && previous?.isConnected) previous.focus({ preventScroll: true });
}
function trapDialogFocus(event) {
  if (!activeDialog || event.key !== "Tab") return;
  const dialog = $(activeDialog);
  const items = Array.from(dialog.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], summary, [tabindex="0"]'))
    .filter((element) => !element.hidden && element.tabIndex >= 0 && element.getClientRects().length);
  if (!items.length) { event.preventDefault(); return; }
  const target = focusTrapTarget(items, document.activeElement, event.shiftKey);
  if (target) { event.preventDefault(); target.focus(); }
}
// ---------- drawer ----------
function openDrawer() { if (authenticated === false) { authError(); return; } openOverlay("drawer", "f-targets"); }
function closeDrawer() { closeOverlay("drawer"); }
$("btn-new").onclick = openDrawer; $("nav-new").onclick = openDrawer;
$("drawer-close").onclick = closeDrawer; $("drawer-cancel").onclick = closeDrawer; $("drawer-scrim").onclick = closeDrawer;

async function submit() {
  if ($("f-submit").disabled) return;
  const requestEpoch = authEpoch;
  const msg = $("f-msg"); msg.className = "msg"; msg.textContent = "";
  let sessions = [];
  const sraw = $("f-sessions").value.trim();
  if (sraw) { try { sessions = JSON.parse(sraw); if (!Array.isArray(sessions)) throw new Error(); } catch (e) { msg.className = "msg err"; msg.textContent = "Auth sessions must be a JSON array of identities."; $("f-sessions").focus(); return; } }
  const invalid = Array.from($("drawer").querySelectorAll("input, textarea, select")).find((field) => !field.checkValidity());
  if (invalid) { invalid.reportValidity(); return; }
  const fields = Object.fromEntries(Array.from($("drawer").querySelectorAll("input, textarea, select"))
    .map((field) => [field.id, field.type === "checkbox" ? field.checked : field.value]));
  const body = buildRunRequest(fields, sessions);
  $("f-submit").disabled = true;
  $("f-submit").textContent = "Launching…";
  $("drawer").setAttribute("aria-busy", "true");
  try {
    const res = await api("/api/runs", { method: "POST", body: JSON.stringify(body) });
    if (authenticated !== true || requestEpoch !== authEpoch) return;
    toast("Run launched", res.run_id, "ok");
    $("f-sessions").value = "";
    closeDrawer();
    await refreshRuns(); selectRun(res.run_id);
    document.querySelector('.tab[data-tab="live"]').click();
  } catch (e) { msg.className = "msg err"; msg.textContent = e.message; toast("Could not launch run", e.message, "err"); }
  finally { $("f-submit").disabled = false; $("f-submit").textContent = "Launch run"; $("drawer").setAttribute("aria-busy", "false"); }
}
on("launch-form", "submit", (event) => { event.preventDefault(); submit(); });

// ---------- runs list ----------
function runRow(r) {
  const target = r.targets && r.targets.length ? r.targets.join(", ") : "No explicit target";
  const description = String(r.description || "").trim();
  const err = r.error ? `<span class="fchip" style="color:var(--red)">${esc(String(r.error).slice(0, 60))}</span>` : "";
  const f = (r.status === "completed" || r.status === "failed")
    ? `<span class="fchip">${count(r.findings_count)} confirmed · ${count(r.suppressed_count)} report-gate suppressions</span>`
    : "";
  return `<button type="button" class="run ${r.id === selected ? "active" : ""}" data-id="${esc(r.id)}" aria-current="${r.id === selected ? "true" : "false"}">
    <span class="rid">${esc(r.id)}</span>
    <span class="rtime">${esc(relTime(r.created_at))}</span>
    <span class="rtarget">${esc(description || target)}</span>
    ${description && r.targets?.length ? `<span class="rendpoint">${esc(target)}</span>` : ""}
    <span class="rmeta">${badge(r.status)}${f || err}</span>
  </button>`;
}
function badge(s) { const status = statusName(s); return `<span class="badge ${status}"><span class="dot" aria-hidden="true"></span>${status}</span>`; }

function renderKeyedMarkup(container, items, markup, action) {
  const hadFocus = container.contains(document.activeElement);
  const focusedId = document.activeElement?.dataset?.id;
  const template = document.createElement("template");
  const nodeFor = (item) => { template.innerHTML = markup(item); return template.content.firstElementChild; };
  reconcileKeyed(container, items, nodeFor, (node, item) => {
    const fresh = nodeFor(item);
    if (node.innerHTML !== fresh.innerHTML) node.innerHTML = fresh.innerHTML;
    node.className = fresh.className;
    node.setAttribute("aria-current", fresh.getAttribute("aria-current"));
    node.onclick = () => action(item.id);
  });
  if (hadFocus && !Array.from(container.children).some((node) => node.dataset.id === focusedId)) {
    container.tabIndex = -1; container.focus({ preventScroll: true });
  }
}
function renderRuns() {
  const filtered = filterRuns(runsCache, $("run-search")?.value || "", $("run-filter")?.value || "all");
  text("runs-count", runsCache.length); text("workspace-count", runSummary(runsCache));
  const el = $("runs");
  if (!filtered.length) {
    const emptyKey = runsCache.length ? "filtered" : "empty";
    if (el.dataset.emptyKey === emptyKey) return;
    el.dataset.emptyKey = emptyKey;
    el.innerHTML = emptyState(runsCache.length ? "No matching runs" : "Your first run starts here",
      runsCache.length ? "Change the search or status filter to see more runs." : "Define a target, authorized scope, and objective to begin.");
    if (!runsCache.length) {
      const button = document.createElement("button"); button.type = "button"; button.className = "btn primary sm";
      button.textContent = "New run"; button.onclick = openDrawer; el.firstElementChild.appendChild(button);
    }
  } else { delete el.dataset.emptyKey; renderKeyedMarkup(el, filtered, runRow, selectRun); }
  $("progress").classList.toggle("on", busy > 0 || anyRunning());
}

async function refreshRuns() {
  if (listLoading || authenticated === false || disposed) return;
  listLoading = true;
  const requestEpoch = authEpoch;
  try {
    const runs = await api("/api/runs");
    if (authenticated !== true || requestEpoch !== authEpoch) return;
    if (!Array.isArray(runs)) throw new Error("Invalid run list response");
    runsCache = runs; renderRuns();
    const current = runsCache.find((run) => run.id === selected);
    if (current) renderDetail(current);
  } catch (_) { /* Keep the last good list visible while reconnecting. */ }
  finally { listLoading = false; }
}

// ---------- detail + live ----------
async function selectRun(id, force = false) {
  if (authenticated === false) { authError(); return; }
  const switching = id !== selected || force || !detailReady;
  setView("runs"); document.body.classList.add("detail-open");
  selected = id;
  if ($("workspace-welcome")) $("workspace-welcome").hidden = true;
  if ($("detail-content")) $("detail-content").hidden = false;
  if (window.matchMedia("(max-width: 760px)").matches) $("detail-back")?.focus();
  renderRuns();
  if (!switching) return;
  gate.select(id);
  if (switching) {
    detailReady = false; $("d-cancel").disabled = false;
    closeStream(); stopLogTimer(); seen.clear(); lastBlock = null; lastBlockKind = null; trimmedEvents = 0;
    reportMd = ""; reportRun = ""; setReportActions(false);
    $("stream-wrap").innerHTML = ""; $("log").textContent = "Loading…";
    $("report").innerHTML = emptyState("Loading report", "Retrieving the latest confirmed findings.");
    $("evidence").innerHTML = emptyState("Loading evidence", "Retrieving validated evidence for this run.");
    text("d-title", id); text("d-err", ""); text("d-meta", "Loading run…");
  }
  const ticket = gate.issue("selection", id);
  const record = await refreshDetail(id);
  if (!gate.accepts(ticket) || !record) return;
  detailReady = true;
  openStream(id);
  loadReport(id); loadEvidence(id); loadLog(id);
  if (record.status === "running" || record.status === "queued") startLogTimer(id);
}

async function refreshDetail(id) {
  const ticket = gate.issue("detail", id);
  const rec = await api("/api/runs/" + encodeURIComponent(id)).catch(() => null);
  if (!gate.accepts(ticket)) return null;
  if (!rec) { text("d-err", "Run details could not be loaded. Refresh the run list to retry."); return null; }
  renderDetail(rec); return rec;
}
function renderDetail(rec) {
  if (rec.id !== selected) return;
  const target = rec.targets?.[0];
  let heading = target || rec.id;
  try { heading = new URL(target).host; } catch (_) {}
  text("d-title", heading);
  $("d-meta").innerHTML = rec ? badge(rec.status) : "";
  $("d-cancel").style.display = rec && (rec.status === "queued" || rec.status === "running") ? "" : "none";
  const e = $("d-err");
  if (rec && rec.error) { e.className = "msg err"; e.textContent = rec.error; }
  else { e.className = "msg"; e.textContent = ""; }
}

function streamEl() {
  let s = document.querySelector("#stream-wrap .stream");
  if (!s) {
    $("stream-wrap").innerHTML = `<div class="runbar" id="runbar"><span class="live" id="live-ind"><i></i>live</span><span id="runbar-txt" role="status">Connecting to activity…</span></div><div class="stream" id="stream" role="log" aria-label="Run activity" aria-live="off"></div>`;
    s = $("stream");
  }
  return s;
}
let trimmedEvents = 0;
function trimStream(s) {
  while (s.children.length > STREAM_LIMIT) { s.firstElementChild.remove(); trimmedEvents += 1; }
  if (trimmedEvents) text("runbar-txt", `Showing recent activity · ${trimmedEvents} earlier blocks omitted`);
}

function renderEvent(ev) {
  const s = streamEl();
  const scroller = document.querySelector(".detail-scroll");
  const follow = scroller && scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - 80;
  const kind = ev.type || "event";
  const p = ev.payload && typeof ev.payload === "object" && !Array.isArray(ev.payload) ? ev.payload : {};
  if (kind === "reasoning_delta" || kind === "assistant_delta") {
    const cls = kind === "reasoning_delta" ? "think" : "answer";
    const identity = [cls, p.agent, p.model].join(":");
    if (!(lastBlock?.isConnected && lastBlockKind === identity)) {
      lastBlock = document.createElement("div");
      lastBlock.className = "block " + cls;
      const who = [p.agent, p.model].filter(Boolean).join(" · ");
      lastBlock.innerHTML = `<div class="bh">${cls === "think" ? "◇ thinking" : "▸ output"}${who ? " — " + esc(who) : ""}</div><pre class="txt"></pre>`;
      s.appendChild(lastBlock); lastBlockKind = identity;
    }
    const content = lastBlock.querySelector(".txt");
    content.textContent = boundedText(content.textContent, p.text || "");
    trimStream(s);
    if (follow) scroller.scrollTop = scroller.scrollHeight;
    return;
  }
  lastBlock = null; lastBlockKind = null;
  addRow(s, ev);
  trimStream(s); if (follow) scroller.scrollTop = scroller.scrollHeight;
}

function addRow(s, ev) {
  const kind = ev.type || "event";
  const p = ev.payload && typeof ev.payload === "object" && !Array.isArray(ev.payload) ? ev.payload : {};
  const t = ev.ts ? new Date(ev.ts * 1000).toLocaleTimeString([], { hour12: false }) : "";
  let summary = "";
  switch (kind) {
    case "reasoning_note": summary = (p.agent ? "[" + p.agent + "] " : "") + (p.text || ""); break;
    case "finding": summary = (p.severity ? "[" + p.severity + "] " : "") + (p.title || p.summary || JSON.stringify(p)); break;
    case "tool_start": summary = (p.tool || "") + " " + (p.command || p.args || ""); break;
    case "tool_result": summary = (p.tool || "") + " → " + (p.status || p.summary || ""); break;
    case "tool_blocked": summary = (p.tool || "") + " blocked: " + (p.reason || ""); break;
    case "error": summary = p.message || p.error || JSON.stringify(p); break;
    case "llm_start": summary = "→ " + [p.agent, p.model, p.mode].filter(Boolean).join(" · "); break;
    case "llm_end": summary = "✓ " + [p.agent, p.model, p.mode].filter(Boolean).join(" · "); break;
    case "agent_start": summary = p.agent || p.role || ""; break;
    case "agent_result": summary = (p.agent || "") + " " + (p.success === false ? "unverified" : (p.status || "done")); break;
    case "token_usage": summary = "tokens " + (p.total ?? p.completion ?? ""); break;
    case "session_start": summary = p.target || p.objective || ""; break;
    case "run_start": summary = "targets: " + (Array.isArray(p.targets) ? p.targets.join(", ") : ""); break;
    case "run_end": summary = "findings: " + (p.findings ?? "") + (p.error ? (" · error: " + p.error) : ""); break;
    default: summary = Object.entries(p).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ");
  }
  const row = document.createElement("div");
  row.className = "ev";
  row.innerHTML = `<span class="t">${esc(t)}</span><span class="k">${esc(kind)}</span><span class="p">${esc(String(summary).slice(0, 900))}</span>`;
  s.appendChild(row);
}

function closeStream() { if (es) es.close(); es = null; streamStatus = "idle"; }
function openStream(id) {
  closeStream();
  streamEl();
  const source = new EventSource("/api/runs/" + encodeURIComponent(id) + "/events");
  es = source; streamStatus = "connecting";
  source.onopen = () => { if (es !== source || selected !== id) return; streamStatus = "live"; updateConnection(); text("runbar-txt", "Live activity"); };
  source.onmessage = (m) => {
    if (es !== source || selected !== id) return;
    let ev; try { ev = JSON.parse(m.data); } catch (e) { return; }
    if (!ev || typeof ev !== "object") return;
    if (ev.type === "_done") { closeStream(); finalize(id); return; }
    if (ev.id != null && !seen.add(ev.id)) return;
    renderEvent(ev);
  };
  source.onerror = () => {
    if (es !== source || selected !== id) return;
    streamStatus = "reconnecting"; updateConnection(); text("runbar-txt", "Connection interrupted · reconnecting…");
    refreshDetail(id); // Distinguish an expired cookie from a reconnectable stream.
  };
}
function finalize(id) {
  if (id !== selected) return;
  updateConnection();
  const ind = $("live-ind"); if (ind) ind.style.display = "none";
  const t = $("runbar-txt"); if (t) t.textContent = "run finished";
  refreshDetail(id); loadReport(id); loadEvidence(id); loadLog(id); stopLogTimer(); refreshRuns();
  if (document.body.classList.contains("mode-findings")) loadFindings();
}

function setReportActions(enabled) { ["r-copy", "r-dl", "r-pdf"].forEach((id) => { $(id).disabled = !enabled; }); }
async function loadReport(id) {
  const ticket = gate.issue("report", id);
  const el = $("report");
  try {
    const r = await api("/api/runs/" + encodeURIComponent(id) + "/report");
    if (!gate.accepts(ticket)) return;
    reportMd = r.markdown || ""; reportRun = id; el.innerHTML = mdToHtml(reportMd); setReportActions(Boolean(reportMd));
  } catch (e) {
    if (!gate.accepts(ticket)) return;
    reportMd = ""; reportRun = ""; setReportActions(false);
    el.innerHTML = emptyState(e.status === 404 ? "Report not ready" : "Report unavailable",
      e.status === 404 ? "A report appears when this run completes. Only confirmed findings are included." : e.message);
  }
}
$("r-copy").onclick = () => reportMd ? copyText(reportMd, "Report Markdown copied") : toast("Nothing to copy", "No report yet", "err");
$("r-dl").onclick = () => reportMd ? downloadText(`reynard-report-${reportRun}.md`, reportMd) : toast("Nothing to download", "No report yet", "err");
$("r-pdf").onclick = () => reportMd ? exportPdf("Reynard report " + reportRun, $("report").innerHTML) : toast("Nothing to export", "No report yet", "err");
async function loadEvidence(id) {
  const ticket = gate.issue("evidence", id);
  const el = $("evidence");
  try {
    const j = await api("/api/runs/" + encodeURIComponent(id) + "/evidence");
    if (!gate.accepts(ticket)) return;
    const targets = (j.targets_assessed || []);
    const rows = [];
    targets.forEach((t) => (t.findings || []).forEach((f) => rows.push(
      `<tr><td>${esc(t.target || "")}</td><td>${esc(f.title || f.name || "")}</td><td>${esc(f.severity || "")}</td><td>${esc(f.verification_status || f.status || "")}</td></tr>`)));
    el.innerHTML = `<dl class="kv"><dt>Targets</dt><dd>${esc(j.target_count ?? "-")}</dd><dt>Confirmed findings</dt><dd>${esc(j.confirmed_count ?? j.finding_count ?? "-")}</dd><dt>Report-gate suppressions</dt><dd>${esc(j.suppressed_count ?? 0)}</dd></dl>` +
      (rows.length ? `<table><thead><tr><th>Target</th><th>Confirmed finding</th><th>Severity</th><th>Status</th></tr></thead><tbody>${rows.join("")}</tbody></table>` : `<p class="hint" style="color:var(--text-faint)">No independently validated vulnerabilities were found.</p>`);
  } catch (e) { if (gate.accepts(ticket)) el.innerHTML = emptyState(e.status === 404 ? "Evidence not ready" : "Evidence unavailable", e.status === 404 ? "Validated evidence appears when this run completes." : e.message); }
}
const pendingLogs = new Set();
async function loadLog(id) {
  if (pendingLogs.has(id)) return;
  pendingLogs.add(id);
  const ticket = gate.issue("log", id);
  try {
    const txt = await api("/api/runs/" + encodeURIComponent(id) + "/log", {}, "text");
    if (!gate.accepts(ticket)) return;
    const el = $("log");
    const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 40;
    el.textContent = txt || "No console output yet.";
    if (atBottom) el.scrollTop = el.scrollHeight;
  } catch (e) { if (gate.accepts(ticket)) text("log", "Console output unavailable. " + e.message); }
  finally { pendingLogs.delete(id); }
}
function startLogTimer(id) { stopLogTimer(); logTimer = setInterval(() => loadLog(id), 2500); }
function stopLogTimer() { if (logTimer) { clearInterval(logTimer); logTimer = null; } }
$("log-refresh").onclick = () => { if (selected) loadLog(selected); };

async function cancel() {
  if (!selected) return;
  const requestEpoch = authEpoch;
  const id = selected; $("d-cancel").disabled = true;
  try {
    const result = await api("/api/runs/" + encodeURIComponent(id) + "/cancel", { method: "POST" });
    if (authenticated !== true || requestEpoch !== authEpoch) return;
    toast(result.cancelled ? "Cancellation requested" : "Run is already finished", id, "info");
    await refreshRuns(); if (selected === id) refreshDetail(id);
  }
  catch (e) { toast("Cancel failed", e.message, "err"); }
  finally { if (selected === id) $("d-cancel").disabled = false; }
}
$("d-cancel").onclick = cancel;

function emptyState(t1, t2) { return `<div class="empty">${svg('<circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/>', 1.6)}<div class="t1">${esc(t1)}</div><div class="t2">${esc(t2)}</div></div>`; }

// Tabs use one tab stop, arrow navigation, and labelled panels.
const tabs = Array.from(document.querySelectorAll(".tab"));
function activateTab(tab, focus = false) {
  tabs.forEach((item) => {
    const active = item === tab; item.classList.toggle("active", active);
    item.setAttribute("aria-selected", String(active)); item.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll(".pane").forEach((pane) => {
    const active = pane.dataset.pane === tab.dataset.tab;
    pane.classList.toggle("active", active); pane.hidden = !active;
  });
  if (focus) tab.focus();
  if (tab.dataset.tab === "console" && selected) loadLog(selected);
}
tabs.forEach((tab, index) => {
  tab.id ||= "tab-" + tab.dataset.tab;
  tab.setAttribute("role", "tab");
  tab.parentElement.setAttribute("role", "tablist"); tab.parentElement.setAttribute("aria-label", "Run details");
  const pane = document.querySelector(`.pane[data-pane="${tab.dataset.tab}"]`);
  if (pane) { pane.id ||= "panel-" + tab.dataset.tab; tab.setAttribute("aria-controls", pane.id); pane.setAttribute("role", "tabpanel"); pane.setAttribute("aria-labelledby", tab.id); pane.tabIndex = 0; }
  tab.onclick = () => activateTab(tab);
  tab.onkeydown = (event) => {
    const next = tabNavigationIndex(event.key, index, tabs.length);
    if (next === null) return;
    event.preventDefault(); activateTab(tabs[next], true);
  };
});
if (tabs.length) activateTab(tabs.find((tab) => tab.classList.contains("active")) || tabs[0]);

// Deliberately small Markdown subset: escape source HTML before formatting.
function mdToHtml(md) {
  const lines = (md || "").split("\n"); let html = "", inCode = false, inList = false, inTable = false;
  const inline = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  for (let i = 0; i < lines.length; i++) {
    let ln = lines[i];
    if (ln.trim().startsWith("```")) { if (inCode) { html += "</code></pre>"; inCode = false; } else { html += "<pre><code>"; inCode = true; } continue; }
    if (inCode) { html += esc(ln) + "\n"; continue; }
    if (/^\s*\|.*\|\s*$/.test(ln)) { const cells = ln.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim()); if (/^[-\s|:]+$/.test(ln)) continue; if (!inTable) { html += "<table>"; inTable = true; } html += "<tr>" + cells.map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>"; continue; } else if (inTable) { html += "</table>"; inTable = false; }
    const h = ln.match(/^(#{1,4})\s+(.*)$/);
    if (h) { if (inList) { html += "</ul>"; inList = false; } html += `<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`; continue; }
    if (/^\s*[-*]\s+/.test(ln)) { if (!inList) { html += "<ul>"; inList = true; } html += `<li>${inline(ln.replace(/^\s*[-*]\s+/, ""))}</li>`; continue; }
    if (inList) { html += "</ul>"; inList = false; }
    if (ln.trim() === "") { html += ""; } else { html += `<p>${inline(ln)}</p>`; }
  }
  if (inCode) html += "</code></pre>"; if (inList) html += "</ul>"; if (inTable) html += "</table>";
  return html || emptyState("Empty report", "The run produced no report body.");
}

// ---------- command palette ----------
let cmdkSel = 0, cmdkItems = [];
function openCmdk() { $("cmdk-input").value = ""; renderCmdk(""); openOverlay("cmdk", "cmdk-input"); }
function closeCmdk() { closeOverlay("cmdk"); }
function renderCmdk(q) {
  q = (q || "").toLowerCase();
  const actions = [
    { t: "New run", d: "Open the launch drawer", ic: '<path d="M12 5v14M5 12h14"/>', run: () => { closeCmdk(); openDrawer(); } },
    { t: "View findings", d: "Copy-paste bug-bounty submissions", ic: '<path d="M12 3l8 4v5c0 4.4-3 8-8 9-5-1-8-4.6-8-9V7l8-4z"/>', run: () => { closeCmdk(); setView("findings"); } },
    { t: "View runs", d: "Back to the run list", ic: '<path d="M4 6h16M4 12h16M4 18h10"/>', run: () => { closeCmdk(); setView("runs"); } },
    { t: "Refresh runs", d: "Reload the run list", ic: '<path d="M20 11a8 8 0 1 0-.5 3M20 5v6h-6"/>', run: () => { closeCmdk(); refreshRuns(); } },
    { t: "Toggle theme", d: "Switch light / dark", ic: '<path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/>', run: () => { closeCmdk(); $("theme-toggle").click(); } },
  ].filter((a) => !q || a.t.toLowerCase().includes(q) || a.d.toLowerCase().includes(q));
  const runs = runsCache.filter((r) => !q || r.id.includes(q) || (r.targets || []).join(" ").toLowerCase().includes(q)).slice(0, 6)
    .map((r) => ({ t: r.id, d: (r.targets || []).join(", ") || r.description || "run", ic: '<circle cx="12" cy="12" r="9"/>', rid: true, status: r.status, run: () => { closeCmdk(); selectRun(r.id); } }));
  cmdkItems = actions.concat(runs); cmdkSel = 0;
  $("cmdk-list").innerHTML = cmdkItems.map((it, i) =>
    `<button type="button" class="cmdk-item ${i === 0 ? "sel" : ""}" data-i="${i}" id="command-${i}"><span class="ci">${svg(it.ic, 1.7)}</span><span class="${it.rid ? "rid" : ""}">${esc(it.t)}</span><span class="tail">${it.status ? badge(it.status) : `<span class="hint" style="color:var(--text-faint)">${esc(it.d)}</span>`}</span></button>`).join("") ||
    `<div class="cmdk-item" style="cursor:default">No matches</div>`;
  $("cmdk-list").querySelectorAll(".cmdk-item[data-i]").forEach((n) => { n.onclick = () => cmdkItems[+n.dataset.i].run(); });
}
function cmdkMove(d) {
  const items = $("cmdk-list").querySelectorAll(".cmdk-item[data-i]"); if (!items.length) return;
  const focused = document.activeElement?.dataset?.i;
  cmdkSel = focused !== undefined ? (+focused + d + items.length) % items.length : d > 0 ? 0 : items.length - 1;
  items.forEach((n, i) => n.classList.toggle("sel", i === cmdkSel));
  items[cmdkSel].focus(); items[cmdkSel].scrollIntoView({ block: "nearest" });
}
$("cmdk-input").addEventListener("input", (e) => renderCmdk(e.target.value));
$("nav-cmdk").onclick = openCmdk;

document.addEventListener("keydown", (e) => {
  trapDialogFocus(e);
  if ($("login-dialog").open) return;
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); activeDialog === "cmdk" ? closeCmdk() : openCmdk(); return; }
  if (e.key === "Escape" && activeDialog) { e.preventDefault(); closeOverlay(activeDialog); return; }
  if ($("cmdk").classList.contains("open")) {
    if (e.key === "ArrowDown") { e.preventDefault(); cmdkMove(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); cmdkMove(-1); }
    else if (e.key === "Enter" && e.target === $("cmdk-input")) { e.preventDefault(); if (cmdkItems[cmdkSel]) cmdkItems[cmdkSel].run(); }
  }
});
$("cmdk").addEventListener("click", (e) => { if (e.target.id === "cmdk") closeCmdk(); });

// ---------- export helpers ----------
async function copyText(text, okMsg) {
  try { await navigator.clipboard.writeText(text); toast(okMsg || "Copied", "", "ok"); }
  catch (e) {
    const previous = document.activeElement;
    const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { if (!document.execCommand("copy")) throw new Error("Copy unavailable"); toast(okMsg || "Copied", "", "ok"); } catch (e2) { toast("Copy failed", "Select and copy manually", "err"); }
    ta.remove(); if (previous?.isConnected) previous.focus({ preventScroll: true });
  }
}
function downloadText(name, text) {
  const blob = new Blob([text], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 100);
  toast("Downloaded", name, "ok");
}
async function downloadFromApi(path, name) {
  const requestEpoch = authEpoch;
  try { const value = await api(path, {}, "text"); if (authenticated === true && requestEpoch === authEpoch) downloadText(name, value); }
  catch (e) { toast("Download failed", e.message, "err"); }
}
function exportPdf(title, innerHtml) {
  const w = window.open("", "_blank");
  if (!w) { toast("Pop-up blocked", "Allow pop-ups to export PDF", "err"); return; }
  w.document.write(`<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title>
    <style>
      body{font:13.5px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;color:#14161b;max-width:800px;margin:32px auto;padding:0 24px;}
      h1{font-size:22px;margin:0 0 14px;} h2{font-size:16px;margin:22px 0 8px;border-bottom:1px solid #e6e8ec;padding-bottom:4px;} h3{font-size:14px;}
      code{font-family:ui-monospace,Menlo,monospace;background:#f2f3f5;padding:1px 5px;border-radius:4px;font-size:12px;}
      pre{background:#f6f7f9;border:1px solid #e6e8ec;border-radius:8px;padding:12px 14px;overflow:auto;} pre code{background:none;padding:0;}
      table{border-collapse:collapse;width:100%;margin:12px 0;} th,td{border:1px solid #e6e8ec;padding:7px 10px;text-align:left;font-size:12.5px;} th{background:#f6f7f9;}
      a{color:#4f46e5;} @media print{body{margin:0;}}
    </style></head><body>${innerHtml}</body></html>`);
  w.onload = () => setTimeout(() => w.print(), 250);
  w.document.close();
}

// ---------- view switching ----------
function setView(v) {
  document.body.classList.toggle("mode-findings", v === "findings");
  $("nav-runs").classList.toggle("active", v === "runs");
  $("nav-findings").classList.toggle("active", v === "findings");
  $("nav-runs").setAttribute("aria-current", v === "runs" ? "page" : "false");
  $("nav-findings").setAttribute("aria-current", v === "findings" ? "page" : "false");
  text("workspace-title", v === "findings" ? "Confirmed findings" : "Runs");
  if (v === "findings") loadFindings();
}
$("nav-runs").onclick = () => setView("runs");
$("nav-findings").onclick = () => setView("findings");

// ---------- findings hub ----------
let fSev = "all";
async function loadFindings() {
  if (findingsLoading || authenticated === false || disposed) return;
  findingsLoading = true; $("f-refresh").disabled = true;
  const requestEpoch = authEpoch;
  try {
    const data = await api("/api/findings");
    if (authenticated !== true || requestEpoch !== authEpoch) return;
    if (!Array.isArray(data.findings)) throw new Error("Invalid findings response");
    // Defense in depth; the server remains the authority for proof and signatures.
    findingsCache = confirmedFindings(data.findings);
    text("f-count", `${count(data.confirmed_count)} confirmed · ${count(data.suppressed_count)} report-gate suppressions`);
    renderFindings();
    if (fSel) {
      const current = findingsCache.find((finding) => finding.finding_id === fSel);
      if (current) renderFindingDetail(current);
      else {
        fSel = null; curSubmission = "";
        text("f-sel-title", "Select a finding");
        $("f-doc").innerHTML = emptyState("Finding no longer available", "Choose a confirmed finding from the list.");
        setFindingActions(false);
      }
    }
  } catch (error) {
    if (authenticated !== false) text("f-count", "Could not refresh findings · " + error.message);
  } finally { findingsLoading = false; $("f-refresh").disabled = false; }
}
function findingRow(f, selectedId = null) {
  const severity = severityName(f.severity);
  return `<button type="button" class="fitem ${f.finding_id === selectedId ? "active" : ""}" data-id="${esc(f.finding_id)}" aria-current="${f.finding_id === selectedId ? "true" : "false"}">
    <span class="ftitle">${esc(f.title || f.vuln_type || "Finding")}</span>
    <span class="fsub">${esc(f.endpoint || f.target || "")}</span>
    <span class="frow"><span class="sev ${severity}">${severity}</span>${f.cvss_score ? `<span class="fchip">CVSS ${esc(f.cvss_score)}</span>` : ""}${f.cwe ? `<span class="fchip">${esc(f.cwe)}</span>` : ""}
      <span class="vchip">${svg('<path d="M20 6L9 17l-5-5"/>', 2)}confirmed</span></span>
  </button>`;
}
function renderFindings() {
  const items = findingsCache.filter((f) => fSev === "all" || f.severity === fSev);
  const el = $("f-items");
  if (!items.length) {
    if (el.dataset.emptyKey === fSev) return;
    el.dataset.emptyKey = fSev;
    el.innerHTML = `<div class="empty">${svg('<path d="M12 3l8 4v5c0 4.4-3 8-8 9-5-1-8-4.6-8-9V7l8-4z"/><path d="M9.2 12l2 2 3.6-3.6"/>', 1.5)}<div class="t1">No independently confirmed findings ${fSev === "all" ? "found" : "at this severity"}</div><div class="t2">Scanner and model candidates stay hidden unless independent replay, controls, and class-specific proof pass.</div></div>`;
    return;
  }
  delete el.dataset.emptyKey;
  renderKeyedMarkup(el, items.map((finding) => ({ ...finding, id: finding.finding_id })), (finding) => findingRow(finding, fSel), selectFinding);
}
function setFindingActions(enabled) { ["f-copy", "f-dl", "f-pdf"].forEach((id) => { $(id).disabled = !enabled; }); }
function selectFinding(id) {
  if (authenticated === false) return;
  const f = findingsCache.find((x) => x.finding_id === id);
  if (!f) return;
  fSel = id; renderFindings(); document.body.classList.add("finding-open");
  if (window.matchMedia("(max-width: 760px)").matches) $("finding-back")?.focus();
  renderFindingDetail(f);
}
function renderFindingDetail(f) {
  $("f-sel-title").textContent = f.title || "Finding";
  const changed = curSubmission !== (f.submission || "");
  curSubmission = f.submission || "";
  curSubName = "reynard-" + (f.title || "finding").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) + ".md";
  if (changed) $("f-doc").innerHTML = mdToHtml(curSubmission);
  setFindingActions(Boolean(curSubmission));
}
$("f-filters").querySelectorAll(".chip").forEach((c) => {
  c.setAttribute("aria-pressed", String(c.dataset.sev === fSev));
  c.onclick = () => {
    fSev = c.dataset.sev; $("f-filters").querySelectorAll(".chip").forEach((x) => {
      x.classList.toggle("active", x === c); x.setAttribute("aria-pressed", String(x === c));
    }); renderFindings();
  };
});
$("f-refresh").onclick = loadFindings;
$("f-export").onclick = () => downloadFromApi("/api/findings.md", "reynard-findings.md");
$("f-copy").onclick = () => curSubmission && copyText(curSubmission, "Submission copied — paste into the program");
$("f-dl").onclick = () => curSubmission && downloadText(curSubName, curSubmission);
$("f-pdf").onclick = () => curSubmission && exportPdf($("f-sel-title").textContent, $("f-doc").innerHTML);

// ---------- boot ----------
let initialTheme = "dark"; try { initialTheme = readTheme(window.localStorage); } catch (_) {}
applyTheme(initialTheme);
$("report").innerHTML = emptyState("No run selected", "Pick a run on the left, or launch a new one.");
$("evidence").innerHTML = emptyState("No run selected", "Evidence appears here after a run.");
$("stream-wrap").innerHTML = emptyState("No run selected", "Select a run to watch live model reasoning and tool activity.");
$("f-doc").innerHTML = emptyState("Select a confirmed finding", "Review its evidence and copy a submission from the list.");
$("runs-refresh").onclick = async () => { await refreshRuns(); if (selected && !detailReady) selectRun(selected, true); };
on("run-search", "input", renderRuns); on("run-filter", "change", renderRuns);
on("welcome-new", "click", openDrawer);
on("detail-back", "click", () => {
  document.body.classList.remove("detail-open");
  Array.from($("runs").children).find((node) => node.dataset.id === selected)?.focus();
});
on("finding-back", "click", () => {
  document.body.classList.remove("finding-open");
  Array.from($("f-items").children).find((node) => node.dataset.id === fSel)?.focus();
});
setReportActions(false); setFindingActions(false); updateConnection();
health(); refreshRuns();
const runTimer = setInterval(() => {
  if (document.hidden) return;
  refreshRuns();
  if (document.body.classList.contains("mode-findings")) loadFindings();
  $("progress").classList.toggle("on", busy > 0 || anyRunning());
}, 3000);
const healthTimer = setInterval(() => { if (!document.hidden) health(); }, 15000);
window.addEventListener("offline", () => { offline = true; updateConnection(); });
window.addEventListener("online", () => { health(); refreshRuns(); });
window.addEventListener("pagehide", () => { disposed = true; closeStream(); stopLogTimer(); clearInterval(runTimer); clearInterval(healthTimer); });
window.addEventListener("pageshow", (event) => { if (event.persisted) window.location.reload(); });

})();
