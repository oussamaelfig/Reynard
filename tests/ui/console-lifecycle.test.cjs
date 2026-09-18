"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// A deliberately small DOM double for lifecycle tests. It does not emulate
// layout; real-browser checks remain necessary for CSS and visual focus.
function harness() {
  const nodes = new Map(), frames = [], requests = [], storageWrites = [];
  let document;
  function element(id = "") {
    const classes = new Set();
    return {
      id, dataset: {}, style: {}, innerHTML: "", textContent: "", value: "", children: [],
      disabled: false, checked: false, required: false, open: false, hidden: false, inert: false, isConnected: true,
      classList: { add(...values) { values.forEach((value) => classes.add(value)); },
        remove(...values) { values.forEach((value) => classes.delete(value)); },
        contains(value) { return classes.has(value); },
        toggle(value, force) { const on = force ?? !classes.has(value); if (on) classes.add(value); else classes.delete(value); return on; } },
      setAttribute(name, value) { this[name] = value; },
      addEventListener() {}, querySelectorAll() { return []; },
      querySelector() { return element("anonymous-button"); },
      appendChild(child) { this.children.push(child); return child; },
      click() { return this.onclick?.(); }, checkValidity() { return true; },
      contains(other) { return other === this || this.children.includes(other); },
      focus() { document.activeElement = this; },
      showModal() { this.open = true; }, close() { this.open = false; },
    };
  }
  function get(id) { if (!nodes.has(id)) nodes.set(id, element(id)); return nodes.get(id); }
  document = {
    body: element("body"), documentElement: element("html"), activeElement: null,
    getElementById: get, querySelectorAll: () => [], querySelector: () => get("app-shell"),
    addEventListener() {}, createElement: element,
  };
  document.activeElement = get("nav-new");
  const context = vm.createContext({
    document, console, AbortController, AbortSignal: { timeout: () => ({}) },
    window: { localStorage: { getItem: () => "dark", setItem(...args) { storageWrites.push(args); } }, addEventListener() {}, matchMedia: () => ({ matches: false }) },
    requestAnimationFrame: (callback) => frames.push(callback),
    setTimeout: () => 1, clearTimeout() {}, setInterval: () => 1, clearInterval() {},
    fetch: (url, options) => new Promise((resolve) => requests.push({ url, options, resolve })),
  });
  const source = fs.readFileSync(path.join(__dirname, "../../src/hacking_agent/harness/ui/console.js"), "utf8");
  // Test-only instrumentation retains the actual private functions and state;
  // no debug hook is exposed by the served production script.
  const hooks = `
    globalThis.testUI = { authError, api, openOverlay, closeOverlay, submit, syncAuthenticatedFields, addRow,
      // The submit lifecycle test ends at acceptance/cleanup; its DOM double
      // does not implement the separate run-list/detail rendering feature.
      suppressPostLaunchNavigation() { refreshRuns = async () => {}; selectRun = () => {}; },
      seed() { authenticated = true; selected = "prior-run"; runsCache = [{ id: "prior-run" }];
        reportMd = "private report"; reportRun = "prior-run"; findingsCache = [{ submission: "private proof" }];
        curSubmission = "private submission"; curSubName = "private.md"; fSel = "prior-finding"; },
      state() { return { selected, runsCache, reportMd, reportRun, findingsCache, curSubmission, curSubName, fSel, authenticated }; }
    };
  `;
  vm.runInContext(source.replace(/\}\)\(\);\s*$/, hooks + "})();"), context);
  return { ui: context.testUI, get, document, requests, storageWrites, flushFrame() { const callbacks = frames.splice(0); callbacks.forEach((callback) => callback()); } };
}

test("actual auth loss clears private DOM, caches, session drafts, and export actions", () => {
  const { ui, get } = harness();
  ui.seed();
  ["runs", "report", "evidence", "stream-wrap", "f-items", "f-doc", "cmdk-list", "toasts"].forEach((id) => { get(id).innerHTML = "private view"; });
  get("f-sessions").value = "private cookie";
  get("f-authenticated-enable").checked = true;
  get("f-authenticated-plan").value = "private research credential";
  get("f-business-rules").value = "private owner value";
  ui.authError();
  assert.doesNotMatch(JSON.stringify(ui.state()), /private|prior/);
  assert.equal(ui.state().authenticated, false);
  ["runs", "report", "evidence", "stream-wrap", "f-items", "f-doc"].forEach((id) => assert.match(get(id).innerHTML, /Session locked/));
  ["r-copy", "r-dl", "r-pdf", "f-copy", "f-dl", "f-pdf", "f-export"].forEach((id) => assert.equal(get(id).disabled, true));
  assert.equal(get("cmdk-list").innerHTML, ""); assert.equal(get("toasts").innerHTML, "");
  assert.equal(get("f-sessions").value, ""); assert.equal(get("login-dialog").open, true);
  assert.equal(get("f-authenticated-enable").checked, false);
  ["f-authenticated-plan", "f-business-rules"].forEach((id) => {
    assert.equal(get(id).value, ""); assert.equal(get(id).disabled, true);
  });
});

test("an API success from the expired auth epoch is rejected before returning private data", async () => {
  const { ui, requests } = harness(); ui.seed();
  const pending = ui.api("/private-fixture");
  ui.authError();
  requests.find((request) => request.url === "/private-fixture").resolve({ ok: true, status: 200, json: async () => ({ secret: "must not render" }) });
  await assert.rejects(pending, /Session changed/);
  assert.equal(ui.state().authenticated, false);
});

test("drawer waits two frames for visibility before focusing and restores its trigger", () => {
  const { ui, get, document, flushFrame } = harness();
  ui.openOverlay("drawer", "f-targets");
  assert.equal(get("app-shell").inert, true);
  assert.equal(document.activeElement, get("nav-new"));
  flushFrame(); assert.equal(document.activeElement, get("nav-new"));
  flushFrame(); assert.equal(document.activeElement, get("f-targets"));
  ui.closeOverlay("drawer");
  assert.equal(get("drawer").inert, true); assert.equal(get("app-shell").inert, false);
  assert.equal(document.activeElement, get("nav-new"));
});

test("a closed or replaced drawer cannot steal focus when its animation frame arrives", () => {
  const { ui, get, document, flushFrame } = harness();
  ui.openOverlay("drawer", "f-targets"); ui.closeOverlay("drawer");
  ui.openOverlay("cmdk", "cmdk-input"); flushFrame(); flushFrame();
  assert.equal(document.activeElement, get("cmdk-input"));
  assert.equal(get("drawer").inert, true);
});

test("authenticated opt-in reveals required fields and disabling clears only research drafts", () => {
  const { ui, get, storageWrites } = harness();
  get("f-authenticated-enable").checked = true; ui.syncAuthenticatedFields();
  assert.equal(get("f-authenticated-fields").hidden, false);
  assert.equal(get("f-authenticated-enable")["aria-expanded"], "true");
  assert.equal(get("f-authenticated-plan").required, true);
  assert.equal(get("f-authenticated-plan").disabled, false);
  get("f-authenticated-plan").value = "private plan";
  get("f-business-rules").value = "private rule";
  get("f-sessions").value = "independent session";
  get("f-authenticated-enable").checked = false; ui.syncAuthenticatedFields();
  assert.equal(get("f-authenticated-fields").hidden, true);
  assert.equal(get("f-authenticated-enable")["aria-expanded"], "false");
  assert.equal(get("f-authenticated-plan").required, false);
  for (const id of ["f-authenticated-plan", "f-business-rules"]) {
    assert.equal(get(id).value, ""); assert.equal(get(id).disabled, true);
  }
  assert.equal(get("f-sessions").value, "independent session");
  assert.doesNotMatch(JSON.stringify(storageWrites), /private|independent/);
});

test("drawer cancellation clears all session and research drafts without a launch", () => {
  const { ui, get, requests } = harness();
  ui.openOverlay("drawer", "f-targets");
  get("f-sessions").value = "private session";
  get("f-authenticated-enable").checked = true;
  get("f-authenticated-plan").value = "private plan";
  get("f-business-rules").value = "private rule";
  get("drawer-cancel").click();
  for (const id of ["f-sessions", "f-authenticated-plan", "f-business-rules"]) assert.equal(get(id).value, "");
  assert.equal(get("f-authenticated-enable").checked, false);
  assert.equal(requests.some((request) => request.options?.method === "POST"), false);
});

test("malformed research JSON prevents launch, identifies the field, and does not echo secrets", async () => {
  const { ui, get, requests, document } = harness(); ui.seed();
  get("f-authenticated-enable").checked = true;
  get("f-authenticated-plan").value = '{"cookie_header":"private-secret"';
  await ui.submit();
  assert.equal(requests.some((request) => request.options?.method === "POST"), false);
  assert.equal(document.activeElement, get("f-authenticated-plan"));
  assert.equal(get("f-authenticated-plan")["aria-invalid"], "true");
  assert.equal(get("f-authenticated-section").open, true);
  assert.match(get("f-msg").textContent, /Research plan must be valid JSON/);
  assert.doesNotMatch(get("f-msg").textContent, /private-secret/);
});

test("successful mocked launch sends explicit research data then clears every sensitive field", async () => {
  const { ui, get, requests, storageWrites } = harness(); ui.seed();
  ui.suppressPostLaunchNavigation();
  ui.openOverlay("drawer", "f-targets");
  get("f-authenticated-enable").checked = true;
  get("f-authenticated-enable").type = "checkbox";
  get("f-authenticated-plan").value = JSON.stringify({
    origin: "https://fixture.test", read_prefixes: ["https://fixture.test/api"],
    identities: [{ name: "owner", cookie_header: "session=private-cookie",
      verification: { url: "https://fixture.test/api/me", marker: "fixture-owner-only" } }],
  });
  get("f-business-rules").value = JSON.stringify([{ name: "private-rule", url: "https://fixture.test/api/record/42",
    owner_identity: "owner", denied_identity: "anonymous", json_path: "/id", expected_value: "fixture-42" }]);
  const values = { "f-targets": "https://fixture.test/", "f-domains": "fixture.test",
    "f-iter": "30", "f-timeout": "1800", "f-rps": "0", "f-maxreq": "0" };
  Object.entries(values).forEach(([id, value]) => { get(id).value = value; });
  get("f-authorized").type = "checkbox"; get("f-authorized").checked = true;
  get("drawer").querySelectorAll = () => ["f-authenticated-enable", "f-authenticated-plan", "f-business-rules", "f-sessions",
    "f-authorized", ...Object.keys(values)].map(get);
  const pending = ui.submit();
  const request = requests.find((item) => item.url === "/api/runs" && item.options?.method === "POST");
  assert.ok(request);
  const body = JSON.parse(request.options.body);
  assert.equal(body.authenticated_research.identities[0].cookie_header, "session=private-cookie");
  assert.equal(body.business_rules[0].name, "private-rule");
  assert.deepEqual(body.auth_sessions, []);
  request.resolve({ ok: true, status: 201, json: async () => ({ run_id: "fixture-run" }) });
  await pending;
  for (const id of ["f-sessions", "f-authenticated-plan", "f-business-rules"]) assert.equal(get(id).value, "");
  assert.equal(get("f-authenticated-enable").checked, false);
  assert.equal(get("f-submit").disabled, false);
  assert.equal(get("f-msg").textContent, "");
  assert.doesNotMatch(JSON.stringify(storageWrites), /private/);
});

test("mixed authentication modes are rejected before fetch and focus the legacy session field", async () => {
  const { ui, get, requests, document } = harness(); ui.seed();
  get("f-authenticated-enable").checked = true;
  get("f-authenticated-plan").value = "{}";
  get("f-sessions").value = '[{"name":"legacy","cookie_header":"private-cookie"}]';
  await ui.submit();
  assert.equal(requests.some((request) => request.options?.method === "POST"), false);
  assert.equal(document.activeElement, get("f-sessions"));
  assert.equal(get("f-sessions")["aria-invalid"], "true");
  assert.equal(get("f-advanced-section").open, true);
  assert.match(get("f-msg").textContent, /Clear Auth sessions or disable authenticated research/);
  assert.doesNotMatch(get("f-msg").textContent, /private-cookie/);
});

test("research summary displays whitelisted counts and rule indices without promoting findings", () => {
  const { ui } = harness(); ui.seed();
  const before = JSON.stringify(ui.state());
  const rows = [];
  ui.addRow({ appendChild: (row) => rows.push(row) }, {
    type: "research_summary", payload: {
      research: { page_count: 7, endpoint_count: 11, total_request_count: 29, partial: true },
      business_rules: { metrics: { passed_count: 1, candidate_count: 1, inconclusive_count: 1 }, results: [
        { rule_index: 0, classification: "passed", reason: "declared_access_denied" },
        { rule_index: 1, classification: "candidate", reason: "private_marker_reproduced" },
        { rule_index: 2, classification: "inconclusive", reason: "identity_verification_failed" },
      ] },
    },
  });
  assert.equal(rows.length, 1); assert.equal(rows[0].className, "block");
  assert.equal(rows[0].dataset.eventType, "research_summary");
  const html = rows[0].innerHTML;
  assert.match(html, /7 pages · 11 endpoints · 29 total requests/);
  assert.match(html, /Partial coverage: yes/);
  assert.match(html, /Rules: 1 passed · 1 candidates · 1 inconclusive/);
  assert.match(html, /zero-based positions/);
  assert.match(html, /Rule \[1\]: candidate · private_marker_reproduced/);
  assert.match(html, /Rule \[2\]: inconclusive · identity_verification_failed/);
  assert.match(html, /not confirmed findings/);
  assert.equal(JSON.stringify(ui.state()), before, "activity rendering must not insert a finding or change export state");
});

test("research summary ignores raw bodies, URLs, markers, messages, and unsafe result fields", () => {
  const { ui } = harness();
  const rows = [];
  ui.addRow({ appendChild: (row) => rows.push(row) }, {
    type: "research_summary", payload: {
      message: "<img src=x onerror=alert(1)> private-message",
      research: { page_count: '<img src=x>', endpoint_count: -1, total_request_count: Infinity, partial: "true",
        observations: [{ url: "https://private.test/object/secret", body: "private-body" }], marker: "private-marker" },
      business_rules: { metrics: { passed_count: "private-count", candidate_count: 1.5, inconclusive_count: null,
        verified_count: 99, reportable_count: 99 }, results: [
        { rule_index: 0, classification: '<img src=x>', reason: "private-reason", evidence: [{ body: "private-evidence" }] },
        { rule_index: '1 onload="bad"', classification: "candidate", reason: "private_marker_reproduced" },
        { rule_index: 20, classification: "candidate", reason: "private_marker_reproduced" },
      ] },
    },
  });
  assert.equal(rows.length, 1);
  assert.match(rows[0].innerHTML, /— pages · — endpoints · — total requests/);
  assert.match(rows[0].innerHTML, /Partial coverage: not reported/);
  assert.match(rows[0].innerHTML, /Rules: — passed · — candidates · — inconclusive/);
  assert.match(rows[0].innerHTML, /Rule \[0\]: unknown · unrecognized_reason/);
  assert.doesNotMatch(rows[0].innerHTML, /<img|private-|private\.test|onload|Infinity|verified_count|reportable_count|Rule \[20\]/);
});

test("research summary bounds rule output to twenty entries and tolerates malformed containers", () => {
  const { ui } = harness();
  const rows = [];
  ui.addRow({ appendChild: (row) => rows.push(row) }, {
    type: "research_summary", payload: {
      research: { page_count: 0, endpoint_count: 0, total_request_count: 0, partial: false },
      business_rules: { results: Array.from({ length: 40 }, (_, rule_index) => ({
        rule_index, classification: "inconclusive", reason: "marker_missing_or_ambiguous",
      })) },
    },
  });
  assert.equal((rows[0].innerHTML.match(/Rule \[/g) || []).length, 20);
  assert.match(rows[0].innerHTML, /Rule \[19\]/);
  assert.match(rows[0].innerHTML, /Partial coverage: no/);
  assert.match(rows[0].innerHTML, /Additional results omitted/);
  assert.ok(rows[0].innerHTML.length < 4000);
  for (const payload of [{}, { research: [], business_rules: "private-raw" }, { business_rules: { results: [null, "private-raw"] } }]) {
    assert.doesNotThrow(() => ui.addRow({ appendChild: (row) => rows.push(row) }, { type: "research_summary", payload }));
  }
  assert.doesNotMatch(rows.slice(1).map((row) => row.innerHTML).join(""), /private-raw/);
  ui.addRow({ appendChild: (row) => rows.push(row) }, {
    type: "research_summary", payload: { message: "Starting scoped authenticated research." },
  });
  assert.match(rows.at(-1).innerHTML, /Starting scoped authenticated research/);
  assert.doesNotMatch(rows.at(-1).innerHTML, /0 pages|completed/);
});
