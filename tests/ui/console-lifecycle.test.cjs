"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// A deliberately small DOM double for lifecycle tests. It does not emulate
// layout; real-browser checks remain necessary for CSS and visual focus.
function harness() {
  const nodes = new Map(), frames = [], requests = [];
  let document;
  function element(id = "") {
    const classes = new Set();
    return {
      id, dataset: {}, style: {}, innerHTML: "", textContent: "", value: "", children: [],
      disabled: false, open: false, hidden: false, inert: false, isConnected: true,
      classList: { add(...values) { values.forEach((value) => classes.add(value)); },
        remove(...values) { values.forEach((value) => classes.delete(value)); },
        contains(value) { return classes.has(value); },
        toggle(value, force) { const on = force ?? !classes.has(value); if (on) classes.add(value); else classes.delete(value); return on; } },
      setAttribute(name, value) { this[name] = value; },
      addEventListener() {}, querySelectorAll() { return []; },
      querySelector() { return element("anonymous-button"); },
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
    window: { localStorage: { getItem: () => "dark", setItem() {} }, addEventListener() {}, matchMedia: () => ({ matches: false }) },
    requestAnimationFrame: (callback) => frames.push(callback),
    setTimeout: () => 1, clearTimeout() {}, setInterval: () => 1, clearInterval() {},
    fetch: (url) => new Promise((resolve) => requests.push({ url, resolve })),
  });
  const source = fs.readFileSync(path.join(__dirname, "../../src/hacking_agent/harness/ui/console.js"), "utf8");
  // Test-only instrumentation retains the actual private functions and state;
  // no debug hook is exposed by the served production script.
  const hooks = `
    globalThis.testUI = { authError, api, openOverlay, closeOverlay,
      seed() { authenticated = true; selected = "prior-run"; runsCache = [{ id: "prior-run" }];
        reportMd = "private report"; reportRun = "prior-run"; findingsCache = [{ submission: "private proof" }];
        curSubmission = "private submission"; curSubName = "private.md"; fSel = "prior-finding"; },
      state() { return { selected, runsCache, reportMd, reportRun, findingsCache, curSubmission, curSubName, fSel, authenticated }; }
    };
  `;
  vm.runInContext(source.replace(/\}\)\(\);\s*$/, hooks + "})();"), context);
  return { ui: context.testUI, get, document, requests, flushFrame() { const callbacks = frames.splice(0); callbacks.forEach((callback) => callback()); } };
}

test("actual auth loss clears private DOM, caches, session drafts, and export actions", () => {
  const { ui, get } = harness();
  ui.seed();
  ["runs", "report", "evidence", "stream-wrap", "f-items", "f-doc", "cmdk-list", "toasts"].forEach((id) => { get(id).innerHTML = "private view"; });
  get("f-sessions").value = "private cookie";
  ui.authError();
  assert.doesNotMatch(JSON.stringify(ui.state()), /private|prior/);
  assert.equal(ui.state().authenticated, false);
  ["runs", "report", "evidence", "stream-wrap", "f-items", "f-doc"].forEach((id) => assert.match(get(id).innerHTML, /Session locked/));
  ["r-copy", "r-dl", "r-pdf", "f-copy", "f-dl", "f-pdf", "f-export"].forEach((id) => assert.equal(get(id).disabled, true));
  assert.equal(get("cmdk-list").innerHTML, ""); assert.equal(get("toasts").innerHTML, "");
  assert.equal(get("f-sessions").value, ""); assert.equal(get("login-dialog").open, true);
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
