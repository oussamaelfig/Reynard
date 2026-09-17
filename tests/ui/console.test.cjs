"use strict";

// No browser, network, package installation, or assessment worker is required.
const test = require("node:test");
const assert = require("node:assert/strict");
const ui = require("../../src/hacking_agent/harness/ui/console.js");

test("untrusted text is escaped in text and quoted attribute contexts", () => {
  assert.equal(ui.esc('&<>"\''), "&amp;&lt;&gt;&quot;&#39;");
  assert.equal(ui.esc(null), "");
  const row = ui.runRow({ id: '\" onclick="alert(1)', targets: ["<img src=x onerror=alert(1)>"], status: "completed" });
  assert.match(row, /^<button type="button" class="run /);
  assert.match(row, /data-id="&quot; onclick=&quot;alert\(1\)"/);
  assert.doesNotMatch(row, /<img|<div/);
  assert.match(row, /aria-current="false"/);
});

test("status and severity are allowlisted before use in CSS classes", () => {
  assert.equal(ui.statusName("running"), "running");
  assert.equal(ui.statusName('failed\" onclick="bad'), "unknown");
  assert.match(ui.badge('failed\" onclick="bad'), /class="badge unknown"/);
  assert.equal(ui.severityName("critical"), "critical");
  assert.equal(ui.severityName('<script>'), "info");
});

test("run rows distinguish research objectives and retain the actual target", () => {
  const row = ui.runRow({ id: "fixture", status: "running", description: "  Account role review  ", targets: ["https://lab.test/"] });
  assert.match(row, /class="rtarget">Account role review<\/span>/);
  assert.match(row, /class="rendpoint">https:\/\/lab.test\/<\/span>/);
  const fallback = ui.runRow({ id: "fixture", status: "running", description: " \n ", targets: ["https://lab.test/"] });
  assert.match(fallback, /class="rtarget">https:\/\/lab.test\/<\/span>/);
  assert.doesNotMatch(fallback, /class="rendpoint"/);
});

test("finding rows are native buttons and escape every untrusted field", () => {
  const row = ui.findingRow({ finding_id: 'a"b', severity: 'high" onfocus="x', title: "<script>x</script>", cvss_score: "<img src=x>", cwe: '"cwe' }, 'a"b');
  assert.match(row, /^<button type="button" class="fitem active"/);
  assert.match(row, /data-id="a&quot;b" aria-current="true"/);
  assert.match(row, /class="sev info"/);
  assert.match(row, /CVSS &lt;img src=x&gt;/);
  assert.doesNotMatch(row, /<script|<img|<div/);
});

test("Markdown source HTML, unsafe links, and code remain inert", () => {
  const rendered = ui.mdToHtml('# <img src=x onerror=alert(1)>\n**safe** [x](javascript:alert(1))\n```html\n</code><script>x</script>\n```');
  assert.match(rendered, /<h1>&lt;img/);
  assert.match(rendered, /<strong>safe<\/strong>/);
  assert.match(rendered, /&lt;\/code&gt;&lt;script&gt;/);
  assert.doesNotMatch(rendered, /<img|<script|<a /);
});

test("Markdown subset closes lists, code, and tables", () => {
  assert.match(ui.mdToHtml("- one\n- two"), /<ul><li>one<\/li><li>two<\/li><\/ul>$/);
  assert.match(ui.mdToHtml("```\nopen"), /<pre><code>open\n<\/code><\/pre>$/);
  assert.match(ui.mdToHtml("| a | b |\n| - | - |\n| c | d |"), /^<table>.*<\/table>$/);
});

test("run search matches targets, IDs, and objectives with status intersection", () => {
  const runs = [
    { id: "r-A", status: "running", targets: ["https://Lab.test"], description: "Review roles" },
    { id: "r-B", status: "failed", targets: ["https://other.test"], description: "Check LAB settings" },
  ];
  assert.deepEqual(ui.filterRuns(runs, " lab "), runs);
  assert.deepEqual(ui.filterRuns(runs, "LAB", "running"), [runs[0]]);
  assert.deepEqual(ui.filterRuns(runs, "r-b"), [runs[1]]);
  assert.deepEqual(ui.filterRuns(runs, "missing"), []);
});

test("workspace summary is derived only from actual run records", () => {
  assert.equal(ui.runSummary([]), "0 runs · 0 running · 0 queued · 0 confirmed");
  assert.equal(ui.runSummary([{ status: "running", findings_count: 2 }, { status: "queued", findings_count: -3 }, { status: "completed", findings_count: 1 }]), "3 runs · 1 running · 1 queued · 3 confirmed");
  assert.equal(ui.runSummary([{ status: "completed", findings_count: "3" }]), "1 run · 0 running · 0 queued · 3 confirmed");
  assert.equal(ui.count(Infinity), 0);
  assert.equal(ui.count("unknown"), 0);
});

test("findings require the server's explicit confirmed flags", () => {
  const confirmed = { finding_id: "yes", verified: true, verification_status: "verified" };
  assert.deepEqual(ui.confirmedFindings([
    confirmed,
    { finding_id: "candidate", verified: false, verification_status: "candidate" },
    { finding_id: "missing-proof", verified: true },
    { finding_id: "truthy-string", verified: "true", verification_status: "verified" },
  ]), [confirmed]);
});

test("a private session reset removes every cached finding and export buffer", () => {
  let state = { selected: "prior-run", runsCache: [{ description: "private objective" }],
    reportMd: "private report", reportRun: "prior-run", findingsCache: [{ submission: "private proof" }],
    fSel: "prior-finding", curSubmission: "private submission", curSubName: "private-title.md" };
  state = ui.emptyPrivateSession();
  assert.deepEqual(state, { selected: null, runsCache: [], reportMd: "", reportRun: "", findingsCache: [],
    fSel: null, curSubmission: "", curSubName: "finding.md" });
  assert.doesNotMatch(JSON.stringify(state), /private|prior/);
  state.runsCache.push({ id: "new-session" });
  assert.deepEqual(ui.emptyPrivateSession().runsCache, []);
});

test("a late run response cannot replace the newly selected run", () => {
  const gate = ui.createRequestGate();
  gate.select("A"); const stale = gate.issue("report", "A");
  gate.select("B"); const current = gate.issue("report", "B");
  assert.equal(gate.accepts(stale), false);
  assert.equal(gate.accepts(current), true);
});

test("switching away and back rejects responses from the earlier visit", () => {
  const gate = ui.createRequestGate();
  gate.select("A"); const previousVisit = gate.issue("evidence", "A");
  gate.select("B"); gate.select("A");
  assert.equal(gate.accepts(previousVisit), false);
  assert.equal(gate.accepts(gate.issue("evidence", "A")), true);
});

test("newer refresh supersedes old refresh without blocking independent channels", () => {
  const gate = ui.createRequestGate(); gate.select("run");
  const older = gate.issue("report", "run");
  const log = gate.issue("log", "run");
  const newer = gate.issue("report", "run");
  assert.equal(gate.accepts(older), false);
  assert.equal(gate.accepts(log), true);
  assert.equal(gate.accepts(newer), true);
});

test("unscoped list requests can be versioned independently of selection", () => {
  const gate = ui.createRequestGate(); const list = gate.issue("list");
  gate.select("A"); assert.equal(gate.accepts(list), true);
  gate.issue("list"); assert.equal(gate.accepts(list), false);
});

test("stream deduplication memory is bounded and can be reset per run", () => {
  const seen = ui.createSeenWindow(3);
  assert.equal(seen.add(1), true); assert.equal(seen.add(1), false);
  [2, 3, 4].forEach((id) => seen.add(id));
  assert.equal(seen.size, 3); assert.equal(seen.add(2), false);
  assert.equal(seen.add(1), true); assert.equal(seen.size, 3);
  seen.clear(); assert.equal(seen.size, 0); assert.equal(seen.add(1), true);
});

test("merged output blocks retain a bounded, recent text tail", () => {
  assert.equal(ui.boundedText("12345", "67890", 6), "567890");
  assert.equal(ui.boundedText("a".repeat(16000), "b".repeat(16000)).length, 16000);
  assert.equal(ui.boundedText("<script>", "alert(1)", 100), "<script>alert(1)");
});

test("theme works when browser storage is denied, absent, or invalid", () => {
  const denied = { getItem() { throw new Error("denied"); }, setItem() { throw new Error("denied"); } };
  assert.equal(ui.readTheme(denied), "dark");
  assert.doesNotThrow(() => ui.writeTheme(denied, "light"));
  assert.equal(ui.readTheme(undefined), "dark");
  assert.equal(ui.readTheme({ getItem: () => "unexpected" }), "dark");
  assert.equal(ui.readTheme({ getItem: () => "light" }), "light");
  const calls = []; ui.writeTheme({ setItem: (...args) => calls.push(args) }, "light");
  assert.deepEqual(calls, [["reynard-theme", "light"]]);
});

test("tab navigation wraps, supports Home/End, and leaves unrelated keys alone", () => {
  assert.equal(ui.tabNavigationIndex("ArrowRight", 3, 4), 0);
  assert.equal(ui.tabNavigationIndex("ArrowLeft", 0, 4), 3);
  assert.equal(ui.tabNavigationIndex("Home", 2, 4), 0);
  assert.equal(ui.tabNavigationIndex("End", 0, 4), 3);
  assert.equal(ui.tabNavigationIndex("Enter", 1, 4), null);
  assert.equal(ui.tabNavigationIndex("ArrowRight", 0, 0), null);
});

test("dialog focus cycles in both directions without disturbing interior Tab order", () => {
  const items = [{ id: "first" }, { id: "middle" }, { id: "last" }];
  assert.equal(ui.focusTrapTarget(items, items[2], false), items[0]);
  assert.equal(ui.focusTrapTarget(items, items[0], true), items[2]);
  assert.equal(ui.focusTrapTarget(items, items[1], false), null);
  assert.equal(ui.focusTrapTarget(items, {}, false), items[0]);
  assert.equal(ui.focusTrapTarget(items, {}, true), items[2]);
  assert.equal(ui.focusTrapTarget([], {}, false), null);
});

function fakeContainer(ids) {
  const container = { children: [], insertBefore(node, before) {
    this.children = this.children.filter((existing) => existing !== node);
    const index = before ? this.children.indexOf(before) : this.children.length;
    this.children.splice(index, 0, node);
  } };
  const node = (id) => ({ dataset: { id }, remove() { container.children = container.children.filter((existing) => existing !== this); } });
  container.children = ids.map(node);
  return { container, node };
}

test("polling reuses row elements so a focused button is not replaced", () => {
  const { container, node } = fakeContainer(["a", "b"]);
  const focused = container.children[1]; const before = [...container.children];
  const updates = [];
  ui.reconcileKeyed(container, [{ id: "a" }, { id: "b" }], (item) => node(item.id), (element, item) => updates.push([element, item.id]));
  assert.deepEqual(container.children, before);
  assert.equal(container.children[1], focused);
  assert.equal(updates.length, 2);
});

test("keyed reconciliation preserves identities while adding, reordering, and removing", () => {
  const { container, node } = fakeContainer(["a", "b", "obsolete"]);
  const a = container.children[0], b = container.children[1];
  ui.reconcileKeyed(container, [{ id: "b" }, { id: "new" }, { id: "a" }], (item) => node(item.id), () => {});
  assert.deepEqual(container.children.map((item) => item.dataset.id), ["b", "new", "a"]);
  assert.equal(container.children[0], b); assert.equal(container.children[2], a);
});

test("launch request preserves domains-only scope and explicit zero budget values", () => {
  const body = ui.buildRunRequest({ "f-targets": "", "f-domains": " app.example.test,\napi.example.test ", "f-iter": "30", "f-timeout": "1800", "f-rps": "0", "f-maxreq": "0", "f-authorized": true });
  assert.deepEqual(body.targets, []);
  assert.deepEqual(body.authorized_domains, ["app.example.test", "api.example.test"]);
  assert.equal(body.max_requests_per_second, 0); assert.equal(body.max_total_requests, 0);
  assert.equal(body.authorized, true); assert.equal(body.allow_destructive, false);
  assert.equal(body.enable_hexstrike, false); assert.deepEqual(body.auth_sessions, []);
});

test("launch identity and explicit opt-ins remain in the request only", () => {
  const sessions = [{ name: "fixture", cookie_header: "session=fixture-only" }];
  const body = ui.buildRunRequest({ "f-targets": "https://lab.test/", "f-prefixes": "https://lab.test/api", "f-oos": "https://lab.test/private", "f-desc": " review ", "f-destructive": true, "f-browser": true, "f-hexstrike": true, "f-authorized": "true" }, sessions);
  assert.equal(body.auth_sessions, sessions);
  assert.deepEqual(body.authorized_url_prefixes, ["https://lab.test/api"]);
  assert.deepEqual(body.out_of_scope, ["https://lab.test/private"]);
  assert.equal(body.description, "review"); assert.equal(body.allow_destructive, true);
  assert.equal(body.enable_browser_use, true); assert.equal(body.enable_hexstrike, true);
  assert.equal(body.authorized, false);
});

test("relative timestamps tolerate malformed and timezone-aware server values", () => {
  assert.equal(ui.relTime("not-a-date"), "");
  assert.equal(ui.relTime(null), "");
  assert.equal(ui.relTime("2999-01-01T00:00:00+02:00"), "0s ago");
});
