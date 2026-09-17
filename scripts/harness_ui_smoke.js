/**
 * CLI-first Playwright smoke check; no @playwright/test dependency.
 * First open the isolated scripts/preview_harness_ui.py fixture and take a
 * playwright-cli snapshot, then run-code --filename scripts/harness_ui_smoke.js.
 * Never launches/cancels a run, writes to the clipboard, or opens print dialogs.
 */
async (page) => {
  const assert = (condition, message) => {
    if (!condition) throw new Error(`Harness UI smoke: ${message}`);
  };
  const origin = { origin: "http://127.0.0.1:8891" };
  const localPath = (url) => url.startsWith(origin.origin + "/")
    ? url.slice(origin.origin.length).split(/[?#]/)[0] : null;
  assert(localPath(page.url()) === "/",
    "refusing a non-fixture location; expected http://127.0.0.1:8891");

  // Read-only identity checks precede every browser interaction and login.
  const healthResponse = await page.request.get(`${origin.origin}/api/health`, { maxRedirects: 0 });
  assert(healthResponse.ok(), "fixture health is unavailable");
  const health = await healthResponse.json();
  assert(health.revision === "demo-local-preview" && health.auth_required === true,
    "refusing a service without the authenticated demo-local-preview identity");
  const fixtureToken = "reynard-local-ui-preview-only";
  const fixtureResponse = await page.request.get(`${origin.origin}/api/runs`, {
    headers: { "x-harness-token": fixtureToken },
    maxRedirects: 0,
  });
  assert(fixtureResponse.ok(), "fixture-only token was not accepted");
  const fixtureRuns = await fixtureResponse.json();
  const completedId = "demo00000002";
  assert(Array.isArray(fixtureRuns) && ["demo00000001", completedId, "demo00000003", "demo00000004"]
    .every((id) => fixtureRuns.some((run) => run.id === id)), "the four seeded fixture states are required");
  assert(fixtureRuns.every((run) => String(run.description).startsWith("[DEMO]")),
    "refusing a store containing non-demo records");

  const context = page.context();
  const initialViewport = page.viewportSize();
  const violations = [];
  const checks = [];
  const row = (id) => page.locator(`#runs > button.run[data-id="${id}"]`);
  const focusIs = (id) => page.waitForFunction((value) => document.activeElement?.id === value, id);
  const enabled = (id) => page.waitForFunction((value) => {
    const element = document.getElementById(value);
    return element && !element.disabled;
  }, id);
  const routeGuard = async (route) => {
    const request = route.request();
    const path = localPath(request.url());
    const allowed = path !== null && (
      request.method() === "GET" || (request.method() === "POST" && path === "/api/session")
    );
    if (!allowed) {
      violations.push(`${request.method()} ${request.url()}`);
      await route.abort("blockedbyclient");
    } else {
      await route.continue();
    }
  };
  const login = async () => {
    await page.locator("#login-token").fill(fixtureToken);
    await page.locator('#login-form button[type="submit"]').click();
    await page.waitForFunction(() => !document.getElementById("login-dialog").open);
    await row(completedId).waitFor({ state: "attached" });
  };
  const noOverflow = async (label) => {
    const bounds = await page.evaluate(() => ({
      viewport: document.documentElement.clientWidth,
      document: document.documentElement.scrollWidth,
      body: document.body.scrollWidth,
    }));
    assert(Math.max(bounds.document, bounds.body) <= bounds.viewport + 1,
      `${label} overflows horizontally: ${JSON.stringify(bounds)}`);
  };
  const tabIs = async (id, panel) => {
    await page.waitForFunction(({ id, panel }) => {
      const tab = document.getElementById(id);
      const content = document.getElementById(panel);
      return tab?.getAttribute("aria-selected") === "true" && tab.tabIndex === 0 && !content?.hidden;
    }, { id, panel });
    await focusIs(id);
    assert(await page.locator('[role="tab"][aria-selected="true"]').count() === 1,
      "exactly one details tab must be selected");
  };

  await page.route("**/*", routeGuard);
  try {
    await page.bringToFront();
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(origin.origin, { waitUntil: "domcontentloaded" });
    await page.waitForFunction(() => document.getElementById("login-dialog")?.open ||
      document.querySelector("#runs > button.run"));
    if (await page.locator("#login-dialog").evaluate((dialog) => dialog.open)) await login();
    await row(completedId).waitFor({ state: "visible" });
    checks.push("fixture identity and authenticated bootstrap");

    await page.locator("#btn-new").click();
    await focusIs("f-targets");
    assert(await page.locator("#app-shell").evaluate((shell) => shell.inert), "drawer must make the app inert");
    assert(!await page.locator("#f-authorized").isChecked(), "authorization cannot be preselected");
    assert(await page.locator("#f-targets").getAttribute("required") === null,
      "domains-only configuration must not require explicit targets");
    await page.locator("#f-submit").focus();
    await page.keyboard.press("Tab");
    await focusIs("drawer-close");
    await page.keyboard.press("Shift+Tab");
    await focusIs("f-submit");
    await page.keyboard.press("Escape");
    await focusIs("btn-new");
    assert(await page.locator("#drawer").getAttribute("aria-hidden") === "true", "drawer did not close");
    assert(!await page.locator("#app-shell").evaluate((shell) => shell.inert), "drawer left the app inert");
    checks.push("native drawer initial focus, two-way trap, authorization, and restoration");

    await page.locator("#nav-cmdk").focus();
    await page.keyboard.press("Control+k");
    await focusIs("cmdk-input");
    await page.locator("#cmdk-input").fill(completedId);
    await page.keyboard.press("ArrowDown");
    await page.waitForFunction(() => document.activeElement?.matches("#cmdk-list button.cmdk-item"));
    await page.keyboard.press("Escape");
    await focusIs("nav-cmdk");
    assert(await page.locator("#cmdk").getAttribute("aria-hidden") === "true", "quick switcher did not close");
    checks.push("keyboard quick switcher and Escape restoration");

    await page.locator("#run-search").fill(completedId);
    await page.waitForFunction(() => document.querySelectorAll("#runs > button.run").length === 1);
    assert(await row(completedId).isVisible(), "run search selected the wrong record");
    await page.locator("#run-search").fill("fixture-with-no-matching-record");
    await page.waitForFunction(() => document.getElementById("runs").textContent.includes("No matching runs"));
    await page.locator("#run-search").fill("");
    await page.locator("#run-filter").selectOption("failed");
    const failedCount = fixtureRuns.filter((run) => run.status === "failed").length;
    await page.waitForFunction((count) => document.querySelectorAll("#runs > button.run").length === count, failedCount);
    assert(await row("demo00000004").isVisible(), "failed status filter omitted its fixture");
    await page.locator("#run-filter").selectOption("all");
    await row(completedId).focus();
    // Observe the ordinary polling response without clicking away from the row.
    await page.waitForResponse((response) => localPath(response.url()) === "/api/runs" && response.ok());
    assert(await row(completedId).evaluate((element) => document.activeElement === element),
      "run-list polling stole keyboard focus");
    checks.push("search, empty search, status filter, and polling focus stability");

    await row(completedId).click();
    await enabled("r-dl");
    await page.locator("#tab-live").focus();
    await page.keyboard.press("ArrowRight");
    await tabIs("tab-console", "pane-console");
    await page.keyboard.press("ArrowRight");
    await tabIs("tab-report", "pane-report");
    await page.waitForFunction(() => document.getElementById("report").textContent.includes("[DEMO]"));
    await page.keyboard.press("End");
    await tabIs("tab-evidence", "pane-evidence");
    await page.waitForFunction(() => document.querySelector("#evidence tbody tr"));
    await page.keyboard.press("Home");
    await tabIs("tab-live", "pane-live");
    await page.waitForFunction(() => document.querySelector("#stream-wrap .ev"));
    checks.push("completed activity, report/evidence rendering, and keyboard tab navigation");

    await page.locator("#nav-findings").click();
    const finding = page.locator("#f-items > button.fitem").first();
    await finding.waitFor({ state: "visible" });
    await finding.click();
    await enabled("f-dl");
    for (const id of ["f-copy", "f-dl", "f-pdf"]) assert(await page.locator(`#${id}`).isEnabled(), `${id} stays disabled after selection`);
    assert(await page.locator("#f-doc").innerText().then((text) => text.includes("[DEMO]")), "finding submission is missing");
    const downloadEvent = page.waitForEvent("download");
    await page.locator("#f-dl").click();
    const download = await downloadEvent;
    assert(download.suggestedFilename().endsWith(".md"), "finding download is not Markdown");
    await download.saveAs("output/playwright/harness-ui-smoke-finding.md");
    checks.push("confirmed finding selection and Markdown download (no clipboard or print)");

    for (const width of [320, 390, 900, 1280, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      await page.locator("#nav-runs").click();
      if (width <= 760 && await page.locator("#detail-back").isVisible()) await page.locator("#detail-back").click();
      await row(completedId).waitFor({ state: "visible" });
      await noOverflow(`${width}px run list`);
      await row(completedId).click();
      await page.locator("#tab-report").click();
      await enabled("r-dl");
      await noOverflow(`${width}px report`);
      if (width <= 760) {
        await page.locator("#detail-back").click();
        assert(await row(completedId).evaluate((element) => document.activeElement === element), "mobile run back lost focus");
        assert(!await page.locator("#workspace-main").isVisible(), "mobile back did not restore run list");
      }
      await page.locator("#nav-findings").click();
      if (width <= 760 && await page.locator("#finding-back").isVisible()) await page.locator("#finding-back").click();
      await finding.waitFor({ state: "visible" });
      await noOverflow(`${width}px findings list`);
      await finding.click();
      await enabled("f-dl");
      await noOverflow(`${width}px finding detail`);
      if (width <= 760) {
        await page.locator("#finding-back").click();
        assert(await finding.evaluate((element) => document.activeElement === element), "mobile finding back lost focus");
        assert(!await page.locator(".fv-detail").isVisible(), "mobile back did not restore findings list");
      }
    }
    checks.push("320/390/900/1280/1440px layouts and mobile list/detail back navigation");

    await page.emulateMedia({ reducedMotion: "reduce" });
    const motion = await page.evaluate(() => ({
      preference: matchMedia("(prefers-reduced-motion: reduce)").matches,
      transitions: getComputedStyle(document.getElementById("drawer")).transitionDuration.split(",").map(Number.parseFloat),
      progress: getComputedStyle(document.getElementById("progress"), "::after").animationName,
    }));
    assert(motion.preference && motion.transitions.every((seconds) => seconds <= 0.001) && motion.progress === "none",
      `reduced-motion styles are ineffective: ${JSON.stringify(motion)}`);
    checks.push("computed reduced-motion transitions and progress animation");

    await page.locator("#nav-runs").click();
    await row(completedId).click();
    await enabled("r-dl");
    const failedRequest = page.waitForEvent("requestfailed", {
      predicate: (request) => localPath(request.url()) === "/api/runs",
    });
    await context.setOffline(true);
    await page.locator("#runs-refresh").click();
    await failedRequest;
    await page.waitForFunction(() => document.getElementById("conn-text").textContent.startsWith("Offline"));
    assert(await row(completedId).isVisible(), "offline mode discarded the last known list");
    const recovered = page.waitForResponse((response) => localPath(response.url()) === "/api/runs" && response.ok());
    await context.setOffline(false);
    await page.locator("#runs-refresh").click();
    await recovered;
    await page.waitForFunction(() => document.getElementById("conn-text").textContent === "Connected");
    checks.push("offline failure and real local API recovery");

    await page.locator("#nav-findings").click();
    await finding.click();
    await enabled("f-dl");
    // Clear only this fixture's cookie, not unrelated browser sessions.
    await context.clearCookies({ name: "reynard_session", domain: "127.0.0.1", path: "/" });
    await page.locator("#f-refresh").click();
    await page.waitForFunction(() => document.getElementById("login-dialog").open);
    for (const id of ["r-copy", "r-dl", "r-pdf", "f-copy", "f-dl", "f-pdf", "f-export"]) {
      assert(await page.locator(`#${id}`).isDisabled(), `${id} retained stale export access after session expiry`);
    }
    for (const id of ["runs", "report", "evidence", "stream-wrap", "f-items", "f-doc", "log"]) {
      assert(!(await page.locator(`#${id}`).textContent()).includes("[DEMO]"), `${id} retained private fixture data after expiry`);
    }
    assert(await page.locator("#runs > button.run").count() === 0, "expired session retained run records");
    assert(await page.locator("#f-items > button.fitem").count() === 0, "expired session retained findings");
    await login();
    await page.locator("#nav-runs").click();
    await row(completedId).waitFor({ state: "visible" });
    checks.push("expired authentication clears cached data/exports and permits reauthentication");

    assert(violations.length === 0, `blocked unexpected requests: ${violations.join(", ")}`);
    return { passed: checks.length, checks, fixture: origin.origin, revision: health.revision,
      download: "output/playwright/harness-ui-smoke-finding.md", researchRunsLaunched: 0 };
  } finally {
    await context.setOffline(false);
    await page.emulateMedia({ reducedMotion: null });
    if (initialViewport) await page.setViewportSize(initialViewport);
    await page.unroute("**/*", routeGuard);
  }
}
