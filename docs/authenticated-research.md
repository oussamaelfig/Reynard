# Authenticated research

Reynard can run explicit account/login recipes, crawl server-rendered pages as
controlled users, and replay declared private-resource checks. This is an
opt-in, scoped HTTP capability—not a universal browser agent or a guarantee of
business-logic coverage.

## What is implemented

| Capability | Boundary |
| --- | --- |
| Account creation | Explicit registration steps plus `allow_account_creation: true` and exact mutation permissions. At most one registration POST per identity. |
| Login | Declared GET/POST form steps; hidden fields can carry CSRF tokens from an earlier fetched form with a matching action. |
| Controlled users | Up to four isolated cookie/header identities, bound to one exact origin. A positive identity probe and negative controls must establish authentication. |
| Deep crawling | Breadth-first HTML links and passive form inventory within explicit read prefixes, page/depth/request limits and the engagement scope. |
| Business-rule checks | Read-only, exact private-resource GET contracts: an owner must see a specific JSON value; another controlled identity must not. Fresh session snapshots and repeat checks detect inconsistent results. |
| Multi-agent handoff | Sanitized discovery and rule observations seed the shared attack surface and agent memory before reasoning starts. |

The engine reuses the existing open-source [HTTPX transport](https://www.python-httpx.org/)
and Python HTML parser. No new runtime dependency, shell crawler, or downloaded
exploit pack is needed. The existing [Playwright implementation](https://github.com/microsoft/playwright-python)
was reviewed, but is **not enabled for production crawling**: browser egress,
redirects, subresources and state-changing interactions need their own constrained
transport before that boundary can be relaxed.

## Configure a run in the console

1. Start `reynard-harness` and open the local console.
2. Create a run with **one target**, explicit authorized scope and budgets.
3. Expand **Authenticated research**, enable it, and paste a plan into the plan
   field. Adapt [the local-only sample](../eval/authenticated-research.sample.json)
   to the actual form field names, URLs and disposable accounts in your app.
4. Add business rules if needed, then acknowledge authorization and launch.

The sample is a template, not a deployed test application. It expects existing
`qa-a` and `qa-b` accounts, `/login` form fields named `username`/`password`, and
`/api/me` returning an account-specific string `id`. Replace its placeholders.
Alternatively, supply each identity's `cookie_header` or `headers` and omit
`setup`; verification is still mandatory. Do not mix the new plan with legacy
`auth_sessions`.

Secrets remain in the operator's input, server/worker memory and stdin pipes.
Plans and business-rule values are excluded from saved run configuration, argv,
child environment and shared agent memory. The UI clears private fields on
disable, drawer close, successful launch and session loss. It does not save
credential drafts. Keep any private source files outside version control; the
ignored `.reynard-private/` directory is one option, **not an encrypted vault**.

## Explicit account creation

Only enable registration when the engagement permits creating disposable test
accounts. Add these steps **before login**, adapting field names to your app:

```json
[
  {"purpose": "register", "method": "GET", "url": "http://127.0.0.1:8080/register"},
  {
    "purpose": "register",
    "method": "POST",
    "url": "http://127.0.0.1:8080/register",
    "include_hidden_from": "http://127.0.0.1:8080/register",
    "fields": {"username": "qa-a", "password": "YOUR_DISPOSABLE_TEST_PASSWORD"}
  }
]
```

Also set `allow_account_creation` to `true` and add an exact permission:

```json
{"method": "POST", "url": "http://127.0.0.1:8080/register", "purpose": "register"}
```

Each identity gets its own credentials and verification value. Exact POST
permissions also apply to login and other declared setup workflows. The broad
`allow_destructive` checkbox does not grant this permission. Discovered forms
are never submitted automatically. POSTs are not retried; 307/308 redirects that
would replay a mutation stop for operator review.

A failed or cancelled run does not undo an account that was already created.
Check the app before retrying and clean up disposable data according to your
engagement. CAPTCHA, MFA, email confirmation, SSO redirects to other origins and
unrecognized forms need operator intervention; this implementation does not
bypass them or create external email accounts.

## Declare the business rule—not just a suspicious URL

For a controlled resource owned by `user-a`, this rule tests whether `user-b`
receives the same private object-specific value:

```json
[
  {
    "name": "private-invoice-owner",
    "url": "http://127.0.0.1:8080/api/invoices/42",
    "owner_identity": "user-a",
    "denied_identity": "user-b",
    "json_path": "/owner_id",
    "expected_value": "qa-a",
    "expected_denied_statuses": [401, 403, 404]
  }
]
```

`json_path` is a bounded RFC 6901 JSON pointer, not executable JSONPath. Use an
object/account-specific string or integer—not a generic `success: true` flag.
The resource must belong to a controlled account and actually be private under
the application's rules. Configure `denied_identity: "anonymous"` to check
unauthenticated exposure instead.

Results are `passed`, `inconclusive`, or `candidate`. `passed` only means this
declared access denial reproduced; it does not mean the application is secure.
Generic HTTP 200 responses, missing/ambiguous JSON markers, public/shared
resources, redirects, expired identities, truncated bodies and inconsistent
replays are not confirmed violations. The evidence contains hashes, response
status and assertion outcomes, not private response bodies or marker values.

**Business-rule candidates are not customer-reportable findings.** These checks
do not mint trusted validation receipts or bypass the existing export gate.
Ownership/access-policy assertions remain operator-supplied assumptions. A
dedicated trusted authorization/state-transition validation adapter is still
needed for confirmed business-logic reports.

## Scope, limits and failure behavior

- One exact origin per plan: scheme, host and port. All configured and runtime
  URLs must also satisfy the engagement's prefixes/exclusions and testing window.
- Every request, redirect and identity probe consumes the same target request
  budget. A separate research cap limits this phase even when the engagement's
  overall cap is higher. Business-rule probes share that cap.
- Only explicit read prefixes are crawled. Query-bearing links and common
  action-like paths are skipped. **GET is not inherently side-effect-free**:
  declare genuinely read-only paths, not a broad prefix containing actions.
- Authentication/setup failure stops the agent handoff. Crawl budget limits
  produce explicit partial coverage; they do not prove the remaining pages safe.
- The research deadline is checked around requests. Transport timeouts are
  per-operation, not an overall timer: rate-limit waits or a slow chunked
  response can overrun it until control returns. The target subprocess timeout
  is the final execution boundary.
- Requests are serial. No races, payment flows, invitations, deletion or privilege
  changes are generated automatically. A permitted setup workflow is not a
  license for the agent to invent additional mutations.
- The new credentials stay private to this constrained research path. They are
  not installed in the legacy tool registry, whose static headers lack equivalent
  origin binding. Agents receive observations, not unrestricted authenticated
  sessions.

This version does not execute JavaScript, inventory fetch/XHR traffic, preserve
browser localStorage, infer arbitrary workflows, test races or automatically
prove shopping-cart/payment/state-machine defects. Those need separate adapters
and local fixture evidence before production enablement.

## API and development

See the [exact local validation record](authenticated-research-validation.md)
for commands, test results, environment caveats and the follow-up loop/capability
issues identified from a stored run.

`POST /api/runs` accepts two additional optional fields:

```json
{"authenticated_research": {"...": "the plan above"}, "business_rules": []}
```

The Python `assess.run_target()` API accepts the same optional keyword arguments.
Existing CLI flags and callers are unchanged; there is no new file-loading CLI
flag. Private input is revalidated on both sides of the worker pipe.

Run local regressions without a provider key or Docker:

```bash
python -m pytest tests/test_authenticated_research.py tests/test_business_logic.py tests/test_authenticated_business_integration.py tests/test_research_pipeline.py
node --test tests/ui/*.test.cjs
```

## Design references

- [OWASP business-logic workflow testing](https://owasp.github.io/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows): application-specific requirements and misuse cases are necessary. This informed explicit operator contracts rather than heuristic vulnerability claims.
- [ZAP authentication concepts](https://www.zaproxy.org/docs/getting-further/authentication/concepts/): authentication and session verification are separate concerns. This informed positive/negative identity probes and expiry checks.
- [Playwright authentication](https://playwright.dev/python/docs/auth): isolated contexts support reproducibility, while stored auth state contains impersonation-capable secrets. This informed identity isolation and private state handling; it does not establish that Reynard has equivalent browser coverage.

These are design references, not evidence that Reynard matches another product's
coverage or performance.
