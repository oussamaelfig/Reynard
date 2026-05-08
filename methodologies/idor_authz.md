# IDOR / Broken Authorization
## (Horizontal & Vertical Privilege)

> #1 paid bug class on B2B SaaS. Cannot be detected by a single-user agent.
> Use multiple registered sessions via `swap_session(name=...)` and the
> `diff_against_baseline` tool to compare cross-user responses.

---

## Phase 1: Setup

### 1.1 Required sessions
At minimum:
- `unauth` — no cookies, no Authorization header
- `user1` — low-privilege account A
- `user2` — low-privilege account B (different tenant if multi-tenant)
- `admin` — high-privilege account

If only one is provided, you can still hunt vertical authz against `unauth`
but you cannot detect horizontal IDOR. Surface this gap in the report.

### 1.2 Endpoint inventory
Pull the candidates from:
- `extract_js_endpoints` against the main page (rich source — SPAs leak everything)
- `discover_apis` (swagger/openapi/graphql)
- nuclei + manual recon endpoints

For each: identify the resource identifier in the URL or body. Common shapes:
- `/api/users/{id}`
- `/api/orders/{order_id}`
- `/api/files/{uuid}`
- `?user_id=`, `?account=`, `?tenant=`
- JSON body: `{"recipient_id": ..., "owner": ...}`

---

## Phase 2: Horizontal IDOR Detection

### 2.1 Capture baselines under user1
For each candidate endpoint that returns a user-scoped resource:
```
swap_session(name="user1")
capture_baseline(name="user1-resource-X", url="...")
```

### 2.2 Probe user2 against user1's resources
```
swap_session(name="user2")
diff_against_baseline(baseline_name="user1-resource-X", url="...")
```

The diff tells you:
- Same status (200) + similar length + matching JSON keyset → **strong IDOR signal**
  (user2 got user1's data)
- 403/404 + smaller length + error message → properly scoped (good)
- 500 → broken authz check, worth reporting
- Same status but different JSON keys → partial info disclosure
  (some fields leaked even though full resource didn't)

### 2.3 Identifier mutations
Even with proper auth, weak ID predictability matters:
- Sequential IDs: probe `id-1`, `id-2`, `id+1`, `id+1000`
- UUIDs: low entropy? predictable timestamp prefix?
- Slugs: predictable from username?

### 2.4 The "create + read as other" test
1. As user1: create a resource `POST /api/notes` → get back `{"id": 42}`
2. As user2: `GET /api/notes/42` — should be 403/404
3. As user2: `PATCH /api/notes/42` — should be 403/404
4. As user2: `DELETE /api/notes/42` — should be 403/404

Each verb is a separate finding if it's broken. Many apps protect GET but
not DELETE.

---

## Phase 3: Vertical Privilege

### 3.1 Admin endpoints under low-priv
```
swap_session(name="admin")
capture_baseline(name="admin-list-users", url="/api/admin/users")
swap_session(name="user1")
diff_against_baseline(baseline_name="admin-list-users", url="/api/admin/users")
```
Same status + similar response = vertical authz bypass.

### 3.2 Method bypasses
Some apps gate on Method but the underlying handler accepts all:
- `POST /admin/users/X/delete` blocked, but `GET /admin/users/X/delete`?
- Override headers: `X-HTTP-Method-Override: DELETE`, `X-Method: DELETE`
- Trailing slash, double slash, encoded variants of admin path:
  `/admin/`, `/admin//`, `/admin/.`, `/Admin/`, `/admin%2f`

### 3.3 Mass assignment (privilege via param)
- As user1, send `PUT /api/users/me` with body `{"role": "admin"}` —
  do you get 200 with `role=admin` echoed back?
- Try also: `is_admin=true`, `permissions=["*"]`, `tenant_id=other-tenant`
- Diff the response shape against a clean baseline — extra echoed fields = signal.

---

## Phase 4: Tenant Isolation (multi-tenant SaaS)
- If user1 and user2 are in different tenants, ANY cross-tenant data
  access is critical-severity, not high.
- Test path-based tenancy: `/t/tenant-a/...` accessed with tenant-b's session
- Test subdomain tenancy: `tenanta.app.com` with tenantb cookies
- Test `X-Tenant-ID` header substitution

---

## Phase 5: Verification + PoC

A reportable IDOR PoC needs:
1. Two sessions, two different identities clearly labelled
2. Baseline capture under one, diff under the other showing same
   resource accessed
3. The actual leaked field values (sanitised in the report — but the
   raw evidence in the EvidenceStore)
4. Statement of impact: read-only / read-write / admin-takeover scope

The validator's counter-probe: rerun with `unauth` session — if THAT
also gets the resource, the original "IDOR" was actually unauth access
(more severe, but a different finding).
