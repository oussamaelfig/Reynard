# HTTP Host Header Attacks Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> Apps that trust the `Host` (or `X-Forwarded-Host`) header can be steered into
> password-reset poisoning, cache poisoning, routing-based SSRF, and auth bypass.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Probe Host Handling
```
# Change the Host header and watch what breaks/reflects
Host: evil.com
Host: target.com:evil.com
X-Forwarded-Host: evil.com
X-Host: evil.com  /  X-Forwarded-Server: evil.com
```
- Does the value get reflected in links, redirects, or cached responses?
- Does the app still serve 200 with an arbitrary Host? (weak validation)

### 1.2 Duplicate / Ambiguous Host
```
Host: target.com
Host: evil.com            (two Host headers)
GET https://target.com/  HTTP/1.1  (absolute URL + Host)
Host: target.com
 Host: evil.com           (indented / line-wrapped)
```

---

## Phase 2: Exploitation Techniques

### 2.1 Password Reset Poisoning
- Trigger a reset for the victim while setting `X-Forwarded-Host: evil.com`.
- The reset email's link points to `evil.com/reset?token=...`; when the victim
  clicks, the token hits your server. Replay it to reset their password.

### 2.2 Web Cache Poisoning via Host
- If the Host feeds an unkeyed cached resource (e.g. an absolute script URL),
  poison the cache so other users load `//evil.com/x.js` (see cache_poisoning.md).

### 2.3 Routing-Based SSRF
- If a front-end proxies to the back-end using the Host, set it to an internal
  host (`192.168.0.1`, `169.254.169.254`) to reach internal services/metadata.

### 2.4 Authentication / Access Bypass
- Some apps grant admin only when accessed via an internal vhost:
  `Host: localhost` or `Host: internal-admin` may expose `/admin`.

### 2.5 Connection-State / Vhost Confusion
- HTTP/2 `:authority` vs Host desync; connection reuse to smuggle a different
  vhost past the front-end.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Basic password reset poisoning**: `X-Forwarded-Host: exploit-server`.
- **Host header authentication bypass**: `Host: localhost` reaches `/admin`.
- **Web cache poisoning via ambiguous requests** / **routing-based SSRF**:
  duplicate Host / absolute URL tricks to reach the admin or internal API.
- **SSRF via a malformed request line**: `GET https://internal/ HTTP/1.1`.
- **Host validation bypass via connection-state attack**: reuse a connection
  whose first request had a valid Host.

---

## Phase 4: Tools & Automation
- Burp **Param Miner** ("Guess headers") to find supported host-override headers.
- Repeater to mutate Host / duplicate it / try absolute request lines.
- Exploit server to receive poisoned reset links.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Host strictly validated | Try `X-Forwarded-Host` / duplicate Host / absolute URI |
| Reset link not poisoned | Look for a dangling-markup or referer leak instead |
| No internal reach | Confirm a front-end proxy exists before routing SSRF |

## Success Criteria
- [ ] Poisoned a reset link, cache entry, or reached an internal/admin resource
- [ ] Completed the account takeover / SSRF objective
- [ ] Lab shows "solved"
