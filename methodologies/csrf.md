# CSRF (Cross-Site Request Forgery) Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> A state-changing request is forgeable if it relies only on cookies and lacks
> an unpredictable, request-bound token.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Find State-Changing Actions
- Email/password change, add/delete, transfer, role change, settings update
- Prefer actions with security impact (email change → account takeover)

### 1.2 Analyze the Anti-CSRF Defense
- Is there a CSRF token? Where (hidden field, header, cookie)?
- Is `SameSite` set on the session cookie? (`Lax`/`Strict`/`None`)
- Does the app check `Origin`/`Referer`?
- Is the token validated at all, tied to the session, and required?

### 1.3 Token Validation Probes
```
1. Remove the csrf param entirely            -> still accepted?
2. Change token length / random value         -> accepted?
3. Reuse another user's valid token           -> accepted (not session-bound)?
4. Swap method GET<->POST                      -> validation skipped?
5. Duplicate-submit cookie == token           -> "double submit" bypass
```

---

## Phase 2: Exploitation Techniques

### 2.1 Classic Auto-Submitting PoC
```html
<form action="https://target/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

### 2.2 Token Not Tied to Session
- Fetch a valid token from your own session, plant it in the PoC — it validates
  against a global pool, not the victim's session.

### 2.3 Token Tied to a Non-Session Cookie
- If the token is validated against a `csrfKey` cookie you can set via CRLF /
  a sibling-domain injection, plant both cookie and token.

### 2.4 SameSite Bypasses
- `SameSite=Lax` still allows top-level GET navigation → use a GET-based action
  or a method-override (`_method=POST`).
- Sibling/subdomain XSS or open redirect to satisfy same-site.
- Newly issued cookies may have a 2-minute `Lax+POST` grace window.

### 2.5 Referer-Based Defense Bypass
- Omit the Referer with `<meta name="referrer" content="no-referrer">`
- If it only checks the domain is *present* in Referer, use
  `https://target.evil.com` or `?target.com` query trick.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **No defenses**: plain auto-submit form.
- **Token validation depends on request method**: switch POST→GET.
- **Token not tied to user session**: reuse your own token.
- **Token tied to non-session cookie**: set attacker `csrfKey` first.
- **Token duplicated in cookie**: double-submit — set cookie=value=token.
- **SameSite Lax bypass via method override**: `_method=POST`.
- **Referer validation broken**: use Referrer-Policy or partial-match trick.

---

## Phase 4: Tools & Automation
- Burp → right-click request → **Engagement tools → Generate CSRF PoC**
- Host the PoC on the exploit server, then "Deliver to victim"
- Verify by checking the victim account's state changed

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Token rejected | Check if session-bound; try omit / swap method |
| SameSite=Strict | Need same-site XSS/redirect; pure CSRF may be impossible |
| Referer enforced | Try no-referrer meta or domain-substring trick |
| Action needs JSON | Use `text/plain` form encoding or fetch with credentials |

## Success Criteria
- [ ] Victim's state changed (email/password/etc.) via cross-site request
- [ ] PoC delivered from the exploit server
- [ ] Lab shows "solved"
