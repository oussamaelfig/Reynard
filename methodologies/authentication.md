# Authentication Vulnerabilities Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> Covers login logic, credential handling, MFA, password reset, and session flaws.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Map the Authentication Surface
- Login, register, logout, password-reset, "remember me", account recovery
- MFA / 2FA step (TOTP, SMS, email code), step-up auth
- SSO / OAuth / SAML entry points (see oauth.md)
- Session cookie name, flags (HttpOnly, Secure, SameSite), JWT vs opaque

### 1.2 Username Enumeration
- Compare responses for valid vs invalid usernames:
  - Different error text ("Invalid username" vs "Invalid password")
  - Different HTTP status / redirect
  - Response time delta (valid user triggers bcrypt, invalid short-circuits)
  - Subtle differences (trailing period, word order) — diff byte-for-byte
```
username=administrator&password=x   -> "Incorrect password"
username=nobody123&password=x       -> "Invalid username"
```

### 1.3 Password Policy & Brute-Force Signals
- Rate limiting present? IP-based or account-based?
- Account lockout after N attempts? Can it be reset/bypassed?
- Is X-Forwarded-For trusted for rate-limit keying?

---

## Phase 2: Exploitation Techniques

### 2.1 Credential Brute-Force
```bash
# Password spray a known/enumerated username
ffuf -w passwords.txt -X POST -d "username=carlos&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://target/login -fr "Incorrect password"
```
- Bypass IP lockout with rotating `X-Forwarded-For: 1.2.3.N`
- Account lock only after failed logins? Interleave a correct guess.

### 2.2 Broken Brute-Force Protection
- Lockout counter resets on correct-password attempt → keep guessing
- Locking the *account* but not detecting valid creds → credential stuffing
- 2FA bypass by skipping the verify step (go straight to authed page)

### 2.3 Multi-Factor Authentication (MFA) Bypass
- Brute-force 4–6 digit codes if no rate limit (0000–9999)
- Verify step not bound to the logging-in user (swap account mid-flow)
- Skip the 2FA POST and request the post-login resource directly
- "Remember me" cookie derived from predictable data (username + weak hash)

### 2.4 Password Reset Poisoning / Logic
- Reset token in URL — is it predictable, reusable, or long-lived?
- Change the `Host`/`X-Forwarded-Host` header so the reset link points to
  attacker domain and leaks the victim's token (see host_header.md)
- Reset token not tied to the account → set `username=victim` in the confirm step
- Mid-flow account swap: request reset for self, submit with victim's username

### 2.5 "Stay Logged In" / Remember-Me Cookies
```
cookie = base64(username + ':' + md5(password))
```
- Decode, identify the scheme, forge for `administrator`
- Offline-crack the hash if it is the password digest

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Username enumeration via different responses**: diff error strings.
- **Username enumeration via response timing**: measure with a long password.
- **2FA broken logic**: log in as your user, capture 2FA verify, then re-issue
  it with the victim's session/username.
- **Password reset broken logic**: intercept the confirm request, replace the
  username with `carlos`.
- **Brute-forcing a stay-logged-in cookie**: reverse the cookie format, brute
  the password digest offline.

---

## Phase 4: Tools & Automation
```bash
# Enumerate usernames by filtering the "invalid username" response
ffuf -w users.txt -X POST -d "username=FUZZ&password=x" \
  -u http://target/login -mr "Incorrect password"

# Brute-force a numeric MFA code
seq -w 0 9999 > codes.txt
ffuf -w codes.txt -X POST -d "mfa-code=FUZZ" -b "session=..." \
  -u http://target/login2 -fr "Incorrect security code"
```

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Rate limiting blocks brute-force | Rotate `X-Forwarded-For`, slow down, or spray |
| 2FA code changes each request | Re-request a fresh code per attempt or find no-rate-limit endpoint |
| Reset token single-use | Trigger a fresh reset; do not consume it while testing |
| CAPTCHA on login | Look for an API/mobile endpoint without it |

## Success Criteria
- [ ] Authenticated as the target account (e.g. `carlos`/`administrator`)
- [ ] Accessed the protected resource / admin panel
- [ ] Lab shows "solved"
