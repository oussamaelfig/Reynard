# Race Conditions Methodology
## Expert-Level Playbook (limit-overrun, multi-endpoint, single-packet attack)

> 5 PortSwigger labs. Race windows let you exceed a "once only" limit or observe
> a transient state. Send synchronized concurrent requests with `race_send`
> (single-packet / last-byte sync) — normal sequential tooling closes the window.

---

## Phase 1: Find the race window

Look for state transitions assumed to be atomic:
- coupon / gift-card / discount redemption (limit overrun)
- password reset / email change token single-use
- account balance / purchase / withdrawal
- MFA / OTP validation attempts
- rate-limit / anti-brute-force counters
- multi-step signup where a check and a use are separated in time

Capture the exact state-changing request (method, path, body, session cookie,
CSRF token). One CSRF token often works for a whole burst.

---

## Phase 2: Attack techniques

### 2.1 Single-packet attack (HTTP/2) — preferred
Put N requests' final bytes into ONE TCP packet so the server processes them
simultaneously, eliminating network jitter.
```
race_send url=https://TARGET/redeem method=POST count=30 mode=parallel \
  headers={"Content-Type":"application/x-www-form-urlencoded"} body="coupon=PROMO"
```
`race_send` uses last-byte synchronization (single-packet on H2, last-byte on
H1). Inspect the summary: multiple `200/302` where only one should succeed ⇒ win.

### 2.2 Last-byte sync (HTTP/1.1)
Withhold the last byte of each request, then release all last bytes together.
`race_send` handles this; fall back to `burp_send_to_intruder` (turbo/racing) or
a raw socket script if needed.

### 2.3 Multi-endpoint races (collision)
Two different endpoints touching the same object (e.g. add-to-cart + apply-credit,
or use-token + validate). Fire them together so the second reads pre-update state.

### 2.4 Multi-step sequence (single-endpoint sub-state)
Send the same endpoint in parallel to hit a transient sub-state (e.g. partial
construction of a user during signup enabling privilege).

---

## Phase 3: Sub-variant tips

| Sub-variant | Move |
|-------------|------|
| Limit overrun | parallel-redeem a one-time coupon/gift card N times |
| Bypass rate limits | burst OTP/login attempts before the counter increments |
| Multi-endpoint | collide two endpoints mutating the same balance/state |
| Single-endpoint | parallel requests hit a transient sub-state |
| Partial construction | race signup so a half-built account gains privilege |
| Time-sensitive (predictable token) | race issuance+use of a predictable reset token |

---

## Phase 4: Tooling

```
race_send        # single-packet / last-byte synchronized concurrent sender (primary)
burp_send_to_intruder   # turbo-intruder-style racing fallback
http_request     # capture the exact state-changing request first
list_sessions / swap_session   # multi-identity collisions
# Verify final state via the UI/API AFTER the burst, not from individual responses.
```

- Keep concurrency modest first (10-30); too many can crash the window.
- Re-check lab state between runs; don't blindly re-fire state-changing races.

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| Only one request succeeds | Increase sync precision (single-packet), reduce jitter |
| CSRF token rejected | Reuse one token for the burst; refresh if the app rotates it |
| No effect | Confirm the action is truly single-use and state-changing |
| Sequential tooling misses it | Use `race_send`, never a for-loop of `http_request` |
| Inconsistent wins | Repeat; races are probabilistic — verify final state each time |

## Validation / Success Criteria
- [ ] Final object/account/order state shows more than one accepted transition.
- [ ] Sequential control attempts do not reproduce it.
- [ ] The concurrent burst (not a single request) caused the effect.
- [ ] Lab solved banner observed.
