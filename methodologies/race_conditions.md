# Race Conditions Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> Exploit the window between a check and its use (TOCTOU) by firing concurrent
> requests so a limit/uniqueness/state guard is evaluated multiple times.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Find Limit-Overrun Candidates
- Discount/gift-card/coupon redemption (apply once)
- Withdraw/transfer funds, redeem points, rate limits
- "One per account" actions, invite/registration bonuses
- MFA/OTP verification attempts (anti-brute-force limits)

### 1.2 Recognize Sub-States
- A single request may transiently pass through a middle state (e.g. "coupon
  valid" -> "coupon spent"). Concurrency lets many requests read the pre-spend
  state before any commit.

---

## Phase 2: Exploitation Techniques

### 2.1 Single-Packet Attack (HTTP/2)
- The gold standard: send 20-30 requests whose *last frame* is withheld, then
  release all final frames at once to neutralize network jitter.
- In Burp: send group **in parallel** using "Send group (single-packet attack)".

### 2.2 Last-Byte Sync (HTTP/1.1)
- Queue requests over multiple connections, withhold the final byte of each,
  then flush them together.

### 2.3 Limit-Overrun (Classic)
- Redeem the same gift card / coupon N times concurrently before the balance
  decrements.

### 2.4 Multi-Endpoint / Single-Endpoint
- **Single-endpoint**: send the same state-changing request many times at once.
- **Multi-endpoint**: race two different requests (e.g. add-to-cart + checkout)
  so they interleave in a profitable order.

### 2.5 Partial Construction / Hidden State
- Trigger a user object mid-creation to bypass an email-verification gate, or
  register `carlos@target-domain` to hijack an account during a race.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Limit overrun**: apply a discount code repeatedly in parallel.
- **Bypassing rate limits**: race the OTP/login attempt counter.
- **Multi-endpoint race**: add item then race checkout to buy over budget.
- **Single-endpoint race**: race the email-change confirm to hijack an address.
- **Partial construction**: race registration to skip email verification.
- **Time-sensitive**: predictable tokens generated at the same second.

---

## Phase 4: Tools & Automation
- **Burp Repeater**: add requests to a group -> "Send group in parallel
  (single-packet attack)". This is the primary tool.
- **Turbo Intruder**: `engine=Engine.BURP2`, `concurrentConnections`, and
  `engine.openGate()` for last-byte sync:
```python
def queueRequests(target):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30,
                           engine=Engine.BURP2)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Requests still serialize | Use single-packet (HTTP/2) attack |
| Network jitter | Withhold final frame/byte, release together |
| Only one succeeds | Increase concurrency; check for locking |
| No visible effect | Race a different endpoint pair (multi-endpoint) |

## Success Criteria
- [ ] Guard evaluated more than once (e.g. coupon applied N times)
- [ ] Achieved the over-limit / state-bypass outcome
- [ ] Lab shows "solved"
