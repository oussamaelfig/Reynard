# HTTP Request Smuggling (HRS) / Desync

> One of the highest-impact bug classes — bypass auth, poison caches,
> hijack sessions of next users in the queue. Hard to detect; easy to
> wreck production with — TIME-BOX testing and prefer time-based detection
> over content-based.

---

## Phase 1: Theory

When a frontend (CDN/LB) and backend disagree on where one request ends
and the next begins, you can append bytes that the backend treats as a
fresh request.

Disagreements stem from `Transfer-Encoding` vs. `Content-Length` parsing.

| Type | Frontend uses | Backend uses |
|------|---------------|--------------|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | TE (different obfuscation) | TE (different obfuscation) |
| H2.CL / H2.TE | HTTP/2 | downgraded HTTP/1.1 reads CL/TE |

---

## Phase 2: Detection (TIME-BASED — safe-ish)

### 2.1 CL.TE detection probe
A delay on the second request indicates desync:
```http
POST / HTTP/1.1
Host: target
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
Frontend (CL=4): forwards "1\r\nA\r\nX". Backend (TE): reads "1\r\nA\r\n",
waits for next chunk → timeout. Anomalous timing on the SECOND request
in the connection = signal.

### 2.2 TE.CL detection probe
```http
POST / HTTP/1.1
Host: target
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
Frontend (TE): forwards everything to "0\r\n\r\n". Backend (CL=6): reads
"0\r\n\r\nX" — leftover "X" gets prepended to next request. Symptom:
404 / different response on the next pipelined request.

### 2.3 HTTP/2 downgrade
If the frontend speaks H2 and downgrades to H1 to the backend:
- Smuggle via H2 pseudo-header injection
- `:path` containing `\r\n` and a smuggled request
- This is the modern variant — most SHI bugs in 2022+ are H2-related

---

## Phase 3: Tooling

### 3.1 burp / smuggler.py / h2cSmuggler
Inside Kali container:
```bash
# Defrag's smuggler.py
python3 /opt/smuggler/smuggler.py -u https://target

# h2cSmuggler for H2C upgrade smuggling
h2cSmuggler -x https://target/ -p ./payload.txt

# h2 downgrade
http2smugl detect target
```

### 3.2 Manual probe via raw curl
```bash
printf 'POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nA\r\nX\r\n\r\n' \
  | timeout 10 openssl s_client -connect target:443 -ign_eof -quiet
```
Watch for the second response (or absence of one) — timing is the tell.

---

## Phase 4: Exploitation Patterns (after desync confirmed)

### 4.1 Auth header smuggling
Smuggle the next user's request and capture their `Authorization` /
`Cookie` from the proxy by responding with a controlled prefix.

### 4.2 Cache poisoning via desync
Smuggle a request that responds with an attacker-controlled body for a
cache-key the next user will fetch.

### 4.3 Internal endpoint access
Smuggle requests that hit `/admin` while the frontend gates on URL —
backend may not see the URL the frontend gated on.

### 4.4 Web socket / SSE hijack
Smuggle into long-lived connections to poison subsequent messages.

---

## Phase 5: SAFETY ON CLIENT INFRA

- **Always** time-box. A desync experiment that succeeds can hijack the
  next legitimate user — only run with explicit permission and outside
  business hours.
- Use detection-only payloads first. Don't escalate to exploitation
  without surfacing the finding to the customer first.
- The ScopeGuard's rate limiter MUST be active for this methodology
  (if implemented). Don't run unbounded detection against shared infra.
- A confirmed desync but no exploited PoC is STILL a critical finding.
  Report it without exploitation if you can't do so safely.

---

## Verification

Validator protocol for HRS:
1. Replay the timing probe — is the anomaly reproducible?
2. Counter-probe: the same request WITHOUT the chunked/CL conflict
   should NOT show the timing anomaly. If it does, the anomaly is
   environmental (loaded backend, network jitter), not desync.
3. Run a fresh probe via a different connection — confirms the
   smuggling is per-request, not connection-state-dependent.
