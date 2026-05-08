# Web Cache Poisoning

> Sister bug to request smuggling. Cheaper to detect, often easier to
> exploit. The diff tool is your primary lens.

---

## Phase 1: Identify the Cache Layer

### Headers that betray a cache
- `X-Cache: HIT|MISS` (CloudFront, Varnish, Fastly)
- `Cache-Control`, `CDN-Cache-Control`
- `Age:` (always present on cached responses)
- `X-Served-By`, `X-Varnish`, `X-Cache-Hits`, `X-Pass`
- `Via:` `1.1 cloudfront`, `1.1 varnish`, `1.1 google`

Capture a baseline, then resend — second response arrives faster and gets
`Age` header populated → cached. That's the surface.

---

## Phase 2: The Cache Key

The cache decides "is this request the same as a previous one?" by hashing
a subset of the request: usually URL + Host. Anything OUTSIDE the cache
key is unkeyed — and unkeyed input that influences the response = poison.

### Detection: unkeyed input via diff
1. `capture_baseline(name="clean", url="/")`
2. Send the same URL but with an extra header you suspect is unkeyed:
   `X-Forwarded-Host: <oob>.attacker.com`
3. `diff_against_baseline(baseline_name="clean", url="/", headers={...})`
4. If response now reflects `<oob>` somewhere AND the cache returns this
   poisoned version on a CLEAN request, you've poisoned the cache.

### Common unkeyed inputs to fuzz
```
X-Forwarded-Host: <oob>
X-Host: <oob>
X-Forwarded-Server: <oob>
X-HTTP-Host-Override: <oob>
Forwarded: for=...;host=<oob>
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Scheme: nothttps
X-Forwarded-Proto: ftp
X-Forwarded-Port: 81
X-Forwarded-For: <oob>
```

For each: send the request, then send a CLEAN request with NO custom
headers from a different origin/IP — does it now return the poisoned
response? Use `diff_against_baseline` to see precisely.

---

## Phase 3: Cache Deception (Sister Technique)

A different bug class but adjacent: trick the cache into storing
sensitive content under a public-looking URL.

```
GET /api/me HTTP/1.1                      <- normal (private, no cache)
GET /api/me/nonexistent.css HTTP/1.1      <- cache thinks it's a CSS,
                                              caches private content
                                              under that URL
```

Try every public-looking suffix the cache might honour:
```
.css .js .jpg .png .ico .svg .woff .woff2 .gif .map .json
```
Mid-path:
```
/api/me/.css
/api/me;.css
/api/me%00.css
/api/me%23.css
/api/me%3F.css
/api/me/x.css
```

Test as user1, then fetch the same path as `unauth` (use `swap_session`)
— if you get user1's data, that's the bug.

---

## Phase 4: Cache Key Normalization Bugs

The cache and the origin disagree on how to normalize URLs. Common splits:
- `/path` vs. `/path/`
- `/PATH` vs. `/path`
- `/path?` vs. `/path`
- `/path#x` vs. `/path` (fragment stripped at one layer not the other)
- `;jsessionid=...` parameter stripping
- `..` and `.` segment normalization

Send variations. If different layers see different paths, you can
poison "X" but the cache stores under "Y", which is fetched by victims.

---

## Phase 5: Verification

A reportable cache poisoning PoC:
1. Send the poisoning request
2. From a fresh client (no cookies, different session): fetch the
   target URL and capture the poisoned response
3. Show the `X-Cache: HIT` / `Age` proving it came from the cache
4. Note the TTL — how long does the poison survive?

The validator's counter-probe: send the SAME headers but to a unique
URL the cache hasn't seen — confirms the headers are the cause, not
some other condition.
