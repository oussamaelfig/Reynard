# Prototype Pollution Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> Inject properties into `Object.prototype` so unrelated objects inherit
> attacker-controlled values, escalating to DOM XSS (client) or RCE (server).

---

## Phase 1: Detection & Fingerprinting

### 1.1 Sources (where pollution enters)
- URL query/hash parsed into an object (`?__proto__[x]=y`)
- JSON request bodies merged recursively (`{"__proto__":{"x":"y"}}`)
- `constructor.prototype` variants when `__proto__` is filtered

### 1.2 Client-Side Detection
- In DevTools console after loading the page with a probe:
```
?__proto__[foo]=bar
> Object.prototype.foo   // "bar"  -> polluted
```
- DOM Invader (Burp) auto-detects sources and gadgets.

---

## Phase 2: Exploitation Techniques

### 2.1 Client-Side Prototype Pollution -> DOM XSS
- Find a **gadget**: a property the app reads from an object without owning it,
  e.g. a config used to build script `src`, `innerHTML`, or `eval` input.
```
?__proto__[transport_url]=data:,alert(1)
?__proto__[hitCallback]=alert(document.cookie)
```
- Common sinks: `<script src>`, `document.write`, jQuery `$.extend`, template
  engines reading `config.*`.

### 2.2 Filter Bypass
```
?constructor[prototype][x]=y            (when __proto__ blocked)
?__pro__proto__to__[x]=y                (naive string strip)
{"constructor":{"prototype":{"x":"y"}}} (JSON variant)
```

### 2.3 Server-Side (Node.js) Prototype Pollution
- Pollute via a JSON body merged by a vulnerable `merge`/`clone`.
- Escalate through a gadget in the runtime/library to RCE, e.g. spawning a
  child process by polluting options like `shell`, `NODE_OPTIONS`, or a
  template's `env`.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **DOM XSS via client-side prototype pollution**: `__proto__[transport_url]`.
- **DOM XSS via an alternative prototype pollution vector**: hash-based source.
- **Client-side pollution via flawed sanitization**: use `constructor.prototype`.
- **Bypassing flawed input filters**: nested/obfuscated `__proto__`.
- **Remote code execution via server-side prototype pollution**: JSON body
  gadget leading to command execution.
- **Detecting server-side prototype pollution without polluted responses**:
  send a payload that changes JSON parsing behavior (e.g. `status` override).

---

## Phase 4: Tools & Automation
- **Burp DOM Invader** with prototype-pollution mode: finds sources + gadgets.
- **Server-Side Prototype Pollution Scanner** (Burp extension) for Node apps.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| `__proto__` filtered | Use `constructor.prototype` or nested obfuscation |
| Pollution works, no gadget | Enumerate config reads; use DOM Invader gadget scan |
| Server-side, no reflection | Use a behavior-change probe to confirm |

## Success Criteria
- [ ] Polluted `Object.prototype` and hit a gadget (XSS or RCE)
- [ ] Executed script in victim context or ran a server command
- [ ] Lab shows "solved"
