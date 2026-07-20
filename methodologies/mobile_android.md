# Mobile (Android) Application Methodology
## Expert Playbook for APK Analysis & Runtime Instrumentation

> Decompile, read the logic, then hook at runtime. Combine static findings
> (secrets/endpoints) with Frida hooks (root/pinning/value dumps).
> See also `android_frida_root_bypass.md`.

---

## Phase 1: Decompile (use the `apk_decompile` tool)
```bash
apktool d -f target.apk -o /data/loot/target/apktool   # resources + smali
jadx -d /data/loot/target/jadx target.apk              # Java source
```
- apktool gives the decoded `AndroidManifest.xml` and smali.
- jadx gives readable Java (best for logic reading).

---

## Phase 2: Static Analysis (use the `apk_analyze` tool)

### 2.1 Manifest
- `package`, `minSdk`, `debuggable`, `allowBackup`.
- **Exported** activities/services/receivers/providers → attack surface.
- Dangerous permissions and custom permissions.

### 2.2 Sinks & Secrets (grep the decompiled tree)
```bash
grep -rInE "addJavascriptInterface|setJavaScriptEnabled\(true|loadUrl\(" src/
grep -rInE "Runtime.*exec|openFileOutput|MODE_WORLD_READABLE" src/
grep -rInE "(api[_-]?key|secret|password|token)\s*[:=]" src/
grep -rInE "https?://[a-z0-9./_-]{6,}" src/
grep -rInE "Cipher.getInstance|SecretKeySpec|IvParameterSpec" src/
```
- Hardcoded keys/endpoints, weak crypto (ECB / static IV), insecure storage,
  WebView `addJavascriptInterface` RCE, exported components without permission.

---

## Phase 3: Runtime Instrumentation (use the `frida_hook` tool)
```bash
frida -U -f com.target.app -l /data/scripts/hook.js --no-pause
```
- Bypass root detection / SSL pinning (see `android_frida_root_bypass.md`).
- Dump values at a check: hook the method and log/alter args + return value.
- Objection shortcuts: `android root disable`, `android sslpinning disable`.

Example hook:
```javascript
Java.perform(function () {
  var C = Java.use('com.target.SecurityCheck');
  C.isValid.implementation = function () {
    console.log('[hook] isValid -> true');
    return true;
  };
});
```

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| jadx fails to decompile | Read smali from apktool output |
| Check is in native `.so` | Hook libc/JNI exports via `Interceptor` |
| App detects Frida | Gadget mode / rename frida-server / spawn early |
| Pinning + root both on | Disable both (objection or combined script) |

## Success Criteria
- [ ] APK decompiled (apktool + jadx)
- [ ] Manifest + sinks + secrets inventoried
- [ ] Hook changes behavior or reveals the guarded value/flag
