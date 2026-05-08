# Android Frida Root Detection Bypass
## Expert Playbook for Root/Jailbreak Bypass via Dynamic Instrumentation

> Methodology for bypassing Android root detection, SafetyNet/Play Integrity,
> and other security checks using Frida and Objection.

---

## Phase 1: Environment Setup

### 1.1 Prerequisites
```bash
# Frida tools (already installed in container)
pip3 install frida-tools objection

# Check Frida version
frida --version

# ADB setup (connect to emulator or device)
adb devices

# If using emulator (e.g., Genymotion, Android Studio)
adb connect <emulator_ip>:5555

# Download Frida server for target architecture
FRIDA_VERSION=$(frida --version)
ARCH="arm64"  # or arm, x86, x86_64
wget "https://github.com/frida/frida/releases/download/$FRIDA_VERSION/frida-server-$FRIDA_VERSION-android-$ARCH.xz"
xz -d frida-server-*.xz
chmod +x frida-server-*

# Push frida-server to device
adb push frida-server-* /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"

# Start frida-server on device (needs root on device)
adb shell "su -c /data/local/tmp/frida-server &"
```

### 1.2 Verify Frida Connection
```bash
# List running processes
frida-ps -U

# List installed apps
frida-ps -Uai

# Target app
frida -U -n "com.target.app" --no-pause
```

---

## Phase 2: Reconnaissance

### 2.1 Static Analysis
```bash
# Decompile APK
apktool d target.apk -o /data/loot/target_decompiled

# Decompile to Java source
jadx target.apk -d /data/loot/target_jadx

# Search for root detection indicators
grep -rn "isRooted\|isDeviceRooted\|detectRoot\|RootBeer\|RootDetection" /data/loot/target_jadx/
grep -rn "SafetyNet\|PlayIntegrity\|safetynet" /data/loot/target_jadx/
grep -rn "su \|Superuser\|SuperSU\|Magisk\|busybox" /data/loot/target_jadx/
grep -rn "test-keys\|dev-keys" /data/loot/target_jadx/
grep -rn "/system/app/Superuser\|/sbin/su\|/system/bin/su\|/system/xbin/su" /data/loot/target_jadx/

# Check for known root detection libraries
grep -rn "rootbeer\|com.scottyab.rootbeer" /data/loot/target_jadx/
grep -rn "com.noshufou.android.su" /data/loot/target_jadx/

# Check for native libraries (might have root checks in C/C++)
find /data/loot/target_decompiled/lib -name "*.so" 2>/dev/null
```

### 2.2 Identify Root Detection Methods
Common root detection techniques to bypass:
1. **File existence checks**: `/system/bin/su`, `/sbin/su`, Magisk paths
2. **Package manager checks**: Superuser, Magisk Manager packages
3. **Build tags check**: `test-keys` in build properties
4. **Directory permissions**: Checking if `/system` is writable
5. **Process checks**: Looking for `su` daemon
6. **SafetyNet/Play Integrity**: Google's attestation API
7. **RootBeer library**: Common OSS root detection
8. **Native checks**: Root detection in JNI/native code

---

## Phase 3: Bypass with Frida Scripts

### 3.1 Generic Root Detection Bypass
```javascript
// Save as /data/scripts/root_bypass.js

Java.perform(function() {
    console.log("[*] Starting root detection bypass...");

    // =========================================================================
    // 1. Bypass java.io.File.exists() for root-related paths
    // =========================================================================
    var File = Java.use("java.io.File");
    var rootPaths = [
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/data/adb/magisk",
        "/sbin/.magisk",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock",
        "/data/adb/modules",
    ];

    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) {
                console.log("[BYPASS] File.exists(" + path + ") -> false");
                return false;
            }
        }
        return this.exists.call(this);
    };

    // =========================================================================
    // 2. Bypass Runtime.exec() for 'su' and 'which su' commands
    // =========================================================================
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmdArray) {
        var cmd = cmdArray.join(" ");
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[BYPASS] Runtime.exec blocked: " + cmd);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmdArray);
    };

    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[BYPASS] Runtime.exec blocked: " + cmd);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmd);
    };

    // =========================================================================
    // 3. Bypass Build.TAGS check (test-keys vs release-keys)
    // =========================================================================
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";
    console.log("[BYPASS] Build.TAGS set to: release-keys");

    // =========================================================================
    // 4. Bypass PackageManager check for root apps
    // =========================================================================
    var PM = Java.use("android.app.ApplicationPackageManager");
    var rootPackages = [
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclean",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
    ];

    PM.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkgName, flags) {
        for (var i = 0; i < rootPackages.length; i++) {
            if (pkgName === rootPackages[i]) {
                console.log("[BYPASS] PackageManager.getPackageInfo blocked: " + pkgName);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkgName);
            }
        }
        return this.getPackageInfo(pkgName, flags);
    };

    // =========================================================================
    // 5. Bypass System.getProperty for ro.debuggable and ro.secure
    // =========================================================================
    var System = Java.use("java.lang.System");
    System.getProperty.overload("java.lang.String").implementation = function(key) {
        if (key === "ro.debuggable") {
            console.log("[BYPASS] System.getProperty(ro.debuggable) -> 0");
            return "0";
        }
        if (key === "ro.secure") {
            console.log("[BYPASS] System.getProperty(ro.secure) -> 1");
            return "1";
        }
        return this.getProperty(key);
    };

    console.log("[*] Root detection bypass loaded successfully!");
});
```

### 3.2 RootBeer Library Bypass
```javascript
// Save as /data/scripts/rootbeer_bypass.js

Java.perform(function() {
    console.log("[*] Bypassing RootBeer root detection...");

    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");

        // Override all detection methods
        RootBeer.isRooted.implementation = function() {
            console.log("[BYPASS] RootBeer.isRooted() -> false");
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log("[BYPASS] RootBeer.isRootedWithoutBusyBoxCheck() -> false");
            return false;
        };
        RootBeer.detectRootManagementApps.implementation = function() {
            return false;
        };
        RootBeer.detectPotentiallyDangerousApps.implementation = function() {
            return false;
        };
        RootBeer.detectTestKeys.implementation = function() {
            return false;
        };
        RootBeer.checkForBusyBoxBinary.implementation = function() {
            return false;
        };
        RootBeer.checkForSuBinary.implementation = function() {
            return false;
        };
        RootBeer.checkSuExists.implementation = function() {
            return false;
        };
        RootBeer.checkForRWPaths.implementation = function() {
            return false;
        };
        RootBeer.checkForDangerousProps.implementation = function() {
            return false;
        };
        RootBeer.checkForRootNative.implementation = function() {
            return false;
        };
        RootBeer.detectRootCloakingApps.implementation = function() {
            return false;
        };

        console.log("[*] RootBeer bypass complete!");
    } catch(e) {
        console.log("[!] RootBeer not found: " + e);
    }
});
```

### 3.3 SafetyNet/Play Integrity Bypass
```javascript
// Save as /data/scripts/safetynet_bypass.js

Java.perform(function() {
    console.log("[*] Attempting SafetyNet bypass...");

    // Hook SafetyNet attestation result
    try {
        var SafetyNetApi = Java.use("com.google.android.gms.safetynet.SafetyNetApi");
        // Note: Full SafetyNet bypass requires more complex work
        // Consider using Magisk Hide + DenyList for production bypasses
        console.log("[*] SafetyNet hooks loaded (basic)");
    } catch(e) {
        console.log("[!] SafetyNet API not accessible: " + e);
    }

    // Hook Play Integrity API 
    try {
        var IntegrityManager = Java.use("com.google.android.play.core.integrity.IntegrityManager");
        console.log("[*] Play Integrity hooks loaded (basic)");
    } catch(e) {
        console.log("[!] Play Integrity not found: " + e);
    }
});
```

---

## Phase 4: Using Objection (Simplified Frida Wrapper)

### 4.1 Quick Root Bypass with Objection
```bash
# Start objection and auto-bypass root detection
objection -g com.target.app explore

# Inside objection:
# Disable root detection
android root disable

# Check SSL pinning (often combined with root detection)
android sslpinning disable

# List activities
android hooking list activities

# List classes matching root detection patterns
android hooking search classes root
android hooking search classes RootBeer
android hooking search classes SafetyNet

# List methods for a specific class
android hooking list class_methods com.target.RootDetector

# Hook and modify return value
android hooking set return_value com.target.RootDetector.isRooted false
```

### 4.2 Objection One-Liner (Automated)
```bash
# Spawn app with root detection disabled
objection -g com.target.app explore --startup-command "android root disable"

# Combined bypass script
objection -g com.target.app explore --startup-script /data/scripts/root_bypass.js
```

---

## Phase 5: Running the Bypass

### 5.1 Frida CLI Usage
```bash
# Attach to running app
frida -U -n "com.target.app" -l /data/scripts/root_bypass.js --no-pause

# Spawn app with bypass (preferred — hooks before app initializes)
frida -U -f com.target.app -l /data/scripts/root_bypass.js --no-pause

# Load multiple scripts
frida -U -f com.target.app \
  -l /data/scripts/root_bypass.js \
  -l /data/scripts/rootbeer_bypass.js \
  -l /data/scripts/safetynet_bypass.js \
  --no-pause

# Frida Python binding for automation
python3 -c "
import frida
device = frida.get_usb_device()
pid = device.spawn(['com.target.app'])
session = device.attach(pid)
with open('/data/scripts/root_bypass.js') as f:
    script = session.create_script(f.read())
script.load()
device.resume(pid)
input('Press Enter to exit...')
"
```

### 5.2 Debugging the Bypass
```bash
# If bypass fails, check:
# 1. Is Frida server running on device?
adb shell "ps | grep frida"

# 2. Is the target class/method name correct?
frida -U -n "com.target.app" -e "
Java.perform(function(){
    Java.enumerateLoadedClasses({
        onMatch: function(name){
            if(name.toLowerCase().indexOf('root') !== -1){
                console.log('Found: ' + name);
            }
        },
        onComplete: function(){}
    });
});
"

# 3. Check for native root detection (harder to bypass)
frida -U -n "com.target.app" -e "
Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        if (path.indexOf('su') !== -1 || path.indexOf('magisk') !== -1) {
            console.log('[NATIVE] fopen(' + path + ')');
        }
    }
});
"
```

---

## Common Failure Modes

| Problem | Solution |
|---------|----------|
| Frida crashes target app | Use `--no-pause` flag, try spawn mode instead of attach |
| Root check in native code | Hook native functions via Interceptor (fopen, access, stat) |
| Multiple root check locations | Enumerate all classes with root/detect keywords, hook them all |
| SafetyNet fails despite bypass | Need Magisk DenyList + Shamiko module (device-level solution) |
| App uses custom detection | Reverse-engineer with jadx, find the exact method, hook it |
| Timing-based detection | Hook `System.currentTimeMillis()` to prevent timing analysis |
| App detects Frida itself | Rename frida-server, use Gadget mode, or patch Frida detection |

## Frida Anti-Detection
```javascript
// Bypass Frida detection (apps that look for frida-server)
// The app might scan /proc/self/maps for frida-agent strings
Java.perform(function() {
    // Hook fopen to hide frida from maps
    var fopen = Module.findExportByName("libc.so", "fopen");
    Interceptor.attach(fopen, {
        onEnter: function(args) {
            this.path = Memory.readUtf8String(args[0]);
        },
        onLeave: function(retval) {
            if (this.path && this.path.indexOf("/proc") !== -1 && 
                this.path.indexOf("maps") !== -1) {
                // Could modify the file descriptor to hide frida entries
                console.log("[ANTIDETECT] Maps file accessed: " + this.path);
            }
        }
    });
});
```

## Success Criteria
- [ ] APK decompiled and root detection methods identified
- [ ] Frida server running on target device
- [ ] Root detection bypass script loaded successfully
- [ ] App runs without root detection alerts/crashes
- [ ] Target functionality accessible on rooted device
- [ ] Bypass scripts saved to /data/scripts/
