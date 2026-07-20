# Cryptography Methodology
## Expert Playbook for CTF Crypto Challenges

> Identify the scheme and its introduced weakness, then attack that specific
> weakness. Do not brute force when a mathematical shortcut exists.

---

## Phase 1: Identify & Normalize
- Recognize the scheme: classical, RSA, AES (mode!), ECC, hashing, PRNG.
- Normalize encodings first with the `crypto_helper` tool:
  `b64decode`, `hexdecode`, `from_binary`, `url_decode`, `hash_identify`.
- Collect all given parameters (n, e, c / key, iv, nonce / points).

---

## Phase 2: Attack by Class

### 2.1 Classical (Caesar/Vigenère/substitution/XOR)
- Frequency analysis; try `rot`/`rot13` and single-byte `xor` via `crypto_helper`.
- Repeating-key XOR: find key length (Hamming/Kasiski), then per-column solve.

### 2.2 RSA
```
Small e (e=3)         -> integer cube root of c
n factorable          -> factordb / Fermat (close primes) / Pollard
Shared modulus        -> common-modulus attack (two e, same n)
Many c, same e        -> Håstad broadcast (CRT)
Given d/phi           -> straight decrypt
Wiener (small d)      -> continued fractions
```

### 2.3 AES / block ciphers
- **ECB** (identical blocks) → byte-at-a-time decryption / cut-and-paste.
- **CBC** → bit-flipping (IV/known plaintext), padding-oracle decryption.
- **CTR/stream** → nonce reuse → XOR keystream recovery.

### 2.4 Hashes & PRNG
- Weak/known hashes → crack with the `hash_crack` tool (john/hashcat + rockyou).
- Length-extension (MD5/SHA1 MAC without HMAC) → `hashpump`-style forge.
- Predictable PRNG (Python `random`, LCG, MT19937) → recover state & predict.

---

## Phase 3: Recover & Verify
- Reimplement decryption with the recovered key/params.
- Confirm the plaintext matches the flag format; a control ciphertext should
  decrypt consistently.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| RSA "unbreakable" | Check small e, factordb, close primes, shared modulus first |
| Ciphertext looks random | Confirm encoding; try XOR keystream / nonce reuse |
| Classical won't crack | Verify it isn't keyed; do proper key-length analysis |
| Hash won't crack | Correct mode/format; try rules and larger wordlist |

## Success Criteria
- [ ] Scheme + weakness identified
- [ ] Weakness-specific attack applied
- [ ] Plaintext/key recovered and flag confirmed
