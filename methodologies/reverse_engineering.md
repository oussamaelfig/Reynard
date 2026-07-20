# Reverse Engineering Methodology
## Expert Playbook for Crackmes & Key Recovery

> Read the check logic instead of brute forcing. Invert the algorithm to
> derive the input the program already accepts.

---

## Phase 1: Fingerprint
```bash
file ./chall            # ELF/PE/.NET/script? packed?
strings -n 6 ./chall | less
rabin2 -I ./chall       # arch, bits, lang, protections
```
- Packed (UPX etc.) → `upx -d` or dump at OEP before analysis.
- .NET/Java/Python → use dnSpy / jadx / uncompyle-style tools instead of r2.

---

## Phase 2: Static Analysis (use the `radare2_analyze` tool)
```bash
r2 -q -c 'aaa; afl; izq' ./chall           # functions + strings
r2 -q -c 'aaa; s main; pdf' ./chall        # disassemble main
```
- Find the comparison that gates success (`strcmp`, `memcmp`, custom loop).
- Trace where user input flows into that comparison.
- Note constants, XOR keys, and lookup tables used to transform input.

---

## Phase 3: Dynamic Analysis (use the `gdb_debug` tool)
```bash
gdb --batch -nx \
  -ex 'break *0x<cmp_addr>' -ex 'run' \
  -ex 'x/2gx $rsi' -ex 'x/2gx $rdi' ./chall
```
- Break at the check and dump both compared buffers — the expected value is
  often computed and sitting in a register/buffer.
- Patch a branch (`set $eflags`) to explore paths when needed.

---

## Phase 4: Invert the Algorithm
- Reimplement the transform and solve for the required input.
- For simple encodings, `crypto_helper` (b64/hex/rot/xor) resolves the value.
- Verify by feeding the derived input back into the real binary.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Static-only, obfuscated | Switch to dynamic; dump the compared buffer |
| Anti-debug (ptrace) | Patch ptrace call / set follow-fork; use r2 `dbg` |
| Packed binary | Unpack or dump memory at OEP first |
| Native + interpreted mix | Analyze each layer with the right tool |

## Success Criteria
- [ ] Check/validation routine located and understood
- [ ] Algorithm inverted or key recovered
- [ ] Derived input passes the program's own success path
