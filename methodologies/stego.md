# Steganography Methodology
## Expert Playbook for Hidden-Data Challenges

> Carriers stack layers. Work cheap-to-deep: metadata → appended data →
> embedded tools → bit-plane / passphrase attacks. Flag-hunt every output.

---

## Phase 1: Fingerprint the Carrier (use the `stego_extract` tool, `auto`)
```bash
file carrier.png
exiftool carrier.png             # comments, GPS, custom tags often hold flags
strings -n 6 carrier.png | grep -iE "flag|ctf|key"
binwalk carrier.png              # appended ZIP/PDF/another image?
```

---

## Phase 2: Extract by Carrier Type

### 2.1 Images (PNG/BMP/JPG/GIF)
```bash
binwalk -e carrier.png                 # carve appended files
zsteg -a carrier.png                   # LSB for PNG/BMP
steghide extract -sf carrier.jpg -p '' # JPG/BMP/WAV/AU (try empty + wordlist)
# stegsolve / plane view for visual LSB, palette, and channel tricks
```
- steghide passphrase unknown → try empty, then a wordlist (`stegcracker`).

### 2.2 Audio (WAV/MP3)
- Inspect the **spectrogram** (text hidden in frequency domain).
- LSB on samples; check individual channels; look for DTMF/morse.

### 2.3 Documents / archives
- `binwalk`/`foremost` to carve; polyglot files (valid image + valid zip).
- Nested archives with passwords → crack with `hash_crack` on the zip hash.

---

## Phase 3: Post-Process
- Pipe extracted bytes through the `flag_hunter` tool.
- Decode further if needed (`crypto_helper`: base64/hex/xor/rot).

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Nothing in metadata/strings | Carve with binwalk; try LSB (zsteg/stegsolve) |
| steghide needs a password | Empty first, then wordlist crack |
| Data extracted but garbled | It's encoded/encrypted — decode with crypto_helper |
| Audio file | Spectrogram + per-channel LSB |

## Success Criteria
- [ ] Carrier type + metadata inspected
- [ ] Successful extraction command found
- [ ] Recovered payload matches the flag format
