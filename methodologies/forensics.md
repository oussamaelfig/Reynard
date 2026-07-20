# Digital Forensics Methodology
## Expert Playbook for PCAP / Disk / Memory Artifacts

> Identify the artifact type, pick the matching toolchain, isolate the
> relevant data, and flag-hunt what you recover.

---

## Phase 1: Identify (use the `forensics_triage` tool, `auto`)
```bash
file artifact.*        # pcap? disk image? memory dump? blob?
```
- pcap/pcapng → network. `.raw/.mem/.vmem/.dmp` → memory. `.dd/.img/.e01` → disk.

---

## Phase 2: Analyze by Type

### 2.1 Network captures (PCAP)
```bash
capinfos capture.pcap
tshark -r capture.pcap -q -z io,phs               # protocol hierarchy
tshark -r capture.pcap -Y http -T fields -e http.request.full_uri
tshark -r capture.pcap --export-objects http,/tmp/out   # dump transferred files
```
- Follow TCP/HTTP streams; look for creds, uploads, exfil, and C2.
- TLS? Search challenge files for keys / `SSLKEYLOGFILE` to decrypt.

### 2.2 Disk images / blobs
```bash
binwalk -e image.bin        # signature carve embedded files
foremost -i image.bin -o out/
exiftool file               # metadata / slack
mount -o ro,loop image.dd /mnt   # then browse; check deleted/slack
```

### 2.3 Memory dumps (Volatility)
```bash
vol.py -f mem.raw imageinfo                 # profile (vol2) / auto (vol3)
vol.py -f mem.raw --profile=<p> pslist
vol.py -f mem.raw --profile=<p> cmdscan / consoles / filescan / dumpfiles
```
- Enumerate processes, network, command history; dump the relevant process/file.

---

## Phase 3: Post-Process
- Run recovered files/streams through the `flag_hunter` tool.
- Decode/deobfuscate follow-on data with `crypto_helper` or `stego_extract`.

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Encrypted pcap (TLS) | Find key material in provided files; use SSLKEYLOGFILE |
| Carving yields fragments | Reassemble by known file signatures/sizes |
| Wrong volatility profile | Re-run imageinfo / use vol3 auto-detect |
| Flag not in obvious place | Check metadata, slack space, deleted entries |

## Success Criteria
- [ ] Artifact type identified and correct toolchain chosen
- [ ] Relevant stream/file/process extracted
- [ ] Flag or required evidence recovered
