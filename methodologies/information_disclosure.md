# Information Disclosure Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> Leaked source, secrets, debug data, backups, and verbose errors that reveal
> data or hand you the keys to a bigger attack.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Common Disclosure Vectors
- Verbose error messages / stack traces (trigger with malformed input)
- Debug pages (`/debug`, `phpinfo`, framework debug mode)
- Backup & temp files (`.bak`, `~`, `.old`, `.swp`, `.git/`, `.DS_Store`)
- Source disclosure via traversal or a `.git`/`.svn` folder
- `robots.txt`, `sitemap.xml`, comments, JS files with API keys/endpoints
- Version banners revealing exploitable software

### 1.2 Trigger Verbose Errors
```
?productId=abc          (type confusion)
?productId[]=1          (array where scalar expected)
malformed JSON / XML    (stack trace with framework + versions)
```

---

## Phase 2: Exploitation Techniques

### 2.1 Files in Hidden Directories
```bash
# TRACE / non-standard methods, robots, and directory brute-force
curl -sk http://target/robots.txt
ffuf -w common.txt -u http://target/FUZZ -mc 200,301,302,403
# Look for /backup, /.git/config, /admin, /server-status
```

### 2.2 Version Control Exposure
```bash
# Dump an exposed .git repo, then read source for secrets
git-dumper http://target/.git/ ./loot
```

### 2.3 Source Code via Backup Files
```
GET /cgi-bin/index.php~        (editor backup)
GET /ProductTemplate.java.bak
```

### 2.4 Debug / Info Endpoints
- `phpinfo.php`, Django/Flask/Rails debug, Spring `/actuator/env`,
  `/actuator/heapdump` — mine for credentials, tokens, internal hosts.

### 2.5 Data via Verbose Errors / Params
- SQL/framework errors echoing table names, versions, file paths.
- Referer/analytics leaks; secrets in JS bundles (`grep -ri apikey`).

---

## Phase 3: PortSwigger Lab-Specific Techniques
- **Error messages**: send `productId=` a non-numeric value to leak the version.
- **Debug page**: find `/cgi-bin/phpinfo.php` disclosing an env secret.
- **Backup files**: `GET /backup/ProductTemplate.java.bak` for DB creds.
- **Info in HTTP TRACE / verbose errors**: read reflected internal headers.
- **Authenticated data via caching / GraphQL introspection**: see cors/graphql.
- Use the disclosed secret (DB password, admin path) to finish the lab.

---

## Phase 4: Tools & Automation
```bash
ffuf -w seclists/Discovery/Web-Content/raft-medium-files.txt \
  -u http://target/FUZZ -mc 200
nuclei -u http://target -t exposures/
```

---

## Common Failure Modes & Solutions
| Problem | Solution |
|---------|----------|
| Errors are generic | Try type confusion / array params to force a stack trace |
| No obvious files | Brute-force backups, `.git`, actuator endpoints |
| Secret found but unused | Feed it into login/admin/DB to complete the objective |

## Success Criteria
- [ ] Disclosed a secret, source file, or admin path
- [ ] Used it to reach the protected objective
- [ ] Lab shows "solved"
