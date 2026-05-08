# Caido Local Bridge Contract

Reynard uses `caido_local_api` for Caido-backed API testing, Replay, and HTTP
history. This is intentionally separate from `caido_cloud_api`, which only
handles Caido account/team/workspace/PAT operations.

The local bridge is expected at:

```text
CAIDO_LOCAL_BRIDGE_URL=http://127.0.0.1:17650
CAIDO_LOCAL_BRIDGE_TOKEN=optional-shared-secret
```

Minimum HTTP contract:

```text
GET  /status
POST /replay/raw
POST /replay/sessions
POST /replay/sessions/{session_id}/send
POST /history/search
GET  /history/{request_id}
POST /findings
```

`POST /replay/raw` and `POST /replay/sessions` accept:

```json
{
  "raw_request": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
  "hostname": "example.com",
  "port": 443,
  "https": true,
  "collection": "Reynard",
  "name": "optional name",
  "send": true
}
```

`POST /history/search` accepts:

```json
{
  "query": "req.host.eq:\"example.com\"",
  "limit": 20,
  "include_response": false
}
```

`POST /findings` accepts:

```json
{
  "title": "SQL injection",
  "severity": "high",
  "description": "Finding summary",
  "request_id": "optional Caido request id",
  "evidence": "optional evidence"
}
```

Implementation note: Caido's backend SDK exposes request sending, proxied
request querying, Replay sessions, and findings. A small Caido plugin can map
those SDK calls to this local HTTP contract.
