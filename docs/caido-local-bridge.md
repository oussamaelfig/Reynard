# Caido Local Bridge Contract

Reynard uses `caido_local_api` for Caido-backed API testing, Replay, and HTTP
history. This is intentionally separate from `caido_cloud_api`, which only
handles Caido account/team/workspace/PAT operations.

The local bridge is expected at:

```text
CAIDO_LOCAL_BRIDGE_URL=http://127.0.0.1:17650
CAIDO_LOCAL_BRIDGE_TOKEN=your-random-secret-at-least-32-characters
```

## Install the Caido plugin

Build the local Caido plugin package:

```powershell
Set-Location integrations/caido-reynard-bridge
pnpm install
pnpm test
pnpm typecheck
pnpm build
```

Install this generated zip in Caido:

```text
integrations/caido-reynard-bridge/dist/plugin_package.zip
```

In Caido, connect to your local instance, open the Plugins page, choose to
install a local package, and select `plugin_package.zip`. In Caido's environment
variables, set `CAIDO_LOCAL_BRIDGE_TOKEN` as a **secret**, with at least 32
characters. Put the identical value in Reynard's environment or `.env`.
The plugin uses `sdk.env.getVar`, not the host operating system's environment;
changing the selected Caido environment can change the active token.

Once enabled, check the local control endpoint:

```powershell
$env:PYTHONPATH = "src"
python -c "from hacking_agent.integrations.caido_local import CaidoLocalBridgeClient; import json; print(json.dumps(CaidoLocalBridgeClient(timeout=2).status(), indent=2))"
```

The bridge is online when the result contains top-level `"ok": true`.

## Local security boundary

Every endpoint, including `/status`, requires `Authorization: Bearer <token>`.
An unset or short server token fails closed with HTTP 503; a mismatched token
returns 401. This intentionally replaces the previous optional-token behavior.
The Python `require_token=False` legacy argument no longer disables authentication.

The listener binds `127.0.0.1:17650`, checks the HTTP Host, rejects all browser
Origin headers, and sends no CORS permissions. The Python client accepts only
loopback origins, compares parsed scheme/host/port exactly, ignores proxy
environment variables, and never follows redirects. Do not expose or reverse
proxy the bridge. It is a transport integration; Reynard's caller must still
enforce engagement scope and reportability.

HTTP headers are limited to 16 KiB and bodies to 1 MiB. Duplicate headers,
ambiguous lengths, chunked bodies, and pipelining are rejected. A socket may
dispatch one operation only, even if more data arrives while an SDK call is
pending. Partial requests expire after 10 seconds. POST bodies must use
`application/json`. The bridge retains at most the most recent 100 Replay
session specifications; older sessions remain in Caido but cannot be sent by
this bridge cache. Tokens, history bodies, and raw exception details are not
included in bridge error logs.

The regression suite uses simulated sockets and SDK calls. A successful build
and typecheck do not verify live Caido Desktop compatibility; validate that
separately in an authorized local lab.

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
