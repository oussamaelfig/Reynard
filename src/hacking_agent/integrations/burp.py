"""
=============================================================================
Reynard — Burp Suite MCP Client
=============================================================================
Provides a Python client that talks to the PortSwigger Burp Suite MCP
server (https://github.com/PortSwigger/mcp-server) over SSE / HTTP.

The Burp MCP server exposes these capabilities:
  - send_http1_request / send_http2_request  — proxy through Burp (logged)
  - get_scanner_issues                       — Burp Professional scanner results
  - get_proxy_http_history                   — full proxy history
  - get_proxy_http_history_regex             — regex-filtered proxy history
  - generate_collaborator_payload            — OOB (Burp Collaborator)
  - get_collaborator_interactions            — poll OOB callbacks
  - create_repeater_tab / send_to_intruder   — queue findings in Burp UI
  - url_encode / url_decode / base64_encode / base64_decode / generate_random_string
  - output_project_options / output_user_options / set_project_options / set_user_options
  - set_task_execution_engine_state          — pause/resume Burp engine
  - set_proxy_intercept_state                — toggle proxy intercept

Architecture
────────────
  Burp Suite (Java, localhost:9876)
      ↕ SSE/HTTP
  burp.py  BurpMCPClient  (this module)
      ↕ JSON-RPC over HTTP
  tools.py  (registered as agent-callable tools)

Prerequisites
─────────────
  1. Burp Suite running with the MCP extension enabled (default: http://127.0.0.1:9876)
  2. pip install httpx  (already in requirements.txt)

Usage
─────
  client = BurpMCPClient()          # reads BURP_MCP_URL from env
  result = client.call_tool("send_http1_request", {
      "content": "GET / HTTP/1.1\\r\\nHost: target.com\\r\\n\\r\\n",
      "targetHostname": "target.com",
      "targetPort": 443,
      "usesHttps": True,
  })
=============================================================================
"""
from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

import httpx


# =============================================================================
# Configuration
# =============================================================================

DEFAULT_BURP_MCP_URL = "http://127.0.0.1:9876"

def _burp_url() -> str:
    """Resolve the Burp MCP SSE server URL from environment or default."""
    return os.getenv("BURP_MCP_URL", DEFAULT_BURP_MCP_URL).rstrip("/")


# =============================================================================
# MCP JSON-RPC helpers
# =============================================================================

def _jsonrpc_request(method: str, params: dict | None = None, id_: str | None = None) -> dict:
    """Build a JSON-RPC 2.0 request body."""
    return {
        "jsonrpc": "2.0",
        "id": id_ or str(uuid.uuid4()),
        "method": method,
        "params": params or {},
    }


# =============================================================================
# BurpMCPClient
# =============================================================================

class BurpMCPClient:
    """Synchronous MCP client for the Burp Suite SSE server.

    Communicates via the SSE transport's JSON-RPC HTTP endpoint.
    Falls back gracefully if Burp is not running — tools return an error
    rather than crashing the orchestrator.
    """

    def __init__(self, base_url: str | None = None, timeout: float = 30.0):
        self.base_url = (base_url or _burp_url()).rstrip("/")
        self.timeout = timeout
        self._available: bool | None = None
        self._client = httpx.Client(timeout=timeout)

    # ---- availability ------------------------------------------------

    def is_available(self, force_check: bool = False) -> bool:
        """Check if the Burp MCP server is reachable.

        Caches the result after the first successful check. Set force_check
        to bypass the cache (e.g. after user starts Burp mid-session).
        """
        if self._available is not None and not force_check:
            return self._available
        import socket
        from urllib.parse import urlparse
        
        parsed = urlparse(self.base_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 9876
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            self._available = (s.connect_ex((host, port)) == 0)
            
        return self._available

    # ---- MCP tool invocation -----------------------------------------

    def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> dict:
        """Invoke a Burp MCP tool via JSON-RPC over the SSE HTTP transport.

        Returns a dict with either {"result": ...} or {"error": ...}.
        """
        if not self.is_available():
            return {
                "error": (
                    f"Burp Suite MCP server not reachable at {self.base_url}. "
                    "Ensure Burp Suite is running with the MCP extension enabled."
                ),
                "available": False,
            }

        # Strip None-valued arguments: the Burp MCP server rejects null fields
        # (e.g. an unset tabName), so only send keys the caller supplied.
        clean_args = {k: v for k, v in (arguments or {}).items() if v is not None}

        payload = _jsonrpc_request(
            method="tools/call",
            params={
                "name": tool_name,
                "arguments": clean_args,
            },
        )

        try:
            resp = self._client.post(
                f"{self.base_url}/message",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

            # JSON-RPC response: either {"result": ...} or {"error": ...}
            if "error" in data:
                return {"error": data["error"], "tool": tool_name}
            result = data.get("result", {})
            # MCP tool results come as content array
            content = result.get("content", [])
            texts = [c.get("text", "") for c in content if c.get("type") == "text"]
            return {
                "result": "\n".join(texts) if texts else json.dumps(result),
                "tool": tool_name,
            }

        except httpx.HTTPStatusError as e:
            return {"error": f"HTTP {e.response.status_code}: {e.response.text[:300]}", "tool": tool_name}
        except httpx.ConnectError:
            self._available = False
            return {"error": f"Connection refused — Burp MCP not running at {self.base_url}", "tool": tool_name}
        except httpx.TimeoutException:
            return {"error": f"Timeout calling Burp MCP tool {tool_name}", "tool": tool_name}
        except Exception as e:
            return {"error": f"Unexpected error: {e}", "tool": tool_name}

    def list_tools(self) -> list[dict]:
        """Ask the Burp MCP server which tools are available."""
        if not self.is_available():
            return []
        payload = _jsonrpc_request(method="tools/list")
        try:
            resp = self._client.post(
                f"{self.base_url}/message",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("result", {}).get("tools", [])
        except Exception:
            return []

    # ---- convenience wrappers ----------------------------------------

    def send_http1(self, raw_request: str, hostname: str, port: int = 443,
                   https: bool = True) -> dict:
        """Send an HTTP/1.1 request through Burp's proxy."""
        return self.call_tool("send_http1_request", {
            "content": raw_request,
            "targetHostname": hostname,
            "targetPort": port,
            "usesHttps": https,
        })

    def get_scanner_issues(self, count: int = 50, offset: int = 0) -> dict:
        """Fetch Burp Scanner issues (Professional edition only)."""
        return self.call_tool("get_scanner_issues", {
            "count": count,
            "offset": offset,
        })

    def get_proxy_history(self, count: int = 50, offset: int = 0) -> dict:
        """Fetch Burp Proxy HTTP history."""
        return self.call_tool("get_proxy_http_history", {
            "count": count,
            "offset": offset,
        })

    def get_proxy_history_regex(self, regex: str, count: int = 50, offset: int = 0) -> dict:
        """Fetch Burp Proxy history filtered by regex."""
        return self.call_tool("get_proxy_http_history_regex", {
            "regex": regex,
            "count": count,
            "offset": offset,
        })

    def generate_collaborator_payload(self, custom_data: str | None = None) -> dict:
        """Generate a Burp Collaborator payload (Professional only)."""
        args: dict[str, Any] = {}
        if custom_data:
            args["customData"] = custom_data
        return self.call_tool("generate_collaborator_payload", args)

    def get_collaborator_interactions(self, payload_id: str | None = None) -> dict:
        """Poll Burp Collaborator for OOB interactions."""
        args: dict[str, Any] = {}
        if payload_id:
            args["payloadId"] = payload_id
        return self.call_tool("get_collaborator_interactions", args)

    def create_repeater_tab(self, raw_request: str, hostname: str,
                            port: int = 443, https: bool = True,
                            tab_name: str | None = None) -> dict:
        """Send a request to Burp Repeater."""
        return self.call_tool("create_repeater_tab", {
            "content": raw_request,
            "targetHostname": hostname,
            "targetPort": port,
            "usesHttps": https,
            "tabName": tab_name,
        })

    def send_to_intruder(self, raw_request: str, hostname: str,
                         port: int = 443, https: bool = True,
                         tab_name: str | None = None) -> dict:
        """Send a request to Burp Intruder."""
        return self.call_tool("send_to_intruder", {
            "content": raw_request,
            "targetHostname": hostname,
            "targetPort": port,
            "usesHttps": https,
            "tabName": tab_name,
        })

    def url_encode(self, content: str) -> dict:
        return self.call_tool("url_encode", {"content": content})

    def url_decode(self, content: str) -> dict:
        return self.call_tool("url_decode", {"content": content})

    def base64_encode(self, content: str) -> dict:
        return self.call_tool("base64_encode", {"content": content})

    def base64_decode(self, content: str) -> dict:
        return self.call_tool("base64_decode", {"content": content})

    def set_intercept(self, enabled: bool) -> dict:
        """Enable or disable Burp Proxy intercept."""
        return self.call_tool("set_proxy_intercept_state", {
            "intercepting": enabled,
        })

    def set_engine_state(self, running: bool) -> dict:
        """Pause or resume Burp's task execution engine."""
        return self.call_tool("set_task_execution_engine_state", {
            "running": running,
        })


# =============================================================================
# Module-level singleton
# =============================================================================

_client: BurpMCPClient | None = None

def get_client() -> BurpMCPClient:
    """Get (or create) the module-level BurpMCPClient singleton."""
    global _client
    if _client is None:
        _client = BurpMCPClient()
    return _client
