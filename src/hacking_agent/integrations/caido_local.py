"""Caido local testing bridge client.

This module talks to a small local Caido plugin/bridge HTTP service. Caido's
Cloud API is account/workspace oriented; Replay, request sending, and HTTP
history access live in the desktop/runtime SDK. The bridge contract here gives
Reynard a stable tool surface without pretending the Cloud API can do proxy
testing.
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx


DEFAULT_CAIDO_BRIDGE_URL = "http://127.0.0.1:17650"
DEFAULT_TIMEOUT = 30.0


def _bridge_url() -> str:
    return (
        os.getenv("CAIDO_LOCAL_BRIDGE_URL")
        or os.getenv("CAIDO_BRIDGE_URL")
        or DEFAULT_CAIDO_BRIDGE_URL
    ).rstrip("/")


def _bridge_token() -> str | None:
    return os.getenv("CAIDO_LOCAL_BRIDGE_TOKEN") or os.getenv("CAIDO_BRIDGE_TOKEN")


def _json_result(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    return {"result": data}


class CaidoLocalBridgeClient:
    """Client for a local Caido bridge plugin/service."""

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.base_url = (base_url or _bridge_url()).rstrip("/")
        self.token = token if token is not None else _bridge_token()
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def status(self) -> dict[str, Any]:
        result = self.request("GET", "/status", require_token=False)
        result.update({
            "bridge_url": self.base_url,
            "token_configured": bool(self.token),
            "contract": "reynard-caido-local-bridge/v1",
            "hint": (
                "This is for Caido Replay/history/request testing. "
                "caido_cloud_api is only for Caido account/workspace operations."
            ),
        })
        return result

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        headers: dict[str, Any] | None = None,
        require_token: bool = False,
    ) -> dict[str, Any]:
        if require_token and not self.token:
            return {
                "error": "Caido local bridge token not configured.",
                "configured": False,
                "bridge_url": self.base_url,
            }

        if path.startswith("http://") or path.startswith("https://"):
            if not path.startswith(self.base_url):
                return {
                    "error": f"Refusing to call non-bridge URL {path!r}",
                    "bridge_url": self.base_url,
                }
            url = path
        else:
            url = f"{self.base_url}/{path.lstrip('/')}"

        req_headers = {
            "Accept": "application/json",
            "User-Agent": "reynard-caido-local-client/1.0",
        }
        if self.token:
            req_headers["Authorization"] = f"Bearer {self.token}"
        if headers:
            for key, value in headers.items():
                if value is not None and str(key).lower() != "authorization":
                    req_headers[str(key)] = str(value)

        try:
            resp = self._client.request(
                method.upper(),
                url,
                params=params,
                json=json_body,
                headers=req_headers,
            )
        except httpx.ConnectError:
            return {
                "error": (
                    f"Caido local bridge not reachable at {self.base_url}. "
                    "Start Caido and enable/install the Reynard bridge plugin."
                ),
                "reachable": False,
                "bridge_url": self.base_url,
            }
        except httpx.TimeoutException:
            return {"error": f"Timeout calling Caido local bridge: {method} {path}"}
        except httpx.HTTPError as exc:
            return {"error": f"Caido local bridge transport error: {exc}"}

        try:
            body = resp.json() if resp.content else None
        except ValueError:
            body = resp.text[:5000]
        return {
            "status_code": resp.status_code,
            "ok": 200 <= resp.status_code < 300,
            "method": method.upper(),
            "path": path,
            "body": body,
        }

    def send_raw(
        self,
        raw_request: str,
        hostname: str,
        port: int = 443,
        https: bool = True,
        *,
        collection: str = "Reynard",
        name: str | None = None,
        send: bool = True,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/replay/raw",
            json_body={
                "raw_request": raw_request,
                "hostname": hostname,
                "port": port,
                "https": https,
                "collection": collection,
                "name": name,
                "send": send,
            },
        )

    def create_replay_session(
        self,
        raw_request: str,
        hostname: str,
        port: int = 443,
        https: bool = True,
        *,
        collection: str = "Reynard",
        name: str | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/replay/sessions",
            json_body={
                "raw_request": raw_request,
                "hostname": hostname,
                "port": port,
                "https": https,
                "collection": collection,
                "name": name,
            },
        )

    def send_replay_session(self, session_id: str) -> dict[str, Any]:
        return self.request("POST", f"/replay/sessions/{session_id}/send")

    def search_history(
        self,
        query: str,
        *,
        limit: int = 20,
        include_response: bool = False,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/history/search",
            json_body={
                "query": query,
                "limit": limit,
                "include_response": include_response,
            },
        )

    def get_history_item(self, request_id: str, include_response: bool = True) -> dict[str, Any]:
        return self.request(
            "GET",
            f"/history/{request_id}",
            params={"include_response": str(include_response).lower()},
        )

    def create_finding(
        self,
        title: str,
        severity: str,
        description: str,
        *,
        request_id: str | None = None,
        evidence: str = "",
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/findings",
            json_body={
                "title": title,
                "severity": severity,
                "description": description,
                "request_id": request_id,
                "evidence": evidence,
            },
        )


def call_operation(operation: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    args = args or {}
    client = get_client()

    if operation == "status":
        return client.status()
    if operation == "send_raw":
        return client.send_raw(
            raw_request=args["raw_request"],
            hostname=args["hostname"],
            port=args.get("port", 443),
            https=args.get("https", True),
            collection=args.get("collection", "Reynard"),
            name=args.get("name"),
            send=args.get("send", True),
        )
    if operation == "create_replay_session":
        return client.create_replay_session(
            raw_request=args["raw_request"],
            hostname=args["hostname"],
            port=args.get("port", 443),
            https=args.get("https", True),
            collection=args.get("collection", "Reynard"),
            name=args.get("name"),
        )
    if operation == "send_replay_session":
        return client.send_replay_session(session_id=args["session_id"])
    if operation == "search_history":
        return client.search_history(
            query=args["query"],
            limit=args.get("limit", 20),
            include_response=args.get("include_response", False),
        )
    if operation == "get_history_item":
        return client.get_history_item(
            request_id=args["request_id"],
            include_response=args.get("include_response", True),
        )
    if operation == "create_finding":
        return client.create_finding(
            title=args["title"],
            severity=args.get("severity", "info"),
            description=args["description"],
            request_id=args.get("request_id"),
            evidence=args.get("evidence", ""),
        )
    if operation == "raw_bridge_request":
        return client.request(
            method=args["method"],
            path=args["path"],
            params=args.get("params"),
            json_body=args.get("json_body"),
            headers=args.get("headers"),
            require_token=args.get("require_token", False),
        )

    return {
        "error": f"Unknown Caido local operation: {operation}",
        "available_operations": [
            "status",
            "send_raw",
            "create_replay_session",
            "send_replay_session",
            "search_history",
            "get_history_item",
            "create_finding",
            "raw_bridge_request",
        ],
    }


_client: CaidoLocalBridgeClient | None = None


def get_client() -> CaidoLocalBridgeClient:
    global _client
    if _client is None:
        _client = CaidoLocalBridgeClient()
    return _client


def dumps(data: Any) -> str:
    return json.dumps(_json_result(data), indent=2)
