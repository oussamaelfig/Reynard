"""
=============================================================================
Hacking Agent - Caido Cloud API Client
=============================================================================
Synchronous helper for Caido's public Cloud API.

The public API is documented at:
  https://developer.caido.io/reference/cloud/api.html

Authentication uses a Personal Access Token (PAT):
  Authorization: Bearer <PAT>

Environment variables:
  CAIDO_PAT              PAT used for public Cloud API calls.
  CAIDO_CLOUD_PAT        Optional Cloud-specific PAT override.
  CAIDO_API_BASE_URL     Defaults to https://api.caido.io.
  CAIDO_SESSION          Dashboard session cookie for PAT create/revoke helpers.
=============================================================================
"""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urljoin

import httpx


DEFAULT_CAIDO_API_BASE_URL = "https://api.caido.io"
DEFAULT_TIMEOUT = 30.0


def _api_base_url() -> str:
    return os.getenv("CAIDO_API_BASE_URL", DEFAULT_CAIDO_API_BASE_URL).rstrip("/")


def _cloud_pat() -> str | None:
    return os.getenv("CAIDO_CLOUD_PAT") or os.getenv("CAIDO_PAT")


def _session_cookie() -> str | None:
    return os.getenv("CAIDO_SESSION")


def _json_result(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    return {"result": data}


class CaidoCloudClient:
    """Minimal client for Caido Cloud REST and documented PAT GraphQL helpers."""

    def __init__(
        self,
        base_url: str | None = None,
        pat: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.base_url = (base_url or _api_base_url()).rstrip("/")
        self.pat = pat if pat is not None else _cloud_pat()
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def is_configured(self) -> bool:
        return bool(self.pat)

    def status(self) -> dict[str, Any]:
        return {
            "configured": self.is_configured(),
            "base_url": self.base_url,
            "pat_env": "CAIDO_CLOUD_PAT" if os.getenv("CAIDO_CLOUD_PAT") else (
                "CAIDO_PAT" if os.getenv("CAIDO_PAT") else None
            ),
            "session_cookie_configured": bool(_session_cookie()),
        }

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            if not path.startswith(self.base_url):
                raise ValueError(
                    f"Refusing to call non-Caido URL {path!r}; base is {self.base_url!r}"
                )
            return path
        if not path.startswith("/"):
            path = "/" + path
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def _auth_headers(self, extra_headers: dict[str, Any] | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "hacking-agent-caido-client/1.0",
        }
        if self.pat:
            headers["Authorization"] = f"Bearer {self.pat}"
        if extra_headers:
            for key, value in extra_headers.items():
                if value is not None:
                    header_name = str(key)
                    if header_name.lower() == "authorization":
                        continue
                    headers[header_name] = str(value)
        return headers

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        headers: dict[str, Any] | None = None,
        require_pat: bool = True,
    ) -> dict[str, Any]:
        """Call a Caido Cloud REST endpoint and return a stable JSON object."""
        if require_pat and not self.pat:
            return {
                "error": "Caido PAT not configured. Set CAIDO_PAT or CAIDO_CLOUD_PAT.",
                "configured": False,
                "base_url": self.base_url,
            }

        try:
            resp = self._client.request(
                method.upper(),
                self._url(path),
                params=params,
                json=json_body,
                headers=self._auth_headers(headers),
            )
        except httpx.TimeoutException:
            return {"error": f"Timeout calling Caido Cloud API: {method} {path}"}
        except httpx.HTTPError as exc:
            return {"error": f"Caido Cloud API transport error: {exc}"}
        except ValueError as exc:
            return {"error": str(exc)}

        parsed_body: Any
        if not resp.content:
            parsed_body = None
        else:
            try:
                parsed_body = resp.json()
            except ValueError:
                parsed_body = resp.text[:5000]

        return {
            "status_code": resp.status_code,
            "ok": 200 <= resp.status_code < 300,
            "method": method.upper(),
            "path": path,
            "body": parsed_body,
        }

    # Public Cloud API wrappers

    def get_team(self) -> dict[str, Any]:
        return self.request("GET", "/api/v1/team")

    def list_team_invitations(self) -> dict[str, Any]:
        return self.request("GET", "/api/v1/team/invitations")

    def create_team_invitation(
        self,
        email: str,
        role: str,
        use_seat: bool = True,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/api/v1/team/invitations",
            json_body={"email": email, "role": role, "use_seat": use_seat},
        )

    def delete_team_invitation(self, invitation_id: str) -> dict[str, Any]:
        return self.request("DELETE", f"/api/v1/team/invitations/{invitation_id}")

    def get_team_subscription(self) -> dict[str, Any]:
        return self.request("GET", "/api/v1/team/subscription")

    def list_team_users(self) -> dict[str, Any]:
        return self.request("GET", "/api/v1/team/users")

    def delete_team_user(self, user_id: str) -> dict[str, Any]:
        return self.request("DELETE", f"/api/v1/team/users/{user_id}")

    def get_user(self) -> dict[str, Any]:
        return self.request("GET", "/api/v1/user")

    def get_workspace(self, workspace_id: str) -> dict[str, Any]:
        return self.request("GET", f"/api/v1/workspace/{workspace_id}")

    def claim_voucher(self, code: str) -> dict[str, Any]:
        return self.request(
            "POST",
            "/api/v1/user/billing/voucher-claims",
            json_body={"code": code},
        )

    # Dashboard GraphQL helpers documented for PAT lifecycle.

    def dashboard_graphql(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        *,
        session_cookie: str | None = None,
    ) -> dict[str, Any]:
        cookie = session_cookie or _session_cookie()
        if not cookie:
            return {
                "error": (
                    "CAIDO_SESSION is required for Caido dashboard GraphQL helpers. "
                    "Use CAIDO_PAT/CAIDO_CLOUD_PAT for public Cloud API calls."
                ),
                "configured": False,
            }

        try:
            resp = self._client.post(
                self._url("/dashboard/graphql"),
                json={"query": query, "variables": variables or {}},
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Cookie": cookie if "=" in cookie else f"CAIDO_SESSION={cookie}",
                    "User-Agent": "hacking-agent-caido-client/1.0",
                },
            )
        except httpx.TimeoutException:
            return {"error": "Timeout calling Caido dashboard GraphQL API"}
        except httpx.HTTPError as exc:
            return {"error": f"Caido dashboard GraphQL transport error: {exc}"}

        try:
            body = resp.json()
        except ValueError:
            body = resp.text[:5000]
        return {
            "status_code": resp.status_code,
            "ok": 200 <= resp.status_code < 300,
            "body": body,
        }

    def create_pat(
        self,
        name: str,
        team_id: str,
        expires_at: str | None = None,
        *,
        session_cookie: str | None = None,
    ) -> dict[str, Any]:
        if expires_at:
            query = """
mutation CreatePat($name: String!, $teamId: ID!, $expiresAt: DateTime!) {
  createPat(input: { name: $name, teamId: $teamId, expiresAt: $expiresAt }) {
    pat { id token }
  }
}
""".strip()
            variables = {"name": name, "teamId": team_id, "expiresAt": expires_at}
        else:
            query = """
mutation CreatePat($name: String!, $teamId: ID!) {
  createPat(input: { name: $name, teamId: $teamId }) {
    pat { id token }
  }
}
""".strip()
            variables = {"name": name, "teamId": team_id}
        return self.dashboard_graphql(query, variables, session_cookie=session_cookie)

    def revoke_pat(self, pat_id: str, *, session_cookie: str | None = None) -> dict[str, Any]:
        query = """
mutation RevokePat($id: ID!) {
  revokePat(id: $id) {
    pat { id }
  }
}
""".strip()
        return self.dashboard_graphql(query, {"id": pat_id}, session_cookie=session_cookie)


def call_operation(operation: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Dispatch a high-level Caido operation used by the agent tool."""
    args = args or {}
    client = get_client()

    if operation == "status":
        return client.status()
    if operation == "get_user":
        return client.get_user()
    if operation == "get_team":
        return client.get_team()
    if operation == "list_team_invitations":
        return client.list_team_invitations()
    if operation == "create_team_invitation":
        return client.create_team_invitation(
            email=args["email"],
            role=args["role"],
            use_seat=args.get("use_seat", True),
        )
    if operation == "delete_team_invitation":
        return client.delete_team_invitation(args["invitation_id"])
    if operation == "get_team_subscription":
        return client.get_team_subscription()
    if operation == "list_team_users":
        return client.list_team_users()
    if operation == "delete_team_user":
        return client.delete_team_user(args["user_id"])
    if operation == "get_workspace":
        return client.get_workspace(args["workspace_id"])
    if operation == "claim_voucher":
        return client.claim_voucher(args["code"])
    if operation == "create_pat":
        return client.create_pat(
            name=args["name"],
            team_id=args["team_id"],
            expires_at=args.get("expires_at"),
            session_cookie=args.get("session_cookie"),
        )
    if operation == "revoke_pat":
        return client.revoke_pat(
            pat_id=args["pat_id"],
            session_cookie=args.get("session_cookie"),
        )

    return {
        "error": f"Unknown Caido operation: {operation}",
        "available_operations": [
            "status",
            "get_user",
            "get_team",
            "list_team_invitations",
            "create_team_invitation",
            "delete_team_invitation",
            "get_team_subscription",
            "list_team_users",
            "delete_team_user",
            "get_workspace",
            "claim_voucher",
            "create_pat",
            "revoke_pat",
        ],
    }


_client: CaidoCloudClient | None = None


def get_client() -> CaidoCloudClient:
    global _client
    if _client is None:
        _client = CaidoCloudClient()
    return _client


def dumps(data: Any) -> str:
    return json.dumps(_json_result(data), indent=2)
