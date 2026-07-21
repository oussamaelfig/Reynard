"""
=============================================================================
Reynard — Shodan / Censys OSINT Clients
=============================================================================
Thin, read-only clients for external attack-surface recon during real
engagements (NOT needed for the isolated PortSwigger labs).

  - Shodan  (https://developer.shodan.io/api) via SHODAN_API_KEY
  - Censys  (https://search.censys.io/api)     via CENSYS_API_ID / CENSYS_API_SECRET

Both degrade gracefully: when the relevant API key is not configured the
tools return a clear, structured message ({"configured": false, ...}) instead
of raising — importing this module never requires any key or network access.
=============================================================================
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx


DEFAULT_SHODAN_BASE_URL = "https://api.shodan.io"
DEFAULT_CENSYS_BASE_URL = "https://search.censys.io"
DEFAULT_TIMEOUT = 30.0


def _shodan_key() -> str | None:
    return os.getenv("SHODAN_API_KEY") or None


def _censys_creds() -> tuple[str | None, str | None]:
    return os.getenv("CENSYS_API_ID") or None, os.getenv("CENSYS_API_SECRET") or None


# =============================================================================
# Shodan
# =============================================================================

class ShodanClient:
    """Minimal synchronous client for the Shodan REST API."""

    def __init__(self, api_key: str | None = None,
                 base_url: str | None = None, timeout: float = DEFAULT_TIMEOUT):
        self.api_key = api_key if api_key is not None else _shodan_key()
        self.base_url = (base_url or os.getenv("SHODAN_BASE_URL", DEFAULT_SHODAN_BASE_URL)).rstrip("/")
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _unconfigured(self) -> dict[str, Any]:
        return {
            "configured": False,
            "error": "SHODAN_API_KEY not set — Shodan recon is unavailable.",
            "hint": "Export SHODAN_API_KEY to enable shodan_host_lookup/shodan_search.",
        }

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self.is_configured():
            return self._unconfigured()
        params = {**params, "key": self.api_key}
        try:
            resp = httpx.get(f"{self.base_url}{path}", params=params, timeout=self.timeout)
            if resp.status_code == 401:
                return {"configured": True, "error": "Shodan rejected the API key (401)."}
            resp.raise_for_status()
            return {"configured": True, "result": resp.json()}
        except httpx.HTTPStatusError as exc:
            return {"configured": True,
                    "error": f"HTTP {exc.response.status_code}: {exc.response.text[:300]}"}
        except httpx.HTTPError as exc:
            return {"configured": True, "error": f"Shodan request failed: {exc}"}

    def api_info(self) -> dict[str, Any]:
        """Lightweight connectivity/credit check (used by the readiness probe)."""
        return self._get("/api-info", {})

    def host_lookup(self, ip: str, history: bool = False,
                    minify: bool = False) -> dict[str, Any]:
        """Look up all services Shodan has seen on an IP address."""
        data = self._get(f"/shodan/host/{ip}", {
            "history": str(bool(history)).lower(),
            "minify": str(bool(minify)).lower(),
        })
        return _summarize_shodan_host(data, ip)

    def search(self, query: str, page: int = 1, facets: str = "") -> dict[str, Any]:
        """Search the Shodan index (uses query credits)."""
        params: dict[str, Any] = {"query": query, "page": max(1, int(page))}
        if facets:
            params["facets"] = facets
        data = self._get("/shodan/host/search", params)
        return _summarize_shodan_search(data, query)


def _summarize_shodan_host(data: dict[str, Any], ip: str) -> dict[str, Any]:
    if not data.get("configured") or data.get("error"):
        return {**data, "ip": ip}
    raw = data.get("result", {}) or {}
    services = []
    for item in raw.get("data", []) or []:
        services.append({
            "port": item.get("port"),
            "transport": item.get("transport"),
            "product": item.get("product"),
            "version": item.get("version"),
            "cpe": item.get("cpe"),
        })
    return {
        "configured": True,
        "ip": ip,
        "org": raw.get("org"),
        "isp": raw.get("isp"),
        "os": raw.get("os"),
        "hostnames": raw.get("hostnames", []),
        "ports": raw.get("ports", []),
        "vulns": raw.get("vulns", []),
        "services": services,
        "summary": (
            f"shodan host {ip}: {len(raw.get('ports', []) or [])} port(s), "
            f"{len(raw.get('vulns', []) or [])} known CVE(s), org={raw.get('org')}"
        ),
    }


def _summarize_shodan_search(data: dict[str, Any], query: str) -> dict[str, Any]:
    if not data.get("configured") or data.get("error"):
        return {**data, "query": query}
    raw = data.get("result", {}) or {}
    matches = []
    for item in (raw.get("matches", []) or [])[:50]:
        matches.append({
            "ip": item.get("ip_str"),
            "port": item.get("port"),
            "org": item.get("org"),
            "product": item.get("product"),
            "hostnames": item.get("hostnames", []),
        })
    return {
        "configured": True,
        "query": query,
        "total": raw.get("total"),
        "matches": matches,
        "summary": f"shodan search {query!r}: total={raw.get('total')}, showing {len(matches)}",
    }


# =============================================================================
# Censys (optional)
# =============================================================================

class CensysClient:
    """Minimal synchronous client for the Censys Hosts API (v2)."""

    def __init__(self, api_id: str | None = None, api_secret: str | None = None,
                 base_url: str | None = None, timeout: float = DEFAULT_TIMEOUT):
        env_id, env_secret = _censys_creds()
        self.api_id = api_id if api_id is not None else env_id
        self.api_secret = api_secret if api_secret is not None else env_secret
        self.base_url = (base_url or os.getenv("CENSYS_BASE_URL", DEFAULT_CENSYS_BASE_URL)).rstrip("/")
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.api_id and self.api_secret)

    def host_lookup(self, ip: str) -> dict[str, Any]:
        if not self.is_configured():
            return {
                "configured": False,
                "ip": ip,
                "error": "CENSYS_API_ID / CENSYS_API_SECRET not set — Censys recon unavailable.",
                "hint": "Export CENSYS_API_ID and CENSYS_API_SECRET to enable censys_host.",
            }
        try:
            resp = httpx.get(
                f"{self.base_url}/api/v2/hosts/{ip}",
                auth=(self.api_id, self.api_secret),
                timeout=self.timeout,
            )
            if resp.status_code in (401, 403):
                return {"configured": True, "ip": ip,
                        "error": f"Censys rejected credentials ({resp.status_code})."}
            resp.raise_for_status()
            payload = resp.json().get("result", {}) or {}
        except httpx.HTTPStatusError as exc:
            return {"configured": True, "ip": ip,
                    "error": f"HTTP {exc.response.status_code}: {exc.response.text[:300]}"}
        except httpx.HTTPError as exc:
            return {"configured": True, "ip": ip, "error": f"Censys request failed: {exc}"}

        services = [{
            "port": svc.get("port"),
            "service_name": svc.get("service_name"),
            "transport": svc.get("transport_protocol"),
        } for svc in payload.get("services", []) or []]
        return {
            "configured": True,
            "ip": ip,
            "autonomous_system": (payload.get("autonomous_system", {}) or {}).get("name"),
            "location": (payload.get("location", {}) or {}).get("country"),
            "services": services,
            "summary": f"censys host {ip}: {len(services)} service(s)",
        }


# =============================================================================
# Module-level singletons + helpers
# =============================================================================

_shodan_client: ShodanClient | None = None
_censys_client: CensysClient | None = None


def get_shodan_client() -> ShodanClient:
    global _shodan_client
    if _shodan_client is None:
        _shodan_client = ShodanClient()
    return _shodan_client


def get_censys_client() -> CensysClient:
    global _censys_client
    if _censys_client is None:
        _censys_client = CensysClient()
    return _censys_client


def status() -> dict[str, Any]:
    """Configuration status for both providers (no network calls)."""
    return {
        "shodan_configured": get_shodan_client().is_configured(),
        "censys_configured": get_censys_client().is_configured(),
    }


def dumps(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)
