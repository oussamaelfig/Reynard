"""
=============================================================================
Reynard — HexStrike AI capability broker (on-demand specialist tools)
=============================================================================
HexStrike AI exposes 150+ security tools behind an HTTP server (default
http://127.0.0.1:8888): ``GET /health`` reports per-tool availability +
version; ``POST /api/tools/<tool>`` runs a specific tool. (Its MCP bridge just
calls this same API, so we use the HTTP API directly — mirroring burp.py.)

Exposing 150+ tools to the LLM would create tool-selection noise, so this module
is a BROKER, not a dump:

  Reynard asks: "what capability am I missing for this hypothesis?"
  -> search_capability(requirement) returns the SMALLEST relevant subset (<=5),
     GAP-first (tools Reynard lacks natively), so native tools stay preferred.
  -> execute_capability(capability, target, params) runs exactly one, scope-checked.

HexStrike is UNTRUSTED and OPTIONAL: results become AttackSurface Observations
(never findings), a missing server degrades to available=False, and the broker
never touches scope/engagement policy.
=============================================================================
"""
from __future__ import annotations

import os
import socket
import time
from typing import Any, Optional
from urllib.parse import urlparse

from hacking_agent.integrations.external.base import (
    CAT_NOTE, ExternalCapability, ExternalObservation, ExternalProvider,
    PROVIDER_HEXSTRIKE, spill_raw, summarize_raw,
)

DEFAULT_HEXSTRIKE_URL = "http://127.0.0.1:8888"

# Tools Reynard already has as first-class native capabilities. When a
# requirement maps to one of these, the broker prefers the native tool and only
# offers the HexStrike variant as a secondary technique.
NATIVE_EQUIVALENTS = {
    "subfinder", "httpx", "nuclei", "katana", "ffuf", "sqlmap", "nmap",
    "naabu", "dnsx", "waybackurls", "jwt_tool", "jwt-tool", "gobuster",
    "wfuzz", "dirb", "whatweb", "nikto",
}

# requirement keyword -> ordered candidate HexStrike tools (best specialist first).
REQUIREMENT_MAP: dict[str, list[str]] = {
    "hidden parameter": ["arjun", "x8", "paramspider"],
    "parameter discovery": ["arjun", "x8", "paramspider"],
    "parameter": ["arjun", "x8", "paramspider"],
    "xss": ["dalfox", "xsstrike"],
    "sqli": ["sqlmap", "ghauri"],
    "sql injection": ["sqlmap", "ghauri"],
    "graphql": ["graphql-cop", "graphw00f", "clairvoyance"],
    "jwt": ["jwt_tool", "jwt-hack"],
    "content discovery": ["feroxbuster", "dirsearch", "ffuf", "gobuster"],
    "directory": ["feroxbuster", "dirsearch", "ffuf", "gobuster"],
    "subdomain": ["amass", "subfinder", "assetfinder"],
    "port": ["naabu", "rustscan", "nmap", "masscan"],
    "service scan": ["nmap", "naabu", "rustscan"],
    "fingerprint": ["whatweb", "wafw00f", "httpx"],
    "waf": ["wafw00f"],
    "cms": ["wpscan", "cmseek"],
    "wordpress": ["wpscan"],
    "cve": ["nuclei"],
    "vuln scan": ["nuclei", "nikto"],
    "vulnerability scan": ["nuclei", "nikto"],
    "crawl": ["hakrawler", "gospider", "katana"],
    "cloud": ["prowler", "scout-suite", "trivy", "cloudmapper"],
    "s3": ["s3scanner", "prowler"],
    "aws": ["prowler", "scout-suite", "pacu"],
    "kubernetes": ["kube-hunter", "kube-bench"],
    "container": ["trivy", "docker-bench-security"],
    "secret": ["trufflehog", "gitleaks"],
    "api": ["arjun", "kiterunner"],
    "fuzz": ["ffuf", "feroxbuster"],
}

# Best-effort tool -> category tag (for display; not authoritative).
_CATEGORY_HINTS = {
    "arjun": "api", "x8": "api", "paramspider": "api", "kiterunner": "api",
    "dalfox": "web_security", "xsstrike": "web_security", "wpscan": "web_security",
    "sqlmap": "web_security", "ghauri": "web_security", "nikto": "web_security",
    "graphql-cop": "api", "graphw00f": "api", "clairvoyance": "api",
    "jwt_tool": "web_security", "jwt-hack": "web_security",
    "feroxbuster": "web_security", "dirsearch": "web_security",
    "amass": "osint", "assetfinder": "osint",
    "naabu": "network", "rustscan": "network", "masscan": "network", "nmap": "network",
    "whatweb": "web_security", "wafw00f": "web_security",
    "prowler": "cloud", "scout-suite": "cloud", "trivy": "cloud",
    "cloudmapper": "cloud", "pacu": "cloud", "s3scanner": "cloud",
    "kube-hunter": "cloud", "kube-bench": "cloud", "docker-bench-security": "cloud",
    "trufflehog": "osint", "gitleaks": "osint",
    "hakrawler": "web_security", "gospider": "web_security",
}


def _env_flag(name: str, default: str = "1") -> bool:
    return os.getenv(name, default).lower() not in ("0", "false", "no", "off")


def _server_url() -> str:
    return os.getenv("HEXSTRIKE_SERVER_URL", DEFAULT_HEXSTRIKE_URL).rstrip("/")


# =============================================================================
# HTTP client (mirrors integrations/burp.py structure)
# =============================================================================

class HexStrikeClient:
    """Synchronous HTTP client for the HexStrike AI server. Degrades gracefully
    when the server is not running."""

    def __init__(self, base_url: str | None = None, timeout: float = 300.0):
        self.base_url = (base_url or _server_url()).rstrip("/")
        self.timeout = timeout
        self._available: bool | None = None
        try:
            import httpx
            self._client = httpx.Client(timeout=timeout)
        except Exception:
            self._client = None

    def is_available(self, force_check: bool = False) -> bool:
        if self._client is None:
            return False
        if self._available is not None and not force_check:
            return self._available
        parsed = urlparse(self.base_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8888
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                self._available = (s.connect_ex((host, port)) == 0)
        except Exception:
            self._available = False
        return self._available

    def safe_get(self, endpoint: str, params: dict | None = None) -> dict[str, Any]:
        if not self.is_available():
            return {"error": f"HexStrike server not reachable at {self.base_url}",
                    "available": False}
        try:
            resp = self._client.get(f"{self.base_url}/{endpoint.lstrip('/')}",
                                    params=params or {})
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            self._available = False
            return {"error": f"HexStrike GET {endpoint} failed: {exc}"}

    def safe_post(self, endpoint: str, json_data: dict) -> dict[str, Any]:
        if not self.is_available():
            return {"error": f"HexStrike server not reachable at {self.base_url}",
                    "available": False}
        try:
            resp = self._client.post(f"{self.base_url}/{endpoint.lstrip('/')}",
                                     json=json_data)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            return {"error": f"HexStrike POST {endpoint} failed: {exc}"}

    def health(self) -> dict[str, Any]:
        return self.safe_get("health")

    def run_tool(self, tool: str, params: dict) -> dict[str, Any]:
        return self.safe_post(f"api/tools/{tool}", params)


# =============================================================================
# Capability broker
# =============================================================================

class HexStrikeCapabilityBroker(ExternalProvider):
    name = PROVIDER_HEXSTRIKE

    def __init__(self, client: HexStrikeClient | None = None):
        self.client = client or HexStrikeClient()
        self._tools_status_cache: dict[str, bool] | None = None
        self._health_cache: dict[str, Any] | None = None

    # ---- availability / health ------------------------------------------

    def available(self) -> bool:
        return _env_flag("HEXSTRIKE_ENABLED") and self.client.is_available()

    def health(self) -> dict[str, Any]:
        if not self.available():
            return {"provider": self.name, "available": False,
                    "error": "HexStrike disabled or server unreachable"}
        h = self.client.health()
        self._health_cache = h
        return {
            "provider": self.name, "available": True,
            "version": h.get("version"),
            "total_tools_available": h.get("total_tools_available"),
            "total_tools_count": h.get("total_tools_count"),
            "category_stats": h.get("category_stats"),
        }

    def version(self) -> str:
        h = self._health_cache or (self.client.health() if self.available() else {})
        return str(h.get("version", "unknown"))

    def _tools_status(self, force: bool = False) -> dict[str, bool]:
        if self._tools_status_cache is not None and not force:
            return self._tools_status_cache
        if not self.available():
            self._tools_status_cache = {}
            return {}
        h = self.client.health()
        self._health_cache = h
        ts = h.get("tools_status")
        self._tools_status_cache = ts if isinstance(ts, dict) else {}
        return self._tools_status_cache

    # ---- capability discovery -------------------------------------------

    def list_capabilities(self) -> list[dict[str, Any]]:
        """All HexStrike tools with availability (used internally / diagnostics —
        NOT exposed wholesale to the LLM)."""
        out = []
        for name, avail in sorted(self._tools_status().items()):
            out.append({
                "capability": name,
                "available": bool(avail),
                "category": _CATEGORY_HINTS.get(name, "additional"),
                "native_equivalent": name in NATIVE_EQUIVALENTS,
            })
        return out

    def search_capability(self, requirement: str, limit: int = 5) -> list[dict[str, Any]]:
        """Return the SMALLEST relevant capability subset for a requirement.

        GAP tools (no native Reynard equivalent) are ranked first so native
        capabilities stay preferred. Only tools that are actually available on
        the server are returned. At most `limit` (default 5) candidates."""
        req = (requirement or "").lower().strip()
        status = self._tools_status()
        if not req or not status:
            return []

        candidates: list[str] = []
        for keyword, tools in REQUIREMENT_MAP.items():
            if keyword in req:
                for t in tools:
                    if t not in candidates:
                        candidates.append(t)
        # Fallback: direct token match against known tool names.
        if not candidates:
            for tool in status:
                if tool in req or (len(tool) >= 4 and tool in req.replace("-", "")):
                    candidates.append(tool)

        # Keep only available tools; rank GAP-first, then by mapping order.
        available = [t for t in candidates if status.get(t, False)]
        gap = [t for t in available if t not in NATIVE_EQUIVALENTS]
        native = [t for t in available if t in NATIVE_EQUIVALENTS]
        ranked = (gap + native)[:limit]

        results = []
        for t in ranked:
            is_native = t in NATIVE_EQUIVALENTS
            results.append({
                "capability": t,
                "category": _CATEGORY_HINTS.get(t, "additional"),
                "available": True,
                "native_equivalent": is_native,
                "note": ("Reynard already has an equivalent native tool — prefer "
                         "native; use this only for a second specialist technique."
                         if is_native else
                         "Fills a capability gap Reynard lacks natively."),
                "params_hint": {"target": "<in-scope target>",
                                "additional_args": "<optional tool flags>"},
            })
        return results

    # ---- execution -------------------------------------------------------

    def execute_capability(self, capability: str, target: str,
                           parameters: dict | None = None,
                           scope_guard: Any = None) -> ExternalCapability:
        """Run exactly one HexStrike capability against an in-scope target."""
        started = time.time()
        parameters = dict(parameters or {})
        cap = ExternalCapability(
            provider=self.name, capability=capability, target=target,
            input={"parameters": parameters})

        if not self.available():
            cap.available = False
            cap.errors.append("HexStrike disabled or server unreachable "
                              f"({self.client.base_url})")
            return cap

        # Scope defense-in-depth (executor also gates the tool call).
        if scope_guard is not None and target:
            try:
                if not scope_guard.is_in_scope(target):
                    cap.errors.append(f"target out of scope: {target}")
                    return cap
            except Exception:
                pass

        # Only run known, available tools.
        if capability not in self._tools_status():
            cap.errors.append(f"unknown/unavailable capability: {capability}")
            return cap

        body = dict(parameters)
        for key in ("target", "url", "domain"):
            body.setdefault(key, target)
        result = self.client.run_tool(capability, body)
        cap.duration = time.time() - started

        if isinstance(result, dict) and result.get("error"):
            cap.errors.append(str(result["error"]))
            return cap

        cap.raw_result_reference = spill_raw(self.name, capability, _raw_text(result))
        cap.structured_observations = _observations_from_tool_result(
            capability, target, result)
        if cap.structured_observations:
            cap.confidence = "probable"
        return cap


# =============================================================================
# Result parsing
# =============================================================================

def _raw_text(result: Any) -> str:
    if isinstance(result, dict):
        for key in ("stdout", "output", "raw_output", "result"):
            v = result.get(key)
            if isinstance(v, str) and v:
                return v
        import json
        return json.dumps(result, default=str)
    return str(result)


def _observations_from_tool_result(capability: str, target: str,
                                   result: Any) -> list[ExternalObservation]:
    """Summarize a HexStrike tool result into structured observations.

    Kept intentionally generic + compact: a short summary observation plus any
    obviously-structured items (discovered parameters/endpoints/urls). Detailed
    reasoning is left to Reynard over the spilled raw reference."""
    obs: list[ExternalObservation] = []
    success = True
    summary_bits = [f"hexstrike:{capability} on {target}"]
    if isinstance(result, dict):
        success = bool(result.get("success", True))
        summary_bits.append(f"success={success}")
        # Common structured fields HexStrike tools emit.
        for key in ("parameters_found", "discovered_parameters", "params"):
            vals = result.get(key)
            if isinstance(vals, list) and vals:
                summary_bits.append(f"{key}={len(vals)}")
                for p in vals[:25]:
                    obs.append(ExternalObservation(
                        category=CAT_NOTE,
                        summary=f"{capability} discovered parameter: {p}"[:200],
                        source=PROVIDER_HEXSTRIKE,
                        data={"parameter": str(p)[:120], "tool": capability}))
        for key in ("endpoints", "urls", "discovered_urls"):
            vals = result.get(key)
            if isinstance(vals, list) and vals:
                summary_bits.append(f"{key}={len(vals)}")
                for u in vals[:25]:
                    u = str(u)
                    if u.startswith("http"):
                        obs.append(ExternalObservation(
                            category="endpoint",
                            summary=f"{capability} found endpoint: {u}"[:200],
                            source=PROVIDER_HEXSTRIKE, url=u,
                            data={"tool": capability}))
    # Always include one compact summary observation.
    obs.insert(0, ExternalObservation(
        category=CAT_NOTE, summary=summarize_raw("; ".join(summary_bits), 300),
        source=PROVIDER_HEXSTRIKE,
        confidence="probable" if success else "suspected",
        data={"tool": capability, "success": success}))
    return obs


# =============================================================================
# Module-level singleton
# =============================================================================

_broker: HexStrikeCapabilityBroker | None = None


def get_broker() -> HexStrikeCapabilityBroker:
    global _broker
    if _broker is None:
        _broker = HexStrikeCapabilityBroker()
    return _broker
