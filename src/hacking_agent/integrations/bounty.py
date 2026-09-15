"""
=============================================================================
Reynard — Bug-bounty program scope import
=============================================================================
Turns a bug-bounty program's scope into a typed ``Engagement`` that feeds the
``ScopeGuard``. Two sources are supported:

  1. OFFLINE structured scope file (YAML/JSON) — works with no network/keys.
     Accepts the hand-written engagement format AND a structured-scope format
     (list of assets with asset_type / asset_identifier / eligible_for_submission,
     or simple in_scope / out_of_scope string lists).

  2. HackerOne API connector — activated ONLY when HACKERONE_API_USERNAME and
     HACKERONE_API_TOKEN are set. Pulls a program's structured scopes and maps
     them into authorized_domains / authorized_cidrs / out_of_scope.

SECURITY INVARIANT
──────────────────
This module only ever *produces* an ``Engagement`` at startup, which the CLI
then attaches to the ``ScopeGuard`` once. It NEVER mutates a live guard, and it
is never reachable from a tool, web page, or MCP response — so a connector or a
fetched page can inform recon but can NEVER widen (or narrow) the authorization
boundary at runtime. That authority stays exclusively with ScopeGuard.
=============================================================================
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from hacking_agent.core.engagement import Engagement, engagement_from_dict


class BountyScopeError(ValueError):
    """Raised when a bounty scope source is malformed or unauthorized."""


# =============================================================================
# Normalisation of scope identifiers
# =============================================================================

# HackerOne asset_type values that map to a host/domain scope entry.
_DOMAIN_ASSET_TYPES = {"URL", "WILDCARD", "DOMAIN"}
_CIDR_ASSET_TYPES = {"CIDR", "IP_RANGE", "IP"}


def normalize_scope_host(identifier: str) -> str:
    """Reduce a scope asset identifier to a bare host/domain.

    ``https://*.example.com/graphql`` -> ``example.com``
    ``*.example.com``                 -> ``example.com``
    ``app.example.com``               -> ``app.example.com``
    """
    ident = (identifier or "").strip().lower()
    if not ident:
        return ""
    if "://" in ident:
        ident = urlsplit(ident).hostname or ""
    else:
        # strip any path/query the program tacked on
        ident = ident.split("/", 1)[0].split("?", 1)[0]
    if ident.startswith("*."):
        ident = ident[2:]
    ident = ident.lstrip(".").rstrip(".")
    # drop a :port if present
    if ident.count(":") == 1 and not ident.startswith("["):
        ident = ident.split(":", 1)[0]
    return ident


def _looks_like_cidr(value: str) -> bool:
    return "/" in value and all(
        part.replace(".", "").replace(":", "").isalnum()
        for part in value.split("/", 1)
    )


# =============================================================================
# Structured scope parsing (shared by file importer + HackerOne connector)
# =============================================================================

@dataclass
class _ScopeBuckets:
    authorized_domains: list[str]
    authorized_cidrs: list[str]
    out_of_scope: list[str]


def parse_structured_scopes(scopes: list[dict[str, Any]]) -> _ScopeBuckets:
    """Map a list of structured-scope entries to allow/deny buckets.

    Each entry may carry ``asset_type``, ``asset_identifier`` and
    ``eligible_for_submission`` (HackerOne shape). Out-of-scope / ineligible
    assets go to the denylist so they override the allowlist in ScopeGuard.
    """
    domains: list[str] = []
    cidrs: list[str] = []
    denied: list[str] = []

    def _add(bucket: list[str], value: str) -> None:
        if value and value not in bucket:
            bucket.append(value)

    for entry in scopes or []:
        if not isinstance(entry, dict):
            continue
        asset_type = str(entry.get("asset_type", "")).upper()
        identifier = str(entry.get("asset_identifier")
                         or entry.get("identifier") or "")
        eligible = entry.get("eligible_for_submission")
        if eligible is None:
            eligible = entry.get("in_scope", True)
        eligible = bool(eligible)

        if asset_type in _CIDR_ASSET_TYPES or _looks_like_cidr(identifier):
            value = identifier.strip()
            _add(cidrs if eligible else denied, value)
        elif asset_type in _DOMAIN_ASSET_TYPES or "." in identifier:
            host = normalize_scope_host(identifier)
            _add(domains if eligible else denied, host)
        # other asset types (mobile apps, source code, etc.) are ignored for
        # network scope — they are not directly testable targets here.
    return _ScopeBuckets(domains, cidrs, denied)


def _coerce_scope_entries(value: Any, *, in_scope: bool) -> list[dict[str, Any]]:
    """Turn a list of strings or dicts into structured-scope entries."""
    out: list[dict[str, Any]] = []
    for item in value or []:
        if isinstance(item, str):
            out.append({"asset_identifier": item, "eligible_for_submission": in_scope})
        elif isinstance(item, dict):
            d = dict(item)
            d.setdefault("eligible_for_submission", d.get("in_scope", in_scope))
            out.append(d)
    return out


# =============================================================================
# Offline file importer
# =============================================================================

def import_scope_file(path: str | Path) -> Engagement:
    """Load a bounty scope file (YAML/JSON) into an Engagement.

    Supported shapes (auto-detected):
      - the hand-written engagement format (authorized_domains/domains/scope)
      - {"scopes": [ {asset_type, asset_identifier, eligible_for_submission}, ...]}
      - {"in_scope": [...], "out_of_scope": [...]}  (strings or dicts)
      - a bare list of structured-scope entries
    """
    p = Path(path)
    if not p.exists():
        raise BountyScopeError(f"Bounty scope file not found: {p}")
    text = p.read_text(encoding="utf-8")
    raw = _parse_text(text, p.suffix.lower())

    # Engagement format? Delegate so RoE fields (rate limits, window) are kept.
    if isinstance(raw, dict) and any(
        k in raw for k in ("authorized_domains", "domains", "scope", "engagement")
    ):
        eng = engagement_from_dict(raw["engagement"] if isinstance(raw.get("engagement"), dict) else raw)
        # Also fold any structured scopes present alongside the RoE.
        extra = _extract_structured(raw)
        if extra:
            _merge_buckets(eng, extra)
        return eng

    buckets = _extract_structured(raw)
    if buckets is None:
        raise BountyScopeError(
            "Unrecognized bounty scope file. Provide authorized_domains, a "
            "'scopes' list, or in_scope/out_of_scope lists."
        )
    meta = raw if isinstance(raw, dict) else {}
    eng = Engagement(
        engagement_name=str(meta.get("engagement_name") or meta.get("name")
                            or meta.get("handle") or "bounty-program"),
        authorized_domains=list(buckets.authorized_domains),
        authorized_cidrs=list(buckets.authorized_cidrs),
        out_of_scope=list(buckets.out_of_scope),
        max_requests_per_second=float(meta.get("max_requests_per_second") or 0.0),
        max_total_requests=int(meta.get("max_total_requests") or 0),
        allow_destructive=bool(meta.get("allow_destructive", False)),
        notes=str(meta.get("notes") or "Imported from bounty scope file."),
    )
    return eng


def _extract_structured(raw: Any) -> Optional[_ScopeBuckets]:
    entries: list[dict[str, Any]] = []
    if isinstance(raw, list):
        entries = _coerce_scope_entries(raw, in_scope=True)
    elif isinstance(raw, dict):
        if isinstance(raw.get("scopes"), list):
            entries = _coerce_scope_entries(raw["scopes"], in_scope=True)
        if isinstance(raw.get("in_scope"), list):
            entries += _coerce_scope_entries(raw["in_scope"], in_scope=True)
        if isinstance(raw.get("out_of_scope"), list):
            entries += _coerce_scope_entries(raw["out_of_scope"], in_scope=False)
    if not entries:
        return None
    return parse_structured_scopes(entries)


def _merge_buckets(eng: Engagement, buckets: _ScopeBuckets) -> None:
    for d in buckets.authorized_domains:
        if d not in eng.authorized_domains:
            eng.authorized_domains.append(d)
    for c in buckets.authorized_cidrs:
        if c not in eng.authorized_cidrs:
            eng.authorized_cidrs.append(c)
    for o in buckets.out_of_scope:
        if o not in eng.out_of_scope:
            eng.out_of_scope.append(o)


def _parse_text(text: str, suffix: str) -> Any:
    if suffix in (".yaml", ".yml"):
        import yaml
        return yaml.safe_load(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        import yaml
        return yaml.safe_load(text)


# =============================================================================
# HackerOne API connector (optional; requires credentials)
# =============================================================================

# An HTTP transport is any callable(method, url, headers) -> (status, json_obj)
# so tests can inject a canned transport without a network.
HttpTransport = Callable[..., tuple]


@dataclass
class HackerOneClient:
    """Minimal read-only HackerOne API client for structured program scopes.

    Uses HTTP Basic auth with (API username, API token) per HackerOne's hacker
    API. Only GET endpoints are used; this client can never modify a program.
    """
    username: str
    token: str
    base_url: str = "https://api.hackerone.com/v1"
    transport: Optional[HttpTransport] = None
    timeout: int = 30

    @classmethod
    def from_env(cls, transport: Optional[HttpTransport] = None) -> Optional["HackerOneClient"]:
        user = os.getenv("HACKERONE_API_USERNAME") or os.getenv("H1_API_USERNAME")
        token = os.getenv("HACKERONE_API_TOKEN") or os.getenv("H1_API_TOKEN")
        if not user or not token:
            return None
        return cls(username=user, token=token, transport=transport)

    def _auth_header(self) -> str:
        raw = f"{self.username}:{self.token}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def _get(self, url: str) -> tuple[int, Any]:
        headers = {"Authorization": self._auth_header(),
                   "Accept": "application/json"}
        if self.transport is not None:
            return self.transport("GET", url, headers=headers)
        try:
            import httpx
            resp = httpx.get(url, headers=headers, timeout=self.timeout)
            try:
                body = resp.json()
            except Exception:
                body = None
            return resp.status_code, body
        except Exception as exc:  # network failure => structured error
            raise BountyScopeError(f"HackerOne API request failed: {exc}") from exc

    def fetch_structured_scopes(self, handle: str) -> list[dict[str, Any]]:
        """Fetch all structured scopes for a program handle (paginated)."""
        url = f"{self.base_url}/hackers/programs/{handle}/structured_scopes"
        scopes: list[dict[str, Any]] = []
        pages = 0
        while url and pages < 50:
            status, body = self._get(url)
            if status == 401 or status == 403:
                raise BountyScopeError(
                    "HackerOne API rejected the credentials (401/403). Check "
                    "HACKERONE_API_USERNAME / HACKERONE_API_TOKEN."
                )
            if status != 200 or not isinstance(body, dict):
                raise BountyScopeError(
                    f"HackerOne API returned status={status} for {handle}."
                )
            for item in body.get("data", []) or []:
                attrs = item.get("attributes", {}) if isinstance(item, dict) else {}
                if attrs:
                    scopes.append(attrs)
            url = ((body.get("links") or {}).get("next")) or ""
            pages += 1
        return scopes

    def build_engagement(self, handle: str, *,
                         max_requests_per_second: float = 0.0,
                         max_total_requests: int = 0) -> Engagement:
        scopes = self.fetch_structured_scopes(handle)
        buckets = parse_structured_scopes(scopes)
        if not (buckets.authorized_domains or buckets.authorized_cidrs):
            raise BountyScopeError(
                f"HackerOne program '{handle}' returned no testable in-scope assets."
            )
        return Engagement(
            engagement_name=f"hackerone:{handle}",
            client=handle,
            authorized_domains=buckets.authorized_domains,
            authorized_cidrs=buckets.authorized_cidrs,
            out_of_scope=buckets.out_of_scope,
            max_requests_per_second=max_requests_per_second,
            max_total_requests=max_total_requests,
            allow_destructive=False,
            notes=f"Imported from HackerOne structured scopes for '{handle}'.",
        )


# =============================================================================
# Unified entry point
# =============================================================================

def build_engagement_from_source(source: str, *,
                                 transport: Optional[HttpTransport] = None) -> Engagement:
    """Build an Engagement from a bounty source.

      - ``hackerone:<handle>``  -> HackerOne connector (needs credentials)
      - any other value         -> treated as a local scope file path
    """
    src = (source or "").strip()
    if src.lower().startswith("hackerone:"):
        handle = src.split(":", 1)[1].strip()
        client = HackerOneClient.from_env(transport=transport)
        if client is None:
            raise BountyScopeError(
                "HackerOne credentials not set. Export HACKERONE_API_USERNAME "
                "and HACKERONE_API_TOKEN, or pass an offline scope file instead."
            )
        return client.build_engagement(handle)
    return import_scope_file(src)
