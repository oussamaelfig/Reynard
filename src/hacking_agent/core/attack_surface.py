"""
=============================================================================
Reynard — Attack Surface Model
=============================================================================
A persistent, structured model of everything Reynard has learned about a
target's attack surface. This is the durable source of truth that turns the
research loop's MAP ATTACK SURFACE phase into a first-class, queryable state
instead of raw scanner text dumped into an LLM prompt.

Every discovery is an ``Asset`` (or ``Observation`` / ``Finding``) and carries:

  - provenance   — WHO/WHAT discovered it and HOW (a list of sources so the
                   same asset seen by subfinder + katana + browser accrues
                   independent corroboration)
  - confidence   — "suspected" | "probable" | "confirmed" (monotonic upgrade)
  - scope_status — "in_scope" | "out_of_scope" | "unknown", annotated via a
                   READ-ONLY ScopeGuard classifier. The surface can never widen
                   or narrow authorization; it only records what the guard says.
  - first_seen / last_seen timestamps — the substrate for delta hunting.

Asset kinds cover the full surface the researcher reasons over: domains,
subdomains, hosts/IPs, URLs, endpoints, parameters, JS bundles + source maps,
APIs, websockets, technologies, identities/sessions, roles, workflows, cloud
assets, credentials — plus behavioural ``Observation`` records and
``Finding`` records.

Design constraints (match the rest of Reynard):
  - THREAD-SAFE: agents run concurrently against one surface.
  - PURE / NO I/O: this module never touches the network. Recon wrappers and
    the browser mapper feed it structured records; persistence lives in
    durable.py.
  - OPT-IN-SAFE persistence: ``persist``/``load`` degrade to no-ops when the
    durable store is unavailable.
=============================================================================
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlparse, urlsplit, parse_qsl


# =============================================================================
# Vocabulary
# =============================================================================

# Canonical asset kinds. Kept as plain strings (not an enum) so serialization
# stays trivial and forward-compatible with kinds added by future wrappers.
KIND_DOMAIN = "domain"
KIND_SUBDOMAIN = "subdomain"
KIND_HOST = "host"           # resolvable hostname (FQDN) with liveness info
KIND_IP = "ip"
KIND_URL = "url"             # a fetched URL (path, no query values)
KIND_ENDPOINT = "endpoint"   # METHOD + path; the unit hypotheses attach to
KIND_PARAMETER = "parameter"
KIND_JS = "js_asset"
KIND_SOURCEMAP = "source_map"
KIND_API = "api"             # API root / spec (swagger/openapi/graphql)
KIND_WEBSOCKET = "websocket"
KIND_TECHNOLOGY = "technology"
KIND_IDENTITY = "identity"   # an auth session / principal
KIND_ROLE = "role"
KIND_WORKFLOW = "workflow"   # a named multi-step business flow
KIND_CLOUD = "cloud_asset"
KIND_CREDENTIAL = "credential"

ASSET_KINDS = frozenset({
    KIND_DOMAIN, KIND_SUBDOMAIN, KIND_HOST, KIND_IP, KIND_URL, KIND_ENDPOINT,
    KIND_PARAMETER, KIND_JS, KIND_SOURCEMAP, KIND_API, KIND_WEBSOCKET,
    KIND_TECHNOLOGY, KIND_IDENTITY, KIND_ROLE, KIND_WORKFLOW, KIND_CLOUD,
    KIND_CREDENTIAL,
})

# Confidence is a small ordered ladder so merges only ever upgrade.
CONFIDENCE_RANK = {"suspected": 0, "probable": 1, "confirmed": 2}
DEFAULT_CONFIDENCE = "suspected"

SCOPE_IN = "in_scope"
SCOPE_OUT = "out_of_scope"
SCOPE_UNKNOWN = "unknown"


def _now() -> str:
    return datetime.utcnow().isoformat()


def _max_confidence(a: str, b: str) -> str:
    a = a if a in CONFIDENCE_RANK else DEFAULT_CONFIDENCE
    b = b if b in CONFIDENCE_RANK else DEFAULT_CONFIDENCE
    return a if CONFIDENCE_RANK[a] >= CONFIDENCE_RANK[b] else b


# =============================================================================
# Normalization helpers (stable identities so re-discovery merges, not dupes)
# =============================================================================

def normalize_host(host: str) -> str:
    host = (host or "").strip().lower()
    if "://" in host:
        host = urlparse(host).hostname or host
    # strip a trailing dot and any :port
    host = host.rstrip(".")
    if host.count(":") == 1 and not host.startswith("["):
        host = host.split(":", 1)[0]
    return host


def normalize_url(url: str, keep_query: bool = False) -> str:
    """Normalize a URL to a stable identity.

    Lowercases scheme+host, drops the fragment, and (by default) strips the
    query string entirely so ``/search?q=a`` and ``/search?q=b`` collapse to
    one URL/endpoint. Query *keys* are surfaced separately as Parameter assets.
    """
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or "/"
    base = f"{scheme}://{host}{port}{path}"
    if keep_query and parts.query:
        base = f"{base}?{parts.query}"
    return base.rstrip("/") if path != "/" else base


def endpoint_key(method: str, url: str) -> str:
    return f"{(method or 'GET').upper()} {normalize_url(url)}"


def query_param_names(url: str) -> list[str]:
    if not url or "?" not in url:
        return []
    try:
        return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except Exception:
        return []


# =============================================================================
# Records
# =============================================================================

@dataclass
class Provenance:
    """One independent attestation of a discovery."""
    source: str                 # "subfinder" | "katana" | "browser_map" | "recon/iter3"
    method: str = ""            # short how ("passive dns", "xhr", "crawl link")
    at: str = field(default_factory=_now)
    detail: str = ""

    def key(self) -> tuple[str, str]:
        return (self.source, self.method)

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "method": self.method,
                "at": self.at, "detail": self.detail}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Provenance":
        return cls(source=d.get("source", ""), method=d.get("method", ""),
                   at=d.get("at") or _now(), detail=d.get("detail", ""))


@dataclass
class Asset:
    """A typed node in the attack surface with provenance + scope + confidence."""
    kind: str
    identifier: str             # normalized, stable within kind
    scope_status: str = SCOPE_UNKNOWN
    confidence: str = DEFAULT_CONFIDENCE
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    provenance: list[Provenance] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)

    @property
    def key(self) -> str:
        return f"{self.kind}::{self.identifier}"

    def add_provenance(self, prov: Provenance) -> None:
        existing = {p.key() for p in self.provenance}
        if prov.key() not in existing:
            self.provenance.append(prov)
        self.last_seen = _now()

    @property
    def sources(self) -> list[str]:
        seen: list[str] = []
        for p in self.provenance:
            if p.source not in seen:
                seen.append(p.source)
        return seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "scope_status": self.scope_status,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "provenance": [p.to_dict() for p in self.provenance],
            "attrs": self.attrs,
            "tags": sorted(self.tags),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Asset":
        return cls(
            kind=d["kind"], identifier=d["identifier"],
            scope_status=d.get("scope_status", SCOPE_UNKNOWN),
            confidence=d.get("confidence", DEFAULT_CONFIDENCE),
            first_seen=d.get("first_seen") or _now(),
            last_seen=d.get("last_seen") or _now(),
            provenance=[Provenance.from_dict(p) for p in d.get("provenance", [])],
            attrs=dict(d.get("attrs") or {}),
            tags=set(d.get("tags") or []),
        )


@dataclass
class Observation:
    """A noticed *behaviour* worth investigating (the IDENTIFY INTERESTING
    BEHAVIOR phase). Not itself a vulnerability — a lead."""
    id: str
    category: str               # "reflection" | "error" | "auth_diff" | "timing" | ...
    summary: str
    source: str = ""
    confidence: str = DEFAULT_CONFIDENCE
    asset_keys: list[str] = field(default_factory=list)
    at: str = field(default_factory=_now)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "category": self.category, "summary": self.summary,
                "source": self.source, "confidence": self.confidence,
                "asset_keys": self.asset_keys, "at": self.at, "data": self.data}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Observation":
        return cls(id=d["id"], category=d.get("category", ""),
                   summary=d.get("summary", ""), source=d.get("source", ""),
                   confidence=d.get("confidence", DEFAULT_CONFIDENCE),
                   asset_keys=list(d.get("asset_keys") or []),
                   at=d.get("at") or _now(), data=dict(d.get("data") or {}))


@dataclass
class Finding:
    """A suspected or confirmed vulnerability recorded on the surface.

    A Finding is only *verified* once it is backed by an EvidenceBundle whose
    verification status is confirmed (see evidence_bundle.py). Scanner output
    lands here as ``status="theoretical"`` and must be validated before it can
    ever be reported as a real finding."""
    id: str
    title: str
    vuln_type: str
    severity: str = "info"       # critical|high|medium|low|info
    status: str = "theoretical"  # theoretical|verified|informational|false_positive
    confidence: str = DEFAULT_CONFIDENCE
    scope_status: str = SCOPE_UNKNOWN
    asset_keys: list[str] = field(default_factory=list)
    evidence_bundle_id: str = ""
    source: str = ""
    at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "vuln_type": self.vuln_type,
                "severity": self.severity, "status": self.status,
                "confidence": self.confidence, "scope_status": self.scope_status,
                "asset_keys": self.asset_keys,
                "evidence_bundle_id": self.evidence_bundle_id,
                "source": self.source, "at": self.at, "updated_at": self.updated_at,
                "data": self.data}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(id=d["id"], title=d.get("title", ""),
                   vuln_type=d.get("vuln_type", ""), severity=d.get("severity", "info"),
                   status=d.get("status", "theoretical"),
                   confidence=d.get("confidence", DEFAULT_CONFIDENCE),
                   scope_status=d.get("scope_status", SCOPE_UNKNOWN),
                   asset_keys=list(d.get("asset_keys") or []),
                   evidence_bundle_id=d.get("evidence_bundle_id", ""),
                   source=d.get("source", ""), at=d.get("at") or _now(),
                   updated_at=d.get("updated_at") or _now(),
                   data=dict(d.get("data") or {}))


@dataclass
class SurfaceDelta:
    """The difference between the current surface and a previous snapshot,
    used to prioritise newly-appeared surface on continuous / delta runs."""
    new_assets: list[Asset] = field(default_factory=list)
    changed_assets: list[Asset] = field(default_factory=list)   # scope/confidence/attr change
    new_findings: list[Finding] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.new_assets or self.changed_assets or self.new_findings)

    def summary(self) -> str:
        if self.is_empty():
            return "No attack-surface changes since the previous run."
        by_kind: dict[str, int] = {}
        for a in self.new_assets:
            by_kind[a.kind] = by_kind.get(a.kind, 0) + 1
        parts = [f"{n} new {k}" for k, n in sorted(by_kind.items())]
        if self.changed_assets:
            parts.append(f"{len(self.changed_assets)} changed")
        if self.new_findings:
            parts.append(f"{len(self.new_findings)} new findings")
        return "Delta since last run: " + ", ".join(parts)


# Kinds worth prioritising as fresh leads on delta runs, in priority order.
_DELTA_PRIORITY = {
    KIND_SUBDOMAIN: 90, KIND_HOST: 85, KIND_API: 88, KIND_ENDPOINT: 70,
    KIND_JS: 65, KIND_CLOUD: 80, KIND_TECHNOLOGY: 55, KIND_PARAMETER: 50,
    KIND_WEBSOCKET: 60, KIND_URL: 40,
}


# =============================================================================
# AttackSurface
# =============================================================================

class AttackSurface:
    """Thread-safe, persistent attack-surface model.

    A ``scope_evaluator`` (typically ``ScopeGuard.classify``) may be attached
    so every asset is annotated in-scope / out-of-scope / unknown at add time.
    The evaluator is READ-ONLY: the surface never mutates scope.
    """

    def __init__(self, target: str = "", scope_key: str = "",
                 scope_evaluator: Optional[Callable[[str], str]] = None):
        self._lock = threading.RLock()
        self.target = target
        # scope_key groups surfaces across runs (engagement name or root domain).
        self.scope_key = scope_key or _root_scope_key(target)
        self._assets: dict[str, Asset] = {}
        self._observations: list[Observation] = []
        self._findings: dict[str, Finding] = {}
        self._obs_seq = 0
        self._find_seq = 0
        self._scope_evaluator = scope_evaluator

    # ---- scope wiring ---------------------------------------------------

    def attach_scope_evaluator(self, evaluator: Callable[[str], str]) -> None:
        """Attach a read-only scope classifier and re-annotate existing assets."""
        with self._lock:
            self._scope_evaluator = evaluator
            for asset in self._assets.values():
                host = self._asset_host(asset)
                if host:
                    asset.scope_status = self._classify(host)

    def _classify(self, host_or_url: str) -> str:
        if not self._scope_evaluator or not host_or_url:
            return SCOPE_UNKNOWN
        try:
            status = self._scope_evaluator(host_or_url)
            return status if status in (SCOPE_IN, SCOPE_OUT, SCOPE_UNKNOWN) else SCOPE_UNKNOWN
        except Exception:
            return SCOPE_UNKNOWN

    @staticmethod
    def _asset_host(asset: Asset) -> str:
        """Best-effort host for scope classification of an asset."""
        if asset.kind in (KIND_DOMAIN, KIND_SUBDOMAIN, KIND_HOST, KIND_IP):
            return asset.identifier
        h = asset.attrs.get("host")
        if h:
            return str(h)
        # endpoints/urls/js encode a URL we can parse
        for cand in (asset.identifier, asset.attrs.get("url", "")):
            cand = str(cand)
            if "://" in cand:
                return normalize_host(cand)
            if " " in cand:  # "GET http://..."
                tail = cand.split(" ", 1)[1]
                if "://" in tail:
                    return normalize_host(tail)
        return ""

    # ---- asset writes ---------------------------------------------------

    def add(self, kind: str, identifier: str, *, source: str = "",
            method: str = "", detail: str = "",
            confidence: str = DEFAULT_CONFIDENCE,
            scope_status: Optional[str] = None,
            host: Optional[str] = None,
            attrs: Optional[dict[str, Any]] = None,
            tags: Optional[Iterable[str]] = None) -> Asset:
        """Create or merge an asset. Idempotent on (kind, identifier).

        Merging accrues provenance, upgrades confidence monotonically, unions
        attrs/tags, and refreshes ``last_seen`` — so the same host seen by three
        tools becomes one asset with three corroborating sources.
        """
        if not identifier:
            raise ValueError("attack surface asset requires a non-empty identifier")
        with self._lock:
            key = f"{kind}::{identifier}"
            asset = self._assets.get(key)
            if asset is None:
                asset = Asset(kind=kind, identifier=identifier,
                              confidence=confidence)
                self._assets[key] = asset
            else:
                asset.confidence = _max_confidence(asset.confidence, confidence)
                asset.last_seen = _now()

            if attrs:
                for k, v in attrs.items():
                    # Union list-valued attrs instead of clobbering.
                    if isinstance(v, list) and isinstance(asset.attrs.get(k), list):
                        merged = list(asset.attrs[k])
                        for item in v:
                            if item not in merged:
                                merged.append(item)
                        asset.attrs[k] = merged
                    else:
                        asset.attrs[k] = v
            if host is not None:
                asset.attrs.setdefault("host", normalize_host(host))
            if tags:
                asset.tags.update(tags)
            if source:
                asset.add_provenance(Provenance(source=source, method=method, detail=detail))

            # Annotate scope (explicit override wins, else evaluator).
            if scope_status in (SCOPE_IN, SCOPE_OUT, SCOPE_UNKNOWN):
                asset.scope_status = scope_status
            else:
                h = host or self._asset_host(asset)
                if h:
                    status = self._classify(h)
                    # Never downgrade a proven out_of_scope back to unknown.
                    if status != SCOPE_UNKNOWN or asset.scope_status == SCOPE_UNKNOWN:
                        asset.scope_status = status
            return asset

    # -- convenience adders (normalize + set sensible kinds) --------------

    def add_host(self, host: str, *, source: str = "", is_subdomain: bool = True,
                 **kw) -> Asset:
        h = normalize_host(host)
        kind = KIND_SUBDOMAIN if (is_subdomain and h.count(".") >= 2) else KIND_HOST
        return self.add(kind, h, source=source, host=h, **kw)

    def add_ip(self, ip: str, *, source: str = "", **kw) -> Asset:
        return self.add(KIND_IP, ip.strip(), source=source, **kw)

    def add_endpoint(self, url: str, *, method: str = "GET", source: str = "",
                     status_code: Optional[int] = None,
                     content_type: str = "", is_api: bool = False,
                     confidence: str = DEFAULT_CONFIDENCE, **kw) -> Asset:
        ident = endpoint_key(method, url)
        attrs: dict[str, Any] = {"method": (method or "GET").upper(),
                                 "url": normalize_url(url)}
        if status_code is not None:
            attrs.setdefault("status_codes", [])
            attrs["status_codes"] = sorted(set(list(attrs["status_codes"]) + [status_code]))
        if content_type:
            attrs["content_type"] = content_type
        if is_api:
            attrs["is_api"] = True
        attrs.update(kw.pop("attrs", {}) or {})
        asset = self.add(KIND_ENDPOINT, ident, source=source,
                         method=kw.pop("method_note", ""), confidence=confidence,
                         host=normalize_host(url), attrs=attrs, **kw)
        # Auto-derive query parameters as Parameter assets.
        for pname in query_param_names(url):
            self.add_parameter(ident, pname, location="query", source=source)
        return asset

    def add_parameter(self, endpoint_ident: str, name: str, *,
                      location: str = "query", source: str = "",
                      confidence: str = DEFAULT_CONFIDENCE, **kw) -> Asset:
        ident = f"{endpoint_ident}::{name}::{location}"
        attrs = {"name": name, "location": location, "endpoint": endpoint_ident}
        attrs.update(kw.pop("attrs", {}) or {})
        return self.add(KIND_PARAMETER, ident, source=source, confidence=confidence,
                        attrs=attrs, **kw)

    def add_js(self, url: str, *, source: str = "", has_source_map: bool = False,
               **kw) -> Asset:
        ident = normalize_url(url, keep_query=False)
        attrs = {"url": ident, "has_source_map": has_source_map}
        attrs.update(kw.pop("attrs", {}) or {})
        return self.add(KIND_JS, ident, source=source, host=normalize_host(url),
                        attrs=attrs, **kw)

    def add_technology(self, name: str, *, version: str = "", source: str = "",
                       host: str = "", **kw) -> Asset:
        ident = name.strip().lower() + (f"@{version}" if version else "")
        attrs = {"name": name}
        if version:
            attrs["version"] = version
        attrs.update(kw.pop("attrs", {}) or {})
        return self.add(KIND_TECHNOLOGY, ident, source=source,
                        host=normalize_host(host) if host else None, attrs=attrs, **kw)

    def add_identity(self, name: str, *, role_hint: str = "unknown",
                     authenticated: bool = False, source: str = "identity_registry",
                     **kw) -> Asset:
        attrs = {"name": name, "role_hint": role_hint, "authenticated": authenticated}
        attrs.update(kw.pop("attrs", {}) or {})
        return self.add(KIND_IDENTITY, name, source=source, attrs=attrs, **kw)

    def add_websocket(self, url: str, *, source: str = "", **kw) -> Asset:
        ident = normalize_url(url, keep_query=True)
        return self.add(KIND_WEBSOCKET, ident, source=source,
                        host=normalize_host(url), attrs={"url": ident}, **kw)

    def add_api(self, url: str, *, source: str = "", spec_type: str = "", **kw) -> Asset:
        ident = normalize_url(url, keep_query=False)
        attrs = {"url": ident}
        if spec_type:
            attrs["spec_type"] = spec_type
        attrs.update(kw.pop("attrs", {}) or {})
        return self.add(KIND_API, ident, source=source, host=normalize_host(url),
                        attrs=attrs, tags={"api"}, **kw)

    def add_cloud_asset(self, identifier: str, *, provider: str = "",
                        asset_type: str = "", source: str = "", **kw) -> Asset:
        attrs = {"provider": provider, "asset_type": asset_type}
        attrs.update(kw.pop("attrs", {}) or {})
        return self.add(KIND_CLOUD, identifier, source=source, attrs=attrs, **kw)

    # ---- observations & findings ---------------------------------------

    def observe(self, category: str, summary: str, *, source: str = "",
                confidence: str = DEFAULT_CONFIDENCE,
                asset_keys: Optional[list[str]] = None,
                data: Optional[dict[str, Any]] = None) -> Observation:
        with self._lock:
            self._obs_seq += 1
            obs = Observation(
                id=f"obs:{self._obs_seq}", category=category, summary=summary,
                source=source, confidence=confidence,
                asset_keys=list(asset_keys or []), data=dict(data or {}),
            )
            self._observations.append(obs)
            return obs

    def record_finding(self, title: str, vuln_type: str, *, severity: str = "info",
                       status: str = "theoretical", confidence: str = DEFAULT_CONFIDENCE,
                       asset_keys: Optional[list[str]] = None,
                       evidence_bundle_id: str = "", source: str = "",
                       finding_id: str = "",
                       data: Optional[dict[str, Any]] = None) -> Finding:
        with self._lock:
            if finding_id and finding_id in self._findings:
                f = self._findings[finding_id]
                f.status = status or f.status
                f.severity = severity or f.severity
                f.confidence = _max_confidence(f.confidence, confidence)
                if evidence_bundle_id:
                    f.evidence_bundle_id = evidence_bundle_id
                if data:
                    f.data.update(data)
                f.updated_at = _now()
                return f
            self._find_seq += 1
            fid = finding_id or f"find:{self._find_seq}"
            scope_status = SCOPE_UNKNOWN
            for k in (asset_keys or []):
                a = self._assets.get(k)
                if a and a.scope_status != SCOPE_UNKNOWN:
                    scope_status = a.scope_status
                    break
            f = Finding(
                id=fid, title=title, vuln_type=vuln_type, severity=severity,
                status=status, confidence=confidence, scope_status=scope_status,
                asset_keys=list(asset_keys or []),
                evidence_bundle_id=evidence_bundle_id, source=source,
                data=dict(data or {}),
            )
            self._findings[fid] = f
            return f

    # ---- reads ----------------------------------------------------------

    def get(self, kind: str, identifier: str) -> Optional[Asset]:
        with self._lock:
            return self._assets.get(f"{kind}::{identifier}")

    def query(self, kind: Optional[str] = None,
              scope_status: Optional[str] = None,
              **attr_filters) -> list[Asset]:
        with self._lock:
            out = []
            for a in self._assets.values():
                if kind and a.kind != kind:
                    continue
                if scope_status and a.scope_status != scope_status:
                    continue
                if all(a.attrs.get(k) == v for k, v in attr_filters.items()):
                    out.append(a)
            return out

    def assets(self) -> list[Asset]:
        with self._lock:
            return list(self._assets.values())

    def observations(self) -> list[Observation]:
        with self._lock:
            return list(self._observations)

    def findings(self) -> list[Finding]:
        with self._lock:
            return list(self._findings.values())

    def counts(self) -> dict[str, int]:
        with self._lock:
            out: dict[str, int] = {}
            for a in self._assets.values():
                out[a.kind] = out.get(a.kind, 0) + 1
            return out

    def stats(self) -> dict[str, Any]:
        with self._lock:
            in_scope = sum(1 for a in self._assets.values() if a.scope_status == SCOPE_IN)
            out_scope = sum(1 for a in self._assets.values() if a.scope_status == SCOPE_OUT)
            return {
                "total_assets": len(self._assets),
                "by_kind": self.counts(),
                "in_scope": in_scope,
                "out_of_scope": out_scope,
                "observations": len(self._observations),
                "findings": len(self._findings),
                "verified_findings": sum(1 for f in self._findings.values()
                                         if f.status == "verified"),
            }

    # ---- prompt rendering ----------------------------------------------

    def render(self, max_per_kind: int = 15, in_scope_only: bool = False) -> str:
        """Compact, LLM-friendly summary of the surface for prompt injection."""
        with self._lock:
            if not self._assets and not self._findings:
                return "## ATTACK SURFACE\n(empty — mapping has not started)"
            buckets: dict[str, list[Asset]] = {}
            for a in self._assets.values():
                if in_scope_only and a.scope_status == SCOPE_OUT:
                    continue
                buckets.setdefault(a.kind, []).append(a)
            lines = ["## ATTACK SURFACE"]
            st = self.stats()
            lines.append(
                f"({st['total_assets']} assets · {st['in_scope']} in-scope · "
                f"{st['out_of_scope']} out-of-scope · {st['findings']} findings)"
            )
            order = [KIND_DOMAIN, KIND_SUBDOMAIN, KIND_HOST, KIND_IP, KIND_API,
                     KIND_ENDPOINT, KIND_PARAMETER, KIND_JS, KIND_WEBSOCKET,
                     KIND_TECHNOLOGY, KIND_IDENTITY, KIND_ROLE, KIND_WORKFLOW,
                     KIND_CLOUD, KIND_CREDENTIAL, KIND_URL, KIND_SOURCEMAP]
            for kind in order:
                ents = buckets.get(kind)
                if not ents:
                    continue
                lines.append(f"\n### {kind} ({len(ents)})")
                for a in ents[:max_per_kind]:
                    flag = {"in_scope": "", "out_of_scope": " [OUT-OF-SCOPE]",
                            "unknown": " [scope?]"}.get(a.scope_status, "")
                    detail = self._render_asset_detail(a)
                    lines.append(f"  - {a.identifier}{flag} "
                                 f"({a.confidence}; via {','.join(a.sources[:3])}){detail}")
                if len(ents) > max_per_kind:
                    lines.append(f"  ... ({len(ents) - max_per_kind} more)")
            if self._observations:
                lines.append(f"\n### interesting behaviour ({len(self._observations)})")
                for o in self._observations[-max_per_kind:]:
                    lines.append(f"  - [{o.category}] {o.summary}")
            if self._findings:
                lines.append(f"\n### findings ({len(self._findings)})")
                for f in list(self._findings.values())[:max_per_kind]:
                    lines.append(f"  - [{f.status}/{f.severity}] {f.title} ({f.vuln_type})")
            return "\n".join(lines)

    @staticmethod
    def _render_asset_detail(a: Asset) -> str:
        bits = []
        if a.kind == KIND_ENDPOINT:
            sc = a.attrs.get("status_codes")
            if sc:
                bits.append(f"status={sc}")
            if a.attrs.get("is_api"):
                bits.append("api")
        elif a.kind == KIND_TECHNOLOGY and a.attrs.get("version"):
            bits.append(f"v{a.attrs['version']}")
        elif a.kind == KIND_IDENTITY:
            bits.append(f"role={a.attrs.get('role_hint','?')}")
        return (" :: " + ", ".join(bits)) if bits else ""

    # ---- delta hunting --------------------------------------------------

    def diff(self, previous: "AttackSurface") -> SurfaceDelta:
        """Compute what is new/changed relative to a previous surface snapshot."""
        delta = SurfaceDelta()
        with self._lock:
            prev_assets = {a.key: a for a in previous.assets()} if previous else {}
            for key, a in self._assets.items():
                old = prev_assets.get(key)
                if old is None:
                    delta.new_assets.append(a)
                elif (a.scope_status != old.scope_status
                      or a.confidence != old.confidence
                      or a.attrs != old.attrs):
                    delta.changed_assets.append(a)
            prev_findings = {f.id for f in previous.findings()} if previous else set()
            for f in self._findings.values():
                if f.id not in prev_findings:
                    delta.new_findings.append(f)
        return delta

    def prioritized_leads(self, previous: Optional["AttackSurface"] = None,
                          limit: int = 25) -> list[Asset]:
        """Rank fresh, in-scope leads for seeding the hypothesis agenda.

        On a delta run, brand-new assets outrank previously-seen ones; admin
        panels, APIs, and new subdomains float to the top. Out-of-scope assets
        are excluded entirely.
        """
        delta = self.diff(previous) if previous else None
        new_keys = {a.key for a in delta.new_assets} if delta else set()
        with self._lock:
            scored: list[tuple[int, Asset]] = []
            for a in self._assets.values():
                if a.scope_status == SCOPE_OUT:
                    continue
                base = _DELTA_PRIORITY.get(a.kind, 20)
                score = base
                if a.key in new_keys:
                    score += 100          # freshly discovered => hunt first
                ident_l = a.identifier.lower()
                if any(m in ident_l for m in ("admin", "internal", "debug",
                                              "staging", "dev", "test", "graphql",
                                              "actuator", "swagger", "api")):
                    score += 25
                if a.attrs.get("is_api"):
                    score += 15
                scored.append((score, a))
            scored.sort(key=lambda t: t[0], reverse=True)
            return [a for _, a in scored[:limit]]

    # ---- knowledge-graph bridge ----------------------------------------

    def ingest_memory_kg(self, memory: Any, source: str = "memory_kg") -> int:
        """Import existing AgentMemory KG entities into the surface so nothing
        discovered by the legacy recon/parsers path is lost. Best-effort."""
        count = 0
        try:
            entities = list(memory.entities.values())
        except Exception:
            return 0
        for e in entities:
            try:
                if e.type == "Endpoint":
                    url = e.attrs.get("url", "")
                    if url:
                        self.add_endpoint(url, method=e.attrs.get("method", "GET"),
                                          source=source)
                        count += 1
                elif e.type == "Technology":
                    name = e.attrs.get("name", "")
                    if name:
                        self.add_technology(name, version=e.attrs.get("version", ""),
                                            source=source)
                        count += 1
                elif e.type == "Parameter":
                    name = e.attrs.get("name", "")
                    if name:
                        self.add(KIND_PARAMETER, f"orphan::{name}::unknown",
                                 source=source, attrs={"name": name, "location": "unknown"})
                        count += 1
                elif e.type == "Target":
                    url = e.attrs.get("url") or memory.target_url
                    host = normalize_host(url) if url else ""
                    if host:
                        self.add_host(host, source=source, is_subdomain=host.count(".") >= 2)
                        count += 1
            except Exception:
                continue
        return count

    def project_to_memory(self, memory: Any) -> int:
        """Project in-scope surface assets into the AgentMemory KG so existing
        prompt injection (kg_snapshot) and coordinator routing keep seeing
        endpoints/technologies discovered by the new structured pipeline."""
        count = 0
        try:
            targets = memory.query("Target")
            target = targets[0] if targets else memory.add_entity(
                "Target", {"url": self.target})
        except Exception:
            return 0
        for a in self.assets():
            if a.scope_status == SCOPE_OUT:
                continue
            try:
                if a.kind == KIND_ENDPOINT:
                    ep = memory.add_entity("Endpoint", {
                        "url": a.attrs.get("url", a.identifier),
                        "method": a.attrs.get("method", "GET"),
                        "notes": f"via {','.join(a.sources[:2])}",
                    })
                    memory.add_relationship(target.id, "HAS_ENDPOINT", ep.id)
                    count += 1
                elif a.kind == KIND_TECHNOLOGY:
                    t = memory.add_entity("Technology", {"name": a.attrs.get("name", a.identifier)})
                    memory.add_relationship(target.id, "USES_TECHNOLOGY", t.id)
                    count += 1
            except Exception:
                continue
        return count

    # ---- serialization / persistence -----------------------------------

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "target": self.target,
                "scope_key": self.scope_key,
                "assets": [a.to_dict() for a in self._assets.values()],
                "observations": [o.to_dict() for o in self._observations],
                "findings": [f.to_dict() for f in self._findings.values()],
            }

    @classmethod
    def from_dict(cls, d: dict[str, Any],
                  scope_evaluator: Optional[Callable[[str], str]] = None) -> "AttackSurface":
        surf = cls(target=d.get("target", ""), scope_key=d.get("scope_key", ""),
                   scope_evaluator=scope_evaluator)
        for ad in d.get("assets", []):
            a = Asset.from_dict(ad)
            surf._assets[a.key] = a
        for od in d.get("observations", []):
            o = Observation.from_dict(od)
            surf._observations.append(o)
            surf._obs_seq = max(surf._obs_seq, _seq_of(o.id))
        for fd in d.get("findings", []):
            f = Finding.from_dict(fd)
            surf._findings[f.id] = f
            surf._find_seq = max(surf._find_seq, _seq_of(f.id))
        return surf

    def persist(self, store: Any) -> bool:
        """Persist the surface to a durable store. No-op if store is None."""
        if store is None:
            return False
        try:
            store.save_surface(self.target, self.scope_key, self.to_dict())
            return True
        except Exception:
            return False

    def load(self, store: Any) -> int:
        """Merge a previously-persisted surface for the same scope_key into
        this (usually empty) surface. Returns the number of assets loaded."""
        if store is None:
            return 0
        try:
            snap = store.load_surface(self.target, self.scope_key)
        except Exception:
            return 0
        if not snap:
            return 0
        prior = AttackSurface.from_dict(snap, scope_evaluator=self._scope_evaluator)
        n = 0
        with self._lock:
            for a in prior.assets():
                if a.key not in self._assets:
                    self._assets[a.key] = a
                    n += 1
            for o in prior.observations():
                self._observations.append(o)
                self._obs_seq = max(self._obs_seq, _seq_of(o.id))
            for f in prior.findings():
                self._findings.setdefault(f.id, f)
                self._find_seq = max(self._find_seq, _seq_of(f.id))
        return n


# =============================================================================
# helpers
# =============================================================================

def _seq_of(ident: str) -> int:
    try:
        return int(str(ident).rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return 0


def _root_scope_key(target: str) -> str:
    """Group runs across the same registrable-ish root so delta hunting lines
    up subdomains under one key. Best-effort (no PSL dependency)."""
    host = normalize_host(target)
    if not host or _looks_like_ip(host):
        return host or "unknown"
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _looks_like_ip(host: str) -> bool:
    return bool(host) and all(p.isdigit() for p in host.split(".") if p) and host.count(".") == 3
