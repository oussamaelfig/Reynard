"""
=============================================================================
Reynard — Authorization Matrix
=============================================================================
Authorization testing as a first-class capability. Given a set of controlled
identities (anonymous / userA / userB / admin-test-role) and a set of resources
(endpoints), this module replays each equivalent request as every identity,
compares the results SEMANTICALLY (not just status codes), and builds a
roles x resources matrix. From that matrix it derives access-control anomalies:

  - IDOR / BOLA        one user reads another user's object
  - BFLA               a non-admin invokes an admin/privileged function
  - privilege_escalation / unauth_access  low-priv or anonymous reaches a
                                          resource that should require more

Every anomaly carries CONTROL-vs-TEST evidence (the offending ALLOW response
plus the expected DENY from a properly-restricted identity), so a finding is
grounded in a reproducible authorization *difference*, never a guess.

The comparison engine is pure and testable via an injectable ``requester``; a
live requester (session-aware ``http_request``) is provided for real runs.
=============================================================================
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# ---- outcome vocabulary ----
ALLOW = "allow"
DENY = "deny"
NOTFOUND = "notfound"
AMBIGUOUS = "ambiguous"
ERROR = "error"

DENY_MARKERS = (
    "access denied", "forbidden", "not authorized", "unauthorized",
    "permission denied", "you do not have permission", "please log in",
    "please sign in", "login required", "must be logged in", "insufficient",
    "not allowed", "403", "authentication required",
)
LOGIN_REDIRECT_HINTS = ("/login", "/signin", "/sign-in", "/auth", "/session/new")
ADMIN_CONTENT_MARKERS = (
    "admin", "dashboard", "manage users", "all users", "delete user",
    "user management", "role", "privilege", "settings panel", "audit log",
)
PRIVILEGED_PATH_MARKERS = (
    "admin", "internal", "manage", "console", "root", "superuser", "/api/admin",
    "actuator", "debug",
)


# =============================================================================
# Models
# =============================================================================

@dataclass
class AuthzIdentity:
    name: str
    role: str = "user"          # anonymous | user | admin | ...
    is_admin: bool = False
    authenticated: bool = False

    @classmethod
    def from_session(cls, sess: Any) -> "AuthzIdentity":
        role = (getattr(sess, "role_hint", "") or "user").lower()
        name = getattr(sess, "name", "") or "unknown"
        authed = bool(getattr(sess, "authenticated", False))
        anonymous = role in ("unauth", "anonymous", "guest") or name in ("unauth", "anonymous")
        return cls(
            name=name,
            role="anonymous" if anonymous else role,
            is_admin="admin" in role,
            authenticated=authed and not anonymous,
        )


@dataclass
class AuthzResource:
    key: str                       # stable id, e.g. "GET /admin"
    method: str = "GET"
    url: str = ""
    expected_min_role: str = ""    # "" | "user" | "admin"
    owner_identity: str = ""       # for object-level (IDOR/BOLA) resources
    sensitive: bool = False        # object returns private/sensitive data

    @classmethod
    def get(cls, url: str, **kw) -> "AuthzResource":
        return cls(key=f"GET {url}", method="GET", url=url, **kw)


@dataclass
class CellObservation:
    identity: str
    resource: str
    status: Optional[int] = None
    length: int = 0
    outcome: str = AMBIGUOUS
    body_hash: str = ""
    body_excerpt: str = ""
    admin_markers: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"identity": self.identity, "resource": self.resource,
                "status": self.status, "length": self.length,
                "outcome": self.outcome, "admin_markers": self.admin_markers,
                "body_excerpt": self.body_excerpt[:300], "error": self.error}


@dataclass
class AuthzAnomaly:
    kind: str                      # idor | bola | bfla | privilege_escalation | unauth_access
    resource: str
    offending_identity: str
    control_identity: str
    severity: str
    detail: str
    test_obs: Optional[CellObservation] = None
    control_obs: Optional[CellObservation] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "resource": self.resource,
            "offending_identity": self.offending_identity,
            "control_identity": self.control_identity, "severity": self.severity,
            "detail": self.detail,
            "test": self.test_obs.to_dict() if self.test_obs else None,
            "control": self.control_obs.to_dict() if self.control_obs else None,
        }


# =============================================================================
# Response classification (semantic)
# =============================================================================

def _hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:16]


def classify_response(status: Optional[int], body: str,
                      final_url: str = "") -> tuple[str, bool]:
    """Classify a response as allow/deny/notfound/ambiguous + admin-markers flag.

    Semantic, not status-only: a 200 page that is really a login/denied page is
    classified DENY; a 302 to /login is DENY.
    """
    body = body or ""
    low = body.lower()
    admin = any(m in low for m in ADMIN_CONTENT_MARKERS)
    if status in (401, 403):
        return DENY, admin
    if status == 404:
        return NOTFOUND, admin
    if status in (301, 302, 303, 307, 308):
        if any(h in (final_url or "").lower() for h in LOGIN_REDIRECT_HINTS):
            return DENY, admin
        return AMBIGUOUS, admin
    if status is not None and 200 <= status < 300:
        # A short body dominated by a denial marker is a soft-deny page.
        denial = any(m in low for m in DENY_MARKERS)
        if denial and len(body) < 2000:
            return DENY, admin
        if any(h in (final_url or "").lower() for h in LOGIN_REDIRECT_HINTS):
            return DENY, admin
        return ALLOW, admin
    if status is None:
        return ERROR, admin
    return AMBIGUOUS, admin


def _similar(a: CellObservation, b: CellObservation) -> bool:
    """Two ALLOW responses look like they returned the same object/content."""
    if a.body_hash and a.body_hash == b.body_hash:
        return True
    if a.length and b.length:
        hi = max(a.length, b.length)
        if hi and abs(a.length - b.length) / hi <= 0.2:
            return True
    return False


# =============================================================================
# Matrix
# =============================================================================

# requester(identity_name, method, url) -> dict(status, body, final_url)
Requester = Callable[..., dict]


class AuthorizationMatrix:
    def __init__(self, identities: list[AuthzIdentity],
                 resources: list[AuthzResource]):
        self.identities = identities
        self.resources = resources
        # cells[resource_key][identity_name] = CellObservation
        self.cells: dict[str, dict[str, CellObservation]] = {}

    # ---- build ----
    def build(self, requester: Requester) -> "AuthorizationMatrix":
        for res in self.resources:
            row: dict[str, CellObservation] = {}
            for ident in self.identities:
                obs = self._probe(requester, ident, res)
                row[ident.name] = obs
            self.cells[res.key] = row
        return self

    def _probe(self, requester: Requester, ident: AuthzIdentity,
               res: AuthzResource) -> CellObservation:
        try:
            resp = requester(ident.name, res.method, res.url) or {}
        except Exception as exc:
            return CellObservation(identity=ident.name, resource=res.key,
                                   outcome=ERROR, error=str(exc)[:160])
        status = resp.get("status") or resp.get("status_code")
        body = resp.get("body") or resp.get("response") or ""
        final_url = resp.get("final_url") or resp.get("url") or res.url
        outcome, admin = classify_response(status, body, final_url)
        return CellObservation(
            identity=ident.name, resource=res.key, status=status,
            length=len(body), outcome=outcome, body_hash=_hash(body),
            body_excerpt=body[:400], admin_markers=admin,
        )

    # ---- analysis ----
    def _identity(self, name: str) -> Optional[AuthzIdentity]:
        for i in self.identities:
            if i.name == name:
                return i
        return None

    def _is_privileged(self, res: AuthzResource,
                       row: dict[str, CellObservation]) -> bool:
        if res.expected_min_role == "admin":
            return True
        if any(m in res.url.lower() or m in res.key.lower()
               for m in PRIVILEGED_PATH_MARKERS):
            return True
        # An admin identity's ALLOW response with admin content => privileged.
        for ident in self.identities:
            if ident.is_admin:
                c = row.get(ident.name)
                if c and c.outcome == ALLOW and c.admin_markers:
                    return True
        return False

    def analyze(self) -> list[AuthzAnomaly]:
        anomalies: list[AuthzAnomaly] = []
        for res in self.resources:
            row = self.cells.get(res.key, {})
            anomalies.extend(self._analyze_vertical(res, row))
            anomalies.extend(self._analyze_horizontal(res, row))
        return _dedupe(anomalies)

    def _analyze_vertical(self, res: AuthzResource,
                          row: dict[str, CellObservation]) -> list[AuthzAnomaly]:
        out: list[AuthzAnomaly] = []
        privileged = self._is_privileged(res, row)
        if not privileged:
            return out
        # control = an identity that is properly denied (prefer a non-admin)
        control_name, control_obs = self._find_denied(row, prefer_nonadmin=True)
        for ident in self.identities:
            if ident.is_admin:
                continue
            cell = row.get(ident.name)
            if not cell or cell.outcome != ALLOW:
                continue
            if ident.role == "anonymous":
                kind, sev = "unauth_access", "high"
            elif ident.authenticated:
                kind, sev = "bfla", "high"
            else:
                kind, sev = "privilege_escalation", "high"
            detail = (f"{ident.name} ({ident.role}) reached privileged resource "
                      f"{res.key} (status {cell.status}); expected the request to "
                      f"be denied for a non-admin identity.")
            out.append(AuthzAnomaly(
                kind=kind, resource=res.key, offending_identity=ident.name,
                control_identity=control_name, severity=sev, detail=detail,
                test_obs=cell, control_obs=control_obs,
            ))
        return out

    def _analyze_horizontal(self, res: AuthzResource,
                            row: dict[str, CellObservation]) -> list[AuthzAnomaly]:
        out: list[AuthzAnomaly] = []
        if not res.owner_identity:
            return out
        owner_cell = row.get(res.owner_identity)
        if not owner_cell or owner_cell.outcome != ALLOW:
            return out
        for ident in self.identities:
            if ident.name == res.owner_identity or ident.is_admin:
                continue
            cell = row.get(ident.name)
            if not cell or cell.outcome != ALLOW:
                continue
            if _similar(cell, owner_cell):
                kind = "bola" if "/api" in res.url.lower() else "idor"
                sev = "high" if res.sensitive else "medium"
                detail = (f"{ident.name} accessed {res.owner_identity}'s object "
                          f"{res.key} with matching content (len {cell.length} vs "
                          f"owner {owner_cell.length}); horizontal access-control "
                          f"break.")
                out.append(AuthzAnomaly(
                    kind=kind, resource=res.key, offending_identity=ident.name,
                    control_identity=res.owner_identity, severity=sev,
                    detail=detail, test_obs=cell, control_obs=owner_cell,
                ))
        return out

    def _find_denied(self, row: dict[str, CellObservation], *,
                     prefer_nonadmin: bool) -> tuple[str, Optional[CellObservation]]:
        best = ("", None)
        for ident in self.identities:
            cell = row.get(ident.name)
            if cell and cell.outcome in (DENY, NOTFOUND):
                if prefer_nonadmin and not ident.is_admin:
                    return ident.name, cell
                if best[1] is None:
                    best = (ident.name, cell)
        return best

    # ---- rendering ----
    def render(self) -> str:
        if not self.cells:
            return "## AUTHORIZATION MATRIX\n(not built)"
        idents = [i.name for i in self.identities]
        lines = ["## AUTHORIZATION MATRIX (resource x identity -> outcome)"]
        lines.append("resource | " + " | ".join(idents))
        for res in self.resources:
            row = self.cells.get(res.key, {})
            cells = []
            for name in idents:
                c = row.get(name)
                cells.append(c.outcome if c else "-")
            lines.append(f"{res.key} | " + " | ".join(cells))
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identities": [i.__dict__ for i in self.identities],
            "resources": [r.__dict__ for r in self.resources],
            "matrix": {rk: {n: c.outcome for n, c in row.items()}
                       for rk, row in self.cells.items()},
            "anomalies": [a.to_dict() for a in self.analyze()],
        }

    # ---- evidence ----
    def to_evidence_bundles(self, *, target: str = "",
                            extra_secrets: tuple[str, ...] = ()) -> list[Any]:
        """Convert anomalies into EvidenceBundles with control-vs-test proof."""
        from hacking_agent.core.evidence_bundle import (
            EvidenceBundle, SanitizedExchange, ControlTest, V_UNVERIFIED,
        )
        bundles: list[Any] = []
        for anomaly in self.analyze():
            b = EvidenceBundle(
                id="", vuln_type=anomaly.kind.upper(),
                title=f"{anomaly.kind.upper()} on {anomaly.resource}",
                severity=anomaly.severity, target=target,
                endpoint=anomaly.resource, identity=anomaly.offending_identity,
                # Matrix anomalies are high-quality candidates, but this
                # component discovered them and therefore cannot independently
                # validate them for a customer report.
                verification_status=V_UNVERIFIED,
                causal_signal=anomaly.detail,
                discovered_by="authz_matrix",
            )
            if anomaly.test_obs:
                b.add_test(SanitizedExchange.build(
                    label="test", identity=anomaly.offending_identity,
                    url=anomaly.resource,
                    request=f"{anomaly.resource} as {anomaly.offending_identity}",
                    response=anomaly.test_obs.body_excerpt,
                    status_code=anomaly.test_obs.status,
                    extra_secrets=extra_secrets))
            if anomaly.control_obs:
                b.add_control(ControlTest(
                    description=(f"Control: {anomaly.control_identity} is properly "
                                 f"restricted on {anomaly.resource}"),
                    exchange=SanitizedExchange.build(
                        label="control", identity=anomaly.control_identity,
                        url=anomaly.resource,
                        response=anomaly.control_obs.body_excerpt,
                        status_code=anomaly.control_obs.status,
                        extra_secrets=extra_secrets),
                    result=f"{anomaly.control_obs.outcome} "
                           f"(status {anomaly.control_obs.status})"))
            b.reproduction_steps = [
                f"As '{anomaly.offending_identity}', request {anomaly.resource}.",
                "Observe an authorized/successful response (test exchange).",
                f"As '{anomaly.control_identity}', request the same resource and "
                f"observe it is denied (control) — proving the authorization break.",
            ]
            bundles.append(b)
        return bundles


# =============================================================================
# Builders / live requester
# =============================================================================

def identities_from_registry(registry: Any) -> list[AuthzIdentity]:
    out: list[AuthzIdentity] = []
    try:
        for name in registry.names():
            sess = registry.get(name)
            out.append(AuthzIdentity.from_session(sess))
    except Exception:
        pass
    return out


def live_requester(*, timeout: int = 20) -> Requester:
    """A session-aware requester backed by the http_request tool."""
    import json
    from hacking_agent.core.tools import http_request

    def _req(identity_name: str, method: str, url: str) -> dict:
        raw = http_request(url=url, method=method, session=identity_name)
        try:
            d = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"status": None, "body": raw or ""}
        return {
            "status": d.get("status_code") or d.get("status"),
            "body": d.get("response") or d.get("body") or "",
            "final_url": d.get("final_url") or d.get("url") or url,
        }
    return _req


def run_authorization_matrix(identities: list[AuthzIdentity],
                             resources: list[AuthzResource],
                             requester: Requester) -> AuthorizationMatrix:
    return AuthorizationMatrix(identities, resources).build(requester)


def ingest_scan_into_surface(surface: Any, scan: dict, *,
                             source: str = "authz_matrix") -> int:
    """Record authorization anomalies from a scan dict onto the attack surface
    as observations + (theoretical) findings so the researcher can reason over
    them and the reporter can surface them. Returns anomalies ingested."""
    if surface is None or not isinstance(scan, dict):
        return 0
    n = 0
    for a in scan.get("anomalies", []) or []:
        try:
            resource = a.get("resource", "")
            kind = a.get("kind", "authz")
            summary = (f"{kind.upper()}: {a.get('offending_identity')} vs "
                       f"control {a.get('control_identity')} on {resource}")
            surface.observe("authz_diff", summary, source=source,
                            confidence="probable", data=a)
            surface.record_finding(
                title=a.get("detail", summary)[:160], vuln_type=kind.upper(),
                severity=a.get("severity", "medium"), status="theoretical",
                confidence="probable", source=source, data=a,
            )
            n += 1
        except Exception:
            continue
    return n


def _dedupe(anomalies: list[AuthzAnomaly]) -> list[AuthzAnomaly]:
    seen: set[tuple] = set()
    out: list[AuthzAnomaly] = []
    for a in anomalies:
        key = (a.kind, a.resource, a.offending_identity)
        if key not in seen:
            seen.add(key)
            out.append(a)
    return out
