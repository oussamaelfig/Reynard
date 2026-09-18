"""Opt-in, deterministic authenticated research over Reynard's scoped HTTP client.

This is not a browser or a general workflow agent. Operators declare exact
setup requests, mutation permissions, identity probes, and read-only crawl
prefixes. Only independently checked identities are crawled. Private request
results contain credentials/content; ``run`` returns metadata only.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time
from collections import deque
from html.parser import HTMLParser
from http.cookiejar import Cookie
from typing import Any, Literal
from urllib.parse import quote, urldefrag, urlencode, urljoin, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from hacking_agent.core import http_transport
from hacking_agent.core.scope import RateLimitExceeded, ScopeGuard, ScopeViolation
from hacking_agent.core.sessions import AuthSession
from hacking_agent.core.target_address import parse_target, parse_url_prefix, scope_path


class ResearchError(RuntimeError):
    """A fixed, credential-free failure code safe to expose to the operator."""


class ResearchLimit(ResearchError):
    """An explicit partial-result boundary, not a finding or successful scan."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True, allow_inf_nan=False)


def _url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Research URLs must fit within 2048 characters")
    target = parse_target(value)
    if not target.is_url or "#" in value:
        raise ValueError("An absolute HTTP(S) URL without a fragment is required")
    scope_path(target.path)
    parts = urlsplit(value)
    host = f"[{target.host}]" if ":" in target.host else target.host
    port = "" if target.port == (443 if target.scheme == "https" else 80) else f":{target.port}"
    return urlunsplit((target.scheme, host + port, parts.path or "/", parts.query, ""))


def _origin(value: str) -> str:
    parts = urlsplit(_url(value))
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _headers(values: dict[str, str]) -> dict[str, str]:
    if len(values) > 16:
        raise ValueError("At most 16 identity headers are supported")
    forbidden = {"host", "content-length", "transfer-encoding", "connection", "cookie",
                 "proxy-authorization", "proxy-connection"}
    seen: set[str] = set()
    for key, value in values.items():
        if (len(key) > 128 or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                or key.lower() in forbidden or key.lower() in seen):
            raise ValueError("Unsupported or duplicate identity header")
        if len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Invalid identity header value")
        seen.add(key.lower())
    return dict(values)


class VerificationProbe(_Model):
    url: str = Field(min_length=1, max_length=2048)
    marker: str | None = Field(default=None, min_length=1, max_length=512, repr=False)
    json_path: str | None = Field(default=None, min_length=1, max_length=256)
    expected: str | int | float | bool | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def check_matcher(self) -> "VerificationProbe":
        if self.marker is not None:
            if not self.marker.strip():
                raise ValueError("A nonempty identity-specific marker is required")
            if self.json_path is not None or "expected" in self.model_fields_set:
                raise ValueError("Choose a literal marker or a typed JSON assertion")
        elif self.json_path is None or "expected" not in self.model_fields_set:
            raise ValueError("An identity-specific verification assertion is required")
        if self.json_path is not None and not self.json_path.startswith("/"):
            raise ValueError("json_path must be an RFC 6901 JSON pointer")
        if self.json_path is not None and re.search(r"~(?![01])", self.json_path):
            raise ValueError("Invalid RFC 6901 escape")
        if self.json_path is not None and (type(self.expected) not in {str, int}
                or isinstance(self.expected, str) and (not self.expected.strip() or len(self.expected) > 512)):
            raise ValueError("Expected identity must be a nonempty string or integer")
        return self


class SetupStep(_Model):
    purpose: Literal["login", "register", "workflow"]
    method: Literal["GET", "POST"]
    url: str = Field(min_length=1, max_length=2048)
    fields: dict[str, str] = Field(default_factory=dict, repr=False)
    include_hidden_from: str | None = Field(default=None, min_length=1, max_length=2048)

    @model_validator(mode="after")
    def check_fields(self) -> "SetupStep":
        if self.method == "GET" and (self.fields or self.include_hidden_from):
            raise ValueError("GET setup steps cannot submit fields")
        if len(self.fields) > 32 or any(not key or len(key) > 128 or len(value) > 4096
                                        for key, value in self.fields.items()):
            raise ValueError("Setup fields exceed supported bounds")
        return self


class MutationPermission(_Model):
    method: Literal["POST"] = "POST"
    url: str = Field(min_length=1, max_length=2048)
    purpose: Literal["login", "register", "workflow"]


class ResearchIdentity(_Model):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    role_hint: str = Field(default="user", min_length=1, max_length=64)
    cookie_header: str = Field(default="", max_length=8192, repr=False)
    headers: dict[str, str] = Field(default_factory=dict, repr=False)
    setup: list[SetupStep] = Field(default_factory=list, max_length=12)
    verification: VerificationProbe

    @field_validator("headers")
    @classmethod
    def check_headers(cls, value: dict[str, str]) -> dict[str, str]:
        return _headers(value)

    @field_validator("cookie_header")
    @classmethod
    def check_cookie(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Cookie header cannot contain control characters")
        return value

    @field_validator("name")
    @classmethod
    def check_name(cls, value: str) -> str:
        if value.lower() in {"anonymous", "default"}:
            raise ValueError("This identity name is reserved")
        return value


class AuthenticatedResearchPlan(_Model):
    origin: str = Field(min_length=1, max_length=2048)
    identities: list[ResearchIdentity] = Field(min_length=1, max_length=4)
    allowed_mutations: list[MutationPermission] = Field(default_factory=list, max_length=32)
    allow_account_creation: bool = False
    read_prefixes: list[str] = Field(min_length=1, max_length=16)
    start_urls: list[str] = Field(default_factory=list, max_length=16)
    max_requests: int = Field(default=80, ge=1, le=400)
    max_pages: int = Field(default=20, ge=1, le=100)
    max_depth: int = Field(default=3, ge=0, le=6)
    deadline_seconds: float = Field(default=120.0, ge=1.0, le=600.0)

    @field_validator("origin")
    @classmethod
    def check_origin(cls, value: str) -> str:
        parts = urlsplit(_url(value))
        if parts.path != "/" or parts.query:
            raise ValueError("origin must contain only scheme, host, and optional port")
        return _origin(value)

    @model_validator(mode="after")
    def check_identities(self) -> "AuthenticatedResearchPlan":
        names = [identity.name.casefold() for identity in self.identities]
        if len(names) != len(set(names)):
            raise ValueError("Identity names must be unique")
        fingerprints: set[tuple[str, str]] = set()
        for identity in self.identities:
            probe = identity.verification
            value = probe.marker if probe.marker is not None else probe.expected
            fingerprint = (type(value).__name__, json.dumps(value, sort_keys=True))
            if fingerprint in fingerprints:
                raise ValueError("Each identity needs a distinct expected verification value")
            fingerprints.add(fingerprint)
            if sum(step.method == "POST" and step.purpose == "register" for step in identity.setup) > 1:
                raise ValueError("At most one account creation request per identity is supported")
        return self

    def validate_scope(self, guard: ScopeGuard, target_url: str) -> None:
        """Validate all policy URLs without requests or consuming a budget."""
        try:
            if _origin(target_url) != self.origin or not guard.is_in_scope(target_url):
                raise ValueError("Research origin must match the authorized target")
            guard.validate_window()
            urls = [target_url, *self.start_urls]
            for prefix in self.read_prefixes:
                parse_url_prefix(prefix)
                urls.append(prefix)
            permissions = {(permission.method, _url(permission.url), permission.purpose)
                           for permission in self.allowed_mutations}
            if len(permissions) != len(self.allowed_mutations):
                raise ValueError("Duplicate mutation permissions are not supported")
            urls.extend(permission.url for permission in self.allowed_mutations)
            for identity in self.identities:
                urls.append(identity.verification.url)
                previous_gets: set[str] = set()
                for step in identity.setup:
                    urls.append(step.url)
                    if step.method == "GET":
                        previous_gets.add(_url(step.url))
                    else:
                        if (step.method, _url(step.url), step.purpose) not in permissions:
                            raise ValueError("Every setup mutation needs an exact permission")
                        if step.purpose == "register" and not self.allow_account_creation:
                            raise ValueError("Account creation requires explicit opt-in")
                    if step.include_hidden_from:
                        urls.append(step.include_hidden_from)
                        if _url(step.include_hidden_from) not in previous_gets:
                            raise ValueError("Hidden fields require an earlier explicit GET step")
            for url in urls:
                if _origin(url) != self.origin or not guard.is_in_scope(_url(url)):
                    raise ValueError("Every research URL must stay within origin and engagement scope")
            for url in self.start_urls:
                if not _read_allowed(self, url):
                    raise ValueError("Crawl starts must use explicit read prefixes without action/query URLs")
        except (ScopeViolation, TypeError, ValueError):
            # Config errors must not echo secret-bearing URLs or field values.
            raise ValueError("Invalid authenticated research scope or permissions") from None


_ACTION_PATH = re.compile(r"(?:^|[/_.-])(?:logout|logoff|signout|delete|remove|destroy|purge|reset|unsubscribe|checkout|purchase|pay|transfer|activate|deactivate|revoke|confirm)(?:$|[/_.-])", re.I)


def _read_allowed(plan: AuthenticatedResearchPlan, url: str) -> bool:
    try:
        normalized = _url(url)
        parts = urlsplit(normalized)
        path = scope_path(parts.path)
        if _origin(normalized) != plan.origin or parts.query or _ACTION_PATH.search(path):
            return False
        return any(path == prefix or path.startswith(prefix.rstrip("/") + "/")
                   for _, _, _, prefix in (parse_url_prefix(value) for value in plan.read_prefixes))
    except (TypeError, ValueError):
        return False


class _Page(HTMLParser):
    """Bounded passive HTML inventory; scripts and forms are never executed."""
    def __init__(self, body: str):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.base: str = ""
        self._form: dict[str, Any] | None = None
        self.feed(body[:http_transport.MAX_RESPONSE_BYTES])

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "base" and not self.base:
            self.base = values.get("href") or ""
        elif tag == "a" and values.get("href") and len(self.links) < 500:
            href = values["href"] or ""
            if len(href) <= 2048:
                self.links.append(href)
        elif tag == "form" and len(self.forms) < 50:
            self._form = {"action": values.get("action") or "", "method": (values.get("method") or "GET").upper(), "hidden": {}, "inputs": 0, "ambiguous": False}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None and self._form["inputs"] < 64:
            self._form["inputs"] += 1
            name, value = values.get("name") or "", values.get("value") or ""
            if (values.get("type") or "").lower() == "hidden" and name:
                if name in self._form["hidden"] or len(name) > 128 or len(value) > 4096:
                    self._form["ambiguous"] = True
                else:
                    self._form["hidden"][name] = value

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def _matches(probe: VerificationProbe, result: dict[str, Any]) -> bool:
    if result["truncated"] or not 200 <= result["status"] < 300:
        return False
    if probe.marker is not None:
        return probe.marker in result["body"]
    try:
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            obj: dict[str, Any] = {}
            for key, item in pairs:
                if key in obj:
                    raise ValueError("Duplicate JSON key")
                obj[key] = item
            return obj

        value: Any = json.loads(result["body"], object_pairs_hook=unique_object)
        for part in (probe.json_path or "")[1:].split("/"):
            key = part.replace("~1", "/").replace("~0", "~")
            value = value[int(key)] if isinstance(value, list) and key.isdigit() else value[key]
        return type(value) is type(probe.expected) and value == probe.expected
    except (KeyError, IndexError, TypeError, ValueError):
        return False


class ResearchRunner:
    def __init__(self, plan: AuthenticatedResearchPlan, guard: ScopeGuard):
        self.plan = plan.model_copy(deep=True)
        self.guard = guard
        self.plan.validate_scope(guard, self.plan.read_prefixes[0])
        self.sessions: dict[str, AuthSession] = {"anonymous": AuthSession("anonymous", role_hint="anonymous")}
        for identity in self.plan.identities:
            headers = dict(identity.headers)
            session = AuthSession(identity.name, role_hint=identity.role_hint, static_headers=headers)
            cookie_names: set[str] = set()
            for item in identity.cookie_header.split(";"):
                if not item.strip():
                    continue
                name, separator, value = item.strip().partition("=")
                if not separator or name in cookie_names or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                    raise ResearchError("invalid_cookie_header")
                cookie_names.add(name)
                session.http_cookies.set_cookie(Cookie(
                    version=0, name=name, value=value, port=None, port_specified=False,
                    domain=urlsplit(self.plan.origin).hostname or "", domain_specified=False,
                    domain_initial_dot=False, path="/", path_specified=True,
                    secure=self.plan.origin.startswith("https:"), expires=None, discard=True,
                    comment=None, comment_url=None, rest={}, rfc2109=False,
                ))
            session.http_cookies_loaded = True
            self.sessions[identity.name] = session
        self.verified_identities: set[str] = set()
        self.identity_fingerprints: dict[str, str] = {}
        self._started = time.monotonic()
        self._requests = 0
        self._pages = 0
        self._lock = threading.RLock()
        self._setup = False
        self._ran = False
        self._observations: list[dict[str, Any]] = []
        self._endpoints: set[tuple[str, str, str]] = set()
        self._forms: set[tuple[str, str, str]] = set()
        self._blocked_links = 0
        self._secrets: set[str] = set()
        for identity in self.plan.identities:
            self._secrets.update(value for value in identity.headers.values() if len(value) >= 3)
            self._secrets.update(value.split(" ", 1)[-1] for value in identity.headers.values() if len(value) >= 3)
            self._secrets.update(part.split("=", 1)[-1].strip() for part in identity.cookie_header.split(";") if "=" in part)
            self._secrets.update(value for step in identity.setup for value in step.fields.values() if len(value) >= 3)

    def clone_session(self, name: str) -> AuthSession:
        """Private snapshot for deterministic controls; never persist or log it."""
        if name not in self.sessions:
            raise ResearchError("unknown_identity")
        if name == "anonymous":
            return AuthSession("anonymous", role_hint="anonymous")
        return AuthSession.from_transfer_dict(self.sessions[name].to_transfer_dict())

    @property
    def request_count(self) -> int:
        return self._requests

    def _deadline(self) -> None:
        if time.monotonic() - self._started >= self.plan.deadline_seconds:
            raise ResearchLimit("deadline_exhausted")

    def verify_session(self, identity_name: str, *, session: AuthSession) -> bool:
        """Fresh private identity probe for before/after business-rule controls."""
        if session.name != identity_name or identity_name not in self.sessions:
            return False
        if identity_name == "anonymous":
            return not session.static_headers and not list(session.http_cookies)
        if identity_name not in self.verified_identities:
            return False
        identity = next(item for item in self.plan.identities if item.name == identity_name)
        response = self.request(identity_name, "GET", identity.verification.url, session=session)
        return response["final_url"] == _url(identity.verification.url) and _matches(identity.verification, response)

    def _public_url(self, value: str) -> str:
        parts = urlsplit(value)
        result = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        for secret in sorted(self._secrets, key=len, reverse=True):
            if len(secret) >= 3:
                result = result.replace(secret, "[redacted]").replace(quote(secret, safe=""), "[redacted]")
        return result

    def _get_allowed(self, url: str) -> bool:
        if _read_allowed(self.plan, url):
            return True
        explicit = { _url(identity.verification.url) for identity in self.plan.identities }
        explicit.update(_url(step.url) for identity in self.plan.identities for step in identity.setup if step.method == "GET")
        return url in explicit and not _ACTION_PATH.search(scope_path(urlsplit(url).path))

    def request(self, identity_name: str, method: str, url: str, *, data: str | None = None,
                headers: dict[str, str] | None = None, session: AuthSession | None = None) -> dict[str, Any]:
        """Private body-bearing API; all network requests share hard budgets.

        Credentials are origin-bound. Only explicit setup POSTs are supported;
        discovering a form never authorizes its submission. Redirects are
        individually gated, and POST-preserving redirects are not replayed.
        """
        with self._lock:
            if identity_name not in self.sessions or (session is not None and session.name != identity_name):
                raise ResearchError("unknown_identity")
            if identity_name != "anonymous" and identity_name not in self.verified_identities and not self._setup:
                raise ResearchError("identity_not_verified")
            identity = session or self.sessions[identity_name]
            if identity_name == "anonymous" and (identity.static_headers or list(identity.http_cookies)):
                raise ResearchError("anonymous_credentials_forbidden")
            extra = dict(headers or {})
            if any(name.lower() in {"authorization", "cookie"} for name in extra):
                raise ResearchError("identity_override_forbidden")
            try:
                _headers(extra)
                current = _url(url)
            except (TypeError, ValueError):
                raise ResearchError("invalid_request") from None
            if not isinstance(method, str) or data is not None and (not isinstance(data, str) or len(data) > 65536):
                raise ResearchError("invalid_request")
            method = method.upper()
            request_headers = {**identity.static_headers, **extra}
            for hop in range(6):
                self._deadline()
                if self._requests >= self.plan.max_requests:
                    raise ResearchLimit("request_budget_exhausted")
                if _origin(current) != self.plan.origin or not self.guard.is_in_scope(current):
                    raise ResearchError("request_out_of_scope")
                if method == "GET":
                    if data is not None or not self._get_allowed(current):
                        raise ResearchError("read_not_permitted")
                elif method == "POST":
                    if not self._setup or not any(permission.method == method and _url(permission.url) == current for permission in self.plan.allowed_mutations):
                        raise ResearchError("mutation_not_permitted")
                else:
                    raise ResearchError("method_not_permitted")
                try:
                    self.guard.validate("http_request", {"url": current, "method": method, "data": data})
                    # Scope validation may wait for an engagement rate slot.
                    # Do not dispatch after that wait consumed our deadline.
                    self._deadline()
                    self._requests += 1
                    raw = http_transport.request(self.guard, identity, url=current, method=method,
                                                 headers=request_headers, data=data, follow_redirects=False)
                except ResearchLimit:
                    raise
                except RateLimitExceeded:
                    raise ResearchLimit("engagement_request_budget_exhausted") from None
                except Exception:
                    raise ResearchError("scoped_request_failed") from None
                self._deadline()
                self._secrets.update(cookie.value for cookie in identity.http_cookies if cookie.value)
                text = str(raw.get("response") or "")
                head, _, body = text.partition("\r\n\r\n")
                response_headers = {key.strip().lower(): value.strip() for line in head.split("\r\n")[1:] if ":" in line for key, value in [line.split(":", 1)]}
                result: dict[str, Any] = {"status": int(raw.get("status_code") or 0), "body": body,
                          "final_url": str(raw.get("url") or current), "headers": response_headers,
                          "truncated": bool(raw.get("truncated", False))}
                if _url(result["final_url"]) != current:
                    raise ResearchError("unexpected_transport_redirect")
                if result["status"] not in {301, 302, 303, 307, 308} or "location" not in response_headers:
                    return result
                if hop == 5:
                    raise ResearchLimit("redirect_limit_exhausted")
                if method == "POST" and result["status"] in {307, 308}:
                    raise ResearchError("mutation_redirect_requires_operator")
                try:
                    current = _url(urljoin(current, response_headers["location"]))
                except (TypeError, ValueError):
                    raise ResearchError("invalid_redirect") from None
                if method == "POST":
                    method, data = "GET", None
                    request_headers = {key: value for key, value in request_headers.items() if key.lower() != "content-type"}
            raise ResearchLimit("redirect_limit_exhausted")

    def _setup_identity(self, identity: ResearchIdentity) -> None:
        documents: dict[str, tuple[_Page, str]] = {}
        for step in identity.setup:
            fields = dict(step.fields)
            if step.include_hidden_from:
                source = documents.get(_url(step.include_hidden_from))
                if source is None:
                    raise ResearchError("hidden_form_source_unavailable")
                page, source_url = source
                base = urljoin(source_url, page.base) if page.base else source_url
                if _origin(base) != self.plan.origin:
                    raise ResearchError("form_base_out_of_scope")
                forms = [form for form in page.forms if form["method"] == "POST" and _url(urljoin(base, form["action"]) if form["action"] else source_url) == _url(step.url)]
                if len(forms) != 1 or forms[0]["ambiguous"]:
                    raise ResearchError("hidden_form_ambiguous")
                hidden = forms[0]["hidden"]
                if any(name in fields and fields[name] != value for name, value in hidden.items()):
                    raise ResearchError("hidden_form_field_conflict")
                fields = {**hidden, **fields}
                self._secrets.update(value for value in hidden.values() if len(value) >= 3)
            result = self.request(identity.name, step.method, step.url,
                                  data=urlencode(fields) if step.method == "POST" else None,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"} if step.method == "POST" else None)
            if result["truncated"] or not 200 <= result["status"] < 300:
                raise ResearchError("setup_failed_or_needs_operator")
            if step.method == "GET":
                documents[_url(step.url)] = (_Page(result["body"]), result["final_url"])

    def _verify(self, identity: ResearchIdentity) -> None:
        anonymous = self.request("anonymous", "GET", identity.verification.url, session=self.clone_session("anonymous"))
        positive = self.request(identity.name, "GET", identity.verification.url)
        if (anonymous["truncated"] or anonymous["status"] >= 500 or anonymous["status"] == 0
                or _matches(identity.verification, anonymous) or not _matches(identity.verification, positive)
                or positive["final_url"] != _url(identity.verification.url)):
            raise ResearchError("identity_verification_failed")
        self.verified_identities.add(identity.name)
        self.sessions[identity.name].authenticated = True

    def _verify_distinct_accounts(self) -> None:
        for owner in self.plan.identities:
            for peer in self.plan.identities:
                if owner.name == peer.name:
                    continue
                response = self.request(peer.name, "GET", owner.verification.url, session=self.clone_session(peer.name))
                if (response["truncated"] or not response["status"] or response["status"] >= 500
                        or _matches(owner.verification, response)):
                    raise ResearchError("identities_not_demonstrably_distinct")
        for identity in self.plan.identities:
            probe = identity.verification
            value = probe.marker if probe.marker is not None else probe.expected
            material = json.dumps([type(value).__name__, value], sort_keys=True).encode("utf-8")
            self.identity_fingerprints[identity.name] = hashlib.sha256(material).hexdigest()

    def _crawl(self, identity: ResearchIdentity) -> None:
        queue = deque((url, 0) for url in (self.plan.start_urls or self.plan.read_prefixes))
        seen: set[str] = set()
        while queue:
            self._deadline()
            url, depth = queue.popleft()
            url = _url(url)
            if url in seen:
                continue
            seen.add(url)
            if not _read_allowed(self.plan, url) or not self.guard.is_in_scope(url):
                self._blocked_links += 1
                continue
            if self._pages >= self.plan.max_pages:
                raise ResearchLimit("page_budget_exhausted")
            response = self.request(identity.name, "GET", url)
            self._pages += 1
            safe_url = self._public_url(response["final_url"])
            self._observations.append({"kind": "page", "identity": identity.name, "url": safe_url,
                                       "method": "GET", "status": response["status"], "truncated": response["truncated"]})
            self._endpoints.add((identity.name, "GET", safe_url))
            if response["status"] in {401, 403}:
                self.verified_identities.discard(identity.name)
                self.sessions[identity.name].authenticated = False
                raise ResearchError("identity_expired_during_crawl")
            if response["truncated"] or not 200 <= response["status"] < 300:
                continue
            content_type = response["headers"].get("content-type", "")
            if content_type and "html" not in content_type.lower():
                continue
            page = _Page(response["body"])
            base = urljoin(response["final_url"], page.base) if page.base else response["final_url"]
            if _origin(base) != self.plan.origin:
                self._blocked_links += len(page.links) + len(page.forms)
                continue
            for form in page.forms:
                try:
                    action = _url(urljoin(base, form["action"]) if form["action"] else response["final_url"])
                    if _origin(action) != self.plan.origin or not self.guard.is_in_scope(action):
                        self._blocked_links += 1
                        continue
                except (TypeError, ValueError):
                    self._blocked_links += 1
                    continue
                form_method = form["method"] if form["method"] in {"GET", "POST"} else "OTHER"
                key = (identity.name, form_method, self._public_url(action))
                if key not in self._forms:
                    self._forms.add(key)
                    self._observations.append({"kind": "form", "identity": identity.name, "method": form_method,
                                               "url": key[2], "input_count": form["inputs"], "submitted": False})
                    self._endpoints.add(key)
            if depth >= self.plan.max_depth:
                continue
            for link in page.links:
                try:
                    next_url = _url(urldefrag(urljoin(base, link))[0])
                except (TypeError, ValueError):
                    self._blocked_links += 1
                    continue
                if _read_allowed(self.plan, next_url) and self.guard.is_in_scope(next_url):
                    if next_url not in seen and len(queue) < self.plan.max_pages * 10:
                        queue.append((next_url, depth + 1))
                else:
                    self._blocked_links += 1
        # Recheck identity after crawling; a login-looking 200 is not enough.
        if not _matches(identity.verification, self.request(identity.name, "GET", identity.verification.url)):
            self.verified_identities.discard(identity.name)
            self.sessions[identity.name].authenticated = False
            raise ResearchError("identity_expired_during_crawl")

    def run(self) -> dict[str, Any]:
        if self._ran:
            raise ResearchError("research_already_started")
        self._ran = True
        partial, reason = False, ""
        try:
            self._setup = True
            for identity in self.plan.identities:
                self._setup_identity(identity)
                self._verify(identity)
            self._verify_distinct_accounts()
            self._setup = False
            for identity in self.plan.identities:
                self._crawl(identity)
        except ResearchLimit as exc:
            partial, reason = True, str(exc)
            if self._setup:
                self.verified_identities.clear()
                self.identity_fingerprints.clear()
                for session in self.sessions.values():
                    session.authenticated = False
        except ResearchError:
            self.verified_identities.clear()
            self.identity_fingerprints.clear()
            for session in self.sessions.values():
                session.authenticated = False
            raise
        except Exception:
            self.verified_identities.clear()
            self.identity_fingerprints.clear()
            raise ResearchError("research_failed") from None
        finally:
            self._setup = False
        return copy.deepcopy({
            "status": "partial" if partial else "completed", "partial": partial, "stop_reason": reason,
            "identities": [{"name": identity.name, "role_hint": identity.role_hint,
                            "verified": identity.name in self.verified_identities,
                            "authenticated": identity.name in self.verified_identities} for identity in self.plan.identities],
            "request_count": self._requests, "page_count": self._pages, "endpoint_count": len(self._endpoints),
            "form_count": len(self._forms), "blocked_link_count": self._blocked_links,
            "observations": self._observations, "findings": [],
            "credential_scope": "private_to_authenticated_research",
            "capabilities": {"javascript": False, "automatic_form_submission": False, "generic_agent_credentials": False},
        })
