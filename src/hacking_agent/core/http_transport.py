"""Scoped HTTP transport used by production tool execution.

Redirects are explicit requests: each hop is authorized and charged to the
engagement budget. Cookies belong to a named identity in this worker process.
The context variable binds a guard to one execution, never to a global target.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

import httpx

from hacking_agent.core.scope import ScopeGuard, ScopeViolation
from hacking_agent.core.sessions import AuthSession


_GUARD: ContextVar[ScopeGuard | None] = ContextVar("reynard_http_guard", default=None)
MAX_RESPONSE_BYTES = 65536
MAX_REDIRECTS = 10


@contextmanager
def execution_scope(guard: ScopeGuard | None) -> Iterator[None]:
    token = _GUARD.set(guard)
    try:
        yield
    finally:
        _GUARD.reset(token)


def active_guard() -> ScopeGuard | None:
    return _GUARD.get()


def request(guard: ScopeGuard, session: AuthSession, *, url: str, method: str,
            headers: dict[str, str], data: str | None, follow_redirects: bool,
            insecure: bool = False) -> dict:
    """First hop was charged by the executor; subsequent hops are charged here."""
    method = method.upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ValueError("Unsupported HTTP method")
    forbidden = {"host", "content-length", "transfer-encoding", "connection",
                 "proxy-authorization", "proxy-connection"}
    if any(key.lower() in forbidden for key in headers):
        raise ScopeViolation("Routing/framing header overrides are not supported in production")
    request_headers = dict(headers)
    request_data = data
    # A new client shares only this identity's cookie jar. It does not inherit
    # ambient proxy settings, credentials, or cookies from another identity.
    with httpx.Client(cookies=session.http_cookies, verify=not insecure,
                      trust_env=False, timeout=30.0, follow_redirects=False) as client:
        for hop in range(MAX_REDIRECTS + 1):
            if hop:
                guard.validate("http_request", {"url": url, "method": method,
                                                "data": request_data})
            else:
                guard.validate_window()
                if not guard.is_in_scope(url):
                    raise ScopeViolation("HTTP destination changed after authorization")
            kwargs = {"headers": request_headers, "content": request_data}
            with client.stream(method, url, **kwargs) as response:
                chunks: list[bytes] = []
                size = 0
                truncated = False
                for chunk in response.iter_bytes():
                    remaining = MAX_RESPONSE_BYTES - size
                    chunks.append(chunk[:remaining])
                    size += len(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
                body = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
                result = {
                    "response": (
                        f"HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n"
                        + "\r\n".join(f"{k}: {v}" for k, v in response.headers.multi_items())
                        + "\r\n\r\n" + body
                    ),
                    "status_code": response.status_code,
                    "url": str(response.url),
                    "method": method,
                    "session": session.name,
                    "stderr": "", "exit_code": 0, "truncated": truncated,
                    "redirect_count": hop,
                }
                if not (follow_redirects and response.is_redirect and "location" in response.headers):
                    return result
                if hop == MAX_REDIRECTS:
                    raise ScopeViolation("HTTP redirect limit exceeded")
                destination = response.url.join(response.headers["location"])
                origin = lambda u: (u.scheme, u.host, u.port)
                if origin(destination) != origin(response.url):
                    # Custom headers may carry secrets too; forward only a
                    # small set of representation preferences to a new origin.
                    request_headers = {k: v for k, v in request_headers.items()
                                       if k.lower() in {"accept", "accept-language", "user-agent"}}
                if response.status_code == 303 and method != "HEAD" or (
                    response.status_code in {301, 302} and method == "POST"
                ):
                    method, request_data = "GET", None
                    request_headers = {k: v for k, v in request_headers.items()
                                       if k.lower() != "content-type"}
                url = str(destination)
    raise RuntimeError("Unreachable redirect state")
