"""Strict, side-effect-free address parsing shared by scope and RoE loaders."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


def normalize_host(value: str) -> str:
    """Normalize a DNS name or literal IP; reject alternative IP spellings."""
    if not isinstance(value, str) or not value:
        raise ValueError("A nonempty hostname is required")
    if any(c.isspace() or ord(c) < 32 for c in value) or any(c in value for c in "\\/%@?#"):
        raise ValueError("Ambiguous hostname")
    host = value.removesuffix(".").lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    # Browsers/curl can resolve 127.1, octal IPv4, and integer/hex IPv4 as IPs.
    if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", host):
        raise ValueError("Noncanonical IP literal")
    try:
        ascii_host = host.encode("idna").decode("ascii")
        # Python's built-in IDNA codec uses IDNA2003; HTTP stacks can use
        # IDNA2008. Reject lossy mappings (e.g. ß -> ss) rather than authorize
        # one DNS name and let the transport contact another.
        if not host.isascii() and ascii_host.encode("ascii").decode("idna") != host:
            raise ValueError("Ambiguous IDNA mapping; use the intended ASCII hostname")
        host = ascii_host
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname") from exc
    if len(host) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise ValueError("Invalid DNS hostname")
    return host


@dataclass(frozen=True)
class TargetAddress:
    host: str
    scheme: str = ""
    port: int | None = None
    path: str = ""
    is_url: bool = False


def parse_target(value: str) -> TargetAddress:
    """Parse one HTTP(S) URL or one host[:port], never a target expression."""
    if not isinstance(value, str) or not value:
        raise ValueError("A nonempty target is required")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("Target contains whitespace, control characters, or backslashes")
    explicit = "://" in value
    if not explicit:
        try:
            return TargetAddress(host=str(ipaddress.ip_address(value)))
        except ValueError:
            pass
        if any(c in value for c in "/?#"):
            raise ValueError("A target path requires an explicit HTTP(S) URL")
    parsed = urlsplit(value if explicit else f"http://{value}")
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP(S) target URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Userinfo in target URLs is not permitted")
    host = normalize_host(parsed.hostname or "")
    port = parsed.port  # Access rejects malformed and out-of-range ports.
    if parsed.netloc.endswith(":") or port == 0:
        raise ValueError("Invalid target port")
    return TargetAddress(
        host=host,
        scheme=parsed.scheme.lower() if explicit else "",
        port=(port or (443 if parsed.scheme.lower() == "https" else 80)) if explicit else port,
        path=parsed.path or "/" if explicit else "",
        is_url=explicit,
    )


def scope_path(path: str) -> str:
    """Normalize safe URL paths and reject ambiguous encoded routing syntax.

    Path-scoped engagements deliberately reject dot segments, encoded path
    separators, matrix parameters, and nested escapes. Different HTTP stacks
    normalize those differently; accepting them could authorize another path.
    Query values are not inspected because they do not define the URL path.
    """
    if re.search(r"%(?![0-9a-fA-F]{2})", path):
        raise ValueError("Malformed path escape")
    if re.search(r"%(?:2f|5c|3f|23|3b|25)", path, re.IGNORECASE):
        raise ValueError("Ambiguous encoded path delimiter")
    decoded = unquote(path, errors="strict")
    if any(c in decoded for c in "\\;\x00") or any(ord(c) < 32 for c in decoded):
        raise ValueError("Ambiguous path")
    if any(segment in {".", ".."} for segment in decoded.split("/")) or "//" in decoded:
        raise ValueError("Ambiguous path segments")
    return decoded or "/"


def parse_url_prefix(value: str) -> tuple[str, str, int | None, str]:
    """Canonical scheme, hostname, effective port, and directory prefix."""
    target = parse_target(value)
    if not target.is_url or "?" in value or "#" in value:
        raise ValueError("Scope URL prefixes require HTTP(S) URLs without queries/fragments")
    return target.scheme, target.host, target.port, scope_path(target.path).rstrip("/") or "/"
