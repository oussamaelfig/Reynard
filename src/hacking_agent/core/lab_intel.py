"""
Small, deterministic target-intelligence helpers for CTF/lab workflows.

These helpers do not replace recon. They let the orchestrator preserve the
user's natural-language objective while handing agents a clean target URL and
an optional lab profile when the challenge description is explicit.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
TARGET_URL_RE = re.compile(
    r"\bTarget\s*:\s*(https?://[^\s\"'<>)]+)",
    re.IGNORECASE,
)
TARGET_HOST_RE = re.compile(
    r"\bTarget\s*:\s*((?:https?://)?[a-zA-Z0-9.-]+(?::\d+)?)",
    re.IGNORECASE,
)
HOST_RE = re.compile(
    r"(?<![\w.-])("
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
    r")(?::\d+)?(?![\w-])"
)


def extract_first_url(text: str) -> str:
    """Return the first URL in text, trimmed for common sentence punctuation."""
    match = URL_RE.search(text or "")
    if not match:
        return (text or "").strip()
    return match.group(0).rstrip(".,;")


def extract_target_url(text: str) -> str:
    """Return the intended primary target URL from a free-form objective.

    Prompts for SSRF/OAuth labs often contain an internal URL to fetch through
    the vulnerable app before the real lab URL. Prefer an explicit "Target:"
    marker when present, then fall back to platform-known lab hosts, then the
    first URL.
    """
    text = text or ""
    marker_matches = TARGET_URL_RE.findall(text)
    if marker_matches:
        return marker_matches[-1].rstrip(".,;")
    host_marker_matches = TARGET_HOST_RE.findall(text)
    if host_marker_matches:
        return host_marker_matches[-1].rstrip(".,;")

    urls = [m.group(0).rstrip(".,;") for m in URL_RE.finditer(text)]
    if not urls:
        host_match = HOST_RE.search(text)
        if host_match:
            return host_match.group(1).rstrip(".,;")
        return text.strip()

    for url in reversed(urls):
        host = urlparse(url).netloc.lower()
        if "web-security-academy.net" in host:
            return url
    if urls:
        return urls[0]

    return text.strip()


def normalize_target_input(raw: str) -> tuple[str, str]:
    """Split a free-form CLI task into (target_url, original_objective)."""
    raw = (raw or "").strip()
    target_url = extract_target_url(raw)
    objective = raw if raw and raw != target_url else ""
    return target_url, objective


def detect_lab_profile(raw: str, target_url: str) -> dict:
    """Detect high-confidence CTF/lab profiles from user objective + target."""
    haystack = f"{raw or ''} {target_url or ''}".lower()
    parsed_target = target_url if "://" in (target_url or "") else f"http://{target_url or ''}"
    host = urlparse(parsed_target).netloc.lower()

    if "web-security-academy.net" not in host:
        return {}

    if "ssrf" in haystack and "dynamic client registration" in haystack:
        return {
            "id": "portswigger_oidc_dynamic_client_registration_ssrf",
            "platform": "portswigger",
            "vulnerability": "ssrf",
            "endpoint_hint": "/.well-known/openid-configuration",
            "registration_endpoint": "client registration endpoint from OIDC discovery",
            "metadata_path": "/latest/meta-data/iam/security-credentials/admin/",
            "credentials_hint": "wiener:peter",
            "purpose": (
                "Register an OAuth client whose metadata induces the OAuth "
                "service to fetch cloud instance metadata and disclose the "
                "secret access key."
            ),
        }

    if "blind xxe" in haystack and "out-of-band" in haystack:
        return {
            "id": "portswigger_blind_xxe_oob",
            "platform": "portswigger",
            "vulnerability": "xxe",
            "endpoint_hint": "/product/stock",
            "method": "POST",
            "content_type": "application/xml",
            "purpose": "Trigger an out-of-band callback from the XML parser.",
        }

    if "command injection" in haystack and "simple case" in haystack:
        return {
            "id": "portswigger_os_command_injection_simple",
            "platform": "portswigger",
            "vulnerability": "command_injection",
            "endpoint_hint": "/product/stock",
            "parameter": "storeId",
            "probe_command": "whoami",
            "purpose": "Inject a shell metacharacter into the stock-check storeId parameter.",
        }

    if (
        "sql injection" in haystack
        and (
            "hidden data" in haystack
            or "where clause" in haystack
            or "retrieval of hidden data" in haystack
        )
    ):
        return {
            "id": "portswigger_sqli_hidden_data",
            "platform": "portswigger",
            "vulnerability": "sql_injection",
            "endpoint_hint": "/filter",
            "parameter": "category",
            "sample_category": "Gifts",
            "primary_payload_template": "{category}' OR 1=1-- ",
            "purpose": "Retrieve hidden/unreleased products from a product category WHERE clause.",
        }

    if "sql injection" in haystack:
        return {
            "id": "portswigger_sqli",
            "platform": "portswigger",
            "vulnerability": "sql_injection",
        }

    return {}
