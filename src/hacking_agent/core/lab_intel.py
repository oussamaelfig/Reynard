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


def extract_first_url(text: str) -> str:
    """Return the first URL in text, trimmed for common sentence punctuation."""
    match = URL_RE.search(text or "")
    if not match:
        return (text or "").strip()
    return match.group(0).rstrip(".,;")


def normalize_target_input(raw: str) -> tuple[str, str]:
    """Split a free-form CLI task into (target_url, original_objective)."""
    raw = (raw or "").strip()
    target_url = extract_first_url(raw)
    objective = raw if raw and raw != target_url else ""
    return target_url, objective


def detect_lab_profile(raw: str, target_url: str) -> dict:
    """Detect high-confidence CTF/lab profiles from user objective + target."""
    haystack = f"{raw or ''} {target_url or ''}".lower()
    host = urlparse(target_url or "").netloc.lower()

    if "web-security-academy.net" not in host:
        return {}

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
