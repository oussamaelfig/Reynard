"""
=============================================================================
Reynard - Baseline Capture + Differential Analysis
=============================================================================
Solves the "single-response" blind-spot in analyzer.py.

Many real-world vulns are only visible through DIFFS:
  - Boolean blind SQLi: response when condition is true vs. false
  - IDOR / horizontal privilege: user1 reading user2's resource
  - Vertical authz: low-priv reading admin endpoints
  - Cache poisoning: cached response after poisoned request
  - Mass assignment: response shape changes when extra params accepted
  - Race conditions: state divergence after parallel requests

The differ stores baselines (status, length, body hash, structural
fingerprint, JSON-key set, header set) and reports the delta when a probe
response is compared against one.

Storage is in-process (lifetime of one orchestrator session). Baselines
are not persisted across sessions on purpose: an old baseline against a
changed app is a footgun.
=============================================================================
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any


# Tokens stripped before comparison so timestamps/CSRF nonces don't flag.
DYNAMIC_NOISE_PATTERNS = [
    re.compile(r'\b\d{10,13}\b'),                     # epoch / unix timestamps
    re.compile(r'[a-f0-9]{32,64}', re.IGNORECASE),    # hashes / nonces
    re.compile(r'csrf[\w-]*\s*[:=]\s*[^&\'"<>]+', re.IGNORECASE),
    re.compile(r'_token\s*[:=]\s*[^&\'"<>]+', re.IGNORECASE),
    re.compile(r'session[\w-]*\s*[:=]\s*[^&\'"<>]+', re.IGNORECASE),
    re.compile(r'\b[A-Z][a-z]{2,8}\s+\d+,?\s+\d{4}'), # "Jan 1, 2024"
]


def _normalize_for_compare(text: str) -> str:
    """Strip volatile tokens that would otherwise pollute every diff."""
    out = text
    for pat in DYNAMIC_NOISE_PATTERNS:
        out = pat.sub("<DYN>", out)
    return out


def _structural_fingerprint(text: str) -> str:
    """Reduce a body to a structural shape hash.

    Strategy: collapse all runs of whitespace, replace digits and longer
    alphanumerics with placeholders. Two responses with the same template
    but different rendered values get the same fingerprint.
    """
    s = _normalize_for_compare(text)
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"\d+", "0", s)
    s = re.sub(r"[a-zA-Z]{20,}", "W", s)
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _json_keyset(text: str) -> set[str] | None:
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    keys: set[str] = set()
    def walk(o: Any, prefix: str = ""):
        if isinstance(o, dict):
            for k, v in o.items():
                keys.add(f"{prefix}{k}")
                walk(v, prefix=f"{prefix}{k}.")
        elif isinstance(o, list):
            for v in o[:10]:
                walk(v, prefix=prefix)
    walk(obj)
    return keys


@dataclass
class Baseline:
    name: str
    status: int = 0
    length: int = 0
    content_hash: str = ""
    structural_hash: str = ""
    json_keys: set[str] | None = None
    header_set: set[str] = field(default_factory=set)
    body_excerpt: str = ""    # first ~3KB normalized — for difflib comparisons
    captured_at: str = ""
    captured_under_session: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "length": self.length,
            "content_hash": self.content_hash,
            "structural_hash": self.structural_hash,
            "json_keys": sorted(self.json_keys) if self.json_keys else None,
            "header_set": sorted(self.header_set),
            "captured_at": self.captured_at,
            "captured_under_session": self.captured_under_session,
        }


class BaselineStore:
    """In-memory store of named baselines."""

    def __init__(self):
        self._lock = threading.RLock()
        self._baselines: dict[str, Baseline] = {}

    def capture(self, name: str, raw_response: str,
                session_name: str = "") -> Baseline:
        from datetime import datetime
        status, headers_text, body = _split_response(raw_response)
        normalized = _normalize_for_compare(body)
        b = Baseline(
            name=name,
            status=status,
            length=len(body),
            content_hash=hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:16],
            structural_hash=_structural_fingerprint(body),
            json_keys=_json_keyset(body),
            header_set={h.split(":", 1)[0].strip().lower()
                        for h in headers_text.splitlines() if ":" in h},
            body_excerpt=normalized[:3000],
            captured_at=datetime.utcnow().isoformat(),
            captured_under_session=session_name,
        )
        with self._lock:
            self._baselines[name] = b
        return b

    def get(self, name: str) -> Baseline | None:
        with self._lock:
            return self._baselines.get(name)

    def diff(self, baseline_name: str, raw_response: str) -> dict[str, Any]:
        b = self.get(baseline_name)
        if b is None:
            return {"error": f"no baseline named '{baseline_name}'",
                    "available": list(self._baselines.keys())}
        status, headers_text, body = _split_response(raw_response)
        normalized = _normalize_for_compare(body)
        new_hash = hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:16]
        new_struct = _structural_fingerprint(body)
        new_keys = _json_keyset(body)
        new_header_set = {h.split(":", 1)[0].strip().lower()
                          for h in headers_text.splitlines() if ":" in h}

        sim = difflib.SequenceMatcher(
            None, b.body_excerpt, normalized[:3000], autojunk=False
        ).ratio()

        result: dict[str, Any] = {
            "baseline_name": baseline_name,
            "status_baseline": b.status,
            "status_new": status,
            "status_delta": status - b.status,
            "length_baseline": b.length,
            "length_new": len(body),
            "length_delta": len(body) - b.length,
            "content_hash_baseline": b.content_hash,
            "content_hash_new": new_hash,
            "content_changed": b.content_hash != new_hash,
            "structural_hash_changed": b.structural_hash != new_struct,
            "content_similarity": round(sim, 4),
            "headers_added": sorted(new_header_set - b.header_set),
            "headers_removed": sorted(b.header_set - new_header_set),
        }
        if b.json_keys is not None and new_keys is not None:
            result["json_keys_added"] = sorted(new_keys - b.json_keys)
            result["json_keys_removed"] = sorted(b.json_keys - new_keys)
        # A simple verdict the agent can pivot on without re-reading the diff.
        result["verdict_summary"] = _summarize_diff(result)
        return result

    def list_names(self) -> list[str]:
        with self._lock:
            return list(self._baselines.keys())


def _split_response(raw: str) -> tuple[int, str, str]:
    """Split a raw curl response (with -D-) into (status, headers, body).

    Falls back gracefully when only the body is present.
    """
    # Status code from the first HTTP/x line (curl -D- with redirects has many).
    status = 0
    last_status_line = ""
    body = raw
    headers_text = ""

    # Try to split on the last header/body boundary "\r\n\r\n" or "\n\n".
    sep = "\r\n\r\n" if "\r\n\r\n" in raw else ("\n\n" if "\n\n" in raw else None)
    if sep:
        # Find the LAST blank-line boundary so redirect headers + body split cleanly.
        idx = raw.rfind(sep)
        # But only treat the prefix as headers if it actually starts with HTTP/
        prefix = raw[:idx]
        if "HTTP/" in prefix.split("\n", 1)[0]:
            headers_text = prefix
            body = raw[idx + len(sep):]

    for line in headers_text.splitlines():
        if line.startswith("HTTP/"):
            last_status_line = line
    if last_status_line:
        try:
            status = int(last_status_line.split()[1])
        except (IndexError, ValueError):
            status = 0
    return status, headers_text, body


def _summarize_diff(d: dict[str, Any]) -> str:
    bits: list[str] = []
    if d["status_delta"] != 0:
        bits.append(f"status {d['status_baseline']}->{d['status_new']}")
    if abs(d["length_delta"]) >= 50:
        bits.append(f"len{d['length_delta']:+d}")
    if d["content_changed"]:
        bits.append("body_changed")
    if d.get("json_keys_added"):
        bits.append(f"+{len(d['json_keys_added'])}keys")
    if d.get("json_keys_removed"):
        bits.append(f"-{len(d['json_keys_removed'])}keys")
    sim = d["content_similarity"]
    if sim < 0.85:
        bits.append(f"sim={sim}")
    if not bits:
        return "no significant difference"
    return ", ".join(bits)


# =============================================================================
# Singleton
# =============================================================================

_STORE: BaselineStore | None = None
_LOCK = threading.RLock()


def get_store() -> BaselineStore:
    global _STORE
    with _LOCK:
        if _STORE is None:
            _STORE = BaselineStore()
        return _STORE
