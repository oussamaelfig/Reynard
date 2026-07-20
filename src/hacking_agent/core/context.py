"""
=============================================================================
Reynard — Context Management (cost efficiency for cheap/local models)
=============================================================================
LLM-FREE, deterministic, zero-cost context shaping. Weak/cheap models burn
tokens re-reading raw response bodies and full knowledge-graph snapshots every
turn. This module keeps the security-relevant signal and drops the boilerplate:

  1. compact_observation(raw, signals, budget)
        Signal-preserving compaction of a tool observation. Replaces the naive
        hard `raw[:6000]` truncation in the specialist agents: keeps status
        lines, notable headers, error/stack signatures, reflected markers, lab
        "solved" banners, forms/links/params, and page titles, while dropping
        scripts/styles/repeated markup.

  2. build_incremental_context(memory, last_snapshot)
        KG-diff based context injection. Instead of re-sending the whole KG
        every call, emit a compact STABLE SUMMARY plus only what CHANGED since
        the previous turn (new/updated entities, new facts, new failures). The
        first turn (last_snapshot is None) returns the full snapshot verbatim so
        one-shot agents behave exactly as before.

  3. cache-friendly prompt assembly + opt-in few-shot exploit transcripts
        assemble_prompt() orders the STABLE prefix (system-adjacent catalog /
        playbook / few-shot) before the VOLATILE tail (KG diff, attempts, last
        observation) so provider prompt caching (DeepSeek/Anthropic) gets a
        stable, cacheable prefix. fewshot_for_vuln() returns compact worked
        examples to steer cheap models on hard vuln classes.

Everything degrades gracefully: when REYNARD_CONTEXT_COMPACTION is disabled the
behavior matches the previous hard-truncation path, and when the KG diff is
disabled callers fall back to the full snapshot.
=============================================================================
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # avoid import cycle at runtime
    from hacking_agent.core.memory import AgentMemory, Entity


# =============================================================================
# Env-driven configuration (all opt-out except few-shot, which is opt-in)
# =============================================================================

DEFAULT_OBSERVATION_BUDGET = 6000


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


def compaction_enabled() -> bool:
    """Signal-preserving observation compaction. Default ON."""
    return _env_flag("REYNARD_CONTEXT_COMPACTION", True)


def kg_diff_enabled() -> bool:
    """KG-diff based incremental context injection. Default ON."""
    return _env_flag("REYNARD_CONTEXT_KG_DIFF", True)


def fewshot_enabled() -> bool:
    """Opt-in few-shot exploit transcripts. Default OFF (token-light, on demand)."""
    return _env_flag("REYNARD_FEWSHOT_EXPLOITS", False)


def observation_budget() -> int:
    """Max chars kept per compacted observation."""
    raw = os.getenv("REYNARD_CONTEXT_MAX_CHARS")
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return DEFAULT_OBSERVATION_BUDGET


# =============================================================================
# 1. Observation compaction
# =============================================================================

_HEADER_RE = re.compile(
    r"(?im)^(?:HTTP/\d(?:\.\d)?\s+\d{3}[^\r\n]*"
    r"|server:[^\r\n]+"
    r"|location:[^\r\n]+"
    r"|set-cookie:[^\r\n]+"
    r"|content-type:[^\r\n]+"
    r"|www-authenticate:[^\r\n]+"
    r"|content-security-policy:[^\r\n]+"
    r"|cache-control:[^\r\n]+"
    r"|x-[\w-]+:[^\r\n]+"
    r"|via:[^\r\n]+)$"
)

_STATUS_JSON_RE = re.compile(r'"status(?:_code)?"\s*:\s*(\d{3})')

_ERROR_RE = re.compile(
    r"(?i)("
    r"SQL syntax|SQLSTATE|Unclosed quotation|ORA-\d+|PG::|PostgreSQL|SQLite|"
    r"mysql_\w+|You have an error in your SQL|ODBC|"
    r"Traceback \(most recent call last\)|Uncaught \w+|Fatal error|"
    r"Warning:|Notice:|Parse error|Stack trace|Exception|"
    r"java\.[\w.]+Exception|at [\w.$]+\([\w.]+:\d+\)|"
    r"undefined index|nil:NilClass|panic:)"
)

_SOLVED_RE = re.compile(
    r"(?i)(congratulations|is-solved|lab solved|solved the lab|"
    r"notification-labsolved|you solved)"
)

_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
_FORM_RE = re.compile(r"(?i)<form[^>]*>")
_INPUT_NAME_RE = re.compile(r"""(?i)<(?:input|textarea|select)[^>]*\bname=["']([^"']+)["']""")
_HREF_RE = re.compile(r"""(?i)href=["']([^"'#][^"']*)["']""")
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)


def _dedupe(items: list[str], limit: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        item = item.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def _signal_footer(signals: dict | None) -> str:
    if not signals:
        return ""
    keep = {k: v for k, v in signals.items() if v not in (None, False, [], 0, "")}
    if not keep:
        return ""
    return f"\n\n[ANALYZER SIGNALS]\n{json.dumps(keep, indent=2)[:1200]}"


def _compact_text(text: str, budget: int) -> str:
    """Deterministically extract security-relevant bits from a large response."""
    if len(text) <= budget:
        return text

    sections: list[str] = []

    status = _STATUS_JSON_RE.search(text)
    if status:
        sections.append(f"[status] {status.group(1)}")

    headers = _dedupe(_HEADER_RE.findall(text), 24)
    if headers:
        sections.append("[headers]\n" + "\n".join(headers))

    title = _TITLE_RE.search(text)
    if title:
        clean = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", title.group(1))).strip()
        if clean:
            sections.append(f"[title] {clean[:200]}")

    if _SOLVED_RE.search(text):
        sections.append("[SOLVED MARKER DETECTED]")

    errors = _dedupe(
        [line.strip() for line in text.splitlines() if _ERROR_RE.search(line)],
        8,
    )
    if errors:
        sections.append("[errors]\n" + "\n".join(e[:200] for e in errors))

    forms = _FORM_RE.findall(text)
    if forms:
        sections.append("[forms]\n" + "\n".join(f[:200] for f in _dedupe(forms, 8)))

    params = _dedupe(_INPUT_NAME_RE.findall(text), 20)
    if params:
        sections.append("[input params] " + ", ".join(params))

    links = _dedupe(
        [l for l in _HREF_RE.findall(text) if not l.lower().startswith(("http", "//", "mailto:"))],
        20,
    )
    if links:
        sections.append("[links] " + ", ".join(l[:120] for l in links))

    comments = _dedupe([c.strip() for c in _COMMENT_RE.findall(text) if c.strip()], 6)
    if comments:
        sections.append("[html comments]\n" + "\n".join(c[:160] for c in comments))

    digest = "\n".join(sections)

    # Preserve a raw head + tail around the structured digest — the head usually
    # carries status/framework hints and the tail often carries banners/errors.
    remaining = max(budget - len(digest) - 120, 800)
    head_len = int(remaining * 0.6)
    tail_len = remaining - head_len
    head = text[:head_len]
    tail = text[-tail_len:] if tail_len > 0 else ""

    compacted = (
        "[COMPACTED OBSERVATION — signal-preserving digest]\n"
        f"{digest}\n\n"
        f"[raw head]\n{head}\n\n[raw tail]\n{tail}"
    )
    return compacted[:budget]


def compact_observation(
    raw: str,
    signals: dict | None = None,
    budget: int | None = None,
) -> str:
    """Compact a tool observation, preserving security-relevant signal.

    When REYNARD_CONTEXT_COMPACTION is disabled this reproduces the previous
    behavior (`raw[:budget]` plus an analyzer-signal footer).
    """
    text = raw or ""
    limit = budget if (budget and budget > 0) else observation_budget()
    if compaction_enabled():
        body = _compact_text(text, limit)
    else:
        body = text[:limit]
    return body + _signal_footer(signals)


# =============================================================================
# 2. KG-diff based incremental context
# =============================================================================

def _entity_fingerprint(entity: "Entity") -> str:
    attrs = json.dumps(entity.attrs, sort_keys=True, default=str)
    facts = json.dumps(
        {k: str(f.value) for k, f in entity.facts.items()}, sort_keys=True
    )
    return hashlib.sha256(f"{attrs}|{facts}".encode("utf-8")).hexdigest()[:16]


def _snapshot(memory: "AgentMemory") -> dict[str, Any]:
    entities = {eid: _entity_fingerprint(e) for eid, e in memory.entities.items()}
    facts = {k: str(f.value) for k, f in memory.facts.items()}
    return {
        "entities": entities,
        "facts": facts,
        "fail_count": len(memory.failed_attempts),
    }


def _render_entity_line(entity: "Entity", detailed: bool) -> str:
    heat = entity.heat_label()
    weight = f"{entity.pheromone_weight():.2f}"
    if detailed:
        attrs = ", ".join(f"{k}={str(v)[:80]}" for k, v in entity.attrs.items())
        line = f"  - {entity.id} [{heat} w={weight}]: {attrs}"
        fact_lines = [
            f"      • {fk}={f.value} ({f.confidence})"
            for fk, f in list(entity.facts.items())[:5]
        ]
        return "\n".join([line, *fact_lines]) if fact_lines else line
    label = entity.attrs.get("url") or entity.attrs.get("name") or entity.attrs.get("vuln_type") or ""
    label = str(label)[:60]
    return f"  - {entity.id} [{heat}]{(' ' + label) if label else ''}"


_TYPE_ORDER = (
    "Target", "Endpoint", "Parameter", "Technology",
    "Vulnerability", "PoC", "Credential",
)


def _stable_summary(memory: "AgentMemory") -> str:
    buckets: dict[str, list["Entity"]] = {}
    for e in memory.entities.values():
        buckets.setdefault(e.type, []).append(e)
    if not buckets:
        return "### STABLE SUMMARY\n(empty — recon has not started)"
    lines = ["### STABLE SUMMARY (unchanged entities elided)"]
    for etype in _TYPE_ORDER:
        ents = buckets.get(etype) or []
        if not ents:
            continue
        ents.sort(key=lambda e: e.pheromone_weight(), reverse=True)
        lines.append(f"\n{etype} ({len(ents)}):")
        for e in ents[:12]:
            lines.append(_render_entity_line(e, detailed=False))
        if len(ents) > 12:
            lines.append(f"  ... ({len(ents) - 12} more)")
    return "\n".join(lines)


def build_incremental_context(
    memory: "AgentMemory",
    last_snapshot: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Return (context_text, new_snapshot).

    First call (last_snapshot is None) or when the KG diff is disabled returns
    the full snapshot verbatim, so one-shot agents are unchanged. Subsequent
    calls emit a compact stable summary plus only the changes since the previous
    turn.
    """
    new_snapshot = _snapshot(memory)

    if last_snapshot is None or not kg_diff_enabled():
        full = memory.kg_snapshot() + "\n\n" + memory.failure_summary(10)
        return full, new_snapshot

    old_entities = last_snapshot.get("entities", {})
    old_facts = last_snapshot.get("facts", {})
    old_fail = int(last_snapshot.get("fail_count", 0))

    new_ids = [eid for eid in new_snapshot["entities"] if eid not in old_entities]
    changed_ids = [
        eid for eid, fp in new_snapshot["entities"].items()
        if eid in old_entities and old_entities[eid] != fp
    ]
    new_fact_keys = [
        k for k, v in new_snapshot["facts"].items()
        if k not in old_facts or old_facts[k] != v
    ]

    parts: list[str] = ["## KNOWLEDGE GRAPH (incremental)", _stable_summary(memory)]

    changes: list[str] = []
    if new_ids:
        changes.append("New entities:")
        for eid in new_ids[:20]:
            e = memory.get_entity(eid)
            if e:
                changes.append(_render_entity_line(e, detailed=True))
    if changed_ids:
        changes.append("Updated entities:")
        for eid in changed_ids[:20]:
            e = memory.get_entity(eid)
            if e:
                changes.append(_render_entity_line(e, detailed=True))
    if new_fact_keys:
        changes.append("New/updated facts:")
        for k in new_fact_keys[:20]:
            changes.append(f"  • {k}={new_snapshot['facts'][k]}")

    parts.append("\n### CHANGES SINCE LAST TURN")
    parts.append("\n".join(changes) if changes else "(no new KG changes since last turn)")

    new_failures = memory.failed_attempts[old_fail:]
    if new_failures:
        parts.append(f"\n### NEW FAILED ATTEMPTS ({len(new_failures)})")
        for f in new_failures[-10:]:
            parts.append(f"  - [{f.phase}/{f.tool}] {f.reason} -> lesson: {f.lesson}")

    return "\n".join(parts), new_snapshot


# =============================================================================
# 3. Cache-friendly prompt assembly + few-shot exploit transcripts
# =============================================================================

def assemble_prompt(stable: list[str], volatile: list[str]) -> str:
    """Join a STABLE prefix before the VOLATILE tail.

    Providers cache the longest stable request prefix (Anthropic explicitly via
    cache_control, DeepSeek/OpenAI-compatible automatically server-side). Emit
    the unchanging catalog/playbook/few-shot first so the volatile KG diff,
    attempts, and last observation don't invalidate the cache.
    """
    stable_body = "\n".join(s for s in stable if s)
    volatile_body = "\n".join(v for v in volatile if v)
    return f"{stable_body}\n{volatile_body}"


# Compact, token-light worked examples. Opt-in via REYNARD_FEWSHOT_EXPLOITS.
_FEWSHOT: dict[str, str] = {
    "sqli": (
        "SQLi (product filter): baseline GET /filter?category=Gifts -> N products; "
        "GET /filter?category=Gifts' OR 1=1-- -  -> all products incl. hidden. "
        "Proof = product count increases or 'released' filter bypassed."
    ),
    "xss": (
        "Reflected XSS: send ?search=\"><svg onload=alert(1)>; confirm the payload "
        "renders unescaped in HTML context (not entity-encoded). For DOM XSS, drive "
        "the sink via browser_execute_js and capture the alert() dialog as proof."
    ),
    "ssrf": (
        "SSRF: put an OOB domain in a URL/stockApi field: stockApi=http://<oob>/. "
        "oob_poll a DNS/HTTP hit = blind SSRF confirmed. Then pivot to "
        "http://169.254.169.254/latest/meta-data/ or internal 127.0.0.1 admin."
    ),
    "idor": (
        "IDOR/authz: capture_baseline as user1 on GET /api/orders/1001, then "
        "diff_against_baseline with user2's session. Same object content across "
        "identities (or 200 vs expected 403) = broken object-level authorization."
    ),
    "ssti": (
        "SSTI: inject {{7*7}} / ${7*7} / #{7*7} into template-reflected fields "
        "(email name, error page). Rendered 49 = engine confirmed; escalate to "
        "{{ ''.__class__... }} (Jinja) or config/self exposure for RCE."
    ),
    "xxe": (
        "XXE: replace an XML body with an external entity referencing an OOB or "
        "file:// resource: <!DOCTYPE r [<!ENTITY x SYSTEM \"http://<oob>/\">]>. "
        "OOB hit or file contents reflected = XXE confirmed."
    ),
}

_FEWSHOT_KEYWORDS: list[tuple[tuple[str, ...], str]] = [
    (("sql", "sqli"), "sqli"),
    (("cross-site scripting", "xss"), "xss"),
    (("ssrf", "server-side request"), "ssrf"),
    (("idor", "authorization", "authz", "access control", "broken object"), "idor"),
    (("ssti", "template injection"), "ssti"),
    (("xxe", "xml external"), "xxe"),
]


def fewshot_for_vuln(vuln_type: str | None) -> str:
    """Return a compact worked example for a vuln class, or '' when disabled.

    Opt-in via REYNARD_FEWSHOT_EXPLOITS so cheap models can be steered on hard
    classes without paying the token cost on every run.
    """
    if not vuln_type or not fewshot_enabled():
        return ""
    needle = vuln_type.lower()
    key: str | None = None
    if needle in _FEWSHOT:
        key = needle
    else:
        for keywords, mapped in _FEWSHOT_KEYWORDS:
            if any(kw in needle for kw in keywords):
                key = mapped
                break
    if not key:
        return ""
    return f"# FEW-SHOT EXAMPLE ({key})\n{_FEWSHOT[key]}\n"
