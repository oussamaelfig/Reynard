"""
=============================================================================
Reynard — PortSwigger lab corpus (authoritative dataset)
=============================================================================
The reference dataset (`eval/portswigger_labs.json`) is the single source of
truth for the coverage matrix, profiler routing, and the batch eval config.
Each entry carries `level`, `title`, canonical `url`, `description`, and
optional `credentials`. The canonical `url` path encodes the vuln class and
sub-variant (e.g. `.../web-security/sql-injection/union-attacks/lab-...`), so
new labs are picked up automatically instead of being hand-maintained.

Apprentice labs are not in the practitioner/expert JSON; additional entries
(any shape matching the same keys) are supported so the corpus can grow.

Nothing here makes a network call. The `url` is documentation, not a runnable
instance — the live instance URL is supplied per run via the eval config.
=============================================================================
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hacking_agent.core.paths import PROJECT_ROOT

# Authoritative corpus + generated-artifact locations.
DEFAULT_CORPUS_PATH = PROJECT_ROOT / "eval" / "portswigger_labs.json"
DEFAULT_EVAL_CONFIG_PATH = PROJECT_ROOT / "eval" / "labs.generated.yaml"

# Placeholder used for the live-instance target in the generated eval config.
# The training loop treats labs whose target is still a placeholder as
# "not-run" rather than as failures.
TARGET_PLACEHOLDER = "TODO_LIVE_INSTANCE_URL"

LEVEL_APPRENTICE = "APPRENTICE"
LEVEL_PRACTITIONER = "PRACTITIONER"
LEVEL_EXPERT = "EXPERT"
LEVELS = (LEVEL_APPRENTICE, LEVEL_PRACTITIONER, LEVEL_EXPERT)

# Canonical PortSwigger URL class-slug -> internal playbook_id / vuln_type
# (keys in core.expert_playbooks.EXPERT_PLAYBOOKS). This is the routing map:
# classify_url() yields the slug, this maps it to the deterministic playbook.
CLASS_TO_PLAYBOOK: dict[str, str] = {
    "sql-injection": "sqli",
    "cross-site-scripting": "xss",
    "csrf": "csrf",
    "clickjacking": "clickjacking",
    "dom-based": "dom_based",
    "cors": "cors",
    "xxe": "xxe",
    "ssrf": "ssrf",
    "request-smuggling": "request_smuggling",
    "os-command-injection": "os_command_injection",
    "server-side-template-injection": "ssti",
    "file-path-traversal": "path_traversal",
    "access-control": "access_control_idor",
    "authentication": "authentication",
    "websockets": "websocket",
    "web-cache-poisoning": "web_cache_poisoning",
    "deserialization": "deserialization",
    "information-disclosure": "information_disclosure",
    "logic-flaws": "business_logic",
    "host-header": "host_header",
    "oauth": "oauth",
    "file-upload": "file_upload",
    "jwt": "jwt",
    "essential-skills": "essential_skills",
    "prototype-pollution": "prototype_pollution",
    "graphql": "graphql_api",
    "race-conditions": "race_condition",
    "nosql-injection": "nosql_injection",
    "api-testing": "api_testing",
    "llm-attacks": "web_llm_attacks",
    "web-cache-deception": "web_cache_deception",
}


@dataclass
class LabEntry:
    """One PortSwigger lab, enriched with derived routing metadata."""

    level: str
    title: str
    url: str
    description: str = ""
    credentials: list[dict[str, str]] = field(default_factory=list)
    vuln_class: str = ""
    subvariant: str = ""
    playbook_id: str = ""
    vuln_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify_url(url: str) -> tuple[str, str]:
    """Derive ``(vuln_class, subvariant)`` from a canonical PortSwigger URL.

    Examples::

        classify_url(".../web-security/sql-injection/union-attacks/lab-x")
            -> ("sql-injection", "union-attacks")
        classify_url(".../web-security/web-cache-deception/lab-x")
            -> ("web-cache-deception", "")

    The class is the segment immediately after ``web-security``; the
    sub-variant is the following segment unless it is already the ``lab-*``
    slug. Returns ``("", "")`` when the path cannot be parsed.
    """
    try:
        path = urlparse(url or "").path
    except (ValueError, TypeError):
        return "", ""
    parts = [p for p in path.strip("/").split("/") if p]
    if "web-security" in parts:
        parts = parts[parts.index("web-security") + 1:]
    if not parts:
        return "", ""
    vuln_class = parts[0]
    subvariant = ""
    if len(parts) >= 2 and not parts[1].startswith("lab"):
        subvariant = parts[1]
    return vuln_class, subvariant


def class_to_playbook(vuln_class: str) -> str:
    """Map a canonical class slug to its internal playbook_id (or "")."""
    return CLASS_TO_PLAYBOOK.get((vuln_class or "").strip().lower(), "")


def normalize_lab_level(value: Any) -> str:
    """Normalize a free-form level into APPRENTICE / PRACTITIONER / EXPERT."""
    text = str(value or "").strip().upper()
    if text in LEVELS:
        return text
    if text.startswith("APP"):
        return LEVEL_APPRENTICE
    if text.startswith("PRAC"):
        return LEVEL_PRACTITIONER
    if text.startswith("EXP"):
        return LEVEL_EXPERT
    return ""


def is_placeholder_target(target: str) -> bool:
    """True when a lab target is still an unfilled live-instance placeholder."""
    token = (target or "").strip()
    if not token:
        return True
    upper = token.upper()
    if TARGET_PLACEHOLDER.upper() in upper:
        return True
    if "TODO" in upper or "XXXX" in upper or "YYYY" in upper or "ZZZZ" in upper:
        return True
    return False


def parse_credentials(raw: Any) -> list[dict[str, str]]:
    """Parse a corpus credentials value into structured ``{username, password}``.

    The dataset stores credentials as ``None`` or a string such as
    ``"wiener:peter"`` or ``"administrator:admin, wiener:peter"``. Structured
    lists (from added apprentice entries) are passed through.
    """
    if not raw:
        return []
    if isinstance(raw, list):
        out: list[dict[str, str]] = []
        for item in raw:
            if isinstance(item, dict) and item.get("username"):
                out.append({
                    "username": str(item.get("username", "")).strip(),
                    "password": str(item.get("password", "")).strip(),
                })
            elif isinstance(item, str):
                out.extend(parse_credentials(item))
        return out
    creds: list[dict[str, str]] = []
    for pair in str(raw).split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        username, _, password = pair.partition(":")
        username = username.strip()
        if username:
            creds.append({"username": username, "password": password.strip()})
    return creds


def _entry_from_dict(item: dict[str, Any]) -> LabEntry:
    url = str(item.get("url", "") or "")
    vuln_class, subvariant = classify_url(url)
    playbook_id = class_to_playbook(vuln_class)
    level = normalize_lab_level(item.get("level")) or LEVEL_PRACTITIONER
    return LabEntry(
        level=level,
        title=str(item.get("title", "") or ""),
        url=url,
        description=str(item.get("description", "") or ""),
        credentials=parse_credentials(item.get("credentials")),
        vuln_class=vuln_class,
        subvariant=subvariant,
        playbook_id=playbook_id,
        vuln_type=playbook_id or vuln_class,
    )


def load_corpus(path: str | Path | None = None) -> list[LabEntry]:
    """Load the lab corpus JSON into enriched ``LabEntry`` records.

    Returns an empty list if the corpus file is missing so callers degrade
    gracefully (e.g. offline tests without the dataset present).
    """
    corpus_path = Path(path) if path else DEFAULT_CORPUS_PATH
    if not corpus_path.exists():
        return []
    raw = json.loads(corpus_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("labs") or raw.get("cases") or []
    if not isinstance(raw, list):
        return []
    return [_entry_from_dict(item) for item in raw if isinstance(item, dict)]


def by_class(entries: list[LabEntry] | None = None) -> dict[str, list[LabEntry]]:
    """Group entries by canonical class slug (URL-derived)."""
    entries = entries if entries is not None else load_corpus()
    out: dict[str, list[LabEntry]] = {}
    for entry in entries:
        out.setdefault(entry.vuln_class or "unknown", []).append(entry)
    return out


def by_level(entries: list[LabEntry] | None = None) -> dict[str, list[LabEntry]]:
    """Group entries by difficulty level."""
    entries = entries if entries is not None else load_corpus()
    out: dict[str, list[LabEntry]] = {}
    for entry in entries:
        out.setdefault(entry.level or LEVEL_PRACTITIONER, []).append(entry)
    return out


def stats(entries: list[LabEntry] | None = None) -> dict[str, Any]:
    """Summarize the corpus: totals, per-class and per-level breakdowns."""
    entries = entries if entries is not None else load_corpus()
    classes: dict[str, dict[str, Any]] = {}
    levels: dict[str, int] = {level: 0 for level in LEVELS}
    for entry in entries:
        slug = entry.vuln_class or "unknown"
        row = classes.setdefault(slug, {
            "total": 0,
            "playbook_id": entry.playbook_id,
            LEVEL_APPRENTICE: 0,
            LEVEL_PRACTITIONER: 0,
            LEVEL_EXPERT: 0,
        })
        row["total"] += 1
        if entry.level in row:
            row[entry.level] += 1
        levels[entry.level] = levels.get(entry.level, 0) + 1
    return {
        "total": len(entries),
        "class_count": len(classes),
        "classes": classes,
        "levels": levels,
    }


def _yaml_scalar(value: Any) -> str:
    """Return a YAML-safe flow scalar (JSON encoding is valid YAML)."""
    return json.dumps("" if value is None else str(value), ensure_ascii=False)


def generate_eval_config(
    out_path: str | Path | None = None,
    corpus_path: str | Path | None = None,
) -> Path:
    """Generate ``eval/labs.generated.yaml`` — one entry per corpus lab.

    Targets are left as ``TARGET_PLACEHOLDER`` (fill with the live instance
    URL), the objective is seeded from the lab description, ``expected_vuln``
    from the derived playbook, plus ``level``/``lab_url`` metadata. Credentials
    use ``${ENV}`` placeholders so no secret is ever written to disk.
    """
    entries = load_corpus(corpus_path)
    out = Path(out_path) if out_path else DEFAULT_EVAL_CONFIG_PATH
    out.parent.mkdir(parents=True, exist_ok=True)

    header = [
        "# =============================================================================",
        "# Reynard — Generated live/training eval config (auto-generated)",
        "# =============================================================================",
        "# Source of truth: eval/portswigger_labs.json (do not hand-edit this file;",
        "# regenerate via: python -m hacking_agent.core.lab_corpus --generate-eval).",
        "#",
        "# Fill each `target` with the live PortSwigger lab instance URL before a run;",
        f"# labs left as {TARGET_PLACEHOLDER!r} are counted as 'not-run' (skipped).",
        "# Credentials use ${ENV} placeholders, e.g. export PORTSWIGGER_PASSWORD=peter",
        "# =============================================================================",
        "",
        f"labs:  # {len(entries)} labs",
    ]
    lines = list(header)
    for entry in entries:
        lines.append(f"  - name: {_yaml_scalar(entry.title)}")
        lines.append(f"    target: {_yaml_scalar(TARGET_PLACEHOLDER)}")
        lines.append(f"    objective: {_yaml_scalar(entry.description or entry.title)}")
        lines.append(f"    expected_vuln: {_yaml_scalar(entry.playbook_id or entry.vuln_class)}")
        lines.append(f"    level: {_yaml_scalar(entry.level)}")
        lines.append(f"    lab_url: {_yaml_scalar(entry.url)}")
        if entry.subvariant:
            lines.append(f"    subvariant: {_yaml_scalar(entry.subvariant)}")
        if entry.credentials:
            raw = ", ".join(
                f"{c['username']}:{c['password']}" for c in entry.credentials
            )
            lines.append(f"    # corpus credentials: {raw}")
            first = entry.credentials[0]
            lines.append("    creds:")
            lines.append(f"      username: {_yaml_scalar(first['username'])}")
            lines.append('      password: "${PORTSWIGGER_PASSWORD}"')
        lines.append("")

    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reynard-lab-corpus",
        description=(
            "Inspect and generate artifacts from the PortSwigger lab corpus."
        ),
    )
    parser.add_argument("--corpus", help="Path to the corpus JSON (default: eval/portswigger_labs.json).")
    parser.add_argument("--generate-eval", action="store_true", help="Write eval/labs.generated.yaml.")
    parser.add_argument("--eval-out", help="Override output path for the generated eval config.")
    parser.add_argument("--generate-matrix", action="store_true", help="Refresh docs/portswigger-coverage-matrix.md.")
    parser.add_argument("--matrix-out", help="Override output path for the coverage matrix.")
    parser.add_argument("--stats", action="store_true", help="Print corpus statistics as JSON.")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _build_arg_parser().parse_args(argv)
    did_something = False
    if args.stats:
        print(json.dumps(stats(load_corpus(args.corpus)), indent=2))
        did_something = True
    if args.generate_eval:
        path = generate_eval_config(args.eval_out, args.corpus)
        print(f"eval config written: {path}")
        did_something = True
    if args.generate_matrix:
        from hacking_agent.core.coverage import generate_coverage_matrix

        path = generate_coverage_matrix(
            out_path=args.matrix_out, corpus_path=args.corpus
        )
        print(f"coverage matrix written: {path}")
        did_something = True
    if not did_something:
        print(json.dumps(stats(load_corpus(args.corpus)), indent=2))


if __name__ == "__main__":
    main()
