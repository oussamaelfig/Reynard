"""
=============================================================================
Reynard — Living PortSwigger coverage matrix generator
=============================================================================
Builds/refreshes `docs/portswigger-coverage-matrix.md` from three sources:

  1. The authoritative lab corpus (all classes + per-level lab counts).
  2. Static capability signals: does a methodology md exist for the class? is
     there a deterministic fast-path? a reusable client-side primitive?
  3. The latest training/eval scorecard JSON (per-class solve-rate), if present.

This is the 0-to-100 ruler: every class is a row, and the columns show how
much scaffolding + measured solve-rate exists behind it. It is regenerated as
part of the training loop, but can also be refreshed on demand:

    python -m hacking_agent.core.lab_corpus --generate-matrix
=============================================================================
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from hacking_agent.core import lab_corpus
from hacking_agent.core.paths import LOG_DIR, METHODOLOGIES_DIR, PROJECT_ROOT

DEFAULT_MATRIX_PATH = PROJECT_ROOT / "docs" / "portswigger-coverage-matrix.md"

# Playbooks with a deterministic fast-path in agents/exploitation.py.
FAST_PATH_PLAYBOOKS: set[str] = {
    "sqli",
    "request_smuggling",
    "csrf",
    "clickjacking",
    "access_control_idor",
}

# Playbooks with a reusable client-side delivery primitive in
# core/exploit_primitives.py.
PRIMITIVE_PLAYBOOKS: set[str] = {
    "xss",
    "dom_xss",
    "dom_based",
    "csrf",
    "clickjacking",
    "cors",
}

# playbook_id -> candidate methodology markdown stems under methodologies/.
METHODOLOGY_STEMS: dict[str, list[str]] = {
    "sqli": ["sqli", "blind"],
    "xss": ["xss_advanced"],
    "dom_xss": ["xss_advanced"],
    "dom_based": ["xss_advanced"],
    "csrf": ["csrf"],
    "clickjacking": ["clickjacking"],
    "cors": ["cors"],
    "xxe": ["xxe"],
    "ssrf": ["ssrf"],
    "request_smuggling": ["request_smuggling"],
    "os_command_injection": ["command_injection"],
    "ssti": ["ssti"],
    "path_traversal": ["path_traversal"],
    "access_control_idor": ["idor_authz"],
    "authentication": ["authentication"],
    "websocket": ["websockets"],
    "web_cache_poisoning": ["cache_poisoning"],
    "deserialization": ["deserialization"],
    "information_disclosure": ["information_disclosure"],
    "business_logic": ["business_logic"],
    "host_header": ["host_header"],
    "oauth": ["oauth"],
    "file_upload": ["file_upload"],
    "jwt": ["jwt"],
    "prototype_pollution": ["prototype_pollution"],
    "graphql_api": ["graphql"],
    "race_condition": ["race_conditions"],
    "nosql_injection": ["nosqli"],
    "web_llm_attacks": ["web_llm"],
    "web_cache_deception": ["web_cache_deception"],
}


def _methodology_exists(playbook_id: str, methodologies_dir: Path) -> bool:
    stems = METHODOLOGY_STEMS.get(playbook_id, [])
    for stem in stems:
        if (methodologies_dir / f"{stem}.md").exists():
            return True
    return False


def latest_scorecard(log_dir: Path | None = None) -> dict[str, Any] | None:
    """Return the newest training/live scorecard payload, if any.

    Prefers a stable ``training_scorecard_latest.json`` written by the training
    loop, then falls back to the newest timestamped scorecard file.
    """
    log_dir = log_dir or LOG_DIR
    if not log_dir.exists():
        return None
    stable = log_dir / "training_scorecard_latest.json"
    candidates: list[Path] = []
    if stable.exists():
        candidates.append(stable)
    candidates.extend(sorted(log_dir.glob("training_scorecard_*.json"), reverse=True))
    candidates.extend(sorted(log_dir.glob("live_scorecard_*.json"), reverse=True))
    for path in candidates:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
    return None


def _class_solve_rate(
    scorecard: dict[str, Any] | None, class_slug: str, playbook_id: str
) -> str:
    """Render a per-class solve-rate cell from a scorecard's by_class block."""
    if not scorecard:
        return "—"
    by_class = scorecard.get("by_class") or {}
    if not isinstance(by_class, dict):
        return "—"
    row = by_class.get(playbook_id) or by_class.get(class_slug)
    if not isinstance(row, dict):
        return "—"
    run = int(row.get("run", 0) or 0)
    solved = int(row.get("solved", 0) or 0)
    if run <= 0:
        return "not-run"
    rate = row.get("solve_rate")
    if rate is None:
        rate = solved / run if run else 0.0
    return f"{solved}/{run} ({float(rate) * 100:.0f}%)"


def _yesno(flag: bool) -> str:
    return "yes" if flag else "no"


def generate_coverage_matrix(
    out_path: str | Path | None = None,
    corpus_path: str | Path | None = None,
    scorecard: dict[str, Any] | None = None,
    methodologies_dir: Path | None = None,
    log_dir: Path | None = None,
) -> Path:
    """Build/refresh the living coverage matrix markdown document."""
    entries = lab_corpus.load_corpus(corpus_path)
    corpus_stats = lab_corpus.stats(entries)
    methodologies_dir = methodologies_dir or METHODOLOGIES_DIR
    if scorecard is None:
        scorecard = latest_scorecard(log_dir)

    out = Path(out_path) if out_path else DEFAULT_MATRIX_PATH
    out.parent.mkdir(parents=True, exist_ok=True)

    classes = corpus_stats["classes"]
    # Order classes by lab volume (wave prioritization), then name.
    ordered = sorted(
        classes.items(), key=lambda kv: (-kv[1]["total"], kv[0])
    )

    generated_at = datetime.utcnow().isoformat()
    sc_note = "no scorecard found yet" if not scorecard else (
        f"scorecard generated {scorecard.get('generated_at', 'unknown')}"
    )

    lines: list[str] = [
        "# PortSwigger Expert Coverage Matrix",
        "",
        "> Auto-generated by `hacking_agent.core.coverage`. Do not hand-edit; "
        "regenerate via `python -m hacking_agent.core.lab_corpus --generate-matrix` "
        "or the training loop.",
        "",
        f"- Generated: {generated_at}",
        f"- Corpus labs: {corpus_stats['total']} across {corpus_stats['class_count']} classes",
        "- Level totals: " + ", ".join(
            f"{level}={corpus_stats['levels'].get(level, 0)}"
            for level in lab_corpus.LEVELS
        ),
        f"- Solve-rate source: {sc_note}",
        "",
        "Columns: **Labs (A/P/E)** = apprentice/practitioner/expert lab counts; "
        "**Methodology** = RAG markdown exists; **Fast-path** = deterministic "
        "solver; **Primitive** = reusable client-side delivery builder; "
        "**Last solve-rate** = most recent eval-passed measure.",
        "",
        "| Class | Playbook | Labs (A/P/E) | Methodology | Fast-path | Primitive | Last solve-rate |",
        "| --- | --- | :---: | :---: | :---: | :---: | :---: |",
    ]

    for class_slug, row in ordered:
        playbook_id = row.get("playbook_id") or lab_corpus.class_to_playbook(class_slug)
        counts = "{}/{}/{}".format(
            row.get(lab_corpus.LEVEL_APPRENTICE, 0),
            row.get(lab_corpus.LEVEL_PRACTITIONER, 0),
            row.get(lab_corpus.LEVEL_EXPERT, 0),
        )
        methodology = _methodology_exists(playbook_id, methodologies_dir)
        fast_path = playbook_id in FAST_PATH_PLAYBOOKS
        primitive = playbook_id in PRIMITIVE_PLAYBOOKS
        solve_rate = _class_solve_rate(scorecard, class_slug, playbook_id)
        lines.append(
            "| {cls} | `{pb}` | {counts} | {meth} | {fp} | {prim} | {sr} |".format(
                cls=class_slug,
                pb=playbook_id or "n/a",
                counts=counts,
                meth=_yesno(methodology),
                fp=_yesno(fast_path),
                prim=_yesno(primitive),
                sr=solve_rate,
            )
        )

    if scorecard and isinstance(scorecard.get("summary"), dict):
        summary = scorecard["summary"]
        lines.extend([
            "",
            "## Latest eval summary",
            "",
            f"- Labs run: {summary.get('run', summary.get('labs', 0))}",
            f"- Solved: {summary.get('solved', 0)}",
            f"- Overall solve-rate: {float(summary.get('solve_rate', 0.0)) * 100:.1f}%",
        ])
        skipped = summary.get("skipped")
        if skipped is not None:
            lines.append(f"- Skipped (placeholder targets / not-run): {skipped}")

    lines.extend([
        "",
        "## Implementation notes",
        "",
        "- The class list, level counts, and routing are derived from "
        "`eval/portswigger_labs.json` via `core.lab_corpus` (keyed by canonical "
        "URL path). New labs are picked up automatically.",
        "- Fast-paths live in `src/hacking_agent/agents/exploitation.py`; "
        "client-side primitives in `src/hacking_agent/core/exploit_primitives.py`.",
        "- Solve-rates come from the newest scorecard under `logs/` "
        "(`training_scorecard_*.json` / `live_scorecard_*.json`).",
        "",
    ])

    out.write_text("\n".join(lines), encoding="utf-8")
    return out


if __name__ == "__main__":
    print(generate_coverage_matrix())
