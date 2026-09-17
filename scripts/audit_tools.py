"""Offline registry/reference inventory; never executes a registered tool.

Static references show maintenance evidence, not runtime reachability or code
coverage. Tools can be selected dynamically by the model, so an absent static
reference (or an unobserved tool in one run) is not evidence that it is dead.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, get_args

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))


def registry_alignment(
    functions: Mapping[str, Any], schemas: Iterable[Any], tool_names: Iterable[str],
) -> dict[str, Any]:
    """Compare names, duplicates, and callability; equal counts are insufficient."""
    schema_names: list[str] = []
    malformed: list[int] = []
    for index, schema in enumerate(schemas):
        function = schema.get("function") if isinstance(schema, Mapping) else None
        name = function.get("name") if isinstance(function, Mapping) else None
        if not isinstance(name, str) or not name:
            malformed.append(index)
        else:
            schema_names.append(name)
    names = set(functions)
    declared = set(tool_names)
    described = set(schema_names)
    errors = {
        "schemas_missing_functions": sorted(described - names),
        "functions_missing_schemas": sorted(names - described),
        "typed_names_missing_functions": sorted(declared - names),
        "functions_missing_typed_names": sorted(names - declared),
        "duplicate_schema_names": sorted(
            name for name, count in Counter(schema_names).items() if count > 1
        ),
        "noncallable_functions": sorted(name for name, fn in functions.items() if not callable(fn)),
        "malformed_schema_indexes": malformed,
    }
    return {
        "ok": not any(errors.values()),
        "function_count": len(names),
        "schema_count": len(schema_names),
        "typed_name_count": len(declared),
        **errors,
    }


def static_references(
    root: Path, names: Iterable[str],
) -> tuple[dict[str, dict[str, list[dict[str, Any]]]], list[str]]:
    """Find exact tool-name tokens/symbols in Python, excluding declaration files.

    A symbol can be unrelated and strings can be prompts/mocks. Neither is a
    proven call. Comments, Markdown, dynamically constructed names and aliases
    are intentionally outside this heuristic.
    """
    registered = set(names)
    references: dict[str, dict[str, list[dict[str, Any]]]] = {
        name: {"source": [], "tests": []} for name in sorted(registered)
    }
    skipped: list[str] = []
    excluded = {
        "src/hacking_agent/core/tools.py",
        "src/hacking_agent/core/schemas.py",
    }
    for directory, category in (("src", "source"), ("tests", "tests")):
        for path in sorted((root / directory).rglob("*.py")):
            relative = path.relative_to(root).as_posix()
            if relative in excluded:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=relative)
            except (OSError, UnicodeError, SyntaxError):
                skipped.append(relative)
                continue
            found: dict[str, set[int]] = {}
            for node in ast.walk(tree):
                tokens: set[str] = set()
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    tokens = set(re.findall(r"[A-Za-z_][A-Za-z_0-9]*", node.value))
                elif isinstance(node, ast.Name):
                    tokens = {node.id}
                elif isinstance(node, ast.Attribute):
                    tokens = {node.attr}
                for name in tokens & registered:
                    found.setdefault(name, set()).add(getattr(node, "lineno", 0))
            for name, lines in found.items():
                references[name][category].append({"file": relative, "lines": sorted(lines)})
    return references, skipped


def observed_usage(paths: Iterable[Path], names: Iterable[str]) -> dict[str, Any]:
    """Count runtime EventBus JSONL tool_result records without copying payloads.

    Results include failed tool calls. Duplicate files are read only once, but
    overlapping event streams cannot be deduplicated safely (event IDs restart
    across processes), so each supplied file should represent a distinct run.
    """
    registered = set(names)
    counts: Counter[str] = Counter()
    unknown: Counter[str] = Counter()
    malformed = 0
    ignored = 0
    inputs = sorted({path.resolve() for path in paths})
    for path in inputs:
        with path.open(encoding="utf-8-sig") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    malformed += 1
                    continue
                if not isinstance(event, dict):
                    malformed += 1
                    continue
                if event.get("type") != "tool_result":
                    ignored += 1
                    continue
                payload = event.get("payload")
                name = payload.get("tool") if isinstance(payload, dict) else None
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,79}", name):
                    malformed += 1
                    continue
                if name in registered:
                    counts[name] += 1
                else:
                    unknown[name] += 1
    return {
        "files_analyzed": len(inputs),
        "registered_tool_results": sum(counts.values()),
        "counts": dict(sorted(counts.items())),
        "unknown_tool_counts": dict(sorted(unknown.items())),
        "malformed_records": malformed,
        "ignored_non_tool_records": ignored,
        "observed_registered_tools": len(counts),
        "registered_tool_count": len(registered),
        "observed_tool_fraction": len(counts) / len(registered) if inputs and registered else None,
    }


def build_inventory(root: Path = ROOT, event_paths: Iterable[Path] = ()) -> dict[str, Any]:
    from hacking_agent.core.schemas import ToolName
    from hacking_agent.core.tools import TOOL_FUNCTIONS, TOOL_SCHEMAS

    alignment = registry_alignment(TOOL_FUNCTIONS, TOOL_SCHEMAS, get_args(ToolName))
    references, skipped = static_references(root, TOOL_FUNCTIONS)
    usage = observed_usage(event_paths, TOOL_FUNCTIONS)
    tools = []
    for name in sorted(TOOL_FUNCTIONS):
        reference = references[name]
        tools.append({
            "name": name,
            "static_source_references": reference["source"],
            "static_test_references": reference["tests"],
            "observed_tool_results": usage["counts"].get(name, 0) if usage["files_analyzed"] else None,
        })
    return {
        "schema_version": 1,
        "measurement": "offline_tool_registry_and_reference_inventory",
        "limitations": [
            "Static references are name-token/symbol matches, not proven calls or executed test coverage.",
            "Registry declarations are excluded; dynamic dispatch, aliases, comments and docs are not analyzed.",
            "A tool without static references or observed results is not proven unused; do not remove it on this basis.",
            "Runtime tool_result events include failures and measure only the supplied distinct run files.",
            "No tool implementations, external binaries, containers or targets were executed.",
        ],
        "alignment": alignment,
        "static_summary": {
            "tools_with_source_references": sum(bool(ref["source"]) for ref in references.values()),
            "tools_with_test_references": sum(bool(ref["tests"]) for ref in references.values()),
            "no_static_source_references": [name for name, ref in references.items() if not ref["source"]],
            "no_static_test_references": [name for name, ref in references.items() if not ref["tests"]],
            "unparsed_python_files": skipped,
        },
        "observed_usage": usage,
        "tools": tools,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, action="append", default=[],
                        help="Optional EventBus events.jsonl from one distinct run; repeat for other runs.")
    parser.add_argument("--check", action="store_true",
                        help="Exit 1 on registry drift, unparsed source, or malformed supplied event records.")
    args = parser.parse_args(argv)
    try:
        report = build_inventory(event_paths=args.events)
    except (OSError, UnicodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    clean = (
        report["alignment"]["ok"]
        and not report["static_summary"]["unparsed_python_files"]
        and not report["observed_usage"]["malformed_records"]
    )
    return 0 if not args.check or clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
