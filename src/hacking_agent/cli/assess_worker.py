"""Internal subprocess entry point for a single isolated assessment target."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from hacking_agent.cli.assess import _run_target_worker


def main() -> None:
    result_path = Path(sys.argv[1])
    try:
        result = _run_target_worker(json.load(sys.stdin))
    except Exception as exc:
        result = {"verdict": f"error: {type(exc).__name__}: {str(exc)[:200]}", "findings": []}
    result_path.write_text(json.dumps(result), encoding="utf-8")


if __name__ == "__main__":
    main()
