"""Internal subprocess entry point for a single isolated assessment target."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from hacking_agent.cli.assess import _run_target_worker


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m hacking_agent.cli.assess_worker <result_path>", file=sys.stderr)
        return 2
    result_path = Path(args[0])
    try:
        config = json.load(sys.stdin)
        if not isinstance(config, dict):
            raise ValueError("worker configuration must be an object")
        result = _run_target_worker(config)
    except Exception as exc:
        # Exception messages can include credentials from worker input.
        result = {"verdict": f"error: target worker failed ({type(exc).__name__})", "findings": []}
    result_path.write_text(json.dumps(result), encoding="utf-8")
    return int(str(result.get("verdict", "")).startswith("error:"))


if __name__ == "__main__":
    raise SystemExit(main())
