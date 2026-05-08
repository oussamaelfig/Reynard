"""Compatibility launcher for the multi-agent orchestrator CLI.

The implementation lives in ``src/hacking_agent/cli/orchestrator.py``.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from hacking_agent.cli.orchestrator import main


if __name__ == "__main__":
    main()
