"""Compatibility launcher for the single-agent CLI.

The implementation lives in ``src/hacking_agent/cli/agent.py``.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from hacking_agent.cli.agent import main


if __name__ == "__main__":
    main()
