"""Filesystem paths for the source-layout project."""
from __future__ import annotations

from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PACKAGE_ROOT.parent
PROJECT_ROOT = SRC_ROOT.parent

ENV_FILE = PROJECT_ROOT / ".env"
LOG_DIR = PROJECT_ROOT / "logs"
METHODOLOGIES_DIR = PROJECT_ROOT / "methodologies"


def ensure_runtime_dirs() -> None:
    """Create runtime directories that should exist during normal execution."""
    LOG_DIR.mkdir(exist_ok=True)
