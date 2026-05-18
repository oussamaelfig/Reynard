from __future__ import annotations

import os
import sys
from importlib import metadata
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

load_dotenv(ROOT / ".env")

from hacking_agent.core.providers import ProviderRegistry  # noqa: E402


def package_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "not installed"


def env_value(name: str) -> str:
    value = os.getenv(name)
    if value is None:
        return "<unset>"
    if "KEY" in name or "TOKEN" in name or "PAT" in name:
        return "<set>" if value else "<empty>"
    return value


def main() -> None:
    expected_venv = ROOT / "venv"
    in_venv = sys.prefix != sys.base_prefix
    using_project_venv = Path(sys.prefix).resolve() == expected_venv.resolve()

    print("Runtime")
    print(f"  python_executable: {sys.executable}")
    print(f"  python_version: {sys.version.split()[0]}")
    print(f"  in_virtualenv: {in_venv}")
    print(f"  project_venv: {expected_venv}")
    print(f"  using_project_venv: {using_project_venv}")
    print()

    print("Packages")
    for name in ("openai", "python-dotenv", "pydantic", "rich", "httpx"):
        print(f"  {name}: {package_version(name)}")
    print()

    print("Environment")
    for name in (
        "LLM_DEFAULT_PROVIDER",
        "LLM_DEFAULT_MODEL",
        "LLM_DEFAULT_BASE_URL",
        "LLM_DEFAULT_API_KEY",
        "OPENAI_API_KEY",
        "MODEL_NAME",
        "API_BASE_URL",
        "LLM_DEFAULT_REASONING_EFFORT",
        "LLM_COORDINATOR_REASONING_EFFORT",
        "LLM_RECON_REASONING_EFFORT",
        "LLM_ANALYST_REASONING_EFFORT",
        "LLM_EXPLOITATION_REASONING_EFFORT",
        "LLM_REPORTER_REASONING_EFFORT",
        "LLM_VALIDATOR_REASONING_EFFORT",
        "LLM_PIVOT_REASONING_EFFORT",
    ):
        print(f"  {name}: {env_value(name)}")
    print()

    print(ProviderRegistry.from_env().describe())


if __name__ == "__main__":
    main()
