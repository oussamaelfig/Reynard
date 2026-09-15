"""Load the operator .env into the harness server and per-run workers.

Windows users typically keep DEEPSEEK_API_KEY only in the repo ``.env``.
``load_dotenv`` does not override an *empty* already-set variable, so a blank
``DEEPSEEK_API_KEY=`` in the system environment would hide the real key. This
helper fills any blank LLM/harness keys from ``.env`` without clobbering a
real value already in the process environment.
"""
from __future__ import annotations

import os
from pathlib import Path

_LLM_KEY_ENVS = (
    "LLM_DEFAULT_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
)

_FILL_IF_BLANK = _LLM_KEY_ENVS + (
    "LLM_DEFAULT_PROVIDER",
    "LLM_DEFAULT_MODEL",
    "LLM_DEFAULT_BASE_URL",
    "LLM_PROVIDER",
    "MODEL_NAME",
    "API_BASE_URL",
    "REYNARD_HARNESS_TOKEN",
    "REYNARD_HOST_EXEC",
)


def env_candidates() -> list[Path]:
    from hacking_agent.core.paths import ENV_FILE
    out: list[Path] = []
    for p in (ENV_FILE, Path.cwd() / ".env"):
        try:
            rp = p.resolve()
        except Exception:
            continue
        if rp.is_file() and rp not in out:
            out.append(rp)
    return out


def load_operator_env() -> Path | None:
    """Load ``.env`` (repo root, then cwd). Returns the file used, if any."""
    try:
        from dotenv import dotenv_values, load_dotenv
    except Exception:
        return None
    loaded: Path | None = None
    for path in env_candidates():
        load_dotenv(path, override=False)
        vals = dotenv_values(path) or {}
        for key in _FILL_IF_BLANK:
            current = (os.getenv(key) or "").strip()
            file_val = str(vals.get(key) or "").strip()
            if not current and file_val:
                os.environ[key] = file_val
        loaded = path
    return loaded


def llm_key_present() -> bool:
    return any((os.getenv(k) or "").strip() for k in _LLM_KEY_ENVS)


def missing_llm_key_error() -> str:
    searched = ", ".join(str(p) for p in env_candidates()) or "(no .env found)"
    return (
        "No LLM API key reached the run worker. Put DEEPSEEK_API_KEY or "
        "LLM_DEFAULT_API_KEY in the repo .env and restart the harness. "
        f"Looked in: {searched}"
    )
