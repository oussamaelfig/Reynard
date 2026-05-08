"""Runtime preflight checks for lab and CTF runs."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from urllib.parse import urlparse

from hacking_agent.core.scope import ScopeGuard
from hacking_agent.core.tools import CONTAINER_NAME, TOOL_FUNCTIONS, TOOL_SCHEMAS


@dataclass
class PreflightCheck:
    name: str
    ok: bool
    message: str
    fatal: bool = False


def run_preflight(target_url: str, scope_guard: ScopeGuard | None = None) -> list[PreflightCheck]:
    """Run cheap local checks before spending LLM/tool budget."""
    checks: list[PreflightCheck] = []

    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    checks.append(PreflightCheck(
        name="target",
        ok=bool(parsed.hostname),
        message=f"primary target={target_url!r}",
        fatal=not bool(parsed.hostname),
    ))

    if scope_guard is not None:
        checks.append(PreflightCheck(
            name="scope",
            ok=scope_guard.is_in_scope(target_url),
            message=scope_guard.describe(),
            fatal=not scope_guard.is_in_scope(target_url),
        ))

    checks.append(PreflightCheck(
        name="tool registry",
        ok=len(TOOL_FUNCTIONS) == len(TOOL_SCHEMAS),
        message=f"{len(TOOL_FUNCTIONS)} tools / {len(TOOL_SCHEMAS)} schemas loaded",
        fatal=len(TOOL_FUNCTIONS) != len(TOOL_SCHEMAS),
    ))

    checks.append(_docker_check())
    checks.append(_container_check())
    return checks


def has_fatal_failure(checks: list[PreflightCheck]) -> bool:
    return any(c.fatal and not c.ok for c in checks)


def _docker_check() -> PreflightCheck:
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        return PreflightCheck("docker", False, "Docker CLI not found.", fatal=True)
    except Exception as exc:
        return PreflightCheck("docker", False, f"Docker check failed: {exc}", fatal=False)

    version = result.stdout.strip()
    ok = result.returncode == 0 and bool(version)
    message = f"Docker server {version}" if ok else (result.stderr.strip() or "Docker server not reachable.")
    return PreflightCheck("docker", ok, message, fatal=False)


def _container_check() -> PreflightCheck:
    try:
        result = subprocess.run(
            [
                "docker", "ps",
                "--filter", f"name={CONTAINER_NAME}",
                "--format", "{{.Names}} {{.Status}}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        return PreflightCheck("container", False, "Docker CLI not found.", fatal=True)
    except Exception as exc:
        return PreflightCheck("container", False, f"Container check failed: {exc}", fatal=False)

    output = result.stdout.strip()
    ok = result.returncode == 0 and CONTAINER_NAME in output
    if ok:
        return PreflightCheck("container", True, output, fatal=False)
    return PreflightCheck(
        "container",
        False,
        f"{CONTAINER_NAME} is not running. Start with: docker compose up -d",
        fatal=False,
    )
