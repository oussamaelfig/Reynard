from __future__ import annotations

import os
import shutil
import subprocess
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

CONTAINER_NAME = os.getenv("CONTAINER_NAME", "reynard-kali")

# Tools the agent expects inside the Kali container. Weighted into readiness.
EXPECTED_KALI_TOOLS = [
    "curl", "nmap", "sqlmap", "ffuf", "gobuster", "nuclei",
    "whatweb", "nikto", "python3", "interactsh-client",
]

# Class-specific OSS tools installed by the Dockerfile (Phase 2 tooling layer).
# ysoserial is verified separately via its jar path (needs java to run).
EXPECTED_CLASS_TOOLS = ["jwt_tool", "phpggc", "sstimap", "java"]


def package_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "not installed"


# =============================================================================
# Preflight self-check (WS6): Kali tools + Chromium/Playwright + Caido bridge
# =============================================================================

def _run(cmd: list[str], timeout: int = 6) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _docker_available() -> bool:
    proc = _run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=5)
    return bool(proc and proc.returncode == 0 and proc.stdout.strip())


def _container_running(name: str) -> bool:
    proc = _run(["docker", "ps", "--filter", f"name={name}", "--format", "{{.Names}}"], timeout=5)
    return bool(proc and proc.returncode == 0 and name in (proc.stdout or ""))


def _tool_in_container(tool: str) -> bool:
    proc = _run(["docker", "exec", CONTAINER_NAME, "which", tool], timeout=6)
    return bool(proc and proc.returncode == 0 and proc.stdout.strip())


def check_kali_tools() -> dict[str, str]:
    """Return {tool: 'ok'|'missing'|'unknown'} for each expected Kali tool.

    Prefers checking inside the container; falls back to local PATH; marks
    'unknown' when neither Docker nor the local binary can be consulted.
    """
    results: dict[str, str] = {}
    container_up = _docker_available() and _container_running(CONTAINER_NAME)
    for tool in EXPECTED_KALI_TOOLS:
        if container_up:
            results[tool] = "ok" if _tool_in_container(tool) else "missing"
        elif shutil.which(tool):
            results[tool] = "ok"
        else:
            results[tool] = "unknown"
    return results


def _file_in_container(path: str) -> bool:
    proc = _run(["docker", "exec", CONTAINER_NAME, "test", "-s", path], timeout=6)
    return bool(proc and proc.returncode == 0)


def check_class_tools() -> dict[str, str]:
    """Return {tool: 'ok'|'missing'|'unknown'} for class-specific OSS tools.

    Mirrors check_kali_tools() but also validates the ysoserial jar (which is
    invoked via java rather than being on PATH).
    """
    results: dict[str, str] = {}
    container_up = _docker_available() and _container_running(CONTAINER_NAME)
    for tool in EXPECTED_CLASS_TOOLS:
        if container_up:
            results[tool] = "ok" if _tool_in_container(tool) else "missing"
        elif shutil.which(tool):
            results[tool] = "ok"
        else:
            results[tool] = "unknown"
    if container_up:
        results["ysoserial.jar"] = (
            "ok" if _file_in_container("/opt/ysoserial/ysoserial.jar") else "missing"
        )
    else:
        results["ysoserial.jar"] = "unknown"
    return results


def check_shodan() -> tuple[str, str]:
    """Return (status, message) for Shodan OSINT readiness.

    'ok' when a key is set and the API answers; 'warn' when no key is set
    (Shodan is optional, only needed for prod assessments); 'error' otherwise.
    """
    try:
        from hacking_agent.integrations import shodan as shodan_mod
        client = shodan_mod.get_shodan_client()
        if not client.is_configured():
            return "warn", "SHODAN_API_KEY not set (optional; prod recon only)"
        info = client.api_info()
        if info.get("error"):
            return "error", f"Shodan configured but unreachable: {info['error']}"
        return "ok", "Shodan API key configured and reachable"
    except Exception as exc:  # noqa: BLE001
        return "unknown", f"Shodan check failed: {exc}"


def check_playwright_chromium() -> tuple[str, str]:
    """Return (status, message) for Chromium/Playwright readiness.

    Playwright runs inside the Kali container, so prefer probing there; degrade
    to a local import check otherwise.
    """
    if _docker_available() and _container_running(CONTAINER_NAME):
        proc = _run(
            ["docker", "exec", CONTAINER_NAME, "python3", "-c",
             "import playwright; from playwright.sync_api import sync_playwright; print('ok')"],
            timeout=15,
        )
        if proc and proc.returncode == 0 and "ok" in (proc.stdout or ""):
            return "ok", "playwright importable in container"
        return "missing", "playwright not importable in container (run: playwright install chromium)"
    try:
        import playwright  # noqa: F401
        return "ok", "playwright importable locally (container not checked)"
    except Exception as exc:
        return "unknown", f"container down; local playwright not importable: {exc}"


def check_caido_bridge() -> tuple[str, str]:
    try:
        from hacking_agent.integrations import caido_local as caido_local_mod
        result = caido_local_mod.CaidoLocalBridgeClient(timeout=2.0).status()
        if result.get("ok"):
            return "ok", "Caido local bridge reachable"
        return "warn", "Caido local bridge not reachable (optional)"
    except Exception as exc:
        return "unknown", f"Caido bridge check failed: {exc}"


def run_self_check() -> dict:
    """Aggregate readiness checks and compute a 0-100 readiness score."""
    tools = check_kali_tools()
    class_tools = check_class_tools()
    pw_status, pw_msg = check_playwright_chromium()
    caido_status, caido_msg = check_caido_bridge()
    shodan_status, shodan_msg = check_shodan()

    # Score: Kali tools 55%, class tools 15%, Playwright 20%, Caido 5%, Shodan 5%.
    # Caido + Shodan are optional (prod-only), so 'warn' still earns their share.
    tool_ok = sum(1 for v in tools.values() if v == "ok")
    tool_score = (tool_ok / len(tools)) * 55 if tools else 0
    class_ok = sum(1 for v in class_tools.values() if v == "ok")
    class_score = (class_ok / len(class_tools)) * 15 if class_tools else 0
    pw_score = 20 if pw_status == "ok" else (10 if pw_status == "unknown" else 0)
    caido_score = 5 if caido_status in ("ok", "warn") else 0
    shodan_score = 5 if shodan_status in ("ok", "warn") else 0
    score = round(tool_score + class_score + pw_score + caido_score + shodan_score)

    return {
        "kali_tools": tools,
        "class_tools": class_tools,
        "playwright": {"status": pw_status, "message": pw_msg},
        "caido_bridge": {"status": caido_status, "message": caido_msg},
        "shodan": {"status": shodan_status, "message": shodan_msg},
        "readiness_score": score,
    }


def print_self_check(report: dict | None = None) -> int:
    report = report or run_self_check()
    print("Preflight self-check")
    tools = report["kali_tools"]
    for tool, status in tools.items():
        mark = {"ok": "OK", "missing": "MISSING", "unknown": "UNKNOWN"}.get(status, status)
        print(f"  kali:{tool}: {mark}")
    for tool, status in report.get("class_tools", {}).items():
        mark = {"ok": "OK", "missing": "MISSING", "unknown": "UNKNOWN"}.get(status, status)
        print(f"  classtool:{tool}: {mark}")
    pw = report["playwright"]
    print(f"  chromium/playwright: {pw['status'].upper()} — {pw['message']}")
    cd = report["caido_bridge"]
    print(f"  caido_bridge: {cd['status'].upper()} — {cd['message']}")
    sh = report["shodan"]
    print(f"  shodan: {sh['status'].upper()} — {sh['message']}")
    print(f"  readiness_score: {report['readiness_score']}/100")
    print()
    return report["readiness_score"]


def env_value(name: str) -> str:
    value = os.getenv(name)
    if value is None:
        return "<unset>"
    if any(s in name for s in ("KEY", "TOKEN", "PAT", "SECRET")):
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
        "SHODAN_API_KEY",
        "CENSYS_API_ID",
        "CENSYS_API_SECRET",
    ):
        print(f"  {name}: {env_value(name)}")
    print()

    print(ProviderRegistry.from_env().describe())
    print()
    print_self_check()


if __name__ == "__main__":
    main()
