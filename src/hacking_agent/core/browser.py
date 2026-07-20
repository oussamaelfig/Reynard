"""
=============================================================================
Reynard — Headless Chromium Browser Service (Playwright)
=============================================================================
Real headless-Chromium browser automation, replacing the previous Lightpanda
CLI. The browser runs INSIDE the Kali Docker container: this module ships a
small self-contained Playwright driver script into the container and runs it
via `docker exec` (mirroring how tools.py runs every other command), so the
orchestrator host needs no browser binaries of its own.

What the driver provides that Lightpanda did not:
  - navigate() with a full Chromium engine (real DOM + JS execution)
  - execute JS and RETURN the script's evaluated value (not an HTML dump)
  - dialog capture: alert() / confirm() / prompt() events are recorded, so a
    fired alert PROVES DOM / stored / reflected XSS
  - form submit / click / type via real CSS selectors
  - injection of the active auth session's cookies (parsed from the session's
    Netscape cookie jar inside the container) + static headers, so
    authenticated client-side labs work

The public helpers (`navigate`, `execute_js`, `interact`) all return a plain
dict; tools.py wraps them into the backward-compatible tool result shape.
=============================================================================
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import uuid
from typing import Any

from hacking_agent.core import sessions as session_mod


CONTAINER_NAME = os.getenv("CONTAINER_NAME", "reynard-kali")
# Optional explicit Chromium path inside the container. When empty, Playwright
# uses the browser it installed via `playwright install chromium`.
CHROMIUM_EXECUTABLE = os.getenv("PLAYWRIGHT_CHROMIUM_PATH", "")
# Extra seconds added on top of the in-page wait so docker exec does not kill
# the driver before Chromium finishes.
BROWSER_EXEC_TIMEOUT = int(os.getenv("BROWSER_EXEC_TIMEOUT", "90"))
DRIVER_PATH = "/tmp/reynard_pw_driver.py"


# =============================================================================
# In-container Playwright driver
# =============================================================================
# This runs INSIDE the Kali container (python3 + playwright). It reads a job
# JSON file, drives Chromium, and prints a single JSON result to stdout. It is
# intentionally dependency-light and never imports Reynard code.

_DRIVER_SOURCE = r'''
import json
import sys


def _parse_netscape_cookies(path):
    cookies = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return cookies
    for line in lines:
        raw = line.rstrip("\n")
        http_only = False
        if raw.startswith("#HttpOnly_"):
            http_only = True
            raw = raw[len("#HttpOnly_"):]
        elif raw.startswith("#") or not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) < 7:
            continue
        domain, _flag, cpath, secure, expires, name, value = parts[:7]
        cookie = {
            "name": name,
            "value": value,
            "domain": domain,
            "path": cpath or "/",
            "secure": str(secure).upper() == "TRUE",
            "httpOnly": http_only,
        }
        try:
            exp = int(expires)
            if exp > 0:
                cookie["expires"] = exp
        except (TypeError, ValueError):
            pass
        cookies.append(cookie)
    return cookies


def _eval_script(page, script):
    body = (script or "").strip()
    if not body:
        return None
    stripped = body.rstrip(";").strip()
    if "\n" in body or "return" in body or ";" in stripped:
        wrapped = "() => {" + body + "}"
    else:
        wrapped = "() => (" + body + ")"
    return page.evaluate(wrapped)


def main():
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        job = json.load(fh)

    result = {
        "ok": False,
        "url": job.get("url", ""),
        "final_url": "",
        "status": None,
        "title": "",
        "dialogs": [],
        "console_errors": [],
        "js_result": None,
        "actions_performed": [],
        "content": "",
        "error": "",
    }
    dialogs = result["dialogs"]
    console_errors = result["console_errors"]

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # playwright missing
        result["error"] = "playwright not installed in container: %s" % exc
        print(json.dumps(result))
        return

    wait_ms = int(job.get("wait_ms", 2000) or 0)
    launch_kwargs = {
        "headless": True,
        "args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
    }
    if job.get("executable_path"):
        launch_kwargs["executable_path"] = job["executable_path"]

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**launch_kwargs)
            context = browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=job.get("headers") or {},
            )
            cookies = _parse_netscape_cookies(job.get("cookie_jar", ""))
            if cookies:
                try:
                    context.add_cookies(cookies)
                except Exception:
                    for ck in cookies:
                        try:
                            context.add_cookies([ck])
                        except Exception:
                            pass
            page = context.new_page()

            def _on_dialog(dialog):
                entry = {"type": dialog.type, "message": dialog.message}
                dialogs.append(entry)
                try:
                    if dialog.type == "prompt":
                        dialog.accept(job.get("prompt_answer", ""))
                    else:
                        dialog.accept()
                except Exception:
                    try:
                        dialog.dismiss()
                    except Exception:
                        pass

            def _on_console(msg):
                try:
                    if msg.type in ("error", "warning"):
                        console_errors.append("%s: %s" % (msg.type, msg.text))
                except Exception:
                    pass

            page.on("dialog", _on_dialog)
            page.on("console", _on_console)

            resp = page.goto(
                job["url"],
                wait_until=job.get("wait_until", "load"),
                timeout=int(job.get("nav_timeout_ms", 30000)),
            )
            if resp is not None:
                result["status"] = resp.status
            if wait_ms > 0:
                page.wait_for_timeout(wait_ms)

            for action in job.get("actions", []) or []:
                kind = action.get("action")
                selector = action.get("selector", "")
                value = action.get("value", "")
                performed = {"action": kind, "selector": selector, "ok": True}
                try:
                    if kind == "click":
                        page.click(selector, timeout=8000)
                    elif kind == "type":
                        page.fill(selector, value, timeout=8000)
                    elif kind == "select":
                        page.select_option(selector, value, timeout=8000)
                    elif kind == "submit":
                        page.eval_on_selector(
                            selector, "el => (el.form ? el.form : el).submit()"
                        )
                    elif kind == "press":
                        page.press(selector, value or "Enter", timeout=8000)
                    else:
                        performed["ok"] = False
                        performed["error"] = "unknown action %r" % kind
                except Exception as exc:
                    performed["ok"] = False
                    performed["error"] = str(exc)[:300]
                result["actions_performed"].append(performed)
                if wait_ms > 0:
                    page.wait_for_timeout(min(wait_ms, 1500))

            if job.get("script"):
                try:
                    value = _eval_script(page, job["script"])
                    try:
                        json.dumps(value)
                        result["js_result"] = value
                    except (TypeError, ValueError):
                        result["js_result"] = repr(value)
                except Exception as exc:
                    result["js_result"] = None
                    result["error"] = "js_error: %s" % (str(exc)[:400])
                if wait_ms > 0:
                    page.wait_for_timeout(min(wait_ms, 1500))

            try:
                result["final_url"] = page.url
                result["title"] = page.title()
            except Exception:
                pass

            if job.get("want_content", True):
                try:
                    if job.get("output_format") == "markdown":
                        result["content"] = page.inner_text("body")
                    else:
                        result["content"] = page.content()
                except Exception as exc:
                    result["error"] = result["error"] or ("content_error: %s" % exc)

            context.close()
            browser.close()
            result["ok"] = True
    except Exception as exc:
        result["error"] = str(exc)[:600]

    max_content = int(job.get("max_content", 200000))
    if isinstance(result["content"], str) and len(result["content"]) > max_content:
        result["content"] = result["content"][:max_content] + "\n[TRUNCATED]"
    print(json.dumps(result))


if __name__ == "__main__":
    main()
'''


# =============================================================================
# Host-side docker plumbing
# =============================================================================

def _docker_exec(command: str, timeout: int) -> dict[str, Any]:
    full_cmd = ["docker", "exec", CONTAINER_NAME, "bash", "-c", command]
    try:
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, timeout=timeout,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"browser driver timed out after {timeout}s",
                "exit_code": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "Docker not found. Is Docker installed and the container running?",
                "exit_code": -1}
    except Exception as exc:
        return {"stdout": "", "stderr": f"browser exec error: {exc}", "exit_code": -1}


def _write_container_file(path: str, content: str, timeout: int = 20) -> bool:
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    cmd = f"echo {b64} | base64 -d > {path}"
    return _docker_exec(cmd, timeout=timeout).get("exit_code") == 0


def _ensure_driver() -> bool:
    return _write_container_file(DRIVER_PATH, _DRIVER_SOURCE)


def _active_session_context(session: str | None) -> tuple[str, dict[str, str], str]:
    """Return (cookie_jar_path, static_headers, session_name) for a session."""
    sess = session_mod.get_registry().get(session)
    return sess.cookie_jar_path(), dict(sess.static_headers or {}), sess.name


def run_job(
    url: str,
    *,
    script: str | None = None,
    actions: list[dict] | None = None,
    wait_ms: int = 2000,
    output_format: str = "html",
    want_content: bool = True,
    session: str | None = None,
    prompt_answer: str = "",
) -> dict[str, Any]:
    """Drive Chromium in the container for one job and return the parsed result.

    Always injects the active (or named) auth session's cookies + static
    headers so authenticated client-side labs work.
    """
    cookie_jar, headers, session_name = _active_session_context(session)

    if not _ensure_driver():
        return {
            "ok": False,
            "url": url,
            "error": "failed to write browser driver into container",
            "session": session_name,
            "dialogs": [],
        }

    job: dict[str, Any] = {
        "url": url,
        "script": script or "",
        "actions": actions or [],
        "wait_ms": wait_ms,
        "output_format": output_format,
        "want_content": want_content,
        "cookie_jar": cookie_jar,
        "headers": headers,
        "prompt_answer": prompt_answer,
        "executable_path": CHROMIUM_EXECUTABLE or "",
    }
    job_path = f"/tmp/reynard_pw_job_{uuid.uuid4().hex}.json"
    if not _write_container_file(job_path, json.dumps(job)):
        return {
            "ok": False,
            "url": url,
            "error": "failed to write browser job into container",
            "session": session_name,
            "dialogs": [],
        }

    timeout = BROWSER_EXEC_TIMEOUT + int(wait_ms / 1000)
    exec_result = _docker_exec(
        f"python3 {DRIVER_PATH} {job_path}; rm -f {job_path}", timeout=timeout,
    )

    stdout = (exec_result.get("stdout") or "").strip()
    parsed: dict[str, Any] | None = None
    if stdout:
        # The driver prints one JSON object; take the last JSON line to be safe.
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    parsed = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue

    if parsed is None:
        return {
            "ok": False,
            "url": url,
            "error": (
                exec_result.get("stderr")
                or stdout[:600]
                or "browser driver produced no output"
            ),
            "session": session_name,
            "dialogs": [],
        }

    parsed["session"] = session_name
    if exec_result.get("stderr") and not parsed.get("error"):
        parsed["driver_stderr"] = exec_result["stderr"][:600]
    return parsed


# =============================================================================
# Public helpers used by tools.py
# =============================================================================

def _dialog_proof(result: dict[str, Any]) -> str:
    dialogs = result.get("dialogs") or []
    if not dialogs:
        return ""
    kinds = ", ".join(f"{d.get('type')}('{d.get('message', '')}')" for d in dialogs)
    return (
        f"XSS PROOF: {len(dialogs)} JavaScript dialog(s) fired during execution "
        f"[{kinds}] — this is concrete proof of client-side script execution."
    )


def navigate(url: str, output_format: str = "html", wait_ms: int = 2000,
             session: str | None = None) -> dict[str, Any]:
    result = run_job(
        url, wait_ms=wait_ms, output_format=output_format,
        want_content=True, session=session,
    )
    proof = _dialog_proof(result)
    if proof:
        result["xss_proof"] = proof
    return result


def execute_js(url: str, script: str, wait_ms: int = 2000,
               session: str | None = None) -> dict[str, Any]:
    result = run_job(
        url, script=script, wait_ms=wait_ms, want_content=False, session=session,
    )
    proof = _dialog_proof(result)
    if proof:
        result["xss_proof"] = proof
    return result


def interact(url: str, actions: list[dict], wait_ms: int = 2000,
             session: str | None = None) -> dict[str, Any]:
    result = run_job(
        url, actions=actions, wait_ms=wait_ms, want_content=True, session=session,
    )
    proof = _dialog_proof(result)
    if proof:
        result["xss_proof"] = proof
    return result
