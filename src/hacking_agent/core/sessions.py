"""
=============================================================================
Hacking Agent - Multi-Session Auth Registry
=============================================================================
Lets the agent operate as multiple authenticated identities in the same run.

Why this is the highest-yield finding-class booster:
  - IDOR is the #1 paid bug class on B2B SaaS pentests.
  - It is fundamentally invisible to a single-user agent: you cannot detect
    that user1 can read user2's data without holding both contexts.
  - Authz tests (vertical privilege - user vs. admin endpoints) need the
    same primitive.

Each session is just a named cookie jar inside the Kali container, plus an
optional set of static headers (e.g. Authorization Bearer tokens). The
"active" session is selected by the agent via the `swap_session` tool and
http_request / browser_* read it implicitly.

Sessions can be:
  - Cookie-based (curl saves and reuses cookies in a per-session jar)
  - Header-based (e.g. JWT Bearer, X-API-Key)
  - Both (web UI flows that mix Set-Cookie and Authorization)

CLI loading
-----------
Sessions can be pre-loaded from a YAML/JSON file at orchestrator start:
  --auth-file engagement-auth.yaml

Or from inline flags:
  --auth admin:cookies=admin.cookies,header=Authorization=Bearer\\ XYZ
=============================================================================
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any


CONTAINER_NAME = os.getenv("CONTAINER_NAME", "hacking-agent-kali")
SESSION_DIR = "/data/sessions"


def _docker_exec(cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, "", str(e)


@dataclass
class AuthSession:
    """One named authenticated identity."""
    name: str
    description: str = ""
    cookie_jar: str = ""           # Container path, e.g. /data/sessions/admin.cookies
    static_headers: dict[str, str] = field(default_factory=dict)
    role_hint: str = "unknown"     # "admin" | "user" | "tenant_a_user" | "unauth" | ...

    def cookie_jar_path(self) -> str:
        return self.cookie_jar or f"{SESSION_DIR}/{self.name}.cookies"


class SessionRegistry:
    """Thread-safe collection of named auth sessions, with one active session.

    The default session is "default" and matches the legacy single-jar
    behaviour at /data/cookies/cookies.txt for backward compat.
    """

    DEFAULT_NAME = "default"
    LEGACY_COOKIE_JAR = "/data/cookies/cookies.txt"

    def __init__(self):
        self._lock = threading.RLock()
        self._sessions: dict[str, AuthSession] = {}
        self._active: str = self.DEFAULT_NAME
        # Always have a default session for back-compat with existing code.
        self._sessions[self.DEFAULT_NAME] = AuthSession(
            name=self.DEFAULT_NAME,
            description="Legacy single-jar default session",
            cookie_jar=self.LEGACY_COOKIE_JAR,
            role_hint="unknown",
        )
        _docker_exec(f"mkdir -p {SESSION_DIR} {os.path.dirname(self.LEGACY_COOKIE_JAR)}")

    # ---- registration ----------------------------------------------------

    def register(self, session: AuthSession, overwrite: bool = False) -> str:
        with self._lock:
            if session.name in self._sessions and not overwrite:
                return f"Session '{session.name}' already registered."
            # Make sure the cookie jar path is initialised (touch the file).
            jar = session.cookie_jar_path()
            session.cookie_jar = jar
            _docker_exec(f"mkdir -p {os.path.dirname(jar)} && touch {jar}")
            self._sessions[session.name] = session
            return f"Session '{session.name}' registered (jar={jar}, role={session.role_hint})."

    def import_cookies_from_host(self, name: str, host_path: str) -> str:
        """Copy a cookies file from the host into the container session jar."""
        with self._lock:
            sess = self._sessions.get(name)
            if not sess:
                return f"Unknown session '{name}'"
            jar = sess.cookie_jar_path()
            try:
                with open(host_path, "rb") as f:
                    data = f.read()
            except OSError as e:
                return f"Could not read host cookie file: {e}"
            # Base64 to safely transit through docker exec.
            import base64
            b64 = base64.b64encode(data).decode("ascii")
            cmd = (f"mkdir -p {os.path.dirname(jar)} && "
                    f"echo {b64} | base64 -d > {jar}")
            rc, _, err = _docker_exec(cmd, timeout=15)
            if rc != 0:
                return f"Failed to copy cookies into container: {err}"
            return f"Imported {len(data)} bytes into session '{name}' jar."

    # ---- active session --------------------------------------------------

    def set_active(self, name: str) -> str:
        with self._lock:
            if name not in self._sessions:
                return (f"ERROR: unknown session '{name}'. "
                        f"Known: {list(self._sessions.keys())}")
            self._active = name
            return f"Active session -> '{name}' ({self._sessions[name].role_hint})"

    def active(self) -> AuthSession:
        with self._lock:
            return self._sessions[self._active]

    def get(self, name: str | None) -> AuthSession:
        """Resolve a session by name, falling back to the active one."""
        with self._lock:
            if name and name in self._sessions:
                return self._sessions[name]
            return self._sessions[self._active]

    # ---- introspection ---------------------------------------------------

    def describe(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active": self._active,
                "sessions": [
                    {
                        "name": s.name,
                        "role_hint": s.role_hint,
                        "cookie_jar": s.cookie_jar_path(),
                        "static_headers": list(s.static_headers.keys()),
                        "description": s.description,
                    }
                    for s in self._sessions.values()
                ],
            }

    def names(self) -> list[str]:
        with self._lock:
            return list(self._sessions.keys())


# =============================================================================
# Module singleton
# =============================================================================

_REGISTRY: SessionRegistry | None = None
_LOCK = threading.RLock()


def get_registry() -> SessionRegistry:
    global _REGISTRY
    with _LOCK:
        if _REGISTRY is None:
            _REGISTRY = SessionRegistry()
        return _REGISTRY


# =============================================================================
# CLI / config loading helpers
# =============================================================================

def load_from_file(path: str) -> list[str]:
    """Load sessions from a JSON or YAML file. Returns log messages.

    File format:
      [
        {
          "name": "admin",
          "role_hint": "admin",
          "cookies_file": "./admin.cookies",
          "static_headers": {"Authorization": "Bearer eyJ..."}
        },
        {"name": "user1", "role_hint": "user", "cookies_file": "./u1.cookies"},
        {"name": "user2", "role_hint": "user", "cookies_file": "./u2.cookies"},
        {"name": "unauth", "role_hint": "unauth"}
      ]
    """
    msgs: list[str] = []
    if not os.path.exists(path):
        return [f"auth file not found: {path}"]
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        if path.endswith((".yml", ".yaml")):
            try:
                import yaml  # optional dep
            except ImportError:
                return ["pyyaml not installed; use a JSON auth file or `pip install pyyaml`"]
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
    except Exception as e:
        return [f"failed to parse auth file: {e}"]

    if not isinstance(data, list):
        return ["auth file must be a JSON/YAML array of session objects"]

    reg = get_registry()
    for entry in data:
        try:
            sess = AuthSession(
                name=entry["name"],
                description=entry.get("description", ""),
                static_headers=entry.get("static_headers", {}) or {},
                role_hint=entry.get("role_hint", "unknown"),
            )
            msgs.append(reg.register(sess, overwrite=True))
            cookies_file = entry.get("cookies_file")
            if cookies_file:
                # Resolve relative paths against the auth-file directory.
                if not os.path.isabs(cookies_file):
                    cookies_file = os.path.join(os.path.dirname(path), cookies_file)
                msgs.append(reg.import_cookies_from_host(sess.name, cookies_file))
        except KeyError as e:
            msgs.append(f"skipping entry {entry!r}: missing key {e}")
    return msgs
