"""
=============================================================================
Reynard - Out-of-Band (OOB) Interaction Channel
=============================================================================
Wraps `interactsh-client` (https://github.com/projectdiscovery/interactsh)
running inside the Kali container. Provides session-scoped subdomains the
agent can plant in payloads, and a polling primitive that surfaces any HTTP
/ DNS / SMTP / LDAP callbacks the target made.

Without this, the agent is blind to:
  - Blind SSRF (target fetches our subdomain on success)
  - Blind SQLi (LOAD_FILE / xp_dirtree / openrowset to our DNS)
  - Blind XXE (DTD pull from our HTTP)
  - Blind Cmd injection (curl/wget/nslookup to our domain)
  - Log4Shell / JNDI variants
  - SSTI with network primitives
  - Webhook-based deserialization

Design
------
- One InteractshSession per orchestrator run (one client process, one base
  hostname). The session lives in the Kali container as a backgrounded
  `interactsh-client` writing JSONL to a shared file at
  /data/oob/interactsh.jsonl. We poll that file rather than talking to the
  CLI's stdout (more reliable).
- We mint per-correlation subdomains by prefixing a short token to the base
  hostname: f"{token}.{base_host}". The polling layer filters interactions
  by token so multiple in-flight payloads don't cross-contaminate.
- If interactsh-client isn't available we fall back to a "disabled" mode
  that returns informative errors so the agent knows OOB isn't available
  and can fall back to in-band techniques.
=============================================================================
"""
from __future__ import annotations

import json
import os
import secrets
import string
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any


CONTAINER_NAME = os.getenv("CONTAINER_NAME", "reynard-kali")
OOB_LOG_PATH = "/data/oob/interactsh.jsonl"
OOB_PID_PATH = "/data/oob/interactsh.pid"
OOB_HOST_PATH = "/data/oob/base_host.txt"

# Default public interactsh server. Override with INTERACTSH_SERVER for
# self-hosted instances (recommended on engagements - cleaner attribution
# and no shared-tenant noise).
DEFAULT_SERVER = os.getenv("INTERACTSH_SERVER", "oast.pro")
DEFAULT_TOKEN_AUTH = os.getenv("INTERACTSH_TOKEN", "")
AUTO_INSTALL_INTERACTSH = (
    os.getenv("AUTO_INSTALL_INTERACTSH", "true").lower()
    not in {"0", "false", "no", "off"}
)


def _docker_exec(cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    """Bare docker exec helper. Avoids importing tools.py to dodge cycles."""
    try:
        r = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", "docker not found"
    except Exception as e:
        return -1, "", str(e)


# =============================================================================
# Session
# =============================================================================

@dataclass
class Interaction:
    """One observed callback from the target."""
    protocol: str           # "http" | "dns" | "smtp" | "ldap" | ...
    full_id: str            # full subdomain that received the callback
    remote_address: str     # source IP
    timestamp: str
    raw_request: str = ""
    raw_response: str = ""
    correlation_id: str = ""  # the token portion if recognised


@dataclass
class InteractshSession:
    """Manages one interactsh-client process running in the Kali container.

    Use:
        sess = InteractshSession.start_or_attach()
        domain = sess.mint_domain("ssrf-1")  # -> "ssrf-1-abc123.<base>"
        # ... agent embeds `domain` in a payload, sends it ...
        hits = sess.poll(token="ssrf-1", timeout=20)
    """
    server: str = DEFAULT_SERVER
    token_auth: str = DEFAULT_TOKEN_AUTH
    base_host: str = ""
    enabled: bool = False
    error: str = ""
    _seen_offsets: dict[str, int] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    @classmethod
    def start_or_attach(cls, server: str | None = None,
                        token_auth: str | None = None) -> "InteractshSession":
        sess = cls(
            server=server or DEFAULT_SERVER,
            token_auth=token_auth or DEFAULT_TOKEN_AUTH,
        )
        sess._ensure_running()
        return sess

    # ---- lifecycle -------------------------------------------------------

    def _ensure_running(self) -> None:
        # 0. Make sure container is reachable.
        rc, _, err = _docker_exec("which interactsh-client")
        if rc != 0:
            if AUTO_INSTALL_INTERACTSH:
                self._try_install_client()
                rc, _, err = _docker_exec("which interactsh-client")
            if rc == 0:
                pass
            else:
                _, log_tail, _ = _docker_exec(
                    "tail -n 40 /tmp/interactsh-install.log 2>/dev/null || true",
                    timeout=5,
                )
                detail = f" Last install log:\n{log_tail}" if log_tail.strip() else ""
                install_hint = (
                    "Install via: go install -v "
                    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest "
                    "&& ln -sf /root/go/bin/interactsh-client /usr/local/bin/interactsh-client"
                )
                self.enabled = False
                self.error = (
                    "interactsh-client not installed in the container. "
                    f"{install_hint}.{detail}"
                )
                return

        _docker_exec("mkdir -p /data/oob")

        # 1. If a previous process is alive AND its base_host is still cached,
        #    reuse it (resilient across orchestrator restarts within a session).
        rc, pid_out, _ = _docker_exec(
            f"if [ -f {OOB_PID_PATH} ]; then "
            f"  pid=$(cat {OOB_PID_PATH}); "
            f"  if kill -0 $pid 2>/dev/null; then echo $pid; fi; "
            f"fi"
        )
        if rc == 0 and pid_out.strip():
            rc2, host_out, _ = _docker_exec(f"cat {OOB_HOST_PATH} 2>/dev/null")
            if rc2 == 0 and host_out.strip():
                self.base_host = host_out.strip()
                self.enabled = True
                return

        # 2. Otherwise start a fresh one.
        token_arg = f"-token {self.token_auth} " if self.token_auth else ""
        # -json -o writes JSONL events; -v silent banner.
        # -ps emits "Listing nn payload" line that contains the base host.
        # We capture the assigned host by parsing the first lines of the log.
        start_cmd = (
            f"rm -f {OOB_LOG_PATH} {OOB_HOST_PATH}; "
            f"nohup interactsh-client -server {self.server} "
            f"{token_arg}-json -o {OOB_LOG_PATH} -v "
            f">> /data/oob/client.stderr 2>&1 & "
            f"echo $! > {OOB_PID_PATH}"
        )
        rc, _, err = _docker_exec(start_cmd, timeout=15)
        if rc != 0:
            self.enabled = False
            self.error = f"failed to start interactsh-client: {err}"
            return

        # 3. Poll stderr for the assigned base hostname (interactsh prints it
        #    on startup: "[INF] Listing 1 payload for OOB Testing"
        #    "[<host>]" pattern). Wait up to ~10 seconds.
        host = self._extract_base_host(deadline=time.time() + 12)
        if not host:
            self.enabled = False
            self.error = "could not parse interactsh base host from startup output"
            return

        self.base_host = host
        _docker_exec(f"echo -n {self.base_host!r} > {OOB_HOST_PATH}")
        self.enabled = True

    def _try_install_client(self) -> None:
        """One controlled runtime repair for older images missing interactsh."""
        install_cmd = (
            "export PATH=$PATH:/root/go/bin; "
            "if ! command -v go >/dev/null 2>&1; then "
            "  echo 'go is not installed' > /tmp/interactsh-install.log; exit 1; "
            "fi; "
            "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest "
            "> /tmp/interactsh-install.log 2>&1 && "
            "ln -sf /root/go/bin/interactsh-client /usr/local/bin/interactsh-client && "
            "command -v interactsh-client"
        )
        _docker_exec(install_cmd, timeout=240)

    def _extract_base_host(self, deadline: float) -> str | None:
        """Parse the assigned base subdomain from interactsh-client's stderr."""
        import re
        pat = re.compile(r"([a-z0-9]{20,40}\.(?:oast\.pro|oast\.live|oast\.site|"
                          r"oast\.online|oast\.fun|oast\.me|interact\.sh|"
                          r"[a-z0-9.-]+))", re.IGNORECASE)
        while time.time() < deadline:
            rc, out, _ = _docker_exec("cat /data/oob/client.stderr 2>/dev/null")
            if rc == 0 and out:
                m = pat.search(out)
                if m:
                    return m.group(1).strip(". ")
            time.sleep(0.5)
        return None

    def stop(self) -> None:
        _docker_exec(
            f"if [ -f {OOB_PID_PATH} ]; then kill $(cat {OOB_PID_PATH}) "
            f"2>/dev/null; rm -f {OOB_PID_PATH}; fi"
        )
        self.enabled = False

    # ---- API consumed by the agent --------------------------------------

    def mint_domain(self, label: str = "") -> dict[str, str]:
        """Return a unique correlation token + the full OOB subdomain.

        Embed `domain` in payloads. Later, call `poll(token=...)` to retrieve
        any callbacks that subdomain received.
        """
        if not self.enabled:
            return {
                "enabled": False,
                "error": self.error or "OOB session not initialised",
                "token": "",
                "domain": "",
            }
        # Token = sanitised label + entropy (for collision-free correlation).
        clean_label = "".join(
            c for c in (label or "x").lower()
            if c in string.ascii_lowercase + string.digits + "-"
        )[:16] or "x"
        rand = secrets.token_hex(4)
        token = f"{clean_label}-{rand}"
        return {
            "enabled": True,
            "token": token,
            "domain": f"{token}.{self.base_host}",
            "http_url": f"http://{token}.{self.base_host}",
            "https_url": f"https://{token}.{self.base_host}",
            "base_host": self.base_host,
        }

    def poll(self, token: str = "", timeout: int = 15,
             since_seconds: int | None = None) -> dict[str, Any]:
        """Wait up to `timeout` seconds for any new interactions.

        If `token` is given, only return interactions whose full-id starts
        with that token. Returns:
          {
            "enabled": bool,
            "interactions": [Interaction-as-dict, ...],
            "polled_seconds": float,
            "matched": int,
          }
        """
        if not self.enabled:
            return {"enabled": False, "interactions": [],
                    "error": self.error, "matched": 0}

        deadline = time.time() + max(1, timeout)
        seen_key = token or "__all__"
        matched: list[Interaction] = []

        # Optional time floor (ignore older interactions).
        floor_ts = (time.time() - since_seconds) if since_seconds else 0.0

        while time.time() < deadline:
            interactions = self._read_jsonl(seen_key)
            for inter in interactions:
                if floor_ts and self._parse_ts(inter.timestamp) < floor_ts:
                    continue
                if token and not inter.full_id.startswith(token):
                    continue
                inter.correlation_id = (inter.full_id.split(".", 1)[0]
                                         if "." in inter.full_id
                                         else inter.full_id)
                matched.append(inter)
            if matched:
                # Drain quickly once we have a hit; an extra ~1s catches
                # bursts (DNS+HTTP from the same callback).
                time.sleep(1.0)
                interactions = self._read_jsonl(seen_key)
                for inter in interactions:
                    if floor_ts and self._parse_ts(inter.timestamp) < floor_ts:
                        continue
                    if token and not inter.full_id.startswith(token):
                        continue
                    inter.correlation_id = (inter.full_id.split(".", 1)[0]
                                             if "." in inter.full_id
                                             else inter.full_id)
                    matched.append(inter)
                break
            time.sleep(1.0)

        return {
            "enabled": True,
            "matched": len(matched),
            "polled_seconds": round(time.time() - (deadline - timeout), 2),
            "interactions": [self._inter_to_dict(i) for i in matched],
        }

    # ---- helpers --------------------------------------------------------

    def _read_jsonl(self, seen_key: str) -> list[Interaction]:
        with self._lock:
            offset = self._seen_offsets.get(seen_key, 0)
            rc, out, _ = _docker_exec(
                f"if [ -f {OOB_LOG_PATH} ]; then "
                f"  tail -c +{offset + 1} {OOB_LOG_PATH}; "
                f"fi",
                timeout=5,
            )
            if rc != 0 or not out:
                return []
            self._seen_offsets[seen_key] = offset + len(out.encode("utf-8"))
            res: list[Interaction] = []
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                res.append(Interaction(
                    protocol=obj.get("protocol", "?"),
                    full_id=obj.get("full-id", obj.get("unique-id", "")),
                    remote_address=obj.get("remote-address", ""),
                    timestamp=obj.get("timestamp", ""),
                    raw_request=obj.get("raw-request", "")[:2000],
                    raw_response=obj.get("raw-response", "")[:1000],
                ))
            return res

    @staticmethod
    def _parse_ts(ts: str) -> float:
        try:
            from datetime import datetime
            # interactsh emits RFC3339Nano e.g. "2024-01-02T03:04:05.123456789Z"
            ts = ts.replace("Z", "+00:00")
            # Trim sub-microsecond precision Python can't parse.
            if "." in ts:
                base, frac_tz = ts.split(".", 1)
                if "+" in frac_tz:
                    frac, tz = frac_tz.split("+", 1)
                    frac = frac[:6]
                    ts = f"{base}.{frac}+{tz}"
                elif "-" in frac_tz:
                    frac, tz = frac_tz.split("-", 1)
                    frac = frac[:6]
                    ts = f"{base}.{frac}-{tz}"
            return datetime.fromisoformat(ts).timestamp()
        except Exception:
            return 0.0

    @staticmethod
    def _inter_to_dict(i: Interaction) -> dict[str, Any]:
        return {
            "protocol": i.protocol,
            "full_id": i.full_id,
            "correlation_id": i.correlation_id,
            "remote_address": i.remote_address,
            "timestamp": i.timestamp,
            "raw_request": i.raw_request,
            "raw_response": i.raw_response,
        }

    def describe(self) -> str:
        if not self.enabled:
            return f"OOB: DISABLED ({self.error or 'not initialised'})"
        return f"OOB: enabled, base={self.base_host}, server={self.server}"


# =============================================================================
# Module-level singleton (lazy, easy access from tools.py)
# =============================================================================

_SESSION: InteractshSession | None = None
_SESSION_LOCK = threading.RLock()


def get_session() -> InteractshSession:
    global _SESSION
    with _SESSION_LOCK:
        if _SESSION is None:
            _SESSION = InteractshSession.start_or_attach()
        return _SESSION


def reset_session() -> None:
    """For tests / forced restart."""
    global _SESSION
    with _SESSION_LOCK:
        if _SESSION is not None:
            _SESSION.stop()
        _SESSION = None
