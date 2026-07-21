"""
=============================================================================
Reynard — Scope Enforcement (Defense in Depth)
=============================================================================
Validates that every tool call targets only approved domains / CIDR ranges.

Inspired by Pentest-Swarm-AI's scope.ValidateAndLog pattern: violations are
logged with the offending tool + target and return an error — they never
silently pass through.

The ScopeGuard also blocks dangerous shell meta-characters in run_shell
commands: backticks, $(), pipes to external hosts, etc.

Usage
─────
  guard = ScopeGuard.from_target_url("https://example.com")
  guard.validate("http_request", {"url": "https://example.com/login"})  # ok
  guard.validate("http_request", {"url": "https://evil.com/steal"})     # raises
=============================================================================
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids a runtime import cycle
    from hacking_agent.core.engagement import Engagement


class ScopeViolation(RuntimeError):
    """Raised when a tool call targets a domain outside the allowed scope."""


class RateLimitExceeded(ScopeViolation):
    """Raised when the engagement's hard request cap is hit.

    Subclasses ScopeViolation so existing call sites that catch ScopeViolation
    (e.g. BudgetedToolExecutor) treat an exhausted request budget as a blocked
    tool call rather than an uncaught crash.
    """


@dataclass
class ScopeGuard:
    """Validates that tool calls stay within the engagement scope.

    Scope is defined by:
      - allowed_domains: explicit domain list (e.g. ["example.com"])
      - allowed_cidrs:   IP ranges (e.g. ["10.0.0.0/8"])
      - include_subdomains: if True, "sub.example.com" is in scope when
        "example.com" is allowed

    The guard also blocks dangerous shell meta-characters to prevent
    command injection attacks from LLM-generated payloads.
    """
    allowed_domains: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    include_subdomains: bool = True

    # ---- engagement rules of engagement (default = open lab behaviour) ----
    # These are populated by attach_engagement()/from_engagement(); left at
    # their inert defaults the guard behaves exactly as it did for labs.
    #   out_of_scope:            denylist that overrides the allowlist
    #   max_requests_per_second: global min-interval rate limit (0 = off)
    #   max_total_requests:      hard cap on scoped requests (0 = off)
    #   block_destructive:       block obviously destructive actions when True
    out_of_scope: list[str] = field(default_factory=list)
    max_requests_per_second: float = 0.0
    max_total_requests: int = 0
    block_destructive: bool = False
    engagement_name: str = ""

    # Always-allowed domains (DNS, portswigger infra, etc.)
    ALLOWLIST: set[str] = field(default_factory=lambda: {
        "localhost",
        "127.0.0.1",
        "portswigger.net",
        "web-security-academy.net",
        "exploit-server.net",
    })

    # Shell meta-characters that should never appear in run_shell commands
    # from an LLM agent (prevents accidental data exfiltration).
    DANGEROUS_SHELL_PATTERNS: list[re.Pattern] = field(default_factory=lambda: [
        re.compile(r'`[^`]+`'),            # backtick subshell
        re.compile(r'\$\([^)]+\)'),        # $() subshell
        re.compile(r'\|.*(?:nc|ncat|curl|wget|bash|sh|python|ruby|perl)',
                   re.IGNORECASE),         # pipe to network/interpreter
        re.compile(r'>\s*/dev/tcp/',       # bash /dev/tcp redirect
                   re.IGNORECASE),
    ])

    # Obviously-destructive patterns blocked when block_destructive is set
    # (i.e. an engagement with allow_destructive=false is loaded). These are
    # never active on the default lab path.
    DESTRUCTIVE_PATTERNS: list[re.Pattern] = field(default_factory=lambda: [
        re.compile(r'\brm\s+-[a-z]*r[a-z]*f', re.IGNORECASE),   # rm -rf / -Rf
        re.compile(r'\brm\s+-[a-z]*f[a-z]*r', re.IGNORECASE),   # rm -fr
        re.compile(r'\bmkfs\b', re.IGNORECASE),
        re.compile(r'\bdd\s+if=', re.IGNORECASE),
        re.compile(r'>\s*/dev/(?:sd[a-z]|nvme\d|null\s*;)', re.IGNORECASE),
        re.compile(r'\b(?:shutdown|reboot|halt|poweroff|init\s+0)\b', re.IGNORECASE),
        re.compile(r':\s*\(\s*\)\s*\{', re.IGNORECASE),         # fork bomb
        re.compile(r'\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b', re.IGNORECASE),
        re.compile(r'\bTRUNCATE\s+TABLE\b', re.IGNORECASE),
        re.compile(r'\bDELETE\s+FROM\b', re.IGNORECASE),
        re.compile(r'\bUPDATE\s+\w+\s+SET\b.*\bWHERE\b', re.IGNORECASE),
        re.compile(r'\bchmod\s+-R\s+0{3}\b', re.IGNORECASE),
        re.compile(r'\bkill\s+-9\s+-1\b', re.IGNORECASE),
    ])

    # The classic PortSwigger "delete the user carlos" win condition is NOT a
    # destructive action against a real client asset. When one of the delete-
    # family patterns matches but this benign lab marker is present, allow it.
    LAB_SAFE_DELETE_MARKER: re.Pattern = field(
        default_factory=lambda: re.compile(r'\b(?:carlos|wiener)\b', re.IGNORECASE)
    )

    def __post_init__(self) -> None:
        # Rate-limit / request-cap state. Kept off the dataclass fields so the
        # public repr stays clean; time/sleep are indirected for testability.
        self._request_count = 0
        self._last_request_time: float | None = None
        self._rate_lock = threading.Lock()
        self._now = time.monotonic
        self._sleep = time.sleep

    @classmethod
    def from_target_url(cls, target_url: str,
                        extra_domains: list[str] | None = None,
                        extra_cidrs: list[str] | None = None) -> "ScopeGuard":
        """Build a ScopeGuard from a target URL, automatically extracting
        the domain and optionally adding extra allowed domains/CIDRs."""
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        domain = parsed.hostname or ""
        domains = [domain] if domain else []
        if extra_domains:
            domains.extend(extra_domains)
        return cls(
            allowed_domains=domains,
            allowed_cidrs=extra_cidrs or [],
        )

    @classmethod
    def from_engagement(cls, engagement: "Engagement") -> "ScopeGuard":
        """Build a ScopeGuard directly from an engagement contract."""
        guard = cls(
            allowed_domains=list(engagement.authorized_domains),
            allowed_cidrs=list(engagement.authorized_cidrs),
        )
        guard.attach_engagement(engagement)
        return guard

    def attach_engagement(self, engagement: "Engagement") -> None:
        """Install an engagement's rules of engagement into this guard.

        Merges the engagement's authorized scope into the allowlist and turns
        on the out-of-scope denylist, rate limit, request cap, and destructive-
        action block. Called on the orchestrator's scope guard in assessment
        mode; never invoked on the default lab path, so lab behaviour is
        unchanged unless an engagement is explicitly attached.

        Duck-typed on the ``Engagement`` attributes so ``scope.py`` needs no
        import of ``engagement.py`` (avoids an import cycle).
        """
        for domain in getattr(engagement, "authorized_domains", []) or []:
            if domain and domain not in self.allowed_domains:
                self.allowed_domains.append(domain)
        for cidr in getattr(engagement, "authorized_cidrs", []) or []:
            if cidr and cidr not in self.allowed_cidrs:
                self.allowed_cidrs.append(cidr)
        self.out_of_scope = list(getattr(engagement, "out_of_scope", []) or [])
        self.max_requests_per_second = float(
            getattr(engagement, "max_requests_per_second", 0.0) or 0.0
        )
        self.max_total_requests = int(
            getattr(engagement, "max_total_requests", 0) or 0
        )
        self.block_destructive = not bool(
            getattr(engagement, "allow_destructive", False)
        )
        self.engagement_name = str(getattr(engagement, "engagement_name", "") or "")

    # ---- public API ------------------------------------------------------

    def validate(self, tool_name: str, args: dict) -> None:
        """Validate a tool call against the scope. Raises ScopeViolation."""
        targets = self._extract_targets(tool_name, args)
        if tool_name == "run_shell":
            self._validate_shell_safety(args.get("command", ""))
        # Destructive-action block only fires when an engagement with
        # allow_destructive=false is attached. On the default lab path
        # block_destructive is False, so this is a no-op and lab solving
        # (including the "delete carlos" win condition) is unaffected.
        if self.block_destructive:
            self._validate_not_destructive(tool_name, args)
        if not targets:
            return  # tools with no target (list_dir, analyze_response) pass

        for target in targets:
            if self._is_out_of_scope(target):
                raise ScopeViolation(
                    f"SCOPE VIOLATION (out-of-scope denylist): tool={tool_name}, "
                    f"target={target!r} matches out_of_scope {self.out_of_scope}"
                )
            if not self._is_in_scope(target):
                raise ScopeViolation(
                    f"SCOPE VIOLATION: tool={tool_name}, "
                    f"target={target!r} is outside allowed scope "
                    f"(allowed: {self.allowed_domains + self.allowed_cidrs})"
                )

        # Enforce RoE request budget only for calls that actually reach a
        # scoped target (after they pass the scope checks above). Non-throwing
        # scope probes go through is_in_scope() and never consume budget.
        self._enforce_request_budget(tool_name)

    def is_in_scope(self, url_or_host: str) -> bool:
        """Non-throwing scope check (useful for filtering, not gating).

        Honours the out-of-scope denylist and does NOT consume the rate limit
        or request-cap budget (it is a read-only predicate, not a gate).
        """
        if not url_or_host:
            return True
        if self._is_out_of_scope(url_or_host):
            return False
        return self._is_in_scope(url_or_host)

    # ---- internals -------------------------------------------------------

    def _extract_target(self, tool_name: str, args: dict) -> str | None:
        """Pull the network target from a tool call's args."""
        targets = self._extract_targets(tool_name, args)
        return targets[0] if targets else None

    def _extract_targets(self, tool_name: str, args: dict) -> list[str]:
        """Pull network targets from a tool call's args."""
        if tool_name in ("http_request", "browser_navigate",
                         "browser_execute_js", "browser_interact"):
            return self._dedupe([args.get("url", "")])
        if tool_name in ("capture_baseline", "diff_against_baseline",
                         "nuclei_scan", "extract_js_endpoints",
                         "ffuf_fuzz", "sqlmap_run"):
            return self._dedupe([args.get("url", "")])
        if tool_name == "request_smuggling_probe":
            return self._dedupe([args.get("url", "")])
        # Racing sender + SSTI probe hit the target app directly via its URL.
        if tool_name in ("race_send", "ssti_probe"):
            return self._dedupe([args.get("url", "")])
        # External recon that reaches the target host (Shodan/Censys query their
        # own APIs about an asset and do not touch the target, so are unscoped).
        if tool_name == "dns_recon":
            return self._dedupe([args.get("domain", "")])
        if tool_name == "tls_info":
            return self._dedupe([args.get("target", "")])
        # jwt_tool is token-only unless an explicit exploit target URL is given.
        if tool_name == "jwt_tool":
            return self._dedupe([args.get("target_url", "")])
        if tool_name == "nmap_scan":
            return self._dedupe([args.get("target", "")])
        if tool_name == "metasploit_run":
            opts = args.get("options", {})
            if isinstance(opts, dict):
                return self._dedupe([
                    str(opts.get("RHOSTS", "")),
                    str(opts.get("RHOST", "")),
                ])
            return []
        if tool_name == "pwn_template":
            return self._dedupe([args.get("remote_host", "")])
        if tool_name == "discover_apis":
            return self._dedupe([args.get("base_url", "")])
        if tool_name == "caido_local_api":
            return self._extract_caido_local_targets(args)
        if tool_name.startswith("burp_"):
            return self._dedupe([args.get("hostname", "")])
        if tool_name == "run_shell":
            return self._extract_shell_targets(args.get("command", ""))
        return []

    def _extract_caido_local_targets(self, args: dict) -> list[str]:
        op_args = args.get("args", {}) if isinstance(args.get("args", {}), dict) else {}
        operation = args.get("operation", "")
        if operation in {"send_raw", "create_replay_session"}:
            return self._dedupe([op_args.get("hostname", "")])
        if operation == "raw_bridge_request":
            json_body = op_args.get("json_body", {})
            if isinstance(json_body, dict):
                return self._dedupe([
                    json_body.get("hostname", ""),
                    json_body.get("host", ""),
                    json_body.get("url", ""),
                ])
        return []

    def _extract_shell_targets(self, command: str) -> list[str]:
        """Extract direct network targets from common non-interactive tools.

        Payload arguments such as curl -d 'url=http://169.254.169.254/...' are
        skipped: for SSRF labs the internal URL is data sent to the in-scope
        app, not the tool's direct destination.
        """
        command = command or ""
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            tokens = command.split()

        if len(tokens) >= 3 and tokens[0] in {"bash", "sh"} and tokens[1] == "-c":
            return self._extract_shell_targets(tokens[2])
        if not tokens:
            return []

        targets: list[str] = []
        data_flags = {
            "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
            "-H", "--header", "-b", "--cookie", "-c", "--cookie-jar",
            "-A", "--user-agent", "-o", "--output", "-w", "--write-out",
            "-X", "--request", "--proxy", "-x",
        }
        target_flags = {"-u", "--url", "-h", "--host"}
        network_tools = {
            "curl", "wget", "sqlmap", "ffuf", "gobuster", "dirb", "wfuzz",
            "nuclei", "nikto", "nmap", "whatweb", "sslscan", "testssl",
            "hydra", "subfinder", "httpx", "httprobe",
        }
        command_names = {self._basename(t) for t in tokens}
        if not command_names.intersection(network_tools):
            return []

        skip_next = False
        expect_target = False
        for token in tokens:
            base = self._basename(token)
            if skip_next:
                skip_next = False
                continue
            if token in data_flags:
                skip_next = True
                continue
            if token.startswith("--data=") or token.startswith("--header="):
                continue
            if token in target_flags:
                expect_target = True
                continue
            if any(token.startswith(f"{flag}=") for flag in target_flags):
                targets.append(token.split("=", 1)[1])
                continue
            if base in network_tools or token.startswith("-"):
                continue
            if expect_target:
                targets.append(token)
                expect_target = False
                continue
            if self._looks_like_direct_target(token):
                targets.append(token)

        return self._dedupe(targets)

    def _looks_like_direct_target(self, token: str) -> bool:
        token = token.strip(" '\"")
        if not token:
            return False
        if token.startswith(("http://", "https://")):
            return True
        if "/" in token or "\\" in token:
            return False
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$", token):
            return True
        return bool(re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?$", token))

    def _basename(self, token: str) -> str:
        return token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    def _dedupe(self, targets: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for target in targets:
            if not target:
                continue
            cleaned = str(target).strip().strip("'\"")
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                out.append(cleaned)
        return out

    def _is_in_scope(self, target: str) -> bool:
        """Check if a target URL/host is within the allowed scope."""
        if not target:
            return True

        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target

        # Allowlist check (always-permitted domains)
        for allowed in self.ALLOWLIST:
            if host == allowed or host.endswith(f".{allowed}"):
                return True

        # Explicit domain check
        for domain in self.allowed_domains:
            if host == domain:
                return True
            if self.include_subdomains and host.endswith(f".{domain}"):
                return True

        # CIDR check (for IP targets)
        try:
            target_ip = ipaddress.ip_address(host)
            for cidr in self.allowed_cidrs:
                if target_ip in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass  # Not an IP — domain check already failed

        return False

    def _validate_shell_safety(self, command: str) -> None:
        """Block dangerous shell meta-characters in run_shell commands."""
        for pattern in self.DANGEROUS_SHELL_PATTERNS:
            match = pattern.search(command)
            if match:
                raise ScopeViolation(
                    f"SHELL SAFETY: blocked dangerous pattern "
                    f"{match.group()!r} in command: {command[:120]}"
                )

    def _is_out_of_scope(self, target: str) -> bool:
        """True if the target matches the engagement's out-of-scope denylist.

        A denylist entry matches its exact host and any subdomain of it, so
        listing ``payments.example.com`` excludes that host even though
        ``example.com`` is authorized.
        """
        if not target or not self.out_of_scope:
            return False
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = (parsed.hostname or target).lower()
        for denied in self.out_of_scope:
            d = denied.strip().lower()
            if not d:
                continue
            if host == d or host.endswith(f".{d}"):
                return True
        return False

    def _destructive_text(self, tool_name: str, args: dict) -> str:
        """Build the text blob scanned for destructive patterns.

        Only the fields that can carry an executable action / SQL payload are
        included, so a benign URL that merely contains the word "delete" in a
        path is not scanned as a shell/SQL command.
        """
        if not isinstance(args, dict):
            return str(args)
        parts: list[str] = []
        if tool_name == "run_shell":
            parts.append(str(args.get("command", "")))
        parts.append(str(args.get("data", "")))
        parts.append(str(args.get("query", "")))
        parts.append(str(args.get("payload", "")))
        parts.append(str(args.get("body", "")))
        parts.append(str(args.get("raw_request", "")))
        return "\n".join(p for p in parts if p)

    def _validate_not_destructive(self, tool_name: str, args: dict) -> None:
        """Block obviously destructive actions when destructive mode is off."""
        blob = self._destructive_text(tool_name, args)
        if not blob:
            return
        for pattern in self.DESTRUCTIVE_PATTERNS:
            match = pattern.search(blob)
            if not match:
                continue
            token = match.group()
            is_delete_family = token.strip().lower().startswith(
                ("delete", "update")
            )
            if is_delete_family and self.LAB_SAFE_DELETE_MARKER.search(blob):
                continue
            raise ScopeViolation(
                f"DESTRUCTIVE ACTION BLOCKED (allow_destructive=false): "
                f"pattern {token!r} in {tool_name} call. Enable allow_destructive "
                f"in the engagement config to permit this."
            )

    def _enforce_request_budget(self, tool_name: str) -> None:
        """Enforce the engagement rate limit + hard request cap.

        - max_total_requests: raises RateLimitExceeded once the cap is hit.
        - max_requests_per_second: a simple min-interval limiter that sleeps
          just long enough to keep the average scoped request rate at or below
          the configured ceiling.

        Both are inert (0 = unlimited) on the default lab path.
        """
        if self.max_total_requests <= 0 and self.max_requests_per_second <= 0:
            return
        with self._rate_lock:
            if self.max_total_requests > 0:
                if self._request_count >= self.max_total_requests:
                    raise RateLimitExceeded(
                        f"MAX REQUESTS EXCEEDED: engagement cap of "
                        f"{self.max_total_requests} scoped requests reached "
                        f"(tool={tool_name})."
                    )
                self._request_count += 1
            if self.max_requests_per_second > 0:
                min_interval = 1.0 / self.max_requests_per_second
                now = self._now()
                if self._last_request_time is not None:
                    elapsed = now - self._last_request_time
                    wait = min_interval - elapsed
                    if wait > 0:
                        self._sleep(wait)
                        now = self._now()
                self._last_request_time = now

    def requests_made(self) -> int:
        """Number of scoped requests counted against the engagement cap."""
        return self._request_count

    def describe(self) -> str:
        """Human-readable scope summary for logging / prompt injection."""
        parts = [f"Scope: domains={self.allowed_domains}"]
        if self.allowed_cidrs:
            parts.append(f"cidrs={self.allowed_cidrs}")
        parts.append(f"subdomains={'yes' if self.include_subdomains else 'no'}")
        if self.out_of_scope:
            parts.append(f"out_of_scope={self.out_of_scope}")
        if self.max_requests_per_second:
            parts.append(f"rps<={self.max_requests_per_second}")
        if self.max_total_requests:
            parts.append(f"max_requests={self.max_total_requests}")
        if self.engagement_name or self.block_destructive:
            parts.append(
                f"engagement={self.engagement_name or 'unnamed'} "
                f"(destructive={'blocked' if self.block_destructive else 'allowed'})"
            )
        return ", ".join(parts)
