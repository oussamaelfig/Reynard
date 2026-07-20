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
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeViolation(RuntimeError):
    """Raised when a tool call targets a domain outside the allowed scope."""


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

    # Always-allowed domains (DNS, portswigger infra, etc.)
    ALLOWLIST: set[str] = field(default_factory=lambda: {
        "localhost",
        "127.0.0.1",
        "portswigger.net",
        "web-security-academy.net",
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

    # ---- public API ------------------------------------------------------

    def validate(self, tool_name: str, args: dict) -> None:
        """Validate a tool call against the scope. Raises ScopeViolation."""
        targets = self._extract_targets(tool_name, args)
        if tool_name == "run_shell":
            self._validate_shell_safety(args.get("command", ""))
        if not targets:
            return  # tools with no target (list_dir, analyze_response) pass

        for target in targets:
            if not self._is_in_scope(target):
                raise ScopeViolation(
                    f"SCOPE VIOLATION: tool={tool_name}, "
                    f"target={target!r} is outside allowed scope "
                    f"(allowed: {self.allowed_domains + self.allowed_cidrs})"
                )

    def is_in_scope(self, url_or_host: str) -> bool:
        """Non-throwing scope check (useful for filtering, not gating)."""
        try:
            self.validate("http_request", {"url": url_or_host})
            return True
        except ScopeViolation:
            return False

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

    def describe(self) -> str:
        """Human-readable scope summary for logging / prompt injection."""
        parts = [f"Scope: domains={self.allowed_domains}"]
        if self.allowed_cidrs:
            parts.append(f"cidrs={self.allowed_cidrs}")
        parts.append(f"subdomains={'yes' if self.include_subdomains else 'no'}")
        return ", ".join(parts)
