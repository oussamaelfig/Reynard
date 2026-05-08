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
        parsed = urlparse(target_url)
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
        # Extract target from tool args
        target = self._extract_target(tool_name, args)
        if not target:
            return  # tools with no target (list_dir, analyze_response) pass

        # Check domain / IP
        if not self._is_in_scope(target):
            raise ScopeViolation(
                f"SCOPE VIOLATION: tool={tool_name}, "
                f"target={target!r} is outside allowed scope "
                f"(allowed: {self.allowed_domains + self.allowed_cidrs})"
            )

        # Check shell safety
        if tool_name == "run_shell":
            self._validate_shell_safety(args.get("command", ""))

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
        if tool_name in ("http_request", "browser_navigate",
                         "browser_execute_js", "browser_interact"):
            return args.get("url", "")
        if tool_name == "run_shell":
            # Extract URLs from curl/wget commands
            cmd = args.get("command", "")
            urls = re.findall(r'https?://[^\s\'"]+', cmd)
            return urls[0] if urls else None
        # read_file, write_file, list_dir, analyze_response → no network target
        return None

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
