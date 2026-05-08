"""
=============================================================================
Reynard — Cleanup Registry
=============================================================================
Tracks exploit side-effects (files created, sessions opened, test users
registered) and runs cleanup functions on normal exit, SIGINT, or crash.

Inspired by Pentest-Swarm-AI's cleanup pattern where every exploit adapter
registers a rollback function that survives cancellation via a detached
context.

Usage
─────
  registry = CleanupRegistry()
  registry.register(
      lambda: run_shell("rm /tmp/test_payload.txt"),
      description="Remove test payload file",
      agent="exploitation",
  )
  # ... on exit ...
  registry.run_all()   # runs in reverse order (LIFO)
=============================================================================
"""
from __future__ import annotations

import atexit
import signal
import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from rich.console import Console

console = Console()


@dataclass
class CleanupEntry:
    """A registered cleanup action."""
    fn: Callable[[], None]
    description: str
    agent: str = ""
    registered_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )


class CleanupRegistry:
    """LIFO cleanup registry with automatic atexit / signal hooks.

    Thread-safe. Cleanup functions are run in reverse order (most recently
    registered first). Failures are logged but never propagate — cleanup
    must be best-effort.
    """

    def __init__(self, install_hooks: bool = True):
        self._lock = threading.RLock()
        self._entries: list[CleanupEntry] = []
        self._ran = False

        if install_hooks:
            atexit.register(self.run_all)
            # Install SIGINT / SIGTERM handlers that call cleanup before
            # re-raising. We store the originals so we can restore them.
            self._orig_sigint = signal.getsignal(signal.SIGINT)
            self._orig_sigterm = signal.getsignal(signal.SIGTERM)
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)

    # ---- public API ------------------------------------------------------

    def register(self, fn: Callable[[], None], description: str,
                 agent: str = "") -> None:
        """Register a cleanup function. Runs in LIFO order on run_all()."""
        with self._lock:
            self._entries.append(CleanupEntry(
                fn=fn, description=description, agent=agent,
            ))

    def run_all(self) -> list[str]:
        """Execute all registered cleanups in reverse order.

        Returns a list of human-readable status strings.
        Safe to call multiple times — only runs once.
        """
        with self._lock:
            if self._ran:
                return ["(cleanup already executed)"]
            self._ran = True
            entries = list(reversed(self._entries))

        if not entries:
            return ["(no cleanups registered)"]

        console.print(f"\n[yellow bold]🧹 Running {len(entries)} cleanup(s)...[/]")
        results: list[str] = []

        for entry in entries:
            try:
                entry.fn()
                msg = f"  ✅ {entry.description} (agent={entry.agent})"
                console.print(f"[green]{msg}[/]")
                results.append(msg)
            except Exception as e:
                msg = (f"  ❌ FAILED: {entry.description} "
                       f"(agent={entry.agent}): {e}")
                console.print(f"[red]{msg}[/]")
                traceback.print_exc()
                results.append(msg)

        return results

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def describe(self) -> str:
        """Human-readable summary for prompt injection / logging."""
        with self._lock:
            if not self._entries:
                return "Cleanup registry: (empty)"
            lines = [f"Cleanup registry ({len(self._entries)} entries):"]
            for entry in self._entries:
                lines.append(
                    f"  - [{entry.agent}] {entry.description} "
                    f"(registered {entry.registered_at})"
                )
            return "\n".join(lines)

    # ---- internals -------------------------------------------------------

    def _signal_handler(self, signum, frame):
        """Handle SIGINT/SIGTERM: run cleanup then re-raise."""
        self.run_all()
        # Restore original handler and re-raise
        if signum == signal.SIGINT and self._orig_sigint:
            signal.signal(signal.SIGINT, self._orig_sigint)
        elif signum == signal.SIGTERM and self._orig_sigterm:
            signal.signal(signal.SIGTERM, self._orig_sigterm)
        # Re-raise the signal
        signal.raise_signal(signum)
