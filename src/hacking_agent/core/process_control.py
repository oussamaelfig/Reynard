"""Bounded cleanup for subprocesses started in their own POSIX sessions.

This controls host descendants. Docker daemon jobs and remote executions require
their own cancellation contract; killing a docker client does not supply one.
"""
from __future__ import annotations

import os
import signal
import subprocess


def stop_process_tree(proc: subprocess.Popen, *, grace_seconds: float = 2.0) -> None:
    """Stop the owned process tree and reap the direct child, or raise.

    POSIX callers must create the process with ``start_new_session=True``.
    """
    if os.name == "nt":
        if proc.poll() is None:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=max(grace_seconds, 1.0) + 5.0,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
    if os.name != "nt":
        # Reap stubborn descendants even when the parent exited on SIGTERM.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    proc.wait(timeout=max(grace_seconds, 1.0))
