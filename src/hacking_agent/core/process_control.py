"""Bounded cleanup for subprocesses started in their own POSIX sessions.

This controls host descendants. Docker daemon jobs and remote executions require
their own cancellation contract; killing a docker client does not supply one.
"""
from __future__ import annotations

import os
import math
import signal
import subprocess


class ProcessCleanupError(RuntimeError):
    """Host process-tree cleanup could not be confirmed; do not launch more work."""


def stop_process_tree(proc: subprocess.Popen, *, grace_seconds: float = 2.0) -> None:
    """Stop the owned process tree and reap the direct child, or raise.

    POSIX callers must create the process with ``start_new_session=True``.
    """
    if not math.isfinite(grace_seconds) or grace_seconds < 0:
        raise ValueError("grace_seconds must be finite and nonnegative")
    cleanup_error: Exception | None = None
    if os.name == "nt":
        if proc.poll() is None:
            try:
                completed = subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False, timeout=max(grace_seconds, 1.0) + 5.0,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if completed.returncode != 0:
                    cleanup_error = RuntimeError("taskkill did not confirm tree termination")
            except (OSError, subprocess.SubprocessError) as exc:
                cleanup_error = exc
    else:
        try:
            getattr(os, "killpg")(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as exc:
            cleanup_error = exc
    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError as exc:
            cleanup_error = exc
    except OSError as exc:
        raise ProcessCleanupError("Could not wait for the target worker") from exc
    if os.name != "nt":
        # Reap stubborn descendants even when the parent exited on SIGTERM.
        try:
            getattr(os, "killpg")(proc.pid, getattr(signal, "SIGKILL"))
        except ProcessLookupError:
            pass
        except OSError as exc:
            cleanup_error = exc
    try:
        proc.wait(timeout=max(grace_seconds, 1.0))
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProcessCleanupError("Could not reap the target worker") from exc
    if cleanup_error is not None:
        raise ProcessCleanupError("Could not confirm host process-tree termination") from cleanup_error
