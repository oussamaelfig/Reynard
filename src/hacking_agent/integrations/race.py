"""
=============================================================================
Reynard — Turbo-Intruder-style batch / racing HTTP sender
=============================================================================
A dependency-light, Python-side concurrent request sender for the attack
classes the Burp MCP cannot drive precisely from an agent loop:

  - HTTP request smuggling / desync verification (fire the smuggle then a
    normal follow-up on a controlled schedule).
  - Race conditions (limit-overrun, TOCTOU) — many identical requests fired
    as close together as possible.
  - Brute-force / batch fuzzing where per-request status + timing matters.

It talks raw sockets over TLS/plain TCP (no curl/browser normalization) so
request bytes are sent verbatim, and it supports a last-byte-synchronized
"single-packet"-style release that lines up N in-flight requests before
completing them together — the classic HTTP/1.1 race primitive.

Nothing here is imported for its side effects; the sender is pure stdlib
(socket / ssl / threading) so it never fails at import time.
=============================================================================
"""
from __future__ import annotations

import socket
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlparse


DEFAULT_COUNT = 20
MAX_COUNT = 200
DEFAULT_TIMEOUT = 10.0


def _parse_target(url: str) -> tuple[str, int, bool, str]:
    """Split a URL into (host, port, https, path?query)."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"Could not parse host from URL: {url!r}")
    https = parsed.scheme != "http"
    port = parsed.port or (443 if https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return host, port, https, path


def _build_request(host: str, path: str, method: str,
                   headers: dict[str, str] | None, body: str) -> bytes:
    """Assemble a raw HTTP/1.1 request. Connection: close for clean reads."""
    method = (method or "GET").upper()
    hdrs: dict[str, str] = {
        "Host": host,
        "User-Agent": "Reynard-race-sender",
        "Accept": "*/*",
        "Connection": "close",
    }
    for key, value in (headers or {}).items():
        # Preserve caller-supplied header casing but let it override defaults.
        for existing in list(hdrs):
            if existing.lower() == str(key).lower():
                hdrs.pop(existing)
        hdrs[str(key)] = str(value)

    body_bytes = (body or "").encode("utf-8")
    if body_bytes and not any(k.lower() == "content-length" for k in hdrs):
        hdrs["Content-Length"] = str(len(body_bytes))

    lines = [f"{method} {path} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in hdrs.items()]
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body_bytes
    return raw


def _connect(host: str, port: int, https: bool, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _read_response(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
    except (socket.timeout, TimeoutError, ssl.SSLError, OSError):
        pass
    return b"".join(chunks)


def _status_of(response: bytes) -> int | None:
    try:
        first = response.split(b"\r\n", 1)[0].decode("latin-1")
        parts = first.split(" ")
        if len(parts) >= 2 and parts[0].startswith("HTTP"):
            return int(parts[1])
    except (ValueError, IndexError):
        return None
    return None


def _summarize(results: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    ok = 0
    for item in results:
        if item.get("error"):
            statuses["error"] = statuses.get("error", 0) + 1
            continue
        ok += 1
        key = str(item.get("status"))
        statuses[key] = statuses.get(key, 0) + 1
    elapsed = [r["elapsed_ms"] for r in results if r.get("elapsed_ms") is not None]
    spread = round(max(elapsed) - min(elapsed), 2) if elapsed else None
    distinct = sorted(k for k in statuses if k not in ("None", "error"))
    return {
        "mode": mode,
        "sent": len(results),
        "responded": ok,
        "status_distribution": statuses,
        "distinct_statuses": distinct,
        "release_spread_ms": spread,
        "summary": (
            f"race_send[{mode}]: sent={len(results)} responded={ok} "
            f"statuses={statuses} spread={spread}ms"
        ),
    }


def race_send(url: str, count: int = DEFAULT_COUNT, concurrency: int = 0,
              method: str = "GET", headers: dict[str, str] | None = None,
              body: str = "", mode: str = "parallel",
              timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Fire ``count`` HTTP requests with controlled concurrency / timing.

    mode:
      - "parallel":   all workers block on a barrier, then send their full
                      request simultaneously (good for race conditions).
      - "single_packet" / "last_byte": open all connections and send every
                      request except its final byte, synchronize, then release
                      the last byte on all connections together (tightest
                      HTTP/1.1 race window; good for limit-overrun / desync).

    Returns per-request status/timing plus an aggregate summary.
    """
    try:
        host, port, https, path = _parse_target(url)
    except ValueError as exc:
        return {"error": str(exc)}

    count = max(1, min(int(count or DEFAULT_COUNT), MAX_COUNT))
    conc = int(concurrency) if concurrency else count
    conc = max(1, min(conc, count))
    mode = (mode or "parallel").lower()
    last_byte = mode in ("single_packet", "last_byte", "single-packet")
    request = _build_request(host, path, method, headers, body)

    results: list[dict[str, Any]] = [{} for _ in range(count)]
    barrier = threading.Barrier(conc if not last_byte else count)
    started = time.monotonic()

    def worker(index: int) -> None:
        record: dict[str, Any] = {"index": index}
        sock: socket.socket | None = None
        try:
            sock = _connect(host, port, https, timeout)
            if last_byte and len(request) > 1:
                sock.sendall(request[:-1])
                barrier.wait(timeout=timeout + 5)
                send_at = time.monotonic()
                sock.sendall(request[-1:])
            else:
                barrier.wait(timeout=timeout + 5)
                send_at = time.monotonic()
                sock.sendall(request)
            response = _read_response(sock, timeout)
            record["status"] = _status_of(response)
            record["length"] = len(response)
            record["elapsed_ms"] = round((time.monotonic() - send_at) * 1000, 2)
        except threading.BrokenBarrierError:
            record["error"] = "barrier timeout (a worker failed to connect)"
        except Exception as exc:  # noqa: BLE001 — surface per-request failure
            record["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        results[index] = record

    # For last-byte mode every connection must be open before release, so all
    # workers run at once. For parallel mode we honor the concurrency window.
    if last_byte:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=timeout + 10)
    else:
        remaining = list(range(count))
        while remaining:
            wave = remaining[:conc]
            remaining = remaining[conc:]
            barrier = threading.Barrier(len(wave))
            threads = [threading.Thread(target=worker, args=(i,)) for i in wave]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=timeout + 10)

    report = _summarize(results, "single_packet" if last_byte else "parallel")
    report.update({
        "target": {"host": host, "port": port, "https": https, "path": path},
        "concurrency": count if last_byte else conc,
        "total_elapsed_ms": round((time.monotonic() - started) * 1000, 2),
        "results": results,
    })
    return report
