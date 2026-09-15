"""
=============================================================================
Reynard — Structured recon wrappers
=============================================================================
Thin, typed wrappers around the ProjectDiscovery-style recon toolchain plus a
couple of passive OSINT sources. The point of this module is to turn noisy
tool output into STRUCTURED records the researcher can reason over, and to feed
those records straight into the persistent Attack Surface model — instead of
dumping thousands of raw lines into an LLM prompt.

Covered sources:
  - subfinder      passive subdomain enumeration        (container CLI)
  - dnsx           DNS resolution (A/AAAA/CNAME)         (container CLI)
  - httpx          HTTP probing (status/title/tech)      (container CLI)
  - naabu          fast port scan                        (container CLI)
  - katana         crawler (endpoints/params/js)         (container CLI)
  - waybackurls    historical URLs                       (container CLI)
  - crt.sh         certificate transparency subdomains   (HTTP)
  - urlscan.io     passive URL/domain intel              (HTTP, key optional)

Design:
  - Each parser is a PURE function of raw tool output -> list[ReconRecord],
    unit-testable with captured samples and NEVER touching the network.
  - Each runner executes the tool (via an injectable ``runner``/``fetch`` so
    tests stay hermetic) and returns a ``ReconResult`` that degrades gracefully
    when the tool/key is unavailable (available=False), so a missing binary is
    a structured no-op rather than a crash.
  - ``ingest_recon_result`` folds records into an AttackSurface with provenance
    tagged to the originating tool.
=============================================================================
"""
from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from hacking_agent.core import attack_surface as asm


# =============================================================================
# Records
# =============================================================================

@dataclass
class ReconRecord:
    """One structured discovery from a recon tool.

    ``kind`` is an Attack-Surface asset kind hint (subdomain/ip/endpoint/js/
    technology/service/url); ``identifier`` is the normalized value; ``attrs``
    carries kind-specific metadata (status_code, method, port, version, ...).
    """
    kind: str
    identifier: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconResult:
    tool: str
    available: bool = True
    ok: bool = True
    records: list[ReconRecord] = field(default_factory=list)
    summary: str = ""
    error: str = ""
    raw_excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "available": self.available,
            "ok": self.ok,
            "count": len(self.records),
            "records": [{"kind": r.kind, "identifier": r.identifier, "attrs": r.attrs}
                        for r in self.records],
            "summary": self.summary or self._auto_summary(),
            "error": self.error,
        }

    def _auto_summary(self) -> str:
        if not self.available:
            return f"{self.tool} not available in runtime"
        by_kind: dict[str, int] = {}
        for r in self.records:
            by_kind[r.kind] = by_kind.get(r.kind, 0) + 1
        if not by_kind:
            return f"{self.tool}: no results"
        return f"{self.tool}: " + ", ".join(f"{n} {k}" for k, n in sorted(by_kind.items()))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


# =============================================================================
# Helpers
# =============================================================================

def _iter_json_lines(stdout: str):
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue


def _strip_wildcard(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    return host


def _is_js(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(".js") or path.endswith(".mjs")


# =============================================================================
# Parsers (pure)
# =============================================================================

def parse_subfinder(stdout: str) -> list[ReconRecord]:
    """subfinder -silent (one host/line) or -oJ/-json ({"host": ...})."""
    out: list[ReconRecord] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        host = ""
        if line.startswith("{"):
            try:
                host = str(json.loads(line).get("host", "")).strip().lower()
            except (json.JSONDecodeError, TypeError):
                host = ""
        else:
            host = line.lower()
        host = _strip_wildcard(host)
        if host and host not in seen and "." in host:
            seen.add(host)
            out.append(ReconRecord(kind=asm.KIND_SUBDOMAIN, identifier=host))
    return out


def parse_dnsx(stdout: str) -> list[ReconRecord]:
    """dnsx -json: {"host":..., "a":[...], "aaaa":[...], "cname":[...]}."""
    out: list[ReconRecord] = []
    for obj in _iter_json_lines(stdout):
        host = str(obj.get("host", "")).strip().lower()
        if host:
            out.append(ReconRecord(kind=asm.KIND_SUBDOMAIN, identifier=host,
                                   attrs={"resolved": True}))
        for ip in list(obj.get("a", []) or []) + list(obj.get("aaaa", []) or []):
            if ip:
                out.append(ReconRecord(kind=asm.KIND_IP, identifier=str(ip),
                                       attrs={"host": host}))
        for cname in (obj.get("cname", []) or []):
            if cname:
                out.append(ReconRecord(kind=asm.KIND_SUBDOMAIN,
                                       identifier=str(cname).lower(),
                                       attrs={"cname_of": host}))
    return out


def parse_httpx(stdout: str) -> list[ReconRecord]:
    """httpx -json: url/status_code/title/webserver/tech/content_type/a."""
    out: list[ReconRecord] = []
    for obj in _iter_json_lines(stdout):
        url = str(obj.get("url") or obj.get("input") or "").strip()
        if not url:
            continue
        status = obj.get("status_code") or obj.get("status-code")
        attrs: dict[str, Any] = {"method": "GET"}
        if status is not None:
            attrs["status_code"] = status
        for k_src in ("content_type", "content-type"):
            if obj.get(k_src):
                attrs["content_type"] = obj[k_src]
                break
        if obj.get("title"):
            attrs["title"] = obj["title"]
        out.append(ReconRecord(kind=asm.KIND_ENDPOINT, identifier=url, attrs=attrs))
        # webserver + tech stack -> technology records
        techs = list(obj.get("tech", []) or obj.get("technologies", []) or [])
        webserver = obj.get("webserver") or obj.get("web-server")
        if webserver:
            techs.append(webserver)
        host = urlsplit(url).hostname or ""
        for t in techs:
            if t:
                out.append(ReconRecord(kind=asm.KIND_TECHNOLOGY, identifier=str(t),
                                       attrs={"host": host, "name": str(t)}))
        for ip in (obj.get("a", []) or []):
            if ip:
                out.append(ReconRecord(kind=asm.KIND_IP, identifier=str(ip),
                                       attrs={"host": host}))
    return out


def parse_naabu(stdout: str) -> list[ReconRecord]:
    """naabu -json: {"host":..., "ip":..., "port":...}."""
    out: list[ReconRecord] = []
    for obj in _iter_json_lines(stdout):
        host = str(obj.get("host", "") or "").strip().lower()
        ip = str(obj.get("ip", "") or "").strip()
        port = obj.get("port")
        if port is None:
            continue
        target = host or ip
        if not target:
            continue
        out.append(ReconRecord(
            kind="service", identifier=f"{target}:{port}",
            attrs={"host": host, "ip": ip, "port": port},
        ))
    return out


def parse_katana(stdout: str) -> list[ReconRecord]:
    """katana -jsonl (new: {"request":{"endpoint","method"}}, old: {"endpoint"})."""
    out: list[ReconRecord] = []
    seen: set[str] = set()
    for obj in _iter_json_lines(stdout):
        req = obj.get("request") or {}
        url = str(req.get("endpoint") or obj.get("endpoint") or obj.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        method = str(req.get("method") or obj.get("method") or "GET").upper()
        resp = obj.get("response") or {}
        attrs: dict[str, Any] = {"method": method}
        status = resp.get("status_code")
        if status is not None:
            attrs["status_code"] = status
        if _is_js(url):
            out.append(ReconRecord(kind=asm.KIND_JS, identifier=url, attrs=attrs))
        else:
            out.append(ReconRecord(kind=asm.KIND_ENDPOINT, identifier=url, attrs=attrs))
    return out


def parse_waybackurls(stdout: str) -> list[ReconRecord]:
    """waybackurls: one URL per line."""
    out: list[ReconRecord] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        url = line.strip()
        if not url or "://" not in url or url in seen:
            continue
        seen.add(url)
        if _is_js(url):
            out.append(ReconRecord(kind=asm.KIND_JS, identifier=url))
        else:
            out.append(ReconRecord(kind=asm.KIND_ENDPOINT, identifier=url,
                                   attrs={"method": "GET", "historical": True}))
    return out


def parse_crtsh(text: str) -> list[ReconRecord]:
    """crt.sh ?output=json -> [{"name_value": "a.x\nb.x", "common_name": ...}]."""
    out: list[ReconRecord] = []
    seen: set[str] = set()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        # crt.sh sometimes returns concatenated objects; try line-by-line.
        data = list(_iter_json_lines(text))
    if isinstance(data, dict):
        data = [data]
    for entry in data or []:
        names = []
        if isinstance(entry, dict):
            names.append(entry.get("common_name", ""))
            names.extend(str(entry.get("name_value", "")).split("\n"))
        for name in names:
            host = _strip_wildcard(name)
            if host and "." in host and host not in seen:
                seen.add(host)
                out.append(ReconRecord(kind=asm.KIND_SUBDOMAIN, identifier=host,
                                       attrs={"source": "certificate_transparency"}))
    return out


def parse_urlscan(text: str) -> list[ReconRecord]:
    """urlscan.io search API -> {"results":[{"page":{"domain","url"},"task":{"url"}}]}."""
    out: list[ReconRecord] = []
    seen_urls: set[str] = set()
    seen_hosts: set[str] = set()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return out
    for res in (data.get("results", []) if isinstance(data, dict) else []):
        page = res.get("page", {}) if isinstance(res, dict) else {}
        task = res.get("task", {}) if isinstance(res, dict) else {}
        domain = _strip_wildcard(str(page.get("domain", "")))
        if domain and domain not in seen_hosts:
            seen_hosts.add(domain)
            out.append(ReconRecord(kind=asm.KIND_SUBDOMAIN, identifier=domain))
        for url in (page.get("url"), task.get("url")):
            url = str(url or "").strip()
            if url and "://" in url and url not in seen_urls:
                seen_urls.add(url)
                out.append(ReconRecord(kind=asm.KIND_URL, identifier=url))
    return out


# =============================================================================
# Runners
# =============================================================================

# A container runner is any callable(command:str, timeout:int) -> dict with
# keys stdout/stderr/exit_code (matches tools._docker_exec).
Runner = Callable[[str, int], dict]
# An HTTP fetch is any callable(url, headers) -> (status_code:int, text:str).
Fetch = Callable[..., tuple]


def _default_runner() -> Runner:
    from hacking_agent.core.tools import _docker_exec  # lazy: avoid import cycle
    return _docker_exec


def _tool_available(tool: str, runner: Runner) -> bool:
    try:
        return runner(f"command -v {tool}", 5).get("exit_code", -1) == 0
    except Exception:
        return False


def _run_cli(tool: str, command: str, parser, *, runner: Optional[Runner] = None,
             timeout: int = 180) -> ReconResult:
    runner = runner or _default_runner()
    if not _tool_available(tool, runner):
        return ReconResult(tool=tool, available=False, ok=False,
                           summary=f"{tool} not installed in runtime")
    try:
        res = runner(command, timeout)
    except Exception as exc:
        return ReconResult(tool=tool, ok=False, error=str(exc)[:200])
    stdout = res.get("stdout", "") or ""
    records = parser(stdout)
    return ReconResult(tool=tool, records=records, raw_excerpt=stdout[:400])


def run_subfinder(domain: str, *, runner: Optional[Runner] = None,
                  timeout: int = 180) -> ReconResult:
    cmd = f"subfinder -d {shlex.quote(domain)} -silent 2>/dev/null"
    return _run_cli("subfinder", cmd, parse_subfinder, runner=runner, timeout=timeout)


def run_dnsx(hosts: list[str], *, runner: Optional[Runner] = None,
             timeout: int = 120) -> ReconResult:
    joined = "\\n".join(shlex.quote(h)[1:-1] if h else "" for h in hosts if h)
    cmd = f"printf '{joined}\\n' | dnsx -json -silent -a -aaaa -cname 2>/dev/null"
    return _run_cli("dnsx", cmd, parse_dnsx, runner=runner, timeout=timeout)


def run_httpx(targets: list[str], *, runner: Optional[Runner] = None,
              timeout: int = 180) -> ReconResult:
    joined = "\\n".join(shlex.quote(t)[1:-1] if t else "" for t in targets if t)
    cmd = (f"printf '{joined}\\n' | httpx -json -silent -status-code -title "
           f"-tech-detect -web-server 2>/dev/null")
    return _run_cli("httpx", cmd, parse_httpx, runner=runner, timeout=timeout)


def run_naabu(host: str, *, top_ports: str = "1000",
              runner: Optional[Runner] = None, timeout: int = 300) -> ReconResult:
    cmd = f"naabu -host {shlex.quote(host)} -top-ports {shlex.quote(top_ports)} -json -silent 2>/dev/null"
    return _run_cli("naabu", cmd, parse_naabu, runner=runner, timeout=timeout)


def run_katana(url: str, *, depth: int = 2, runner: Optional[Runner] = None,
               timeout: int = 240) -> ReconResult:
    cmd = (f"katana -u {shlex.quote(url)} -jsonl -silent -d {int(depth)} "
           f"-jc -kf all 2>/dev/null")
    return _run_cli("katana", cmd, parse_katana, runner=runner, timeout=timeout)


def run_waybackurls(domain: str, *, runner: Optional[Runner] = None,
                    timeout: int = 120) -> ReconResult:
    cmd = f"echo {shlex.quote(domain)} | waybackurls 2>/dev/null"
    return _run_cli("waybackurls", cmd, parse_waybackurls, runner=runner, timeout=timeout)


def run_crtsh(domain: str, *, fetch: Optional[Fetch] = None,
              timeout: int = 30) -> ReconResult:
    """Certificate-transparency subdomains via crt.sh (HTTP, no key)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    status, text = _http_get(url, fetch=fetch, timeout=timeout)
    if status != 200 or not text:
        return ReconResult(tool="crtsh", ok=False,
                           error=f"crt.sh returned status={status}")
    return ReconResult(tool="crtsh", records=parse_crtsh(text), raw_excerpt=text[:400])


def run_urlscan(domain: str, *, api_key: str = "", fetch: Optional[Fetch] = None,
                timeout: int = 30) -> ReconResult:
    """Passive URL/domain intel from urlscan.io. API key optional (raises the
    rate limit); absence is a graceful degrade, not a failure."""
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    headers = {"API-Key": api_key} if api_key else {}
    status, text = _http_get(url, headers=headers, fetch=fetch, timeout=timeout)
    if status != 200 or not text:
        return ReconResult(tool="urlscan", available=bool(api_key) or status != 0,
                           ok=False, error=f"urlscan returned status={status}")
    return ReconResult(tool="urlscan", records=parse_urlscan(text), raw_excerpt=text[:400])


def _http_get(url: str, *, headers: Optional[dict] = None,
              fetch: Optional[Fetch] = None, timeout: int = 30) -> tuple[int, str]:
    if fetch is not None:
        try:
            return fetch(url, headers=headers or {})
        except TypeError:
            return fetch(url)
    try:
        import httpx  # local dependency
        resp = httpx.get(url, headers=headers or {}, timeout=timeout,
                         follow_redirects=True)
        return resp.status_code, resp.text
    except Exception:
        return 0, ""


# Tool names (in tools.py) that emit ReconResult JSON and should auto-populate
# the attack surface.
RECON_WRAPPER_TOOLS = frozenset({
    "subfinder_scan", "dnsx_resolve", "httpx_probe", "naabu_scan",
    "katana_crawl", "waybackurls_fetch", "crtsh_lookup", "urlscan_lookup",
})


def result_from_json(raw: str) -> Optional[ReconResult]:
    """Reconstruct a ReconResult from a tool's JSON output (best-effort)."""
    try:
        d = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(d, dict) or "records" not in d:
        return None
    records = [
        ReconRecord(kind=r.get("kind", ""), identifier=r.get("identifier", ""),
                    attrs=dict(r.get("attrs") or {}))
        for r in d.get("records", []) if r.get("identifier")
    ]
    return ReconResult(
        tool=d.get("tool", ""), available=bool(d.get("available", True)),
        ok=bool(d.get("ok", True)), records=records,
        summary=d.get("summary", ""), error=d.get("error", ""),
    )


# =============================================================================
# Ingest into the Attack Surface
# =============================================================================

def ingest_recon_result(surface: "asm.AttackSurface", result: ReconResult,
                        *, method: str = "") -> int:
    """Fold a ReconResult's records into an AttackSurface with provenance tagged
    to the originating tool. Returns the number of assets touched.

    Out-of-scope discoveries are still recorded (so the surface is complete and
    the researcher can see what was found) but the ScopeGuard classifier tags
    them out_of_scope; downstream lead-selection excludes them from active
    hunting."""
    if not result or not result.records:
        return 0
    src = result.tool
    n = 0
    for r in result.records:
        try:
            if r.kind in (asm.KIND_SUBDOMAIN, asm.KIND_HOST):
                surface.add_host(r.identifier, source=src, method=method,
                                 attrs=r.attrs)
            elif r.kind == asm.KIND_IP:
                surface.add_ip(r.identifier, source=src, method=method,
                               attrs=r.attrs)
            elif r.kind == asm.KIND_ENDPOINT:
                surface.add_endpoint(
                    r.attrs.get("url", r.identifier),
                    method=r.attrs.get("method", "GET"), source=src,
                    status_code=r.attrs.get("status_code"),
                    content_type=r.attrs.get("content_type", ""),
                    attrs={k: v for k, v in r.attrs.items()
                           if k not in ("url", "method", "status_code", "content_type")},
                )
            elif r.kind == asm.KIND_JS:
                surface.add_js(r.identifier, source=src, attrs=r.attrs)
            elif r.kind == asm.KIND_URL:
                surface.add(asm.KIND_URL, asm.normalize_url(r.identifier),
                            source=src, method=method,
                            host=asm.normalize_host(r.identifier), attrs=r.attrs)
            elif r.kind == asm.KIND_TECHNOLOGY:
                surface.add_technology(r.attrs.get("name", r.identifier),
                                       version=r.attrs.get("version", ""),
                                       source=src, host=r.attrs.get("host", ""))
            elif r.kind == "service":
                surface.add(asm.KIND_HOST, r.attrs.get("host") or r.attrs.get("ip") or r.identifier,
                            source=src, attrs={"ports": [r.attrs.get("port")]})
                surface.add(asm.KIND_ENDPOINT, r.identifier, source=src,
                            host=r.attrs.get("host") or r.attrs.get("ip"),
                            attrs={"service": True, **r.attrs})
            else:
                surface.add(r.kind, r.identifier, source=src, attrs=r.attrs)
            n += 1
        except Exception:
            continue
    return n
