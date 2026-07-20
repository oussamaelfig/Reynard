"""
=============================================================================
Reynard — Structured Tool-Output Parsers
=============================================================================
Turns opaque scanner output into structured records the agents (and the
knowledge graph) can consume, instead of dumping raw strings into the LLM.

Parsers provided:
  - parse_ffuf      : ffuf JSON output   -> endpoints
  - parse_sqlmap    : sqlmap stdout/log  -> injectable params + findings
  - parse_nuclei    : nuclei JSONL       -> findings
  - parse_nmap      : nmap XML or -oG    -> services (+ endpoints for web ports)

Every parser returns a common `ParsedRecords`-shaped dict:

    {
        "source": "ffuf" | "sqlmap" | "nuclei" | "nmap",
        "endpoints":   [{"url", "method", "status", "notes"}...],
        "parameters":  [{"name", "endpoint", "notes"}...],
        "services":    [{"host", "port", "protocol", "service",
                         "product", "version", "notes"}...],
        "findings":    [{"type", "severity", "name", "matched_at",
                         "detail"}...],
        "summary": str,
    }

KG INGESTION POINT
------------------
`ingest_into_memory(memory, records, target_url="")` is the single, documented
place where parsed records are written into the knowledge graph using ONLY the
existing memory APIs (add_entity / add_relationship / add_fact). tools.py is
stateless (no memory handle), so the structured tool wrappers return these
records as JSON; the agent layer (e.g. BudgetedToolExecutor or a specialist)
calls `ingest_into_memory` with its live `AgentMemory` to persist them. This
keeps memory.py untouched while giving parser output a clean home in the KG.
=============================================================================
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlsplit


def _empty(source: str) -> dict[str, Any]:
    return {
        "source": source,
        "endpoints": [],
        "parameters": [],
        "services": [],
        "findings": [],
        "summary": "",
    }


# =============================================================================
# ffuf
# =============================================================================

def parse_ffuf(raw: str) -> dict[str, Any]:
    """Parse ffuf `-of json` output into endpoint records."""
    records = _empty("ffuf")
    raw = (raw or "").strip()
    if not raw:
        records["summary"] = "ffuf produced no output"
        return records
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Some ffuf runs emit trailing text; grab the first JSON object.
        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end == -1:
            records["summary"] = "ffuf output was not JSON"
            return records
        try:
            data = json.loads(raw[start:end + 1])
        except json.JSONDecodeError:
            records["summary"] = "ffuf output was not JSON"
            return records

    for item in data.get("results", []) or []:
        url = item.get("url", "")
        fuzz = ""
        inp = item.get("input", {}) or {}
        if isinstance(inp, dict):
            fuzz = inp.get("FUZZ", "") or next(iter(inp.values()), "")
        records["endpoints"].append({
            "url": url,
            "method": (item.get("method") or "GET").upper(),
            "status": item.get("status"),
            "notes": (
                f"ffuf hit FUZZ={fuzz} "
                f"len={item.get('length')} words={item.get('words')} "
                f"lines={item.get('lines')} ct={item.get('content-type', '')}"
            ).strip(),
        })
    records["summary"] = f"ffuf: {len(records['endpoints'])} matched path(s)"
    return records


# =============================================================================
# sqlmap
# =============================================================================

_SQLMAP_PARAM_RE = re.compile(r"^\s*Parameter:\s*(?P<name>[^\(]+)\((?P<place>[^\)]+)\)", re.I)
_SQLMAP_TYPE_RE = re.compile(r"^\s*Type:\s*(?P<type>.+)$", re.I)
_SQLMAP_TITLE_RE = re.compile(r"^\s*Title:\s*(?P<title>.+)$", re.I)
_SQLMAP_DBMS_RE = re.compile(r"back-end DBMS:\s*(?P<dbms>.+)$", re.I)
_SQLMAP_URL_RE = re.compile(r"^\s*(?:URL|target URL):\s*(?P<url>\S+)", re.I)


def parse_sqlmap(raw: str, url: str = "") -> dict[str, Any]:
    """Parse sqlmap stdout/log into injectable parameters + findings."""
    records = _empty("sqlmap")
    text = raw or ""
    dbms = ""
    detected_url = url
    current_param: dict[str, Any] | None = None
    types: list[str] = []
    titles: list[str] = []

    def _flush(param: dict[str, Any] | None) -> None:
        if not param:
            return
        detail = "; ".join(param.get("titles", []))
        records["parameters"].append({
            "name": param["name"],
            "endpoint": detected_url,
            "notes": (
                f"sqlmap: injectable ({param['place']}) "
                f"types={', '.join(param.get('types', []))}"
            ).strip(),
        })
        records["findings"].append({
            "type": "SQL injection",
            "severity": "high",
            "name": f"SQLi in {param['name']} ({param['place']})",
            "matched_at": detected_url,
            "detail": detail[:400],
        })

    for line in text.splitlines():
        m = _SQLMAP_URL_RE.match(line)
        if m and not detected_url:
            detected_url = m.group("url")
        m = _SQLMAP_DBMS_RE.search(line)
        if m:
            dbms = m.group("dbms").strip()
        m = _SQLMAP_PARAM_RE.match(line)
        if m:
            _flush(current_param)
            current_param = {
                "name": m.group("name").strip(),
                "place": m.group("place").strip(),
                "types": [],
                "titles": [],
            }
            continue
        if current_param is not None:
            mt = _SQLMAP_TYPE_RE.match(line)
            if mt:
                current_param["types"].append(mt.group("type").strip())
                types.append(mt.group("type").strip())
                continue
            mtitle = _SQLMAP_TITLE_RE.match(line)
            if mtitle:
                current_param["titles"].append(mtitle.group("title").strip())
                titles.append(mtitle.group("title").strip())
                continue
    _flush(current_param)

    if dbms:
        records["findings"].append({
            "type": "technology",
            "severity": "info",
            "name": f"DBMS: {dbms}",
            "matched_at": detected_url,
            "detail": dbms,
        })

    injectable = bool(records["parameters"])
    records["summary"] = (
        f"sqlmap: {'INJECTABLE' if injectable else 'no injection confirmed'}"
        f"{f'; DBMS={dbms}' if dbms else ''}"
        f" ({len(records['parameters'])} param(s))"
    )
    return records


# =============================================================================
# nuclei
# =============================================================================

def parse_nuclei(raw: str) -> dict[str, Any]:
    """Parse nuclei JSONL (one JSON object per line) into findings."""
    records = _empty("nuclei")
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        matched = obj.get("matched-at") or obj.get("host") or ""
        records["findings"].append({
            "type": obj.get("template-id", "nuclei"),
            "severity": info.get("severity", "unknown"),
            "name": info.get("name", obj.get("template-id", "")),
            "matched_at": matched,
            "detail": (info.get("description") or "")[:300],
            "cve": classification.get("cve-id"),
            "cwe": classification.get("cwe-id"),
        })
        if matched:
            records["endpoints"].append({
                "url": matched,
                "method": "GET",
                "status": None,
                "notes": f"nuclei matched template {obj.get('template-id', '')}",
            })
    records["summary"] = f"nuclei: {len(records['findings'])} finding(s)"
    return records


# =============================================================================
# nmap
# =============================================================================

_WEB_SERVICE_HINTS = ("http", "https", "http-proxy", "http-alt", "ssl/http")


def parse_nmap(raw: str) -> dict[str, Any]:
    """Parse nmap XML (-oX) or greppable (-oG) output into service records."""
    text = (raw or "").strip()
    if "<nmaprun" in text or text.startswith("<?xml"):
        return _parse_nmap_xml(text)
    return _parse_nmap_grep(text)


def _register_web_endpoint(records: dict[str, Any], host: str, port: int,
                           service: str) -> None:
    if service and any(hint in service for hint in _WEB_SERVICE_HINTS):
        scheme = "https" if ("https" in service or "ssl" in service or port == 443) else "http"
        records["endpoints"].append({
            "url": f"{scheme}://{host}:{port}/",
            "method": "GET",
            "status": None,
            "notes": f"nmap web service {service} on {port}",
        })


def _parse_nmap_xml(text: str) -> dict[str, Any]:
    records = _empty("nmap")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        records["summary"] = "nmap XML could not be parsed"
        return records

    for host in root.findall("host"):
        addr_el = host.find("address")
        host_addr = addr_el.get("addr") if addr_el is not None else ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None and hn.get("name"):
                host_addr = hn.get("name")
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state_el = port.find("state")
            if state_el is not None and state_el.get("state") != "open":
                continue
            portid = int(port.get("portid", "0") or 0)
            protocol = port.get("protocol", "tcp")
            svc = port.find("service")
            service = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            records["services"].append({
                "host": host_addr,
                "port": portid,
                "protocol": protocol,
                "service": service,
                "product": product,
                "version": version,
                "notes": " ".join(x for x in (product, version) if x),
            })
            _register_web_endpoint(records, host_addr, portid, service)

    records["summary"] = f"nmap: {len(records['services'])} open service(s)"
    return records


_GREP_PORTS_RE = re.compile(r"Host:\s*(?P<host>\S+).*?Ports:\s*(?P<ports>.+)$", re.I)


def _parse_nmap_grep(text: str) -> dict[str, Any]:
    records = _empty("nmap")
    for line in text.splitlines():
        m = _GREP_PORTS_RE.search(line)
        if not m:
            continue
        host = m.group("host")
        for chunk in m.group("ports").split(","):
            fields = [f.strip() for f in chunk.split("/")]
            if len(fields) < 3:
                continue
            try:
                portid = int(fields[0])
            except ValueError:
                continue
            state = fields[1]
            if state != "open":
                continue
            protocol = fields[2]
            service = fields[4] if len(fields) > 4 else ""
            version = fields[6] if len(fields) > 6 else ""
            records["services"].append({
                "host": host,
                "port": portid,
                "protocol": protocol,
                "service": service,
                "product": "",
                "version": version,
                "notes": version,
            })
            _register_web_endpoint(records, host, portid, service)
    records["summary"] = f"nmap: {len(records['services'])} open service(s)"
    return records


# =============================================================================
# Knowledge-graph ingestion (documented ingestion point)
# =============================================================================

def ingest_into_memory(memory: Any, records: dict[str, Any],
                       target_url: str = "") -> dict[str, int]:
    """Persist parsed records into the knowledge graph via existing memory APIs.

    Uses only public AgentMemory methods (add_entity / add_relationship /
    add_fact / query). memory.py is never modified. Returns a small count
    summary so the caller can log what was ingested.

    Call site (integration phase): the agent layer resolves its live
    `AgentMemory` and calls this with the JSON returned by the ffuf_fuzz /
    sqlmap_run / nmap_scan tools.
    """
    counts = {"endpoints": 0, "parameters": 0, "services": 0, "findings": 0}
    if not memory or not isinstance(records, dict):
        return counts

    source = records.get("source", "parser")

    target = None
    if target_url:
        existing = memory.query("Target", url=target_url)
        target = existing[0] if existing else memory.add_entity(
            "Target", {"url": target_url}
        )

    def _endpoint_entity(url: str, method: str, notes: str):
        found = memory.query("Endpoint", url=url)
        ep = found[0] if found else memory.add_entity("Endpoint", {
            "url": url, "method": method, "notes": notes,
        })
        if target is not None and not found:
            memory.add_relationship(target.id, "HAS_ENDPOINT", ep.id)
        return ep

    for ep in records.get("endpoints", []):
        url = ep.get("url")
        if not url:
            continue
        entity = _endpoint_entity(
            url, ep.get("method", "GET"), ep.get("notes", "") or source,
        )
        if ep.get("status") is not None:
            memory.add_fact("http_status", ep["status"], source=source,
                            entity_id=entity.id)
        counts["endpoints"] += 1

    for param in records.get("parameters", []):
        name = param.get("name")
        if not name:
            continue
        endpoint_url = param.get("endpoint") or ""
        parent = None
        if endpoint_url:
            parent = _endpoint_entity(endpoint_url, "GET", f"{source} parameter host")
        p_entity = memory.add_entity("Parameter", {
            "name": name, "notes": param.get("notes", "") or source,
        })
        if parent is not None:
            memory.add_relationship(parent.id, "HAS_PARAMETER", p_entity.id)
        counts["parameters"] += 1

    for svc in records.get("services", []):
        host = svc.get("host", "")
        port = svc.get("port", "")
        tech_name = " ".join(
            str(x) for x in (svc.get("service"), svc.get("product"),
                             svc.get("version")) if x
        ) or f"{host}:{port}"
        tech = memory.add_entity("Technology", {
            "name": tech_name,
            "host": host,
            "port": port,
            "protocol": svc.get("protocol", ""),
            "source": source,
        })
        if target is not None:
            memory.add_relationship(target.id, "USES_TECHNOLOGY", tech.id)
        counts["services"] += 1

    for finding in records.get("findings", []):
        anchor = target
        matched = finding.get("matched_at")
        if matched:
            host = urlsplit(matched).netloc or matched
            if target is None or host:
                anchor = _endpoint_entity(matched, "GET", f"{source} finding")
        if anchor is None:
            continue
        vuln = memory.add_entity("Vulnerability", {
            "vuln_type": finding.get("type", source),
            "severity": finding.get("severity", "unknown"),
            "status": "reported_by_tool",
            "source": source,
            "name": finding.get("name", ""),
            "notes": finding.get("detail", ""),
        })
        memory.add_relationship(anchor.id, "POTENTIALLY_VULNERABLE_TO", vuln.id)
        counts["findings"] += 1

    return counts
