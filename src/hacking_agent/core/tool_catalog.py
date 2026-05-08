"""
Tool-selection catalog for the Kali/CTF container.

The Dockerfile installs many tools, but an LLM will not reliably infer when to
use each one from a package list. This catalog is injected into agent prompts
and exposed via tool_inventory so agents can choose the right tool at the
right time.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolEntry:
    name: str
    phase: str
    use_when: str
    avoid_when: str
    example: str


CATALOG: tuple[ToolEntry, ...] = (
    ToolEntry(
        "http_request",
        "web baseline, precise payloads, cookies",
        "You need one HTTP request, stable cookie handling, or analyzer signals.",
        "You need complex shell pipelines or a dedicated scanner.",
        "http_request GET https://target/filter?category=Gifts%27+OR+1%3D1--",
    ),
    ToolEntry(
        "curl",
        "manual HTTP proof",
        "You need exact URL encoding, grep/sed/jq piping, or response files.",
        "A simple request can use http_request and benefit from auto-analysis.",
        "curl -sk -D- 'https://target/path?x=test'",
    ),
    ToolEntry(
        "sqlmap",
        "SQL injection",
        "Injection is non-trivial, blind/time-based, many params, or data extraction is required.",
        "A known simple lab can be proven faster with one manual payload.",
        "sqlmap -u 'https://target/item?id=1' --batch --level=5 --risk=3",
    ),
    ToolEntry(
        "ffuf",
        "content/parameter fuzzing",
        "You need fast path, vhost, extension, or parameter discovery.",
        "You already have the exact endpoint/parameter for a small lab.",
        "ffuf -u https://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    ),
    ToolEntry(
        "gobuster/dirb/wfuzz",
        "directory fuzzing",
        "ffuf is unavailable or you need a familiar alternative.",
        "The target is a single known PortSwigger lab endpoint.",
        "gobuster dir -u https://target -w /usr/share/wordlists/dirb/common.txt",
    ),
    ToolEntry(
        "nuclei",
        "known CVE/misconfig",
        "The target exposes a real service/app stack and known templates may apply.",
        "Tiny challenge apps where template noise wastes time.",
        "nuclei -u https://target -severity medium,high,critical -silent",
    ),
    ToolEntry(
        "nmap",
        "network/service recon",
        "You have an IP/host with unknown ports/services.",
        "You only have a single HTTPS web lab URL.",
        "nmap -sV -sC -Pn -oN /data/loot/nmap.txt target",
    ),
    ToolEntry(
        "whatweb/nikto",
        "web fingerprinting",
        "You need quick tech/server hints or common web server issues.",
        "The app identity and vulnerable parameter are already explicit.",
        "whatweb https://target && nikto -h https://target",
    ),
    ToolEntry(
        "subfinder/httpx/httprobe/waybackurls",
        "external recon",
        "The scope allows subdomains or historical URLs.",
        "A CTF gives one fixed lab URL and forbids broader scope.",
        "subfinder -d example.com | httpx -silent",
    ),
    ToolEntry(
        "hydra",
        "credential attacks",
        "A CTF explicitly authorizes online password guessing and a wordlist is provided.",
        "No authorization for brute force or lockout risk exists.",
        "hydra -L users.txt -P pass.txt target http-post-form '/login:u=^USER^&p=^PASS^:F=Invalid'",
    ),
    ToolEntry(
        "john/hashcat",
        "offline cracking",
        "You have hashes/files locally and cracking is in scope.",
        "You only have a live web injection proof to verify.",
        "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt",
    ),
    ToolEntry(
        "metasploit/searchsploit",
        "known exploit research",
        "A service/version has a known exploit and CTF rules allow using frameworks.",
        "A manual web payload is simpler and more transparent.",
        "searchsploit apache 2.4; msfconsole -q -x 'search cve:YYYY'",
    ),
    ToolEntry(
        "sslscan/testssl",
        "TLS analysis",
        "TLS configuration is part of the challenge or assessment.",
        "You are solving an application-layer lab with a known input bug.",
        "testssl https://target",
    ),
    ToolEntry(
        "binwalk/radare2/steghide/foremost",
        "forensics/reversing/stego",
        "The challenge provides binaries, firmware, archives, or images.",
        "The task is only a live web endpoint.",
        "binwalk -e firmware.bin; steghide extract -sf image.jpg",
    ),
    ToolEntry(
        "adb/apktool/jadx/frida/objection",
        "Android",
        "The target is an APK/mobile challenge.",
        "The task is a web-only lab.",
        "jadx -d /data/loot/app jadx-target.apk",
    ),
    ToolEntry(
        "Lightpanda browser_*",
        "JS-rendered web/XSS/CSRF",
        "You need DOM execution, rendered HTML, JS redirects, or form interaction.",
        "curl/http_request sees the full page and no JS behavior matters.",
        "browser_navigate(url, output_format='html')",
    ),
    ToolEntry(
        "OOB interactsh",
        "blind vulns",
        "SSRF, blind command injection, XXE, log4shell, or blind SQLi needs callbacks.",
        "The target gives a clear in-band response.",
        "oob_get_domain(label='xxe'); embed returned domain; oob_poll(token)",
    ),
    ToolEntry(
        "Caido Local Bridge",
        "preferred API/replay/proxy workflow",
        "A local Caido bridge plugin is reachable and you need Replay, request collections, HTTP history, or manual-review artifacts.",
        "The bridge status is offline; fall back to http_request/browser tools. Cloud API is not a Replay/proxy API.",
        "caido_local_api(operation='send_raw', args={raw_request, hostname, port, https})",
    ),
    ToolEntry(
        "Caido Cloud API",
        "Caido account/team/workspace automation",
        "You need Caido Cloud user/team/subscription/workspace/PAT operations.",
        "You expect proxy history/replay; this integration is Cloud API, not local Caido proxy.",
        "caido_cloud_api(operation='status')",
    ),
    ToolEntry(
        "Burp MCP",
        "fallback Burp-specific traffic/repeater/intruder",
        "Burp MCP extension is online and you specifically need Burp Collaborator, Scanner, Intruder, or an existing Burp workflow.",
        "MCP is offline, Caido Local Bridge can handle Replay/history, or http_request is enough.",
        "burp_create_repeater_tab(raw_request=..., hostname=...)",
    ),
    ToolEntry(
        "/opt/hackingtool/hackingtool.py",
        "Z4nzu hackingtool wrapper",
        "You want to inspect or launch tools from the Z4nzu menu suite.",
        "The wrapper is interactive; prefer direct commands for automation.",
        "python3 /opt/hackingtool/hackingtool.py",
    ),
)


def render_tool_catalog(role: str = "general") -> str:
    """Render a compact prompt section tailored by role."""
    role = (role or "general").lower()
    if role == "recon":
        names = {
            "http_request", "curl", "ffuf", "gobuster/dirb/wfuzz", "nuclei",
            "nmap", "whatweb/nikto", "subfinder/httpx/httprobe/waybackurls",
            "Lightpanda browser_*", "Caido Local Bridge", "Caido Cloud API", "Burp MCP",
            "/opt/hackingtool/hackingtool.py",
        }
    elif role == "exploitation":
        names = {
            "http_request", "curl", "sqlmap", "hydra", "john/hashcat",
            "metasploit/searchsploit", "Lightpanda browser_*", "OOB interactsh",
            "adb/apktool/jadx/frida/objection", "binwalk/radare2/steghide/foremost",
            "Caido Local Bridge", "Caido Cloud API", "Burp MCP", "/opt/hackingtool/hackingtool.py",
        }
    else:
        names = {entry.name for entry in CATALOG}

    lines = [
        "# TOOL-SELECTION CATALOG",
        "Choose tools by hypothesis and evidence need. Prefer direct, non-interactive commands. Prefer Caido Local Bridge over Burp MCP for Replay/history/API-testing workflows when it is reachable.",
    ]
    for entry in CATALOG:
        if entry.name not in names:
            continue
        lines.append(
            f"- {entry.name} [{entry.phase}]\n"
            f"  Use when: {entry.use_when}\n"
            f"  Avoid when: {entry.avoid_when}\n"
            f"  Example: {entry.example}"
        )
    return "\n".join(lines)


def known_command_names() -> list[str]:
    """Commands worth checking inside the Kali container."""
    return sorted({
        "curl", "sqlmap", "ffuf", "gobuster", "dirb", "wfuzz", "nuclei",
        "nmap", "whatweb", "nikto", "subfinder", "httpx", "httprobe",
        "waybackurls", "hydra", "john", "hashcat", "msfconsole",
        "searchsploit", "sslscan", "testssl", "interactsh-client", "binwalk", "radare2",
        "r2", "steghide", "foremost", "adb", "apktool", "jadx", "frida",
        "objection", "python3", "go", "ruby", "proxychains4", "tor",
        "bettercap", "ettercap", "aircrack-ng", "lightpanda",
    })
