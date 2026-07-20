"""
Small, deterministic target-intelligence helpers for CTF/lab workflows.

These helpers do not replace recon. They let the orchestrator preserve the
user's natural-language objective while handing agents a clean target URL and
an optional lab profile when the challenge description is explicit.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from hacking_agent.core.expert_playbooks import enrich_lab_profile

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
TARGET_URL_RE = re.compile(
    r"\bTarget\s*:\s*(https?://[^\s\"'<>)]+)",
    re.IGNORECASE,
)
TARGET_HOST_RE = re.compile(
    r"\bTarget\s*:\s*((?:https?://)?[a-zA-Z0-9.-]+(?::\d+)?)",
    re.IGNORECASE,
)
HOST_RE = re.compile(
    r"(?<![\w.-])("
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
    r")(?::\d+)?(?![\w-])"
)
CREDENTIAL_PAIR_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])([A-Za-z][A-Za-z0-9_.@+-]{1,40})\s*:\s*([^\s,;\"'<>)]{2,80})"
)

COMMON_PORTSWIGGER_USERS = {
    "wiener", "carlos", "administrator", "admin", "content-manager",
    "victim", "attacker",
}

# ---------------------------------------------------------------------------
# Target-category profiler (web / network / binary / mobile / crypto /
# stego / forensics / misc). Web detection stays fully backward-compatible:
# PortSwigger hosts and clear web signals still resolve to CATEGORY_WEB.
# ---------------------------------------------------------------------------
CATEGORY_WEB = "web"
CATEGORY_NETWORK = "network"
CATEGORY_BINARY = "binary"
CATEGORY_MOBILE = "mobile"
CATEGORY_CRYPTO = "crypto"
CATEGORY_STEGO = "stego"
CATEGORY_FORENSICS = "forensics"
CATEGORY_MISC = "misc"

CATEGORIES = (
    CATEGORY_WEB, CATEGORY_NETWORK, CATEGORY_BINARY, CATEGORY_MOBILE,
    CATEGORY_CRYPTO, CATEGORY_STEGO, CATEGORY_FORENSICS, CATEGORY_MISC,
)

# When two categories tie on score, earlier entries win (more specific first).
_CATEGORY_PRIORITY = (
    CATEGORY_MOBILE, CATEGORY_BINARY, CATEGORY_FORENSICS, CATEGORY_STEGO,
    CATEGORY_CRYPTO, CATEGORY_NETWORK, CATEGORY_WEB,
)

_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    CATEGORY_MOBILE: (
        "apk", ".apk", "android", "androidmanifest", "dalvik", "smali",
        "apktool", "jadx", "frida", "objection", ".ipa", ".dex", ".aab",
        "mobile app", "play store", "root detection", "ssl pinning",
    ),
    CATEGORY_BINARY: (
        "pwn", "buffer overflow", "stack overflow", "heap overflow", "rop",
        "ret2", "shellcode", "gadget", "format string", "strcpy", "gets(",
        "radare", "ghidra", "gdb", "disassemble", "reverse engineer",
        "reverse-engineering", "reverse engineering", ".elf", "binary exploitation",
        "canary", "nx bit", "aslr", "got overwrite", "use-after-free",
        "heap exploitation", "pwntools", "one_gadget", "libc",
    ),
    CATEGORY_CRYPTO: (
        "rsa", "aes", "3des", "xor cipher", "ciphertext", "plaintext",
        "decrypt", "encryption", "cryptograph", "discrete log",
        "elliptic curve", "ecdsa", "ecb", "cbc", "ctr mode", "padding oracle",
        "modulus", "public key", "private key", "factorize", "factordb",
        "nonce reuse", "one-time pad", "caesar", "vigenere",
        "substitution cipher", "affine cipher",
    ),
    CATEGORY_STEGO: (
        "steg", "steganography", "steghide", "zsteg", "lsb",
        "least significant bit", "hidden in the image", "hidden message",
        "spectrogram", "stegsolve", "outguess", "exiftool", "exif data",
    ),
    CATEGORY_FORENSICS: (
        "forensic", "pcap", "pcapng", "wireshark", "tshark",
        "network capture", "packet capture", "memory dump", "memdump",
        "volatility", "disk image", "file carving", ".raw image", ".mem",
        "autopsy", "registry hive", "evtx", "recover deleted", "binwalk",
        "foremost",
    ),
    CATEGORY_NETWORK: (
        "nmap", "port scan", "portscan", " smb", "samba", " ssh", " ftp",
        "telnet", "rdp", "snmp", "service enumeration", "metasploit",
        "msfconsole", "msfvenom", "active directory", "kerberos", "ldap",
        "netbios", "reverse shell", "bind shell", "privilege escalation",
        "lateral movement", "/24", "subnet", "open port",
    ),
    CATEGORY_WEB: (
        "http://", "https://", "cookie", "xss", "sql injection", "sqli",
        "csrf", "ssrf", "web app", "login page", "api endpoint", "jwt",
        ".php", "javascript", "http header", "query parameter", "file upload",
        "graphql", "oauth", "cors", "web-security-academy", "portswigger",
        "request smuggling", "ssti", "path traversal", "deserialization",
    ),
}

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$")
_HOST_PORT_RE = re.compile(r"^[a-zA-Z0-9.-]+:\d+$")
_MOBILE_EXTS = (".apk", ".ipa", ".dex", ".aab")
_BINARY_EXTS = (".elf", ".bin", ".exe", ".so", ".o", ".out")
_STEGO_EXTS = (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".wav", ".mp3")
_FORENSICS_EXTS = (".pcap", ".pcapng", ".raw", ".mem", ".dmp", ".vmem", ".e01", ".evtx")

_CATEGORY_PLAYBOOKS: dict[str, list[str]] = {
    CATEGORY_WEB: ["essential_skills"],
    CATEGORY_NETWORK: ["network_pentest", "metasploit"],
    CATEGORY_BINARY: ["binary_pwn", "reverse_engineering"],
    CATEGORY_MOBILE: ["mobile_android"],
    CATEGORY_CRYPTO: ["crypto"],
    CATEGORY_STEGO: ["stego"],
    CATEGORY_FORENSICS: ["forensics"],
    CATEGORY_MISC: ["ctf_misc"],
}


def category_playbooks(category: str) -> list[str]:
    """Return the ordered playbook keys associated with a target category."""
    return list(_CATEGORY_PLAYBOOKS.get((category or "").strip().lower(), []))


def _target_shape_scores(target: str) -> dict[str, int]:
    """Score categories from the *shape* of the target token alone."""
    scores: dict[str, int] = {}
    token = (target or "").strip()
    if not token:
        return scores
    lower = token.lower()
    if lower.startswith(("http://", "https://")):
        scores[CATEGORY_WEB] = scores.get(CATEGORY_WEB, 0) + 2
    if lower.endswith(_MOBILE_EXTS):
        scores[CATEGORY_MOBILE] = scores.get(CATEGORY_MOBILE, 0) + 3
    elif lower.endswith(_BINARY_EXTS):
        scores[CATEGORY_BINARY] = scores.get(CATEGORY_BINARY, 0) + 3
    elif lower.endswith(_FORENSICS_EXTS):
        scores[CATEGORY_FORENSICS] = scores.get(CATEGORY_FORENSICS, 0) + 3
    elif lower.endswith(_STEGO_EXTS):
        scores[CATEGORY_STEGO] = scores.get(CATEGORY_STEGO, 0) + 2
    if "://" not in lower:
        if _IPV4_RE.match(lower):
            scores[CATEGORY_NETWORK] = scores.get(CATEGORY_NETWORK, 0) + 2
        elif _HOST_PORT_RE.match(lower):
            scores[CATEGORY_NETWORK] = scores.get(CATEGORY_NETWORK, 0) + 1
    return scores


def detect_target_category(target: str, objective: str = "") -> str:
    """Classify an objective/target into one of ``CATEGORIES``.

    Deterministic keyword + target-shape scorer. PortSwigger hosts and clear
    web signals resolve to ``CATEGORY_WEB`` so existing web detection is
    preserved. Returns ``CATEGORY_MISC`` when no signal is found.
    """
    haystack = f" {(objective or '').lower()} {(target or '').lower()} "

    parsed_host = ""
    token = (target or "").strip()
    if token:
        parsed = urlparse(token if "://" in token else f"http://{token}")
        parsed_host = (parsed.hostname or "").lower()
    if "web-security-academy.net" in parsed_host or "portswigger" in haystack:
        return CATEGORY_WEB

    scores: dict[str, int] = {c: 0 for c in _CATEGORY_PRIORITY}
    for category, needles in _CATEGORY_KEYWORDS.items():
        for needle in needles:
            if needle in haystack:
                scores[category] += 1
    for category, bonus in _target_shape_scores(target).items():
        scores[category] = scores.get(category, 0) + bonus

    best = max(scores.values()) if scores else 0
    if best <= 0:
        if parsed_host and (_IPV4_RE.match(token.lower()) or _HOST_PORT_RE.match(token.lower())):
            return CATEGORY_NETWORK
        if token.lower().startswith(("http://", "https://")):
            return CATEGORY_WEB
        return CATEGORY_MISC

    for category in _CATEGORY_PRIORITY:
        if scores.get(category, 0) == best:
            return category
    return CATEGORY_MISC


def extract_first_url(text: str) -> str:
    """Return the first URL in text, trimmed for common sentence punctuation."""
    match = URL_RE.search(text or "")
    if not match:
        return (text or "").strip()
    return match.group(0).rstrip(".,;")


def extract_target_url(text: str) -> str:
    """Return the intended primary target URL from a free-form objective.

    Prompts for SSRF/OAuth labs often contain an internal URL to fetch through
    the vulnerable app before the real lab URL. Prefer an explicit "Target:"
    marker when present, then fall back to platform-known lab hosts, then the
    first URL.
    """
    text = text or ""
    marker_matches = TARGET_URL_RE.findall(text)
    if marker_matches:
        return marker_matches[-1].rstrip(".,;")
    host_marker_matches = TARGET_HOST_RE.findall(text)
    if host_marker_matches:
        return host_marker_matches[-1].rstrip(".,;")

    urls = [m.group(0).rstrip(".,;") for m in URL_RE.finditer(text)]
    if not urls:
        host_match = HOST_RE.search(text)
        if host_match:
            return host_match.group(1).rstrip(".,;")
        return text.strip()

    for url in reversed(urls):
        host = urlparse(url).netloc.lower()
        if "web-security-academy.net" in host:
            return url
    if urls:
        return urls[0]

    return text.strip()


EXPLOIT_SERVER_MARKER_RE = re.compile(
    r"exploit[\s_-]*server[^\n]*?(https?://[^\s\"'<>)]+)",
    re.IGNORECASE,
)


def extract_exploit_server_url(text: str) -> str:
    """Return the PortSwigger exploit-server URL referenced in an objective.

    Cheap models frequently hallucinate the exploit-server hostname/id, then
    trip the scope guard. Parsing the exact URL from the mission text lets the
    orchestrator pin the real host into scope and memory so agents reuse it
    verbatim instead of guessing. Best-effort: empty string when none found.
    """
    text = text or ""
    marker = EXPLOIT_SERVER_MARKER_RE.search(text)
    if marker:
        return marker.group(1).rstrip(".,;")
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;")
        host = urlparse(url).hostname or ""
        host = host.lower()
        if host.endswith("exploit-server.net") or host.startswith("exploit-"):
            return url
    return ""


def normalize_target_input(raw: str) -> tuple[str, str]:
    """Split a free-form CLI task into (target_url, original_objective)."""
    raw = (raw or "").strip()
    target_url = extract_target_url(raw)
    objective = raw if raw and raw != target_url else ""
    return target_url, objective


def extract_credentials(text: str) -> list[dict[str, str]]:
    """Extract simple lab credential hints such as ``wiener:peter``.

    This intentionally stays conservative so URLs and header values do not
    become fake credentials.
    """
    credentials: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for match in CREDENTIAL_PAIR_RE.finditer(text or ""):
        username = match.group(1).strip()
        password = match.group(2).strip().rstrip(".,")
        lower_user = username.lower()
        lower_pass = password.lower()
        if lower_user in {"http", "https", "target", "url"}:
            continue
        if "/" in password or "\\" in password:
            continue
        if lower_pass.startswith("//"):
            continue
        # Prefer known lab user names, but allow obvious local credential
        # context in the preceding text.
        context = (text or "")[max(0, match.start() - 80):match.start()].lower()
        credential_context = any(
            word in context
            for word in ("credential", "login", "log in", "account", "using", "password")
        )
        if lower_user not in COMMON_PORTSWIGGER_USERS and not credential_context:
            continue
        key = (username, password)
        if key in seen:
            continue
        seen.add(key)
        credentials.append({"username": username, "password": password})
    return credentials


def _portswigger_profile(raw: str, profile: dict) -> dict:
    credentials = extract_credentials(raw)
    if credentials:
        profile["credentials"] = credentials
        if len(credentials) == 1:
            profile["credentials_hint"] = (
                f"{credentials[0]['username']}:{credentials[0]['password']}"
            )
    profile.setdefault("category", CATEGORY_WEB)
    return enrich_lab_profile(profile, raw)


def detect_lab_profile(raw: str, target_url: str) -> dict:
    """Detect high-confidence CTF/lab profiles from user objective + target."""
    haystack = f"{raw or ''} {target_url or ''}".lower()
    parsed_target = target_url if "://" in (target_url or "") else f"http://{target_url or ''}"
    host = urlparse(parsed_target).netloc.lower()

    if "web-security-academy.net" not in host:
        return {}

    if "ssrf" in haystack and "dynamic client registration" in haystack:
        return _portswigger_profile(raw, {
            "id": "portswigger_oidc_dynamic_client_registration_ssrf",
            "platform": "portswigger",
            "vulnerability": "ssrf",
            "playbook_id": "oauth_ssrf_dynamic_registration",
            "endpoint_hint": "/.well-known/openid-configuration",
            "registration_endpoint": "client registration endpoint from OIDC discovery",
            "metadata_path": "/latest/meta-data/iam/security-credentials/admin/",
            "credentials_hint": "wiener:peter",
            "purpose": (
                "Register an OAuth client whose metadata induces the OAuth "
                "service to fetch cloud instance metadata and disclose the "
                "secret access key."
            ),
        })

    if "blind xxe" in haystack and "out-of-band" in haystack:
        return _portswigger_profile(raw, {
            "id": "portswigger_blind_xxe_oob",
            "platform": "portswigger",
            "vulnerability": "xxe",
            "playbook_id": "blind_xxe_oob",
            "endpoint_hint": "/product/stock",
            "method": "POST",
            "content_type": "application/xml",
            "purpose": "Trigger an out-of-band callback from the XML parser.",
        })

    if "command injection" in haystack and "simple case" in haystack:
        return _portswigger_profile(raw, {
            "id": "portswigger_os_command_injection_simple",
            "platform": "portswigger",
            "vulnerability": "command_injection",
            "playbook_id": "os_command_injection",
            "endpoint_hint": "/product/stock",
            "parameter": "storeId",
            "probe_command": "whoami",
            "purpose": "Inject a shell metacharacter into the stock-check storeId parameter.",
        })

    if (
        "sql injection" in haystack
        and "nosql" not in haystack
        and (
            "hidden data" in haystack
            or "where clause" in haystack
            or "retrieval of hidden data" in haystack
        )
    ):
        return _portswigger_profile(raw, {
            "id": "portswigger_sqli_hidden_data",
            "platform": "portswigger",
            "vulnerability": "sql_injection",
            "playbook_id": "sqli",
            "endpoint_hint": "/filter",
            "parameter": "category",
            "sample_category": "Gifts",
            "primary_payload_template": "{category}' OR 1=1-- ",
            "purpose": "Retrieve hidden/unreleased products from a product category WHERE clause.",
        })

    topic_profiles: list[tuple[str, tuple[str, ...], str, str]] = [
        ("portswigger_jwt", ("jwt", "json web token", "jwk", "jku", "kid header"), "jwt", "JWT authentication/token flaw."),
        ("portswigger_oauth", ("oauth authentication", "oauth", "openid connect", "oidc"), "oauth", "OAuth authentication flaw."),
        ("portswigger_host_header", ("host header", "http host", "password reset poisoning", "routing-based ssrf", "x-forwarded-host"), "host_header", "HTTP Host header attack."),
        ("portswigger_authentication", ("authentication", "password reset", "mfa", "multi-factor", "remember me", "login bypass", "username enumeration"), "authentication", "Authentication vulnerability."),
        ("portswigger_access_control_idor", ("access control", "idor", "insecure direct object", "horizontal privilege", "vertical privilege"), "access_control_idor", "Broken access control or IDOR."),
        ("portswigger_request_smuggling", ("request smuggling", "desync", "cl.te", "te.cl", "http request smuggling"), "request_smuggling", "HTTP request smuggling/desync."),
        ("portswigger_web_cache_deception", ("web cache deception", "cache deception"), "web_cache_deception", "Web cache deception."),
        ("portswigger_web_cache_poisoning", ("web cache poisoning", "cache poisoning", "unkeyed cache", "unkeyed header"), "web_cache_poisoning", "Web cache poisoning."),
        ("portswigger_ssti", ("server-side template injection", "ssti", "template injection"), "ssti", "Server-side template injection."),
        ("portswigger_deserialization", ("deserialization", "deserialisation", "serialized", "serialised"), "deserialization", "Insecure deserialization."),
        ("portswigger_prototype_pollution", ("prototype pollution", "__proto__", "constructor.prototype"), "prototype_pollution", "Prototype pollution."),
        ("portswigger_graphql", ("graphql", "graph ql", "introspection", "mutation"), "graphql_api", "GraphQL API weakness."),
        ("portswigger_race_condition", ("race condition", "race conditions", "single packet", "parallel requests"), "race_condition", "Race condition."),
        ("portswigger_api_testing", ("api testing", "api lab", "api endpoint", "openapi", "swagger"), "api_testing", "API testing weakness."),
        ("portswigger_web_llm_attacks", ("web llm", "llm attack", "llm attacks", "prompt injection", "ai-powered scanner"), "web_llm_attacks", "Web LLM attack."),
        ("portswigger_essential_skills", ("essential skills", "mystery lab"), "essential_skills", "Essential web security lab skill."),
        ("portswigger_clickjacking", ("clickjacking", "ui redress", "iframe overlay"), "clickjacking", "Clickjacking."),
        ("portswigger_dom_based", ("dom-based vulnerabilities", "dom vulnerability", "dom-based vulnerability"), "dom_based", "DOM-based vulnerability."),
        ("portswigger_dom_xss", ("dom xss", "dom-based xss"), "dom_xss", "DOM-based cross-site scripting."),
        ("portswigger_xss", ("cross-site scripting", "xss"), "xss", "Cross-site scripting."),
        ("portswigger_file_upload", ("file upload", "upload vulnerability", "web shell", "polyglot"), "file_upload", "File upload bypass."),
        ("portswigger_path_traversal", ("path traversal", "file path traversal", "directory traversal", "../"), "path_traversal", "Path traversal."),
        ("portswigger_csrf", ("csrf", "cross-site request forgery", "samesite"), "csrf", "Cross-site request forgery."),
        ("portswigger_cors", ("cors", "cross-origin resource sharing"), "cors", "CORS misconfiguration."),
        ("portswigger_websocket", ("websocket", "web socket", "ws://", "wss://"), "websocket", "WebSocket security flaw."),
        ("portswigger_business_logic", ("business logic", "logic flaw", "excessive trust", "workflow"), "business_logic", "Business logic flaw."),
        ("portswigger_information_disclosure", ("information disclosure", "info disclosure", "debug page", "source code disclosure", "backup file"), "information_disclosure", "Information disclosure."),
        ("portswigger_nosql", ("nosql", "mongodb", "operator injection"), "nosql_injection", "NoSQL injection."),
        ("portswigger_ssrf", ("ssrf", "server-side request forgery", "stock check"), "ssrf", "Server-side request forgery."),
        ("portswigger_xxe", ("xxe", "xml external entity", "external entity"), "xxe", "XML external entity injection."),
        ("portswigger_command_injection", ("command injection", "os command", "cmdi"), "os_command_injection", "OS command injection."),
    ]
    for profile_id, needles, playbook_id, purpose in topic_profiles:
        if any(needle in haystack for needle in needles):
            vulnerability = playbook_id
            return _portswigger_profile(raw, {
                "id": profile_id,
                "platform": "portswigger",
                "vulnerability": vulnerability,
                "playbook_id": playbook_id,
                "purpose": purpose,
            })

    if "sql injection" in haystack and "nosql" not in haystack:
        return _portswigger_profile(raw, {
            "id": "portswigger_sqli",
            "platform": "portswigger",
            "vulnerability": "sql_injection",
            "playbook_id": "sqli",
        })

    return {}
