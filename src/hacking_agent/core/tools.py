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
  - browser_navigate:   Load a URL in Lightpanda headless browser (JS rendered)
  - browser_execute_js: Execute JavaScript in the browser (prove XSS, extract DOM)
  - browser_interact:   Click elements or type into forms
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

from hacking_agent.core import differ as differ_mod
from hacking_agent.core import oob
from hacking_agent.core import sessions as session_mod
from hacking_agent.core.tool_catalog import known_command_names, render_tool_catalog
from hacking_agent.core import web_research as web_research_mod
from hacking_agent.integrations import burp as burp_mod
from hacking_agent.integrations import caido as caido_mod
from hacking_agent.integrations import caido_local as caido_local_mod

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
    # Lightpanda Headless Browser Tools
    # =========================================================================
    {
        "type": "function",
        "function": {
            "name": "browser_navigate",
            "description": (
                "Navigate to a URL using Lightpanda headless browser inside the Kali container. "
                "Unlike curl, this renders the page with a full JavaScript engine (v8), "
                "executing client-side JS, DOM manipulation, and dynamic content. "
                "Returns the fully rendered HTML or Markdown. Essential for: "
                "XSS labs (JS execution), DOM XSS, pages with JS redirects/rendering, "
                "CSRF token extraction from dynamic forms, and SPAs."
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
                            "Output format: 'html' for raw rendered HTML (better for "
                            "XSS/injection analysis), 'markdown' for readable text "
                            "(better for content extraction). Default: html."
                        ),
                    },
                    "wait_ms": {
                        "type": "integer",
                        "description": (
                            "Milliseconds to wait after page load for JS to execute. "
                            "Default: 2000. Increase for slow-loading SPAs."
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
                "Execute JavaScript code on a page loaded in Lightpanda headless browser. "
                "This is CRITICAL for XSS labs — use it to: (1) Navigate to a URL with an "
                "XSS payload and check if alert/confirm/prompt was called, (2) Extract "
                "DOM elements dynamically generated by JS, (3) Read cookies via "
                "document.cookie, (4) Interact with client-side frameworks like AngularJS. "
                "The script runs in the page context with full DOM access."
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
                            "JavaScript code to execute in the page context. "
                            "Examples: 'document.cookie', 'document.title', "
                            "'document.querySelector(\"#csrf\").value', "
                            "'window.location.href'. The return value is captured."
                        ),
                    },
                    "wait_ms": {
                        "type": "integer",
                        "description": (
                            "Milliseconds to wait after page load before executing JS. "
                            "Default: 2000."
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
                "Interact with a web page using Lightpanda — click buttons, "
                "fill input fields, submit forms. Uses CSS selectors to target "
                "elements. Useful for: login forms with CSRF tokens, multi-step "
                "exploits, and pages that require user interaction before revealing "
                "content. The page is rendered with JS before interaction."
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
                                    "enum": ["click", "type", "select"],
                                    "description": "The action to perform.",
                                },
                                "selector": {
                                    "type": "string",
                                    "description": "CSS selector for the target element.",
                                },
                                "value": {
                                    "type": "string",
                                    "description": "Value to type or select (for 'type' and 'select' actions).",
                                },
                            },
                            "required": ["action", "selector"],
                        },
                        "description": (
                            "List of actions to perform in order. Example: "
                            "[{action:'type', selector:'#username', value:'admin'}, "
                            "{action:'type', selector:'#password', value:'test'}, "
                            "{action:'click', selector:'button[type=submit]'}]"
                        ),
                    },
                    "wait_ms": {
                        "type": "integer",
                        "description": "Milliseconds to wait after page load. Default: 2000.",
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
# Lightpanda Browser Functions
# =============================================================================

def browser_navigate(
    url: str,
    output_format: str = "html",
    wait_ms: int = 2000,
) -> str:
    """
    Navigate to a URL using Lightpanda headless browser.
    Renders the page with full JavaScript execution (v8 engine).
    """
    dump_flag = "markdown" if output_format == "markdown" else "html"
    cmd = (
        f"lightpanda fetch"
        f" --dump {dump_flag}"
        f" --wait-ms {wait_ms}"
        f" '{url}'"
        f" 2>&1"
    )
    result = _docker_exec(cmd, timeout=60)
    return json.dumps({
        "rendered_content": result["stdout"],
        "exit_code": result["exit_code"],
        "format": dump_flag,
        "url": url,
    }, indent=2)


def browser_execute_js(
    url: str,
    script: str,
    wait_ms: int = 2000,
) -> str:
    """
    Execute JavaScript on a page rendered by Lightpanda.
    Uses --wait-script to run custom JS after page load.
    Returns the page HTML with JS effects applied.
    """
    # Escape the script for shell
    escaped_script = script.replace("'", "'\\''")
    cmd = (
        f"lightpanda fetch"
        f" --dump html"
        f" --wait-ms {wait_ms}"
        f" --wait-script '{escaped_script}'"
        f" '{url}'"
        f" 2>&1"
    )
    result = _docker_exec(cmd, timeout=60)
    return json.dumps({
        "rendered_html": result["stdout"],
        "script": script,
        "exit_code": result["exit_code"],
        "url": url,
    }, indent=2)


def browser_interact(
    url: str,
    actions: list[dict],
    wait_ms: int = 2000,
) -> str:
    """
    Interact with a page using Lightpanda via a Puppeteer-style script.
    Generates a small Node.js/Puppeteer script, writes it to the container,
    and executes it against Lightpanda's CDP server.
    """
    # Build the interaction as a sequence of JS commands using Lightpanda's
    # wait-script feature: first navigate, then execute interactions
    js_parts = []
    for action in actions:
        selector = action["selector"].replace("'", "\\'")
        if action["action"] == "click":
            js_parts.append(
                f"document.querySelector('{selector}').click();"
            )
        elif action["action"] == "type":
            value = action.get("value", "").replace("'", "\\'")
            js_parts.append(
                f"var el = document.querySelector('{selector}');"
                f"el.value = '{value}';"
                f"el.dispatchEvent(new Event('input', {{bubbles: true}}));"
            )
        elif action["action"] == "select":
            value = action.get("value", "").replace("'", "\\'")
            js_parts.append(
                f"var el = document.querySelector('{selector}');"
                f"el.value = '{value}';"
                f"el.dispatchEvent(new Event('change', {{bubbles: true}}));"
            )

    interaction_script = " ".join(js_parts)
    escaped_script = interaction_script.replace("'", "'\\''")

    cmd = (
        f"lightpanda fetch"
        f" --dump html"
        f" --wait-ms {wait_ms}"
        f" --wait-script '{escaped_script}'"
        f" '{url}'"
        f" 2>&1"
    )
    result = _docker_exec(cmd, timeout=60)
    return json.dumps({
        "rendered_html": result["stdout"],
        "actions_performed": actions,
        "exit_code": result["exit_code"],
        "url": url,
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
    rc, _, _ = _docker_exec("which nuclei", timeout=5)
    if rc != 0:
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
