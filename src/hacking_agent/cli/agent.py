"""
=============================================================================
Reynard — Structured Exploitation Engine
=============================================================================
A disciplined, phase-based autonomous agent that uses DeepSeek V4 Pro
to solve security labs and penetration testing challenges.

Architecture:
  1. Controller Loop:  PLAN → ACT → OBSERVE → UPDATE → NEXT
  2. Memory System:    Persistent facts, payload history, progress tracking
  3. Response Analyzer: Auto-parses HTTP responses into structured signals
  4. Strategy Engine:   6-phase exploitation pipeline with methodology
  5. Deduplication:     Never resends the same payload twice

Inspired by @Tur24Tur's DeepSeek V4 Pro autonomous hacking experiments.

Usage:
  python agent.py "Solve this expert PortSwigger lab: https://..."
  python agent.py --interactive

Environment Variables:
  DEEPSEEK_API_KEY   — API key for DeepSeek
  API_BASE_URL       — Override base URL (default: https://api.deepseek.com)
  MODEL_NAME         — Override model name (default: deepseek-chat)
  CONTAINER_NAME     — Docker container name (default: reynard-kali)
  MAX_ITERATIONS     — Max tool call iterations (default: 500)
=============================================================================
"""

import os
import sys
import json
import time
import glob
import argparse
from datetime import datetime
from pathlib import Path

from openai import OpenAI
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
from dotenv import load_dotenv

from hacking_agent.core.analyzer import ResponseAnalyzer
from hacking_agent.core.events import emit
from hacking_agent.core.expert_playbooks import render_playbook_context
from hacking_agent.core.lab_intel import detect_lab_profile, normalize_target_input
from hacking_agent.core.memory import AgentMemory
from hacking_agent.core.paths import (
    ENV_FILE,
    LOG_DIR as PROJECT_LOG_DIR,
    METHODOLOGIES_DIR,
    ensure_runtime_dirs,
)
from hacking_agent.core.scope import ScopeGuard, ScopeViolation
from hacking_agent.core.strategy import StrategyEngine
from hacking_agent.core.tool_catalog import render_tool_catalog
from hacking_agent.core.tools import TOOL_SCHEMAS, execute_tool
from hacking_agent.ui.live import start_dashboard

# ---------------------------------------------------------------------------
# Load environment variables from .env file if present
# ---------------------------------------------------------------------------
if ENV_FILE.exists():
    load_dotenv(ENV_FILE)
else:
    load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_PROVIDER = (os.getenv("LLM_DEFAULT_PROVIDER") or os.getenv("LLM_PROVIDER") or "deepseek").lower()
_PROVIDER_BASE_URLS = {
    "deepseek": "https://api.deepseek.com",
    "openai": "https://api.openai.com/v1",
    "gpt": "https://api.openai.com/v1",
    "qwen": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
    "dashscope": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
    "local": "http://localhost:8000/v1",
    "ollama": "http://localhost:11434/v1",
}
_PROVIDER_MODELS = {
    "deepseek": "deepseek-chat",
    "openai": "gpt-4o",
    "gpt": "gpt-4o",
    "qwen": "qwen-plus",
    "dashscope": "qwen-plus",
    "local": "local-model",
    "ollama": "qwen2.5-coder",
}

API_KEY = (
    os.getenv("LLM_DEFAULT_API_KEY")
    or os.getenv("DEEPSEEK_API_KEY")
    or os.getenv("OPENAI_API_KEY")
    or os.getenv("QWEN_API_KEY")
    or ""
)
API_BASE_URL = (
    os.getenv("LLM_DEFAULT_BASE_URL")
    or (None if os.getenv("LLM_DEFAULT_PROVIDER") else os.getenv("API_BASE_URL"))
    or _PROVIDER_BASE_URLS.get(_PROVIDER)
    or "https://api.deepseek.com"
)
MODEL_NAME = os.getenv("LLM_DEFAULT_MODEL") or os.getenv("MODEL_NAME") or _PROVIDER_MODELS.get(_PROVIDER, "deepseek-chat")

# Agent limits
MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "500"))
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds between retries on rate limit

# Logging
LOG_DIR = str(PROJECT_LOG_DIR)

# Rich console for pretty output
console = Console()


# =============================================================================
# System Prompt — Structured Exploitation Engine
# =============================================================================

SYSTEM_PROMPT = """You are an autonomous expert penetration tester operating inside a fully-equipped Kali Linux Docker container with root access. You have access to ALL standard Kali pentesting tools plus a Lightpanda headless browser for JavaScript rendering.

# CRITICAL: STRUCTURED EXECUTION FORMAT

You MUST follow this EXACT format for EVERY step. No exceptions.

```
PLAN:
<1-2 sentences: what hypothesis are you testing? what phase are you in?>

ACTION:
<describe what you will do: which tool, what payload, why>

OBSERVATION: (filled after tool result)
<structured analysis of the response>

UPDATE:
<what did you learn? any new facts? which facts changed?>

NEXT:
<what is the next step based on what you learned?>
```

# EXECUTION RULES (NON-NEGOTIABLE)

1. ONE PAYLOAD PER STEP. Send one request, analyze it fully, then decide next.
2. NEVER REPEAT a payload you already sent. Check PAYLOAD HISTORY below.
3. NEVER RE-DERIVE a fact you already know. Check KNOWN FACTS below.
4. ACT > THINK. Prefer sending a test payload over writing paragraphs of analysis.
5. EVERY HTTP response must be analyzed for: reflection, encoding, context, errors.
6. ALWAYS state your hypothesis BEFORE acting.
7. If a phase has failed too many times, MOVE ON to the next approach.
8. RECORD every finding as a fact by explicitly stating: "NEW FACT: key = value"

# PHASE-BASED METHODOLOGY

You are following a strict 6-phase exploitation pipeline. Check your current phase in the EXPLOITATION PROGRESS section below and follow its instructions.

## Phase 1: RECON
- Make a plain GET request to see the page
- Identify technology stack (Angular? React? plain HTML?)
- Find injection points (search boxes, URL params, forms)
- Record: technology_stack, injection_point, base_behavior

## Phase 2: INJECTION  
- Send probe payloads to test reflection
- Map encoding behavior for: < > " ' {{ }} / \\
- Record: reflection_confirmed, encoding_behavior, characters_blocked

## Phase 3: CONTEXT
- Determine WHERE your input appears (HTML body, attribute, JS string, Angular template)
- For Angular: identify version, test {{7*7}} evaluation
- Record: context, angular_version, angular_sandbox

## Phase 4: CAPABILITY
- Test what operations work in your context
- For Angular sandbox: test constructor, prototype, $eval access
- Record: capabilities_mapped, accessible_objects, blocked_operations

## Phase 5: ESCAPE
- Build sandbox escape / filter bypass using known constraints
- Use version-specific techniques (see methodology files)
- Adapt payloads based on ALL known constraints simultaneously
- Record: escape_technique, working_bypass

## Phase 6: EXPLOIT
- Combine escape technique with required trigger (usually alert())
- URL-encode properly for delivery
- Verify lab solved
- Record: lab_solved, final_payload

# AVAILABLE TOOLS

- run_shell: Execute commands in Kali (nmap, sqlmap, ffuf, curl, scripts, etc.)
- tool_inventory: Tool catalog with when-to-use guidance and optional container checks
- read_file / write_file / list_dir: File operations in the container
- http_request: HTTP with persistent cookie jar (auto cookie management)
- browser_navigate: Render pages with JavaScript via Lightpanda headless browser
- browser_execute_js: Execute JS on rendered pages (prove XSS, extract DOM)
- browser_interact: Click/type/select on page elements
- analyze_response: Parse HTTP response into structured security signals
- caido_local_api: Preferred Caido local Replay/history/request-testing bridge
  when the Caido bridge plugin is running.
- caido_cloud_api / caido_cloud_request: Caido Cloud account/workspace API
  access only (team, user, invitations, workspace, subscription, PAT lifecycle);
  do not use Cloud API for Replay/proxy history.
- web_search / web_fetch: Search public writeups, CVEs, advisories, official
  docs, then fetch relevant pages into context for authorized CTF/lab work

# KEY TECHNIQUES

- PortSwigger labs: Solve by performing the required action (alert, data exfil, etc.)
- Cookie jar: Persists at /data/cookies/cookies.txt across all http_request calls
- For HTTPS: Always use insecure=true to skip cert verification
- SQLMap: Use --batch for non-interactive. Specify --forms or -u with injection points.
- XSS: Use browser_execute_js to PROVE alert() fires, not just inject HTML
- Angular: Version-specific sandbox escapes are critical. Check /data/methodologies/

# BEHAVIORAL CONSTRAINTS

- Be a disciplined penetration tester, not a guessing LLM
- If you've tried 5+ payloads without progress, STOP and reassess your approach
- If an approach isn't working after the methodology's max attempts, switch strategies
- Never send more than 3 requests without extracting at least one new fact
- When you solve the lab, state: "LAB SOLVED" with the exact payload that worked
"""


# =============================================================================
# Methodology Loader
# =============================================================================

def load_methodologies(methodologies_dir: str | os.PathLike = METHODOLOGIES_DIR) -> str:
    """
    Load all methodology files and return them as a formatted string
    to include in the system context.
    """
    methodology_text = "\n\n## LOADED METHODOLOGY FILES\n\n"
    md_files = glob.glob(os.path.join(str(methodologies_dir), "*.md"))

    if not md_files:
        methodology_text += "(No methodology files found. Create them in /data/methodologies/)\n"
        return methodology_text

    for md_file in sorted(md_files):
        filename = os.path.basename(md_file)
        try:
            with open(md_file, "r", encoding="utf-8") as f:
                content = f.read()
            methodology_text += f"### {filename}\n```\n{content}\n```\n\n"
        except Exception as exc:
            methodology_text += f"### {filename}\n(Error reading: {exc})\n\n"

    return methodology_text


# =============================================================================
# Session Logger
# =============================================================================

class SessionLogger:
    """Logs the entire agent session for post-run review."""

    def __init__(self, task: str):
        ensure_runtime_dirs()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_task = "".join(c if c.isalnum() or c in "-_ " else "" for c in task[:50])
        self.log_file = os.path.join(LOG_DIR, f"session_{timestamp}_{safe_task}.json")
        self.entries: list[dict] = []
        self.start_time = time.time()
        self.task = task
        self.tool_call_count = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def log(self, entry_type: str, data: dict):
        """Add an entry to the session log."""
        self.entries.append({
            "timestamp": datetime.now().isoformat(),
            "elapsed_seconds": round(time.time() - self.start_time, 2),
            "type": entry_type,
            **data,
        })

    def save(self, memory: AgentMemory | None = None):
        """Write the session log to disk."""
        session_data = {
            "task": self.task,
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "end_time": datetime.now().isoformat(),
            "duration_seconds": round(time.time() - self.start_time, 2),
            "tool_calls": self.tool_call_count,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "memory_state": memory.to_dict() if memory else {},
            "entries": self.entries,
        }
        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2, ensure_ascii=False)
        return self.log_file


# =============================================================================
# Streamed Response Helpers
# =============================================================================

class _FunctionObj:
    """Minimal function object matching the OpenAI tool_call.function interface."""
    def __init__(self, name: str, arguments: str):
        self.name = name
        self.arguments = arguments


class _ToolCall:
    """Assembled tool call from streamed deltas."""
    def __init__(self, id: str, name: str, arguments: str):
        self.id = id
        self.function = _FunctionObj(name, arguments)


class StreamedMessage:
    """
    Holds the fully assembled response from a streamed API call.
    Mimics the interface of openai ChatCompletionMessage so the
    rest of the code works without changes.
    """
    def __init__(self, content: str = "", tool_calls: list | None = None):
        self.content = content
        self.tool_calls = tool_calls  # None = no tool calls (falsy)


# =============================================================================
# Agent Core — Structured Exploitation Engine
# =============================================================================

class HackingAgent:
    """
    Autonomous Reynard using an OpenAI-compatible LLM with a structured
    exploitation pipeline: PLAN → ACT → OBSERVE → UPDATE → NEXT.

    Integrates:
      - Memory system for persistent state
      - Response analyzer for structured signal extraction
      - Strategy engine for phase-based methodology
    """

    REPEATABLE_TOOLS = {
        "oob_poll",
        "list_sessions",
        "swap_session",
        "burp_get_scanner_issues",
        "burp_get_collaborator_interactions",
        "caido_cloud_api",
        "caido_local_api",
    }

    SENSITIVE_ARG_PARTS = ("authorization", "cookie", "token", "api_key", "password", "secret")

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        scope_domains: list[str] | None = None,
        scope_cidrs: list[str] | None = None,
    ):
        """Initialize the agent with API credentials and model config."""

        if not api_key:
            console.print("[bold red]ERROR: No API key found![/]")
            console.print("Set LLM_DEFAULT_API_KEY, DEEPSEEK_API_KEY, OPENAI_API_KEY, or QWEN_API_KEY in .env.")
            sys.exit(1)

        # Initialize OpenAI-compatible client
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url,
        )
        self.model = model

        # Conversation history (maintained across all iterations)
        self.messages: list[dict] = []

        # NEW: Core subsystems
        self.memory = AgentMemory()
        self.analyzer = ResponseAnalyzer()
        self.strategy = StrategyEngine()
        self.scope_domains = scope_domains or []
        self.scope_cidrs = scope_cidrs or []
        self.scope_guard: ScopeGuard | None = None
        self.lab_profile: dict = {}
        self.expert_playbook_context = ""

        # Session statistics
        self.iteration = 0

        console.print(Panel(
            f"[bold green]Agent Initialized[/]\n"
            f"Model: {model}\n"
            f"API: {base_url}\n"
            f"Container: {os.getenv('CONTAINER_NAME', 'reynard-kali')}\n"
            f"Architecture: Structured Exploitation Engine v2.0",
            title="🤖 Reynard",
            border_style="green",
        ))

    def _build_system_prompt(self) -> str:
        """
        Build the full system prompt with:
        1. Core instructions (structured format, methodology)
        2. Loaded methodology files
        3. Current memory state (facts, progress, payloads)
        4. Current phase instructions from strategy engine
        """
        # Base prompt + methodology files
        prompt_parts = [SYSTEM_PROMPT]
        prompt_parts.append(render_tool_catalog("general"))
        prompt_parts.append(load_methodologies())
        if self.expert_playbook_context:
            prompt_parts.append(
                "\n\n# DETECTED EXPERT LAB PLAYBOOK\n\n"
                f"{self.expert_playbook_context}\n\n"
                "Treat this as a high-confidence prior for authorized labs. "
                "Confirm with target evidence before claiming success."
            )

        # Inject current memory state
        memory_context = self.memory.get_context_injection()
        prompt_parts.append(f"\n\n# CURRENT STATE (updated every iteration)\n\n{memory_context}")

        # Inject current phase instructions
        current_phase = self.memory.get_current_phase()
        facts = self.memory.get_all_facts()
        phase_prompt = self.strategy.get_phase_prompt(current_phase, facts)
        prompt_parts.append(f"\n\n# PHASE INSTRUCTIONS\n\n{phase_prompt}")

        return "\n".join(prompt_parts)

    def _call_api(self, logger: SessionLogger) -> StreamedMessage:
        """
        Make a STREAMING API call to DeepSeek.
        Displays the agent's reasoning in real-time (token by token)
        so the user can watch the AI think.
        Returns a StreamedMessage with assembled content and tool calls.
        """
        # UPDATE system prompt with fresh memory state before every call
        self.messages[0] = {"role": "system", "content": self._build_system_prompt()}
        emit("llm_start", {
            "agent": "single",
            "model": self.model,
            "mode": "tool_stream",
            "phase": self.memory.get_current_phase(),
        })

        for attempt in range(MAX_RETRIES):
            try:
                stream = self.client.chat.completions.create(
                    model=self.model,
                    messages=self.messages,
                    tools=TOOL_SCHEMAS,
                    tool_choice="auto",
                    temperature=0.0,
                    max_tokens=16384,
                    stream=True,
                )

                # ----- Stream and display in real-time -----
                content_parts: list[str] = []
                tool_calls_map: dict[int, dict] = {}  # index → {id, name, arguments}
                is_streaming_content = False

                for chunk in stream:
                    # Track usage from the final summary chunk (if API provides it)
                    if hasattr(chunk, "usage") and chunk.usage:
                        logger.total_input_tokens += getattr(chunk.usage, "prompt_tokens", 0) or 0
                        logger.total_output_tokens += getattr(chunk.usage, "completion_tokens", 0) or 0

                    if not chunk.choices:
                        continue

                    delta = chunk.choices[0].delta

                    # --- Stream reasoning text to console in real-time ---
                    if delta.content:
                        if not is_streaming_content:
                            # Print header on first token
                            phase = self.memory.get_current_phase().upper()
                            console.print(f"\n[bold magenta]💭 Agent Reasoning (Phase: {phase}):[/]")
                            console.print(f"[dim]{'─' * 60}[/]")
                            is_streaming_content = True
                        # Write each token as it arrives
                        sys.stdout.write(delta.content)
                        sys.stdout.flush()
                        content_parts.append(delta.content)
                        emit("reasoning_delta", {
                            "agent": "single",
                            "model": self.model,
                            "phase": self.memory.get_current_phase(),
                            "text": delta.content,
                            "raw": False,
                        })

                    # --- Accumulate tool-call deltas (arrive in pieces) ---
                    if delta.tool_calls:
                        for tc_delta in delta.tool_calls:
                            idx = tc_delta.index
                            if idx not in tool_calls_map:
                                tool_calls_map[idx] = {
                                    "id": "", "name": "", "arguments": ""
                                }
                            if tc_delta.id:
                                tool_calls_map[idx]["id"] = tc_delta.id
                            if tc_delta.function:
                                if tc_delta.function.name:
                                    tool_calls_map[idx]["name"] += tc_delta.function.name
                                if tc_delta.function.arguments:
                                    tool_calls_map[idx]["arguments"] += tc_delta.function.arguments

                # ----- Finish streaming display -----
                if is_streaming_content:
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    console.print(f"[dim]{'─' * 60}[/]")

                # ----- Assemble the final tool calls list -----
                assembled_tool_calls = None
                if tool_calls_map:
                    assembled_tool_calls = []
                    for idx in sorted(tool_calls_map.keys()):
                        tc = tool_calls_map[idx]
                        assembled_tool_calls.append(
                            _ToolCall(tc["id"], tc["name"], tc["arguments"])
                        )

                full_content = "".join(content_parts)
                emit("llm_end", {
                    "agent": "single",
                    "model": self.model,
                    "mode": "tool_stream",
                    "phase": self.memory.get_current_phase(),
                    "tool_calls": len(assembled_tool_calls or []),
                })
                return StreamedMessage(
                    content=full_content,
                    tool_calls=assembled_tool_calls,
                )

            except Exception as exc:
                error_msg = str(exc)
                is_rate_limit = "rate" in error_msg.lower() or "429" in error_msg

                if is_rate_limit and attempt < MAX_RETRIES - 1:
                    wait_time = RETRY_DELAY * (attempt + 1)
                    console.print(
                        f"[yellow]⏳ Rate limited. Retrying in {wait_time}s "
                        f"(attempt {attempt + 1}/{MAX_RETRIES})...[/]"
                    )
                    logger.log("rate_limit", {"wait_seconds": wait_time, "attempt": attempt + 1})
                    emit("error", {
                        "agent": "single",
                        "component": "llm",
                        "message": f"rate limited; retrying in {wait_time}s",
                    })
                    time.sleep(wait_time)
                    continue

                # Non-rate-limit error or final retry
                console.print(f"[bold red]API Error: {error_msg}[/]")
                logger.log("api_error", {"error": error_msg, "attempt": attempt + 1})
                emit("error", {
                    "agent": "single",
                    "component": "llm",
                    "message": error_msg[:1000],
                })

                if attempt == MAX_RETRIES - 1:
                    raise

        raise RuntimeError("Max API retries exceeded")

    def _extract_payload_from_args(self, tool_name: str, arguments: dict) -> str | None:
        """Extract the payload/URL from tool arguments for tracking."""
        if tool_name == "http_request":
            url = arguments.get("url", "")
            data = arguments.get("data", "")
            return f"{arguments.get('method', 'GET')} {url}" + (f" body={data}" if data else "")
        elif tool_name == "browser_navigate":
            return f"BROWSE {arguments.get('url', '')}"
        elif tool_name == "browser_execute_js":
            return f"JS@{arguments.get('url', '')} :: {arguments.get('script', '')[:80]}"
        elif tool_name == "browser_interact":
            return f"INTERACT@{arguments.get('url', '')} :: {json.dumps(arguments.get('actions', []))[:80]}"
        elif tool_name == "run_shell":
            cmd = arguments.get("command", "")
            if "curl" in cmd:
                return f"SHELL_CURL {cmd.strip()}"
            return None  # Don't track non-curl shell commands as payloads
        elif tool_name == "tool_inventory":
            return (
                f"TOOL_INVENTORY {arguments.get('role', 'general')} "
                f"check={bool(arguments.get('check_container', False))}"
            )
        elif tool_name == "caido_cloud_api":
            return f"CAIDO {arguments.get('operation', '')} {json.dumps(arguments.get('args', {}), sort_keys=True)[:120]}"
        elif tool_name == "caido_cloud_request":
            return f"CAIDO_RAW {arguments.get('method', 'GET')} {arguments.get('path', '')}"
        elif tool_name == "caido_local_api":
            op = arguments.get("operation", "")
            op_args = arguments.get("args", {}) or {}
            if op in {"send_raw", "create_replay_session"}:
                return f"CAIDO_LOCAL {op} {op_args.get('hostname', '')} {str(op_args.get('raw_request', ''))[:160]}"
            if op == "send_replay_session":
                return f"CAIDO_LOCAL send_replay_session {op_args.get('session_id', '')}"
            return None
        elif tool_name.startswith("burp_"):
            return f"BURP {tool_name} {json.dumps(arguments, sort_keys=True)[:160]}"
        elif tool_name == "discover_apis":
            return f"DISCOVER_APIS {str(arguments.get('base_url', '')).rstrip('/')}"
        elif tool_name == "extract_js_endpoints":
            return f"EXTRACT_JS {str(arguments.get('url', '')).rstrip('/')}"
        elif tool_name == "nuclei_scan":
            return f"NUCLEI {str(arguments.get('url', '')).rstrip('/')} {arguments.get('severity', '')}"
        elif tool_name == "web_search":
            return f"WEB_SEARCH {arguments.get('focus', 'ctf')} {str(arguments.get('query', '')).strip().lower()}"
        elif tool_name == "web_fetch":
            return f"WEB_FETCH {str(arguments.get('url', '')).rstrip('/')}"
        return None

    def _redact_args(self, args: dict) -> dict:
        """Remove secrets before tool calls are streamed to the live UI."""
        redacted = {}
        for key, value in (args or {}).items():
            if any(part in str(key).lower() for part in self.SENSITIVE_ARG_PARTS):
                redacted[key] = "[redacted]"
            elif isinstance(value, dict):
                redacted[key] = self._redact_args(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._redact_args(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                redacted[key] = value
        return redacted

    def _brief_result(self, raw_result: str) -> str:
        return raw_result.replace("\n", " ")[:300]

    def _auto_analyze_response(self, tool_name: str, arguments: dict,
                                result: str) -> dict | None:
        """
        Automatically analyze HTTP/browser responses using the ResponseAnalyzer.
        Returns structured signals or None if not applicable.
        """
        analyzable_tools = {"http_request", "browser_navigate", "browser_execute_js", "browser_interact"}
        if tool_name not in analyzable_tools:
            return None

        try:
            # Extract the payload for reflection detection
            payload = ""
            if tool_name == "http_request":
                url = arguments.get("url", "")
                # Extract search term or payload from URL params
                if "?" in url:
                    params = url.split("?", 1)[1]
                    # Get the last parameter value as likely payload
                    for param in params.split("&"):
                        if "=" in param:
                            payload = param.split("=", 1)[1]
                # Also check POST body
                if arguments.get("data"):
                    data = arguments["data"]
                    if "=" in data:
                        payload = data.split("=")[-1]
                    else:
                        payload = data

            # Parse result JSON to get response body
            try:
                result_data = json.loads(result)
                response_text = (
                    result_data.get("response", "") or
                    result_data.get("rendered_content", "") or
                    result_data.get("rendered_html", "") or
                    ""
                )
            except (json.JSONDecodeError, TypeError):
                response_text = result

            if not response_text:
                return None

            # Run the analyzer
            from urllib.parse import unquote
            signals = self.analyzer.analyze(
                response_text=response_text,
                payload=unquote(payload) if payload else "",
                url=arguments.get("url", ""),
            )

            return signals

        except Exception as exc:
            console.print(f"[dim yellow]Auto-analysis warning: {exc}[/]")
            return None

    def _failure_reason(self, raw_result: str, signals: dict | None) -> str:
        if signals:
            if signals.get("waf_detected"):
                return "Target or proxy appears to have blocked the request."
            if signals.get("error_detected"):
                return "Response analyzer detected an application error."
        try:
            parsed = json.loads(raw_result)
        except (json.JSONDecodeError, TypeError):
            return "Tool returned an error string." if '"error"' in raw_result[:300] else ""
        if isinstance(parsed, dict):
            if parsed.get("error"):
                return str(parsed.get("error"))[:300]
            status = parsed.get("status_code")
            if isinstance(status, int) and status >= 400:
                return f"HTTP status {status} for exact request."
            if parsed.get("ok") is False:
                return "Tool returned ok=false."
        return ""

    def _update_memory_from_signals(self, signals: dict, iteration: int) -> None:
        """Update memory facts based on structured signals from the analyzer."""
        if not signals:
            return

        # Auto-discover facts from signals
        if signals.get("reflected"):
            self.memory.add_fact("reflection_confirmed", True,
                                source="auto_analyzer", iteration=iteration)
        if signals.get("reflection_context"):
            self.memory.add_fact("context", signals["reflection_context"],
                                source="auto_analyzer", iteration=iteration)
        if signals.get("angular_detected"):
            self.memory.add_fact("technology_stack", "AngularJS",
                                source="auto_analyzer", iteration=iteration)
        if signals.get("angular_version"):
            self.memory.add_fact("angular_version", signals["angular_version"],
                                source="auto_analyzer", iteration=iteration)
        if signals.get("angular_evaluated"):
            self.memory.add_fact("angular_evaluated", True,
                                source="auto_analyzer", iteration=iteration)
        if signals.get("ng_app_present"):
            self.memory.add_fact("ng_app_present", True,
                                source="auto_analyzer", iteration=iteration)
        if signals.get("csp_header"):
            self.memory.add_fact("csp", signals["csp_header"],
                                source="auto_analyzer", iteration=iteration)
        if signals.get("html_encoded"):
            self.memory.add_fact("html_encoding_active", True,
                                source="auto_analyzer", iteration=iteration)
        if signals.get("waf_detected"):
            self.memory.add_fact("waf_detected", True,
                                source="auto_analyzer", iteration=iteration)
        if signals.get("lab_solved"):
            self.memory.add_fact("lab_solved", True,
                                source="auto_analyzer", iteration=iteration)
            self.memory.update_progress("exploit", "done")

    def _check_and_advance_phase(self) -> None:
        """Check if the current phase should be advanced based on facts."""
        current = self.memory.get_current_phase()
        facts = self.memory.get_all_facts()

        if self.strategy.should_advance(current, facts):
            self.memory.update_progress(current, "done")
            new_phase = self.memory.get_current_phase()
            self.memory.update_progress(new_phase, "in_progress")
            console.print(f"\n[bold green]📊 PHASE ADVANCED: {current.upper()} → {new_phase.upper()}[/]")
        elif self.strategy.should_abandon(current):
            self.memory.update_progress(current, "skipped")
            new_phase = self.memory.get_current_phase()
            self.memory.update_progress(new_phase, "in_progress")
            console.print(f"\n[bold yellow]⏭️ PHASE SKIPPED (max attempts): {current.upper()} → {new_phase.upper()}[/]")

    def _execute_tool_calls(self, tool_calls: list, logger: SessionLogger) -> list[dict]:
        """
        Execute all tool calls from the model's response and return
        tool result messages for the conversation.

        Enhanced with:
          - Auto-analysis of HTTP responses
          - Payload tracking and dedup
          - Memory updates from signals
        """
        tool_results = []

        for tool_call in tool_calls:
            tool_name = tool_call.function.name
            try:
                arguments = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                arguments = {"error": f"Invalid JSON arguments: {tool_call.function.arguments}"}

            if self.scope_guard is not None:
                try:
                    self.scope_guard.validate(tool_name, arguments)
                except ScopeViolation as exc:
                    reason = str(exc)
                    emit("tool_blocked", {
                        "agent": "single",
                        "tool": tool_name,
                        "reason": reason,
                        "phase": self.memory.get_current_phase(),
                    })
                    self.memory.add_failed_attempt(
                        tool=tool_name,
                        args=arguments,
                        phase=self.memory.get_current_phase(),
                        reason=reason,
                        lesson=(
                            "Stay within the declared engagement scope or ask "
                            "the user to expand scope explicitly."
                        ),
                        iteration=self.iteration,
                    )
                    tool_results.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps({
                            "error": reason,
                            "guidance": "This target is outside the declared scope.",
                        }),
                    })
                    continue

            # --- Payload dedup check ---
            payload_str = self._extract_payload_from_args(tool_name, arguments)
            if payload_str and self.memory.is_duplicate(payload_str):
                emit("tool_blocked", {
                    "agent": "single",
                    "tool": tool_name,
                    "reason": "duplicate payload",
                    "phase": self.memory.get_current_phase(),
                    "payload": payload_str[:160],
                })
                console.print(f"\n[bold yellow]⚠️ DUPLICATE PAYLOAD — skipping: {payload_str[:80]}[/]")
                tool_results.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps({
                        "error": "DUPLICATE PAYLOAD. This exact request was already sent. "
                                 "Check PAYLOAD HISTORY for the result. Try a DIFFERENT payload.",
                        "duplicate_of": payload_str[:120],
                    }),
                })
                continue

            if (
                tool_name not in self.REPEATABLE_TOOLS
                and self.memory.is_known_failed_attempt(tool_name, arguments)
            ):
                reason = f"Known failed attempt blocked: {tool_name}"
                emit("tool_blocked", {
                    "agent": "single",
                    "tool": tool_name,
                    "reason": reason,
                    "phase": self.memory.get_current_phase(),
                })
                tool_results.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps({
                        "error": reason,
                        "guidance": "Change payload, endpoint, session, or detection primitive instead of repeating this exact call.",
                    }),
                })
                continue

            # Log the tool call
            logger.tool_call_count += 1
            logger.log("tool_call", {
                "tool": tool_name,
                "arguments": arguments,
                "call_number": logger.tool_call_count,
                "phase": self.memory.get_current_phase(),
            })

            # Display tool call with phase context
            phase = self.memory.get_current_phase().upper()
            console.print(f"\n[bold cyan]🔧 Tool #{logger.tool_call_count} [{phase}]: {tool_name}[/]")
            if tool_name == "run_shell":
                console.print(f"[dim]   $ {arguments.get('command', '?')[:120]}[/]")
            elif tool_name == "tool_inventory":
                console.print(
                    f"[dim]   role={arguments.get('role', 'general')} "
                    f"check={bool(arguments.get('check_container', False))}[/]"
                )
            elif tool_name == "http_request":
                console.print(f"[dim]   {arguments.get('method', 'GET')} {arguments.get('url', '?')[:100]}[/]")
            elif tool_name in ("browser_navigate", "browser_execute_js", "browser_interact"):
                console.print(f"[dim]   🌐 {arguments.get('url', '?')[:100]}[/]")
            elif tool_name in ("read_file", "write_file", "list_dir"):
                console.print(f"[dim]   📁 {arguments.get('path', '?')}[/]")
            elif tool_name == "caido_cloud_api":
                console.print(f"[dim]   Caido {arguments.get('operation', '?')}[/]")
            elif tool_name == "caido_cloud_request":
                console.print(f"[dim]   Caido {arguments.get('method', 'GET')} {arguments.get('path', '?')[:100]}[/]")
            elif tool_name == "caido_local_api":
                console.print(f"[dim]   Caido local {arguments.get('operation', '?')}[/]")

            # Execute the tool
            start_time = time.time()
            emit("tool_start", {
                "agent": "single",
                "tool": tool_name,
                "args": self._redact_args(arguments),
                "phase": self.memory.get_current_phase(),
            })
            result = execute_tool(tool_name, arguments)
            elapsed = round(time.time() - start_time, 2)

            # --- Auto-analyze HTTP responses ---
            signals = self._auto_analyze_response(tool_name, arguments, result)
            analysis_addendum = ""
            if signals:
                # Format interesting signals for the agent
                formatted = self.analyzer.format_signals(signals)
                analysis_addendum = f"\n\n--- AUTO-ANALYSIS SIGNALS ---\n{formatted}"

                # Update memory from signals
                self._update_memory_from_signals(signals, self.iteration)

                # Display key findings
                findings = []
                if signals.get("reflected"):
                    ctx = signals.get("reflection_context", "?")
                    findings.append(f"reflected={signals['reflected']} (context: {ctx})")
                if signals.get("angular_detected"):
                    ver = signals.get("angular_version", "?")
                    findings.append(f"angular={ver}")
                if signals.get("angular_evaluated"):
                    findings.append("angular_evaluated=TRUE")
                if signals.get("html_encoded"):
                    findings.append("html_encoded=TRUE")
                if signals.get("waf_detected"):
                    findings.append("WAF_DETECTED")
                if signals.get("lab_solved"):
                    findings.append("🎉 LAB SOLVED!")

                if findings:
                    emit("finding", {
                        "agent": "single",
                        "tool": tool_name,
                        "summary": " | ".join(findings),
                        "phase": self.memory.get_current_phase(),
                    })
                    console.print(f"[bold green]   📊 Signals: {' | '.join(findings)}[/]")

            # --- Track payload ---
            if payload_str:
                result_summary = "error" if '"error"' in result[:200] else "ok"
                if signals:
                    if signals.get("lab_solved"):
                        result_summary = "SOLVED"
                    elif signals.get("reflected"):
                        result_summary = "reflected"
                    elif signals.get("waf_detected"):
                        result_summary = "blocked"
                    elif signals.get("error_detected"):
                        result_summary = "error"

                self.memory.add_payload(
                    payload=payload_str,
                    hypothesis=self.memory.current_hypothesis or "testing",
                    phase=self.memory.get_current_phase(),
                    result=result_summary,
                    signals=signals or {},
                    iteration=self.iteration,
                )
                self.strategy.record_attempt(self.memory.get_current_phase())

            failure_reason = self._failure_reason(result, signals)
            if failure_reason:
                self.memory.add_failed_attempt(
                    tool=tool_name,
                    args=arguments,
                    phase=self.memory.get_current_phase(),
                    reason=failure_reason,
                    lesson="Do not repeat this exact call; change payload, endpoint, session, or detection primitive.",
                    iteration=self.iteration,
                )

            # Log the result
            logger.log("tool_result", {
                "tool": tool_name,
                "elapsed_seconds": elapsed,
                "result_length": len(result),
                "signals": signals if signals else None,
                "phase": self.memory.get_current_phase(),
            })
            emit("tool_result", {
                "agent": "single",
                "tool": tool_name,
                "phase": self.memory.get_current_phase(),
                "elapsed_seconds": elapsed,
                "result_length": len(result),
                "signals": signals,
                "failure_reason": failure_reason,
                "summary": self._brief_result(result),
            })

            # Show brief result summary
            console.print(f"[dim]   ✓ Completed in {elapsed}s ({len(result)} chars)[/]")

            # --- Enrich the tool result with analysis ---
            enriched_result = result + analysis_addendum

            # Add tool result to conversation
            tool_results.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": enriched_result,
            })

        return tool_results

    def run(self, task: str, max_iterations: int = MAX_ITERATIONS) -> str:
        """
        Main execution loop: PLAN → ACT → OBSERVE → UPDATE → NEXT.

        Args:
            task: Natural language description of the hacking task.
            max_iterations: Maximum number of tool-call iterations.

        Returns:
            The agent's final response text.
        """
        logger = SessionLogger(task)
        logger.log("task_start", {"task": task})
        target_url, objective = normalize_target_input(task)
        self.lab_profile = detect_lab_profile(task, target_url)
        self.expert_playbook_context = render_playbook_context(self.lab_profile)
        emit("session_start", {
            "target": target_url,
            "objective": objective,
            "lab_profile": self.lab_profile,
            "mode": "single_agent",
            "model": self.model,
            "max_iterations": max_iterations,
        })

        # Reset subsystems for new task
        self.memory = AgentMemory(target_url=target_url)
        self.strategy = StrategyEngine()
        if objective:
            self.memory.add_fact("task_objective", objective, source="cli")
        if self.lab_profile:
            self.memory.add_fact(
                "lab_profile", self.lab_profile.get("id", "unknown"), source="cli"
            )
            if self.lab_profile.get("playbook_id"):
                self.memory.add_fact(
                    "expert_playbook", self.lab_profile["playbook_id"], source="cli"
                )
            for credential in self.lab_profile.get("credentials", []):
                username = credential.get("username")
                password = credential.get("password")
                if username and password:
                    self.memory.add_fact(
                        f"credential_{username}",
                        password,
                        source="lab_profile",
                    )
        guard = ScopeGuard.from_target_url(
            target_url,
            extra_domains=self.scope_domains,
            extra_cidrs=self.scope_cidrs,
        )
        self.scope_guard = guard if guard.allowed_domains else None
        self.memory.update_progress("recon", "in_progress")

        # Initialize conversation with system prompt and user task
        self.messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": task},
        ]

        console.print(Panel(
            f"[bold]{task}[/]",
            title="📋 Task",
            border_style="blue",
        ))

        # Show initial progress
        console.print(Panel(
            self.memory.get_progress_string(),
            title="📊 Exploitation Progress",
            border_style="magenta",
        ))

        final_response = ""

        # =================================================================
        # Main Execution Loop: PLAN → ACT → OBSERVE → UPDATE → NEXT
        # =================================================================
        while self.iteration < max_iterations:
            self.iteration += 1

            phase = self.memory.get_current_phase().upper()
            payloads_sent = self.memory.get_payload_count()
            facts_known = len(self.memory.facts)
            emit("state", {
                "state": "running",
                "agent": "single",
                "iteration": self.iteration,
                "max_iterations": max_iterations,
                "phase": phase,
                "facts": facts_known,
                "payloads": payloads_sent,
            })

            console.print(f"\n{'='*60}")
            console.print(
                f"[bold magenta]Iteration {self.iteration}/{max_iterations}[/] | "
                f"[cyan]Phase: {phase}[/] | "
                f"[green]Facts: {facts_known}[/] | "
                f"[yellow]Payloads: {payloads_sent}[/]"
            )
            console.print(f"{'='*60}")

            # ----- Check for lab solved -----
            if self.memory.get_fact("lab_solved"):
                console.print("\n[bold green]🎉 LAB SOLVED! Agent detected success signal.[/]")
                logger.log("lab_solved", {"iteration": self.iteration})
                break

            # ----- PLAN + ACT: Call the model -----
            try:
                response_message = self._call_api(logger)
            except Exception as exc:
                error_msg = f"Fatal API error: {exc}"
                console.print(f"[bold red]{error_msg}[/]")
                logger.log("fatal_error", {"error": str(exc)})
                emit("error", {
                    "agent": "single",
                    "component": "agent_loop",
                    "message": error_msg[:1000],
                })
                break

            # ----- Extract hypothesis from reasoning -----
            if response_message.content:
                content = response_message.content
                # Try to extract hypothesis from structured output
                if "PLAN:" in content:
                    plan_line = content.split("PLAN:")[1].split("\n")[0].strip()
                    self.memory.current_hypothesis = plan_line[:200]

                # Try to extract facts from "NEW FACT:" markers
                for line in content.split("\n"):
                    if "NEW FACT:" in line.upper():
                        fact_text = line.split(":", 2)[-1].strip()
                        if "=" in fact_text:
                            key, value = fact_text.split("=", 1)
                            self.memory.add_fact(
                                key.strip(), value.strip(),
                                source="agent_stated", iteration=self.iteration,
                            )

                logger.log("agent_reasoning", {
                    "content": content,
                    "phase": self.memory.get_current_phase(),
                    "hypothesis": self.memory.current_hypothesis,
                })
                emit("reasoning_note", {
                    "agent": "single",
                    "text": content[:2000],
                    "phase": self.memory.get_current_phase(),
                    "hypothesis": self.memory.current_hypothesis,
                    "append_to_stream": False,
                })
                final_response = content

            # ----- Check for tool calls -----
            if not response_message.tool_calls:
                # No tool calls = agent is done
                console.print("\n[bold green]✅ Agent completed — no more tool calls.[/]")
                logger.log("task_complete", {"final_response": final_response})
                break

            # ----- Add assistant message to conversation -----
            assistant_msg = {"role": "assistant", "content": response_message.content or ""}
            if response_message.tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in response_message.tool_calls
                ]
            self.messages.append(assistant_msg)

            # ----- OBSERVE: Execute tools and add results -----
            tool_results = self._execute_tool_calls(
                response_message.tool_calls, logger
            )
            self.messages.extend(tool_results)

            # ----- UPDATE: Check phase advancement -----
            self._check_and_advance_phase()

            # ----- Prune conversation if too long -----
            # Keep system + last 40 messages to avoid token overflow
            if len(self.messages) > 50:
                system_msg = self.messages[0]
                user_msg = self.messages[1]
                # Keep a summary of what was pruned
                pruned_count = len(self.messages) - 42
                self.messages = [system_msg, user_msg] + self.messages[-40:]
                console.print(f"[dim]📝 Pruned {pruned_count} old messages to save tokens[/]")

        else:
            console.print(f"\n[bold yellow]⚠️ Max iterations ({max_iterations}) reached.[/]")
            logger.log("max_iterations", {"iterations": max_iterations})

        # =================================================================
        # Session Summary
        # =================================================================
        log_file = logger.save(memory=self.memory)
        emit("session_end", {
            "target": task,
            "mode": "single_agent",
            "success": bool(self.memory.get_fact("lab_solved")),
            "iterations": self.iteration,
            "tool_calls": logger.tool_call_count,
            "facts": len(self.memory.facts),
            "log_file": log_file,
        })

        # Display final progress
        console.print(Panel(
            self.memory.get_progress_string(),
            title="📊 Final Exploitation Progress",
            border_style="green" if self.memory.get_fact("lab_solved") else "yellow",
        ))

        # Display facts discovered
        if self.memory.facts:
            facts_table = Table(title="🧠 Facts Discovered", border_style="cyan")
            facts_table.add_column("Key", style="cyan")
            facts_table.add_column("Value", style="green")
            facts_table.add_column("Confidence", style="yellow")
            for key, fact in self.memory.facts.items():
                facts_table.add_row(key, str(fact.value), fact.confidence)
            console.print(facts_table)

        # Display summary
        summary_table = Table(title="📊 Session Summary", border_style="blue")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        summary_table.add_row("Total Tool Calls", str(logger.tool_call_count))
        summary_table.add_row("Payloads Sent", str(self.memory.get_payload_count()))
        summary_table.add_row("Facts Discovered", str(len(self.memory.facts)))
        summary_table.add_row("Iterations", str(self.iteration))
        summary_table.add_row("Final Phase", self.memory.get_current_phase().upper())
        summary_table.add_row(
            "Duration",
            f"{round(time.time() - logger.start_time, 1)}s"
        )
        summary_table.add_row("Input Tokens", f"{logger.total_input_tokens:,}")
        summary_table.add_row("Output Tokens", f"{logger.total_output_tokens:,}")
        summary_table.add_row("Log File", log_file)

        lab_result = "✅ SOLVED" if self.memory.get_fact("lab_solved") else "❌ Not solved"
        summary_table.add_row("Lab Result", lab_result)
        console.print(summary_table)

        # Post-run suggestion
        console.print(Panel(
            f"[bold]💡 Post-run Self-Review:[/]\n\n"
            f"Feed this session log back to DeepSeek V4 Pro for self-review:\n"
            f"  [cyan]python agent.py \"Review my session log at {log_file}. "
            f"Identify missed opportunities and suggest methodology improvements.\"[/]\n\n"
            f"Or use interactive mode:  [cyan]python agent.py --interactive[/]",
            title="🔍 Review",
            border_style="yellow",
        ))

        return final_response


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """CLI entrypoint for the Reynard."""
    parser = argparse.ArgumentParser(
        description="Autonomous Reynard - multi-provider LLM + Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py "Solve this PortSwigger SQLi lab: https://LAB_URL"
  python agent.py "Scan 192.168.1.0/24 for vulnerabilities"
  python agent.py --interactive

Environment Variables:
  LLM_DEFAULT_API_KEY / DEEPSEEK_API_KEY / OPENAI_API_KEY / QWEN_API_KEY
  LLM_DEFAULT_BASE_URL or API_BASE_URL
  LLM_DEFAULT_MODEL or MODEL_NAME
  CONTAINER_NAME
  MAX_ITERATIONS
        """,
    )

    parser.add_argument(
        "task",
        nargs="?",
        help="The hacking task to perform (natural language prompt).",
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Run in interactive mode (multi-turn conversation).",
    )
    parser.add_argument(
        "--model",
        default=MODEL_NAME,
        help=f"Model name to use (default: {MODEL_NAME}).",
    )
    parser.add_argument(
        "--base-url",
        default=API_BASE_URL,
        help=f"API base URL (default: {API_BASE_URL}).",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=MAX_ITERATIONS,
        help=f"Maximum tool call iterations (default: {MAX_ITERATIONS}).",
    )
    parser.add_argument(
        "--scope-domain",
        action="append",
        default=[],
        help="Additional in-scope domain. Can be repeated.",
    )
    parser.add_argument(
        "--scope-cidr",
        action="append",
        default=[],
        help="Additional in-scope CIDR range. Can be repeated.",
    )
    parser.add_argument(
        "--ui",
        action="store_true",
        default=os.getenv("LIVE_UI", "false").lower() == "true",
        help="Start the live browser dashboard while the agent runs.",
    )
    parser.add_argument(
        "--ui-host",
        type=str,
        default=os.getenv("LIVE_UI_HOST", "127.0.0.1"),
        help="Live dashboard host (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--ui-port",
        type=int,
        default=int(os.getenv("LIVE_UI_PORT", "8765")),
        help="Live dashboard port (default: 8765).",
    )

    args = parser.parse_args()

    # Override max iterations if specified via CLI
    max_iter = args.max_iterations

    dashboard = None
    if args.ui:
        dashboard = start_dashboard(args.ui_host, args.ui_port)
        console.print(f"[bold green]Live dashboard:[/] {dashboard.url}")

    # Banner
    console.print(Panel(
        "[bold cyan]"
        " █▀▀ █ █ ▄▀█ █▀▀ █▄▀ █ █▄ █ █▀▀   ▄▀█ █▀▀ █▀▀ █▄ █ ▀█▀\n"
        " █▀▀ █▀█ █▀█ █▄▄ █ █ █ █ ▀█ █▄█   █▀█ █▄█ ██▄ █ ▀█  █ \n"
        "[/]\n"
        "[dim]Structured Exploitation Engine v2.1 - multi-provider LLM + Kali Linux[/]\n"
        "[dim]Inspired by @Tur24Tur's experiments[/]",
        border_style="cyan",
    ))

    # Initialize agent
    agent = HackingAgent(
        api_key=API_KEY,
        base_url=args.base_url,
        model=args.model,
        scope_domains=args.scope_domain,
        scope_cidrs=args.scope_cidr,
    )

    if args.interactive:
        # Interactive mode
        console.print("[bold green]Interactive mode. Type 'exit' or 'quit' to stop.[/]\n")
        while True:
            try:
                task = console.input("[bold cyan]🎯 Task > [/]")
                if task.strip().lower() in ("exit", "quit", "q"):
                    console.print("[bold]Goodbye! 👋[/]")
                    break
                if not task.strip():
                    continue
                agent.run(task.strip(), max_iterations=max_iter)
                # Reset iteration counter for next task
                agent.iteration = 0
            except KeyboardInterrupt:
                console.print("\n[bold yellow]Interrupted. Type 'exit' to quit.[/]")
                continue
    else:
        if not args.task:
            parser.print_help()
            console.print("\n[bold red]Error: Please provide a task or use --interactive mode.[/]")
            sys.exit(1)

        agent.run(args.task, max_iterations=max_iter)


if __name__ == "__main__":
    main()
