"""
=============================================================================
Reynard — Browser Use adapter (semantic workflow discovery)
=============================================================================
Wraps the optional `browser-use` library as Reynard's semantic navigation /
workflow-exploration layer. It does NOT replace Reynard's deterministic
Playwright (`core/browser.py` / `browser_map`), which stays the source of
network-capture/screenshot proof.

Browser Use explores an app like a real user (signup/login/onboarding/invites/
role changes/checkout/uploads/dynamic UI) and returns STRUCTURED observations:
pages, actions, discovered network/API requests, auth state, and workflow
states. Those become AttackSurface Observations for Reynard to reason over.

Guardrails:
  - Optional: a missing `browser-use` install degrades to available=False.
  - Scope: the browser is hard-restricted to ScopeGuard's allowed domains
    (allowed_domains) with the out-of-scope denylist as prohibited_domains, and
    every returned URL is re-validated with ScopeGuard.classify (out-of-scope
    dropped). Adapters never mutate scope.
  - Authenticated exploration reuses Reynard's session cookies (storage_state).
  - Output is data, not instructions; raw output is spilled to a file.
=============================================================================
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import time
from typing import Any, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from hacking_agent.core import attack_surface as asm
from hacking_agent.integrations.external.base import (
    CAT_NETWORK, CAT_NAVIGATION, CAT_NOTE, CAT_AUTH_STATE, CAT_WORKFLOW_STATE,
    ExternalCapability, ExternalObservation, ExternalProvider,
    PROVIDER_BROWSER_USE, spill_raw,
)


# =============================================================================
# Structured output schema the Browser Use agent must return
# =============================================================================

class DiscoveredRequest(BaseModel):
    method: str = "GET"
    url: str = ""
    kind: str = ""          # xhr | fetch | document | api | other
    notes: str = ""


class WorkflowStep(BaseModel):
    page: str = ""
    action: str = ""        # click | type | submit | navigate | ...
    element: str = ""
    input: str = ""
    result: str = ""
    navigation: str = ""    # URL navigated to as a result, if any


class WorkflowExploration(BaseModel):
    """The structured result Browser Use returns from an exploration."""
    pages: list[str] = Field(default_factory=list)
    steps: list[WorkflowStep] = Field(default_factory=list)
    network_requests: list[DiscoveredRequest] = Field(default_factory=list)
    auth_state: str = ""
    workflow_states: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)


# =============================================================================
# Adapter
# =============================================================================

def _env_flag(name: str, default: str = "1") -> bool:
    return os.getenv(name, default).lower() not in ("0", "false", "no", "off")


class BrowserUseExplorer(ExternalProvider):
    name = PROVIDER_BROWSER_USE

    def __init__(self, max_steps: int | None = None, timeout: int | None = None):
        self.max_steps = int(max_steps or os.getenv("BROWSER_USE_MAX_STEPS", "12"))
        self.timeout = int(timeout or os.getenv("BROWSER_USE_TIMEOUT", "180"))

    # ---- availability ----------------------------------------------------

    def available(self) -> bool:
        if not _env_flag("BROWSER_USE_ENABLED"):
            return False
        try:
            return importlib.util.find_spec("browser_use") is not None
        except Exception:
            return False

    # ---- public API ------------------------------------------------------

    def explore(self, task: str, url: str, *, session: str | None = None,
                scope_guard: Any = None) -> ExternalCapability:
        """Explore `url` with a semantic task and return structured observations.

        Every returned URL is re-validated against ScopeGuard; out-of-scope URLs
        are dropped. The browser itself is hard-restricted to allowed_domains."""
        started = time.time()
        cap = ExternalCapability(
            provider=self.name, capability="workflow_exploration",
            target=url, input={"task": task, "session": session or ""})

        if not self.available():
            cap.available = False
            cap.errors.append("browser-use is not installed or disabled "
                              "(pip install 'reynard[external]', BROWSER_USE_ENABLED=1)")
            return cap

        # Scope pre-check on the entry URL (executor also gates this).
        if scope_guard is not None:
            try:
                if scope_guard.classify(url) == asm.SCOPE_OUT:
                    cap.errors.append(f"entry URL out of scope: {url}")
                    return cap
            except Exception:
                pass

        try:
            history = self._run_agent(task, url, session, scope_guard)
        except Exception as exc:  # never crash the orchestrator
            cap.errors.append(f"browser-use run failed: {exc}")
            cap.duration = time.time() - started
            return cap

        cap.duration = time.time() - started
        self._parse_history(history, cap, scope_guard)
        return cap

    # ---- internals -------------------------------------------------------

    def _run_agent(self, task: str, url: str, session: str | None,
                   scope_guard: Any):
        from browser_use import Agent  # lazy import

        llm = self._build_llm()
        if llm is None:
            raise RuntimeError("no LLM configured for browser-use "
                               "(set BROWSER_USE_LLM_* or LLM_DEFAULT_*)")

        profile = self._build_profile(url, session, scope_guard)
        full_task = (
            f"You are exploring the web application at {url} like a real user to "
            f"map its functionality and workflows. {task}\n"
            "Exercise signup/login/onboarding/invites/role changes/settings/"
            "dashboards/checkout/uploads and any multi-step forms you find. "
            "Record every page, action, and network/API request you observe, the "
            "authentication state, and the workflow states you pass through. Do "
            "NOT attempt exploitation — only discover and report."
        )
        agent = Agent(task=full_task, llm=llm, browser_profile=profile,
                      output_model_schema=WorkflowExploration)

        async def _runner():
            return await asyncio.wait_for(
                agent.run(max_steps=self.max_steps), timeout=self.timeout)

        return asyncio.run(_runner())

    def _build_llm(self):
        """Construct an LLM for Browser Use, reusing Reynard's provider config."""
        provider = (os.getenv("BROWSER_USE_LLM_PROVIDER")
                    or os.getenv("LLM_DEFAULT_PROVIDER") or "openai").lower()
        model = (os.getenv("BROWSER_USE_LLM_MODEL")
                 or os.getenv("LLM_DEFAULT_MODEL") or "gpt-4o-mini")
        api_key = (os.getenv("BROWSER_USE_LLM_API_KEY")
                   or os.getenv("LLM_DEFAULT_API_KEY")
                   or os.getenv("OPENAI_API_KEY")
                   or os.getenv("DEEPSEEK_API_KEY") or "")
        base_url = (os.getenv("BROWSER_USE_LLM_BASE_URL")
                    or os.getenv("LLM_DEFAULT_BASE_URL")
                    or (os.getenv("DEEPSEEK_API_KEY") and "https://api.deepseek.com"))
        try:
            if provider in ("anthropic", "claude"):
                from browser_use import ChatAnthropic
                return ChatAnthropic(model=model, api_key=api_key or None)
            if provider in ("browser-use", "browseruse", "bu"):
                from browser_use import ChatBrowserUse
                return ChatBrowserUse()
            from browser_use import ChatOpenAI
            kwargs: dict[str, Any] = {"model": model}
            if api_key:
                kwargs["api_key"] = api_key
            if base_url:
                kwargs["base_url"] = base_url
            return ChatOpenAI(**kwargs)
        except Exception:
            return None

    def _build_profile(self, url: str, session: str | None, scope_guard: Any):
        from browser_use import BrowserProfile  # lazy import

        allowed = _allowed_domain_patterns(scope_guard, url)
        prohibited = list(getattr(scope_guard, "out_of_scope", []) or []) if scope_guard else []
        kwargs: dict[str, Any] = {"headless": True}
        if allowed:
            kwargs["allowed_domains"] = allowed
        if prohibited:
            kwargs["prohibited_domains"] = prohibited
        storage_state = _storage_state_from_session(url, session)
        if storage_state:
            kwargs["storage_state"] = storage_state
        har = _har_path()
        if har:
            kwargs["record_har_path"] = har
            self._last_har = har
        else:
            self._last_har = ""
        try:
            return BrowserProfile(**kwargs)
        except TypeError:
            # Older/newer versions may not accept every kwarg — degrade safely.
            safe = {"headless": True}
            if allowed:
                safe["allowed_domains"] = allowed
            return BrowserProfile(**safe)

    def _parse_history(self, history: Any, cap: ExternalCapability,
                       scope_guard: Any) -> None:
        obs: list[ExternalObservation] = []

        structured = getattr(history, "structured_output", None)
        if isinstance(structured, WorkflowExploration):
            obs.extend(_observations_from_structured(structured, scope_guard))

        # HAR network capture (authoritative network/API discovery).
        har = getattr(self, "_last_har", "")
        if har:
            cap.artifacts.append(har)
            obs.extend(_observations_from_har(har, scope_guard))

        # Visited URLs -> navigation observations (scope-checked).
        try:
            for u in (history.urls() or []):
                if _in_scope(scope_guard, u):
                    obs.append(ExternalObservation(
                        category=CAT_NAVIGATION, summary=f"visited {u}",
                        source=self.name, url=str(u)))
        except Exception:
            pass

        # Spill the raw agent trace (thoughts/actions) to a file, not the LLM.
        try:
            raw_parts = []
            fr = history.final_result()
            if fr:
                raw_parts.append(f"FINAL RESULT:\n{fr}")
            raw_parts.append(f"ACTIONS:\n{history.model_actions()}")
            cap.raw_result_reference = spill_raw(self.name, cap.capability,
                                                 "\n\n".join(str(p) for p in raw_parts))
        except Exception:
            pass

        cap.structured_observations = _dedupe_observations(obs)
        if cap.structured_observations:
            cap.confidence = "probable"

        # Best-effort cost/usage.
        try:
            usage = getattr(history, "usage", None)
            if usage is not None:
                cap.cost = float(getattr(usage, "total_cost", 0.0) or 0.0)
        except Exception:
            pass


# =============================================================================
# Helpers (module-level, pure where possible)
# =============================================================================

def _in_scope(scope_guard: Any, url: str) -> bool:
    if not url:
        return False
    if scope_guard is None:
        return True
    try:
        return scope_guard.classify(url) != asm.SCOPE_OUT
    except Exception:
        return True


def _allowed_domain_patterns(scope_guard: Any, url: str) -> list[str]:
    """Build Browser Use allowed_domains patterns from ScopeGuard's allowlist."""
    domains: list[str] = []
    if scope_guard is not None:
        for d in list(getattr(scope_guard, "allowed_domains", []) or []):
            if d:
                domains.append(f"*.{d}")
                domains.append(d)
    host = urlsplit(url if "://" in url else f"http://{url}").hostname
    if host and host not in domains:
        domains.append(host)
    # de-dup, preserve order
    seen, out = set(), []
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _storage_state_from_session(url: str, session: str | None) -> Optional[dict]:
    """Build a Playwright storage_state (cookies) from a Reynard session so
    Browser Use can explore authenticated areas. Best-effort; returns None when
    no cookies are available (e.g. no container / anonymous)."""
    try:
        from hacking_agent.core import sessions as session_mod
        reg = session_mod.get_registry()
        cookies = reg.read_cookies(session) if hasattr(reg, "read_cookies") else {}
    except Exception:
        cookies = {}
    if not cookies:
        return None
    host = urlsplit(url if "://" in url else f"http://{url}").hostname or ""
    if not host:
        return None
    cookie_list = [
        {"name": str(k), "value": str(v), "domain": host, "path": "/"}
        for k, v in cookies.items() if k
    ]
    return {"cookies": cookie_list, "origins": []} if cookie_list else None


def _har_path() -> str:
    try:
        from hacking_agent.core.paths import LOG_DIR, ensure_runtime_dirs
        ensure_runtime_dirs()
        d = LOG_DIR / "external"
        d.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        return str(d / f"browser_use_{ts}_{os.getpid()}.har")
    except Exception:
        return ""


def _looks_like_api(url: str, content_type: str = "", kind: str = "") -> bool:
    low = (url or "").lower()
    if kind in ("xhr", "fetch"):
        return True
    if "/api" in low or "graphql" in low or low.rstrip("/").endswith(".json"):
        return True
    return "json" in (content_type or "").lower()


def _observations_from_structured(w: "WorkflowExploration",
                                  scope_guard: Any) -> list[ExternalObservation]:
    out: list[ExternalObservation] = []
    for req in w.network_requests or []:
        url = (req.url or "").strip()
        if not url or not _in_scope(scope_guard, url):
            continue
        is_api = _looks_like_api(url, kind=req.kind)
        out.append(ExternalObservation(
            category="api" if is_api else "endpoint",
            summary=f"{(req.method or 'GET').upper()} {url}"
                    + (f" ({req.kind})" if req.kind else ""),
            source=PROVIDER_BROWSER_USE, url=url,
            method=(req.method or "GET").upper(),
            kind_hint=asm.KIND_API if is_api else asm.KIND_ENDPOINT,
            data={"notes": req.notes, "kind": req.kind}))
    for step in w.steps or []:
        nav = (step.navigation or "").strip()
        if nav and _in_scope(scope_guard, nav):
            out.append(ExternalObservation(
                category=CAT_NAVIGATION,
                summary=f"{step.action} on {step.page} -> {nav}",
                source=PROVIDER_BROWSER_USE, url=nav,
                data={"element": step.element, "input_present": bool(step.input),
                      "result": step.result}))
        else:
            out.append(ExternalObservation(
                category=CAT_NOTE,
                summary=f"{step.action or 'step'} on {step.page}: {step.result}"[:300],
                source=PROVIDER_BROWSER_USE,
                data={"element": step.element}))
    if w.auth_state:
        out.append(ExternalObservation(
            category=CAT_AUTH_STATE, summary=f"auth state: {w.auth_state}",
            source=PROVIDER_BROWSER_USE, data={"auth_state": w.auth_state}))
    for ws in w.workflow_states or []:
        out.append(ExternalObservation(
            category=CAT_WORKFLOW_STATE, summary=f"workflow state: {ws}",
            source=PROVIDER_BROWSER_USE, data={"name": ws, "state": ws}))
    for note in w.observations or []:
        out.append(ExternalObservation(
            category=CAT_NOTE, summary=str(note)[:300], source=PROVIDER_BROWSER_USE))
    return out


def _observations_from_har(har_path: str,
                           scope_guard: Any) -> list[ExternalObservation]:
    """Parse a Playwright HAR into network/API observations (scope-checked)."""
    out: list[ExternalObservation] = []
    try:
        import json
        with open(har_path, "r", encoding="utf-8", errors="replace") as fh:
            har = json.load(fh)
        entries = (har.get("log", {}) or {}).get("entries", []) or []
    except Exception:
        return out
    seen: set[tuple] = set()
    for e in entries:
        try:
            req = e.get("request", {}) or {}
            resp = e.get("response", {}) or {}
            url = str(req.get("url", ""))
            method = str(req.get("method", "GET")).upper()
            if not url.startswith("http") or not _in_scope(scope_guard, url):
                continue
            key = (method, url.split("#", 1)[0])
            if key in seen:
                continue
            seen.add(key)
            ctype = ""
            for h in (resp.get("headers", []) or []):
                if str(h.get("name", "")).lower() == "content-type":
                    ctype = str(h.get("value", ""))
                    break
            is_api = _looks_like_api(url, content_type=ctype,
                                     kind=str(e.get("_resourceType", "")))
            out.append(ExternalObservation(
                category=CAT_NETWORK,
                summary=f"{method} {url}",
                source=PROVIDER_BROWSER_USE, url=url, method=method,
                kind_hint=asm.KIND_API if is_api else asm.KIND_ENDPOINT,
                data={"status": resp.get("status"), "content_type": ctype}))
        except Exception:
            continue
    return out


def _dedupe_observations(obs: list[ExternalObservation]) -> list[ExternalObservation]:
    seen: set[tuple] = set()
    out: list[ExternalObservation] = []
    for o in obs:
        key = (o.category, o.method, o.url, o.summary[:80])
        if key not in seen:
            seen.add(key)
            out.append(o)
    return out


# Module-level singleton.
_explorer: BrowserUseExplorer | None = None


def get_explorer() -> BrowserUseExplorer:
    global _explorer
    if _explorer is None:
        _explorer = BrowserUseExplorer()
    return _explorer
