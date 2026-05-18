"""
=============================================================================
Reynard — Multi-Provider LLM Abstraction
=============================================================================
Unified `LLMProvider` interface for any model behind any vendor:

  - OpenAI            (api.openai.com)
  - DeepSeek          (api.deepseek.com)
  - Qwen / DashScope  (dashscope-intl.aliyuncs.com/compatible-mode/v1)
  - Kimi / Moonshot   (api.moonshot.cn/v1)
  - Local models      (vLLM, Ollama, LM Studio — all OpenAI-compatible)
  - Anthropic Claude  (Messages API + tool_use schema enforcement)

Per-agent provider binding is supported via env vars, so the Coordinator
can run on Claude Sonnet while the Exploitation Agent runs on a local
DeepSeek instance, etc.

Strict JSON validation: every typed call retries (with the validator error
appended to the conversation) until either the schema validates or the
retry budget is exhausted.
=============================================================================
"""
from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from hacking_agent.core.events import emit
from hacking_agent.core.schemas import ProviderConfig

T = TypeVar("T", bound=BaseModel)

DEFAULT_MAX_RETRIES = 2
RETRY_DELAY_SECONDS = 3


class ProviderError(RuntimeError):
    """Raised when an LLM call fails terminally (transport or schema)."""


# =============================================================================
# Abstract base
# =============================================================================

class LLMProvider(ABC):
    """Common interface implemented by all provider adapters."""

    config: ProviderConfig

    @abstractmethod
    def call_typed(
        self,
        system: str,
        user: str,
        schema: type[T],
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> T:
        """Call the LLM and validate the response into `schema`."""

    @abstractmethod
    def call_text(
        self,
        system: str,
        user: str,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> str:
        """Free-form text response (used by the reporter)."""


def _augment_for_schema(system: str, schema: type[BaseModel]) -> str:
    """Append a strict-JSON instruction with the target schema."""
    schema_json = schema.model_json_schema()
    return (
        system
        + "\n\n# RESPONSE FORMAT (STRICT)\n"
        + "Respond with a SINGLE JSON object that EXACTLY matches this schema:\n\n"
        + "```json\n"
        + json.dumps(schema_json, indent=2)
        + "\n```\n\n"
        + "Do not include any text outside the JSON. No markdown fences. No commentary."
    )


def _strip_fence(text: str) -> str:
    """Defensive: strip markdown fences and <think> blocks."""
    import re
    # Remove <think>...</think> blocks if present
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    
    s = text.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[-1]
        if s.endswith("```"):
            s = s[:-3]
        elif "```" in s:
            s = s.rsplit("```", 1)[0]
    return s.strip()


def _is_openai_reasoning_chat_model(model: str) -> bool:
    """Return True for OpenAI Chat Completions models with newer param names."""
    normalized = (model or "").lower().strip()
    return normalized.startswith(("gpt-5", "o1", "o3", "o4"))


def _provider_display_name(config: ProviderConfig) -> str:
    """Human-friendly provider label for logs and terminal output."""
    base_url = (config.base_url or "").lower().rstrip("/")
    model = (config.model or "").lower()
    if config.kind == "anthropic":
        return "anthropic"
    if "api.openai.com" in base_url or model.startswith(("gpt-", "o1", "o3", "o4")):
        return "openai"
    if "deepseek" in base_url or model.startswith("deepseek"):
        return "deepseek"
    if "dashscope" in base_url or model.startswith("qwen"):
        return "qwen"
    if "moonshot" in base_url or model.startswith("kimi"):
        return "kimi"
    if "localhost" in base_url or "127.0.0.1" in base_url:
        return "local-openai-compatible"
    return config.kind


def _apply_openai_compatible_params(kwargs: dict[str, Any], config: ProviderConfig) -> None:
    """Apply model-specific Chat Completions parameters.

    GPT-5/o-series Chat Completions models reject legacy `max_tokens` and
    expect `max_completion_tokens`. Many third-party OpenAI-compatible
    providers still expect `max_tokens`, so keep the legacy name unless the
    selected model is one of the known OpenAI reasoning families.
    """
    if _is_openai_reasoning_chat_model(config.model):
        kwargs["max_completion_tokens"] = config.max_tokens
    else:
        kwargs["max_tokens"] = config.max_tokens
        kwargs["temperature"] = config.temperature


def _token_param_name(config: ProviderConfig) -> str:
    return "max_completion_tokens" if _is_openai_reasoning_chat_model(config.model) else "max_tokens"


def _emit_llm_request_trace(config: ProviderConfig, *, mode: str, schema: str | None, attempt: int) -> None:
    """Print and publish a concise, secret-free LLM call trace."""
    provider = _provider_display_name(config)
    effort = config.reasoning_effort or "provider-default"
    token_param = _token_param_name(config)
    endpoint = "chat.completions" if config.kind == "openai-compatible" else config.kind
    summary = (
        f"LLM call role={config.role} provider={provider} model={config.model} "
        f"endpoint={endpoint} mode={mode}"
    )
    if schema:
        summary += f" schema={schema}"
    summary += f" {token_param}={config.max_tokens} reasoning_effort={effort}"
    if attempt:
        summary += f" retry={attempt}"
    if provider == "openai" and _is_openai_reasoning_chat_model(config.model):
        summary += " (OpenAI raw reasoning is hidden; configured effort is shown)"

    from rich.console import Console

    Console().print(f"[dim]{summary}[/]")
    emit("reasoning_note", {
        "agent": config.role,
        "model": config.model,
        "provider": provider,
        "text": summary,
    })


# =============================================================================
# OpenAI-compatible provider (OpenAI, DeepSeek, Qwen, Kimi, vLLM, Ollama, ...)
# =============================================================================

class OpenAICompatibleProvider(LLMProvider):
    """Adapter for any vendor exposing the OpenAI Chat Completions schema."""

    def __init__(self, config: ProviderConfig):
        self.config = config
        try:
            from openai import OpenAI
        except ImportError as e:
            raise ProviderError(f"openai package required: pip install openai ({e})")
        self._client = OpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
            default_headers=config.extra_headers or None,
        )

    def call_typed(self, system, user, schema, max_retries=DEFAULT_MAX_RETRIES):
        augmented_system = _augment_for_schema(system, schema)
        messages: list[dict] = [
            {"role": "system", "content": augmented_system},
            {"role": "user", "content": user},
        ]
        last_error: Exception | None = None
        emit("llm_start", {
            "agent": self.config.role,
            "model": self.config.model,
            "provider": self.config.kind,
            "mode": "typed",
            "schema": schema.__name__,
        })

        for attempt in range(max_retries + 1):
            try:
                kwargs: dict[str, Any] = dict(
                    model=self.config.model,
                    messages=messages,
                )
                _apply_openai_compatible_params(kwargs, self.config)
                if self.config.supports_json_mode:
                    kwargs["response_format"] = {"type": "json_object"}
                if self.config.reasoning_effort and self.config.reasoning_effort != "none":
                    kwargs["reasoning_effort"] = self.config.reasoning_effort
                if self.config.enable_thinking_param:
                    kwargs["extra_body"] = {"enable_thinking": True}

                kwargs["stream"] = True
                _emit_llm_request_trace(
                    self.config,
                    mode="typed",
                    schema=schema.__name__,
                    attempt=attempt,
                )
                resp = self._client.chat.completions.create(**kwargs)
                
                from rich.console import Console
                console = Console()
                
                raw = ""
                is_first_reasoning = True
                
                for chunk in resp:
                    if not chunk.choices:
                        continue
                    delta = chunk.choices[0].delta
                    
                    # Print reasoning content natively supported by API (e.g. DeepSeek-R1, OpenAI O1/O3)
                    reasoning_chunk = getattr(delta, "reasoning_content", None)
                    if reasoning_chunk:
                        if is_first_reasoning:
                            console.print("\n[dim italic]🤔 Thinking...[/]", style="dim")
                            is_first_reasoning = False
                        console.print(reasoning_chunk, end="", style="dim")
                        emit("reasoning_delta", {
                            "agent": self.config.role,
                            "model": self.config.model,
                            "text": reasoning_chunk,
                            "raw": True,
                        })
                        
                    content_chunk = getattr(delta, "content", None)
                    if content_chunk:
                        # If the model sends <think> blocks inside content, we print them out live as well
                        raw += content_chunk
                        emit("assistant_delta", {
                            "agent": self.config.role,
                            "model": self.config.model,
                            "text": content_chunk,
                        })
                        
                if not is_first_reasoning:
                    console.print() # Newline after reasoning completes

                data = json.loads(_strip_fence(raw))
                validated = schema.model_validate(data)
                emit("llm_end", {
                    "agent": self.config.role,
                    "model": self.config.model,
                    "mode": "typed",
                    "schema": schema.__name__,
                })
                return validated

            except (ValidationError, json.JSONDecodeError) as e:
                last_error = e
                emit("llm_validation_error", {
                    "agent": self.config.role,
                    "model": self.config.model,
                    "error": str(e)[:1000],
                })
                # Re-prompt the model with the validator's error so it can self-correct.
                messages.append({
                    "role": "user",
                    "content": (
                        f"Your previous response failed validation:\n{e}\n\n"
                        "Re-emit a SINGLE JSON object that matches the schema exactly. "
                        "No prose, no markdown fences, no commentary."
                    ),
                })
            except Exception as e:
                last_error = e
                msg = str(e).lower()
                if any(s in msg for s in ("rate", "429", "timeout")):
                    time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                    continue
                if "reasoning_effort" in msg:
                    self.config.reasoning_effort = None
                    continue
                if "enable_thinking" in msg:
                    self.config.enable_thinking_param = False
                    continue
                # Some local servers reject response_format — retry without it.
                if "response_format" in msg or "not supported" in msg:
                    self.config.supports_json_mode = False
                    continue
                emit("error", {
                    "agent": self.config.role,
                    "component": "llm",
                    "message": str(e)[:1000],
                })
                raise ProviderError(f"OpenAI-compatible API error: {e}") from e

        emit("error", {
            "agent": self.config.role,
            "component": "llm",
            "message": f"Schema validation failed: {last_error}"[:1000],
        })
        raise ProviderError(
            f"Schema validation failed after {max_retries + 1} attempts. "
            f"Last error: {last_error}"
        )

    def call_text(self, system, user, max_retries=DEFAULT_MAX_RETRIES):
        emit("llm_start", {
            "agent": self.config.role,
            "model": self.config.model,
            "provider": self.config.kind,
            "mode": "text",
        })
        for attempt in range(max_retries + 1):
            try:
                kwargs: dict[str, Any] = dict(
                    model=self.config.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                )
                _apply_openai_compatible_params(kwargs, self.config)
                if self.config.reasoning_effort and self.config.reasoning_effort != "none":
                    kwargs["reasoning_effort"] = self.config.reasoning_effort
                if self.config.enable_thinking_param:
                    kwargs["extra_body"] = {"enable_thinking": True}
                    
                kwargs["stream"] = True
                _emit_llm_request_trace(
                    self.config,
                    mode="text",
                    schema=None,
                    attempt=attempt,
                )
                resp = self._client.chat.completions.create(**kwargs)
                
                from rich.console import Console
                console = Console()
                
                raw = ""
                is_first_reasoning = True
                
                for chunk in resp:
                    if not chunk.choices:
                        continue
                    delta = chunk.choices[0].delta
                    
                    reasoning_chunk = getattr(delta, "reasoning_content", None)
                    if reasoning_chunk:
                        if is_first_reasoning:
                            console.print("\n[dim italic]🤔 Thinking...[/]", style="dim")
                            is_first_reasoning = False
                        console.print(reasoning_chunk, end="", style="dim")
                        emit("reasoning_delta", {
                            "agent": self.config.role,
                            "model": self.config.model,
                            "text": reasoning_chunk,
                            "raw": True,
                        })

                    content_chunk = getattr(delta, "content", None)
                    if content_chunk:
                        raw += content_chunk
                        emit("assistant_delta", {
                            "agent": self.config.role,
                            "model": self.config.model,
                            "text": content_chunk,
                        })
                
                if not is_first_reasoning:
                    console.print()
                    
                emit("llm_end", {
                    "agent": self.config.role,
                    "model": self.config.model,
                    "mode": "text",
                })
                return raw
            except Exception as e:
                msg = str(e).lower()
                if attempt < max_retries and any(s in msg for s in ("rate", "429", "timeout")):
                    time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                    continue
                if "reasoning_effort" in msg:
                    self.config.reasoning_effort = None
                    continue
                if "enable_thinking" in msg:
                    self.config.enable_thinking_param = False
                    continue
                if attempt < max_retries:
                    continue
                emit("error", {
                    "agent": self.config.role,
                    "component": "llm",
                    "message": str(e)[:1000],
                })
                raise ProviderError(f"OpenAI-compatible API error: {e}") from e
        emit("error", {
            "agent": self.config.role,
            "component": "llm",
            "message": "OpenAI-compatible text call reached unreachable state.",
        })
        raise ProviderError("unreachable")


# =============================================================================
# Anthropic provider (schema enforced via tool_use)
# =============================================================================

class AnthropicProvider(LLMProvider):
    """Adapter for Anthropic's Messages API.

    Schema enforcement uses Anthropic's tool_use feature: we declare a single
    "respond_with_structured_output" tool whose input_schema is the target
    Pydantic schema, and force `tool_choice` to that tool. The resulting
    block.input is guaranteed to match the schema (modulo the model's
    accuracy)."""

    def __init__(self, config: ProviderConfig):
        self.config = config
        try:
            from anthropic import Anthropic
        except ImportError as e:
            raise ProviderError(f"anthropic package required: pip install anthropic ({e})")
        self._client = Anthropic(api_key=config.api_key, base_url=config.base_url)

    def call_typed(self, system, user, schema, max_retries=DEFAULT_MAX_RETRIES):
        schema_json = schema.model_json_schema()
        tool_def = {
            "name": "respond_with_structured_output",
            "description": "Emit your structured response. ALWAYS use this tool.",
            "input_schema": schema_json,
        }
        last_error: Exception | None = None
        emit("llm_start", {
            "agent": self.config.role,
            "model": self.config.model,
            "provider": self.config.kind,
            "mode": "typed",
            "schema": schema.__name__,
        })

        for attempt in range(max_retries + 1):
            try:
                msg_kwargs: dict[str, Any] = dict(
                    model=self.config.model,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    system=system,
                    tools=[tool_def],
                    tool_choice={"type": "tool", "name": "respond_with_structured_output"},
                    messages=[{"role": "user", "content": user}],
                )
                if self.config.thinking_enabled:
                    # Extended thinking requires temperature=1 and disables tool_choice
                    # forcing — but typed output still works because we ask for the tool
                    # in the system prompt and the model picks it up.
                    msg_kwargs["thinking"] = {
                        "type": "enabled",
                        "budget_tokens": self.config.thinking_budget_tokens,
                    }
                    msg_kwargs["temperature"] = 1.0
                    msg_kwargs.pop("tool_choice", None)
                resp = self._client.messages.create(**msg_kwargs)
                for block in resp.content:
                    if getattr(block, "type", None) == "thinking":
                        emit("reasoning_delta", {
                            "agent": self.config.role,
                            "model": self.config.model,
                            "text": getattr(block, "thinking", "") or getattr(block, "text", ""),
                            "raw": True,
                        })
                    if getattr(block, "type", None) == "tool_use":
                        validated = schema.model_validate(block.input)
                        emit("llm_end", {
                            "agent": self.config.role,
                            "model": self.config.model,
                            "mode": "typed",
                            "schema": schema.__name__,
                        })
                        return validated
                raise ProviderError("Anthropic response had no tool_use block.")

            except ValidationError as e:
                last_error = e
                emit("llm_validation_error", {
                    "agent": self.config.role,
                    "model": self.config.model,
                    "error": str(e)[:1000],
                })
                if attempt >= max_retries:
                    break
                # Retry with a corrective hint.
                user = (
                    f"{user}\n\n[validator error from previous attempt: {e} — please re-emit "
                    "valid JSON matching the tool's input_schema]"
                )
            except Exception as e:
                last_error = e
                msg = str(e).lower()
                if any(s in msg for s in ("rate", "429", "overloaded", "timeout")):
                    time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                    continue
                emit("error", {
                    "agent": self.config.role,
                    "component": "llm",
                    "message": str(e)[:1000],
                })
                raise ProviderError(f"Anthropic API error: {e}") from e

        emit("error", {
            "agent": self.config.role,
            "component": "llm",
            "message": f"Anthropic schema validation failed: {last_error}"[:1000],
        })
        raise ProviderError(f"Anthropic schema validation failed: {last_error}")

    def call_text(self, system, user, max_retries=DEFAULT_MAX_RETRIES):
        emit("llm_start", {
            "agent": self.config.role,
            "model": self.config.model,
            "provider": self.config.kind,
            "mode": "text",
        })
        for attempt in range(max_retries + 1):
            try:
                msg_kwargs: dict[str, Any] = dict(
                    model=self.config.model,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                )
                if self.config.thinking_enabled:
                    msg_kwargs["thinking"] = {
                        "type": "enabled",
                        "budget_tokens": self.config.thinking_budget_tokens,
                    }
                    msg_kwargs["temperature"] = 1.0
                resp = self._client.messages.create(**msg_kwargs)
                parts: list[str] = []
                for block in resp.content:
                    if getattr(block, "type", None) == "thinking":
                        emit("reasoning_delta", {
                            "agent": self.config.role,
                            "model": self.config.model,
                            "text": getattr(block, "thinking", "") or getattr(block, "text", ""),
                            "raw": True,
                        })
                    if getattr(block, "type", None) == "text":
                        parts.append(block.text)
                        emit("assistant_delta", {
                            "agent": self.config.role,
                            "model": self.config.model,
                            "text": block.text,
                        })
                emit("llm_end", {
                    "agent": self.config.role,
                    "model": self.config.model,
                    "mode": "text",
                })
                return "".join(parts)
            except Exception as e:
                msg = str(e).lower()
                if attempt < max_retries and any(s in msg for s in ("rate", "429", "overloaded", "timeout")):
                    time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                    continue
                if attempt < max_retries:
                    continue
                emit("error", {
                    "agent": self.config.role,
                    "component": "llm",
                    "message": str(e)[:1000],
                })
                raise ProviderError(f"Anthropic API error: {e}") from e
        raise ProviderError("unreachable")


# =============================================================================
# Provider registry — env-driven, per-agent overrides
# =============================================================================

class ProviderRegistry:
    """Builds and caches `LLMProvider` instances per agent role.

    Configuration via env vars:
      LLM_DEFAULT_PROVIDER     openai-compatible | anthropic
      LLM_DEFAULT_MODEL        e.g. deepseek-chat / claude-sonnet-4-6 / gpt-4o
      LLM_DEFAULT_API_KEY      provider API key
      LLM_DEFAULT_BASE_URL     base URL (only for openai-compatible)
      LLM_DEFAULT_JSON_MODE    "true"|"false" (default true)

    Per-agent overrides (any subset):
      LLM_COORDINATOR_PROVIDER / _MODEL / _API_KEY / _BASE_URL
      LLM_RECON_*
      LLM_ANALYST_*
      LLM_EXPLOITATION_*
      LLM_REPORTER_*

    Backward compat: also reads legacy DEEPSEEK_API_KEY / API_BASE_URL / MODEL_NAME.
    """

    AGENT_ROLES = ("default", "coordinator", "recon", "analyst", "exploitation", "reporter", "validator", "pivot")
    PROVIDER_PROFILES: dict[str, dict[str, Any]] = {
        "openai-compatible": {
            "kind": "openai-compatible",
            "model": "model-name",
            "base_url": None,
            "key_env": ("LLM_DEFAULT_API_KEY",),
        },
        "deepseek": {
            "kind": "openai-compatible",
            "model": "deepseek-chat",
            "base_url": "https://api.deepseek.com",
            "key_env": ("DEEPSEEK_API_KEY",),
        },
        "openai": {
            "kind": "openai-compatible",
            "model": "gpt-4o",
            "base_url": "https://api.openai.com/v1",
            "key_env": ("OPENAI_API_KEY",),
        },
        "gpt": {
            "kind": "openai-compatible",
            "model": "gpt-4o",
            "base_url": "https://api.openai.com/v1",
            "key_env": ("OPENAI_API_KEY",),
        },
        "anthropic": {
            "kind": "anthropic",
            "model": "claude-sonnet-4-6",
            "base_url": None,
            "key_env": ("ANTHROPIC_API_KEY",),
        },
        "claude": {
            "kind": "anthropic",
            "model": "claude-sonnet-4-6",
            "base_url": None,
            "key_env": ("ANTHROPIC_API_KEY",),
        },
        "qwen": {
            "kind": "openai-compatible",
            "model": "qwen-plus",
            "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            "key_env": ("QWEN_API_KEY", "DASHSCOPE_API_KEY"),
        },
        "dashscope": {
            "kind": "openai-compatible",
            "model": "qwen-plus",
            "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            "key_env": ("QWEN_API_KEY", "DASHSCOPE_API_KEY"),
        },
        "local": {
            "kind": "openai-compatible",
            "model": "local-model",
            "base_url": "http://localhost:8000/v1",
            "key_env": ("LOCAL_LLM_API_KEY",),
            "fallback_key": "dummy",
        },
        "ollama": {
            "kind": "openai-compatible",
            "model": "qwen2.5-coder",
            "base_url": "http://localhost:11434/v1",
            "key_env": ("OLLAMA_API_KEY",),
            "fallback_key": "ollama",
            "json_mode": False,
        },
    }

    # Sensible reasoning defaults per role (used when no per-role override is set).
    # The Analyst proposes hypotheses (worth thinking hard about); pivot is the
    # "I'm stuck" deep-think branch; everything else stays cheap by default.
    DEFAULT_REASONING_EFFORT: dict[str, str | None] = {
        "default":      None,
        "coordinator":  "medium",
        "recon":        "low",
        "analyst":      "high",
        "exploitation": "high",
        "reporter":     "low",
        "validator":    "high",
        "pivot":        "xhigh",
    }

    def __init__(self, configs: dict[str, ProviderConfig]):
        if "default" not in configs:
            raise ValueError("ProviderRegistry requires a 'default' configuration.")
        self._configs = configs
        self._cache: dict[str, LLMProvider] = {}

    @classmethod
    def _profile(cls, provider_name: str) -> dict[str, Any]:
        provider_key = (provider_name or "openai-compatible").strip().lower()
        if provider_key not in cls.PROVIDER_PROFILES:
            # Unknown provider names are treated as OpenAI-compatible. The user
            # can supply LLM_*_BASE_URL for any compatible gateway.
            provider_key = "openai-compatible"
        return cls.PROVIDER_PROFILES[provider_key]

    @staticmethod
    def _first_env(names: tuple[str, ...] | list[str]) -> str:
        for name in names:
            value = os.getenv(name)
            if value:
                return value
        return ""

    @classmethod
    def _provider_key(cls, provider_name: str) -> str:
        profile = cls._profile(provider_name)
        return cls._first_env(profile.get("key_env", ())) or profile.get("fallback_key", "")

    @classmethod
    def from_env(cls) -> "ProviderRegistry":
        # Legacy fallback (single-agent agent.py uses these).
        legacy_key = os.getenv("DEEPSEEK_API_KEY", "")
        legacy_base = os.getenv("API_BASE_URL", "https://api.deepseek.com")
        legacy_model = os.getenv("MODEL_NAME", "deepseek-chat")

        default_provider = os.getenv("LLM_DEFAULT_PROVIDER") or os.getenv("LLM_PROVIDER")
        if not default_provider:
            default_provider = "deepseek" if legacy_key else "openai-compatible"
        default_profile = cls._profile(default_provider)
        default_kind = default_profile["kind"]
        default_model = os.getenv("LLM_DEFAULT_MODEL") or os.getenv("MODEL_NAME") or default_profile["model"] or legacy_model
        default_key = os.getenv("LLM_DEFAULT_API_KEY") or cls._provider_key(default_provider) or legacy_key
        default_base = (
            os.getenv("LLM_DEFAULT_BASE_URL")
            or os.getenv("API_BASE_URL")
            or default_profile.get("base_url")
            or legacy_base
        )
        default_json = os.getenv(
            "LLM_DEFAULT_JSON_MODE",
            str(default_profile.get("json_mode", True)),
        ).lower() != "false"

        if not default_key:
            raise ValueError(
                "No API key found. Set LLM_DEFAULT_API_KEY (preferred) or legacy "
                "DEEPSEEK_API_KEY in your .env."
            )

        # Default reasoning controls (apply unless per-role overrides set).
        default_reasoning = os.getenv("LLM_DEFAULT_REASONING_EFFORT") or None
        default_thinking = os.getenv("LLM_DEFAULT_THINKING", "false").lower() == "true"
        default_thinking_budget = int(os.getenv("LLM_DEFAULT_THINKING_BUDGET", "8000"))
        default_enable_thinking_param = os.getenv(
            "LLM_DEFAULT_ENABLE_THINKING_PARAM", "false"
        ).lower() == "true"

        default_cfg = ProviderConfig(
            role="default",
            kind=default_kind,
            model=default_model,
            api_key=default_key,
            base_url=default_base if default_kind == "openai-compatible" else os.getenv("LLM_DEFAULT_BASE_URL"),
            supports_json_mode=default_json,
            reasoning_effort=default_reasoning,
            thinking_enabled=default_thinking,
            thinking_budget_tokens=default_thinking_budget,
            enable_thinking_param=default_enable_thinking_param,
        )
        configs: dict[str, ProviderConfig] = {"default": default_cfg}

        # Per-role overrides
        for role in cls.AGENT_ROLES:
            if role == "default":
                continue
            prefix = f"LLM_{role.upper()}"
            # Build the role config if ANY override is set, OR if we have a
            # built-in reasoning default for this role that differs from default.
            role_default_effort = cls.DEFAULT_REASONING_EFFORT.get(role)
            has_explicit_override = any(
                os.getenv(f"{prefix}_{suffix}") is not None
                for suffix in ("API_KEY", "MODEL", "REASONING_EFFORT",
                               "THINKING", "ENABLE_THINKING_PARAM")
            )
            if not has_explicit_override and role_default_effort is None:
                continue
            requested_provider = os.getenv(f"{prefix}_PROVIDER", default_provider)
            profile = cls._profile(requested_provider)
            kind = profile["kind"]
            base_url = (
                os.getenv(f"{prefix}_BASE_URL")
                or (default_base if requested_provider == default_provider else profile.get("base_url"))
                or default_base
            )
            json_mode = os.getenv(
                f"{prefix}_JSON_MODE",
                str(profile.get("json_mode", default_json)),
            ).lower() != "false"

            explicit_effort = os.getenv(f"{prefix}_REASONING_EFFORT")
            effort = explicit_effort if explicit_effort is not None else (
                default_reasoning if default_reasoning is not None else role_default_effort
            )
            if effort == "":
                effort = None
            thinking_enabled = os.getenv(
                f"{prefix}_THINKING", str(default_thinking)
            ).lower() == "true"
            thinking_budget = int(os.getenv(
                f"{prefix}_THINKING_BUDGET", str(default_thinking_budget)
            ))
            enable_thinking_param = os.getenv(
                f"{prefix}_ENABLE_THINKING_PARAM", str(default_enable_thinking_param)
            ).lower() == "true"

            configs[role] = ProviderConfig(
                role=role,
                kind=kind,
                model=os.getenv(f"{prefix}_MODEL") or (
                    default_model if requested_provider == default_provider else profile["model"]
                ),
                api_key=os.getenv(f"{prefix}_API_KEY") or cls._provider_key(requested_provider) or default_key,
                base_url=base_url if kind == "openai-compatible" else os.getenv(f"{prefix}_BASE_URL"),
                supports_json_mode=json_mode,
                reasoning_effort=effort,
                thinking_enabled=thinking_enabled,
                thinking_budget_tokens=thinking_budget,
                enable_thinking_param=enable_thinking_param,
            )

        return cls(configs)

    def get(self, role: str) -> LLMProvider:
        cfg = self._configs.get(role) or self._configs["default"]
        cache_key = f"{cfg.kind}:{cfg.model}:{id(cfg)}"
        if cache_key not in self._cache:
            self._cache[cache_key] = self._build(cfg)
        return self._cache[cache_key]

    @staticmethod
    def _build(cfg: ProviderConfig) -> LLMProvider:
        if cfg.kind == "anthropic":
            return AnthropicProvider(cfg)
        return OpenAICompatibleProvider(cfg)

    def describe(self) -> str:
        lines = ["LLM Provider Configuration:"]
        for role in self.AGENT_ROLES:
            override = self._configs.get(role)
            cfg = override or self._configs["default"]
            tag = "" if override else "(default)"
            provider = _provider_display_name(cfg)
            think_bits = []
            if cfg.reasoning_effort:
                think_bits.append(f"effort={cfg.reasoning_effort}")
            if cfg.thinking_enabled:
                think_bits.append(f"thinking={cfg.thinking_budget_tokens}t")
            if cfg.enable_thinking_param:
                think_bits.append("enable_thinking")
            think_str = f" [{', '.join(think_bits)}]" if think_bits else ""
            lines.append(f"  {role:14} -> {provider:24} {cfg.model:30} {tag}{think_str}")
        return "\n".join(lines)
