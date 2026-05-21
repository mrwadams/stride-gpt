"""Context management — token counting and message compression."""

from __future__ import annotations

from enum import Enum

import httpx
import litellm

from stride_gpt.core.llm import call_llm
from stride_gpt.core.schemas import LLMConfig
from stride_gpt.models import get_model

# Default context limits per model family (input tokens).
# Conservative — leaves room for output.
DEFAULT_LIMITS: dict[str, int] = {
    "claude": 180_000,
    "gpt": 120_000,
    "gemini": 900_000,
    "llama": 120_000,
    "mistral": 28_000,
    "default": 28_000,
}

COMPRESSION_THRESHOLD = 0.80  # Compress when at 80% of limit
KEEP_RECENT = 6  # Number of recent messages to keep uncompressed


class TokenBudgetSource(Enum):
    """How the token budget was determined."""

    QUERIED = "queried"  # Got the actual configured value from the provider API
    INFERRED = "inferred"  # Guessed from model name
    EXPLICIT = "explicit"  # Caller provided context_window directly


class ContextManager:
    """Track token usage and compress messages when approaching the context limit."""

    def __init__(self, config: LLMConfig, context_window: int | None = None):
        self.model = config.model_name
        if context_window:
            self.context_window = context_window
            self.budget_source = TokenBudgetSource.EXPLICIT
        else:
            self.context_window, self.budget_source = self._resolve_limit(config)

    def count_tokens(self, messages: list[dict]) -> int:
        """Count tokens in a message list using LiteLLM's counter."""
        try:
            return litellm.token_counter(model=self.model, messages=messages)
        except Exception:
            # Rough fallback: ~4 chars per token
            total_chars = sum(len(str(m.get("content", ""))) for m in messages)
            return total_chars // 4

    def needs_compression(self, messages: list[dict]) -> bool:
        """Check if messages are approaching the context limit."""
        tokens = self.count_tokens(messages)
        return tokens > int(self.context_window * COMPRESSION_THRESHOLD)

    def compress(self, config: LLMConfig, messages: list[dict]) -> list[dict]:
        """Compress older messages by summarizing tool results.

        Keeps the system prompt, the analysis plan context, and recent messages
        intact. Summarizes everything in between into a condensed findings block.
        """
        if len(messages) <= KEEP_RECENT + 2:
            return messages  # Nothing worth compressing

        # Split: system message(s) at the start, recent messages, middle to compress
        system_msgs = []
        rest = []
        for msg in messages:
            if msg["role"] == "system" and not rest:
                system_msgs.append(msg)
            else:
                rest.append(msg)

        if len(rest) <= KEEP_RECENT:
            return messages

        to_compress = rest[:-KEEP_RECENT]
        to_keep = rest[-KEEP_RECENT:]

        # Build summary of the compressed section
        compressed_text = self._summarize(config, to_compress)
        summary_msg = {
            "role": "user",
            "content": f"[Previous exploration summary]\n{compressed_text}",
        }

        return system_msgs + [summary_msg] + to_keep

    def _summarize(self, config: LLMConfig, messages: list[dict]) -> str:
        """Summarize a list of messages into key findings."""
        # Build a text representation of the messages
        parts: list[str] = []
        for msg in messages:
            role = msg.get("role", "unknown")
            content = str(msg.get("content", ""))[:2000]  # Truncate long entries
            parts.append(f"[{role}] {content}")

        conversation = "\n---\n".join(parts)

        summary_messages = [
            {
                "role": "system",
                "content": "Summarize the following agent exploration into a concise list of key findings. Focus on: files examined, security-relevant patterns found, architectural observations, and any threats identified. Be brief but preserve important details.",
            },
            {"role": "user", "content": conversation},
        ]

        response = call_llm(config, summary_messages)
        return response.content

    @staticmethod
    def _resolve_limit(config: LLMConfig) -> tuple[int, TokenBudgetSource]:
        """Resolve the context token limit for the model.

        Queries LM Studio for the actual loaded context length.
        Otherwise reads the per-model context window from the registry,
        falling back to name-based inference for unregistered models.
        """
        if config.provider == "LM Studio Server" and config.api_base:
            result = _query_lm_studio_context(config.api_base, config.model_name)
            if result:
                return result, TokenBudgetSource.QUERIED

        registered = get_model(config.provider, config.model_name)
        if registered is not None:
            return registered.max_tokens, TokenBudgetSource.QUERIED

        return _infer_limit_from_name(config.model_name), TokenBudgetSource.INFERRED


def _infer_limit_from_name(model: str) -> int:
    """Infer context limit from model name keywords."""
    lower = model.lower()
    for key, limit in DEFAULT_LIMITS.items():
        if key in lower:
            return limit
    return DEFAULT_LIMITS["default"]


def _query_lm_studio_context(api_base: str, model_name: str) -> int | None:
    """Query LM Studio's native API for the model's loaded context length."""
    try:
        url = api_base.rstrip("/") + "/api/v1/models"
        resp = httpx.get(url, timeout=5)
        resp.raise_for_status()
        for model in resp.json().get("models", []):
            if model.get("key") != model_name:
                continue
            loaded_instances = model.get("loaded_instances", [])
            if not loaded_instances:
                continue
            loaded_ctx = loaded_instances[0].get("config", {}).get("context_length", 0)
            if loaded_ctx > 0:
                return loaded_ctx
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        pass
    return None
