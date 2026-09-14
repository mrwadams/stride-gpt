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
# Share of the context window for recent turns kept verbatim. The newest turn
# is always kept, even if it alone is over budget.
KEEP_RECENT_FRACTION = 0.25
SUMMARY_HEADER = "[Previous exploration summary]"

SUMMARY_PROMPT = f"""You are compressing the history of a security-focused codebase exploration. The agent will continue from your summary alone, so it must record what has been concluded and what is left to do.

Write exactly these four sections, with these headings, in this order. Never omit a section; if one has nothing to report, write "none" under it.

## Threats identified so far
Each threat found, with the files and code involved.

## Files examined and conclusions
What each tool call established, including negative results (e.g. "no raw SQL in `db/`").

## Pending work
Files or questions the agent still meant to look at.

## Current focus
What the agent was doing when this summary was written.

If the input begins with a {SUMMARY_HEADER}, merge it into your sections: carry its threats and conclusions forward, and drop pending items that have since been done.

Be brief, but keep file paths, function names and other specifics."""


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
        """Compress older turns into a summary.

        Keeps the leading system message(s), the task (the first user
        message), and the most recent whole turns within
        ``KEEP_RECENT_FRACTION`` of the context window. Everything in between
        is summarised and appended to the task message, so user and assistant
        messages still alternate.

        A turn is a message plus the ``tool`` results that follow it. Turns
        are never split: providers reject a tool result whose assistant
        ``tool_calls`` message is missing.

        Returns ``messages`` itself (the same object) when there is nothing
        to compress or the summary couldn't be produced.

        `config` is the LLM used to *perform* the summarization (an architect-
        tier reasoning task). The context window the ContextManager tracks is
        the worker's — that's the model whose conversation we're compressing.
        """
        head_len = 0
        while head_len < len(messages) and messages[head_len]["role"] == "system":
            head_len += 1
        head = messages[:head_len]
        rest = messages[head_len:]

        task: dict | None = None
        previous_summary = None
        if rest and rest[0]["role"] == "user" and isinstance(rest[0].get("content"), str):
            task, rest = rest[0], rest[1:]
            task_text, _, previous_summary = task["content"].partition(
                f"\n\n{SUMMARY_HEADER}\n"
            )

        turns = _group_turns(rest)
        budget = int(self.context_window * KEEP_RECENT_FRACTION)
        keep_from = len(turns)
        kept_tokens = 0
        while keep_from > 0:
            cost = self.count_tokens(turns[keep_from - 1])
            if keep_from < len(turns) and kept_tokens + cost > budget:
                break
            kept_tokens += cost
            keep_from -= 1

        if keep_from == 0:
            return messages  # Nothing older than the kept turns

        to_compress = [msg for turn in turns[:keep_from] for msg in turn]
        to_keep = [msg for turn in turns[keep_from:] for msg in turn]

        try:
            summary = self._summarize(config, to_compress, previous_summary or None)
        except Exception:
            # Carrying on uncompressed beats failing the whole subsystem;
            # the next turn will try again.
            return messages
        if not summary.strip():
            return messages

        if task is not None:
            summary_msg = {**task, "content": f"{task_text}\n\n{SUMMARY_HEADER}\n{summary}"}
        else:
            summary_msg = {"role": "user", "content": f"{SUMMARY_HEADER}\n{summary}"}

        return [*head, summary_msg, *to_keep]

    def _summarize(
        self,
        config: LLMConfig,
        messages: list[dict],
        previous_summary: str | None = None,
    ) -> str:
        """Summarize a list of messages into the sections of ``SUMMARY_PROMPT``."""
        # Build a text representation of the messages. An earlier summary is
        # included in full so a second compression doesn't lose its findings.
        parts: list[str] = []
        if previous_summary:
            parts.append(f"{SUMMARY_HEADER}\n{previous_summary}")
        for msg in messages:
            role = msg.get("role", "unknown")
            content = str(msg.get("content") or "")[:2000]  # Truncate long entries
            # Tool calls carry no content, but show which files were examined
            if msg.get("tool_calls"):
                calls = ", ".join(
                    f"{tc.get('function', {}).get('name', '?')}({tc.get('function', {}).get('arguments', '')})"
                    for tc in msg["tool_calls"]
                )
                content = f"{content}\nCalled: {calls}" if content.strip() else f"Called: {calls}"
            parts.append(f"[{role}] {content}")

        conversation = "\n---\n".join(parts)

        summary_messages = [
            {"role": "system", "content": SUMMARY_PROMPT},
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


def _group_turns(messages: list[dict]) -> list[list[dict]]:
    """Group messages into turns: a message plus the tool results after it."""
    turns: list[list[dict]] = []
    for msg in messages:
        if msg["role"] == "tool" and turns:
            turns[-1].append(msg)
        else:
            turns.append([msg])
    return turns


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
        # Best-effort probe of the optional LM Studio server. If it is down or
        # the response shape is unfamiliar, the context length is simply
        # unknown, which is the None below, and callers fall back to a default.
        pass
    return None
