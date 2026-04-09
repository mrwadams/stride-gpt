"""Context management — token counting and message compression."""

from __future__ import annotations

import litellm

from stride_gpt.core.llm import call_llm
from stride_gpt.core.schemas import LLMConfig

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


class ContextManager:
    """Track token usage and compress messages when approaching the context limit."""

    def __init__(self, model: str, max_tokens: int | None = None):
        self.model = model
        self.max_tokens = max_tokens or self._infer_limit(model)

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
        return tokens > int(self.max_tokens * COMPRESSION_THRESHOLD)

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
    def _infer_limit(model: str) -> int:
        """Infer context limit from model name."""
        lower = model.lower()
        for key, limit in DEFAULT_LIMITS.items():
            if key in lower:
                return limit
        return DEFAULT_LIMITS["default"]
