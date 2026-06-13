"""LLM client abstraction.

The scorer depends only on the small :class:`LLMClient` protocol, so tests can
inject a fake and the offline heuristic can bypass the network entirely. v1
ships a single concrete client: Claude via the Anthropic SDK.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMClient(Protocol):
    """Anything that can turn a (system, user) prompt pair into text."""

    def complete(self, system: str, user: str) -> str:  # pragma: no cover - protocol
        ...


class AnthropicClient:
    """Claude via the Anthropic SDK.

    The ``anthropic`` package is imported lazily so the rest of VulnScope (and
    the test suite) does not require it to be installed.
    """

    def __init__(
        self,
        model: str,
        api_key: str | None,
        *,
        max_tokens: int = 1500,
        timeout: float = 120.0,
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - import guard
            raise RuntimeError(
                "The 'anthropic' package is required for live scoring. Install "
                "it (pip install anthropic) or run with --offline."
            ) from exc

        if not api_key:
            raise RuntimeError(
                "No Anthropic API key. Set ANTHROPIC_API_KEY, pass --api-key, or "
                "run with --offline."
            )

        self._client = anthropic.Anthropic(api_key=api_key, timeout=timeout)
        self._model = model
        self._max_tokens = max_tokens

    def complete(self, system: str, user: str) -> str:
        message = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(
            block.text for block in message.content if getattr(block, "type", "") == "text"
        )
