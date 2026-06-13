"""LLM client abstraction.

The scorer depends only on the small :class:`LLMClient` protocol, so tests can
inject a fake and the offline heuristic can bypass the network entirely.

Live scoring is routed through LiteLLM — the same multi-provider pattern
STRIDE-GPT uses — so VulnScope supports Anthropic, OpenAI, Google Gemini, Groq,
Mistral, and self-hosted models via Ollama or an OpenAI-compatible endpoint
(LM Studio), all selected through the model string. See ``providers.py``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from vulnscope.providers import (
    GEMINI_SAFETY_SETTINGS,
    is_gemini,
    normalise_model,
)


@runtime_checkable
class LLMClient(Protocol):
    """Anything that can turn a (system, user) prompt pair into text."""

    def complete(self, system: str, user: str) -> str:  # pragma: no cover - protocol
        ...


class LiteLLMClient:
    """Multi-provider LLM client backed by LiteLLM.

    ``litellm`` is imported lazily so the rest of VulnScope (and the test
    suite) does not require it to be installed.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        api_base: str | None = None,
        max_tokens: int = 1500,
        timeout: float = 120.0,
    ) -> None:
        try:
            import litellm
        except ImportError as exc:  # pragma: no cover - import guard
            raise RuntimeError(
                "The 'litellm' package is required for live scoring. Install it "
                "(pip install litellm) or run with --offline."
            ) from exc

        litellm.suppress_debug_info = True
        # Silently drop params a given provider rejects (e.g. max_tokens vs
        # max_completion_tokens on OpenAI reasoning models, temperature limits)
        # so one client works across every provider without per-model branching.
        litellm.drop_params = True

        self._litellm = litellm
        self._model = normalise_model(model)
        self._api_key = api_key
        self._api_base = api_base
        self._max_tokens = max_tokens
        self._timeout = timeout

    @property
    def model(self) -> str:
        return self._model

    def complete(self, system: str, user: str) -> str:
        kwargs: dict = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": self._max_tokens,
            # Retry transient errors (429s, timeouts, 5xx); LiteLLM delegates to
            # the provider SDK's exponential backoff.
            "num_retries": 3,
            "timeout": self._timeout,
        }
        if self._api_key:
            kwargs["api_key"] = self._api_key
        if self._api_base:
            kwargs["api_base"] = self._api_base
        if is_gemini(self._model):
            kwargs["safety_settings"] = GEMINI_SAFETY_SETTINGS

        response = self._litellm.completion(**kwargs)
        return response.choices[0].message.content or ""
