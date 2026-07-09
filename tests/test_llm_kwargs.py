"""Regression tests for _build_litellm_kwargs — provider-specific kwarg shape."""

from __future__ import annotations

from stride_gpt.core.llm import _build_litellm_kwargs
from stride_gpt.core.schemas import LLMConfig


class TestGeminiKwargs:
    def test_no_thinking_kwarg(self):
        """Gemini's litellm provider rejects the Anthropic-shaped
        `thinking={"type": "enabled", ...}` kwarg for newer models such as
        gemini-3.1-flash-lite. Thinking-capable Gemini models have it enabled
        by default; we just consume `thinking_blocks` from the response."""
        cfg = LLMConfig(
            provider="Google AI API",
            model_name="gemini-3.1-flash-lite",
            api_key="fake",
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert "thinking" not in kwargs

    def test_safety_settings_still_applied(self):
        cfg = LLMConfig(
            provider="Google AI API",
            model_name="gemini-3.5-flash",
            api_key="fake",
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert "safety_settings" in kwargs


class TestAnthropicKwargs:
    def test_thinking_enabled_when_requested(self):
        cfg = LLMConfig(
            provider="Anthropic API",
            model_name="claude-sonnet-4-5-20250929",
            api_key="fake",
            use_thinking=True,
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert kwargs["thinking"] == {"type": "enabled", "budget_tokens": 16000}

    def test_thinking_omitted_when_not_requested(self):
        cfg = LLMConfig(
            provider="Anthropic API",
            model_name="claude-sonnet-4-5-20250929",
            api_key="fake",
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert "thinking" not in kwargs


class TestDeepSeekKwargs:
    def test_model_gets_deepseek_prefix(self):
        """DeepSeek routes through LiteLLM's native `deepseek/` provider, which
        knows the hosted endpoint — so no explicit api_base is needed."""
        cfg = LLMConfig(
            provider="DeepSeek API",
            model_name="deepseek-v4-pro",
            api_key="fake",
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert kwargs["model"] == "deepseek/deepseek-v4-pro"
        assert "api_base" not in kwargs

    def test_max_tokens_left_to_provider_by_default(self):
        """No explicit output cap unless the user sets one; DeepSeek applies its
        own default (mirrors the Groq/Mistral behaviour)."""
        cfg = LLMConfig(
            provider="DeepSeek API",
            model_name="deepseek-v4-flash",
            api_key="fake",
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert "max_tokens" not in kwargs
