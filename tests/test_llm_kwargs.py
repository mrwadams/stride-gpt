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
            model_name="gemini-3.8-flash",
            api_key="fake",
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert "safety_settings" in kwargs


class TestAnthropicKwargs:
    def test_thinking_kwarg_never_sent(self):
        """Current Claude models think by default and reject budget_tokens with a 400."""
        cfg = LLMConfig(
            provider="Anthropic API",
            model_name="claude-sonnet-5-5",
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

    def test_schema_falls_back_to_json_object(self):
        """DeepSeek rejects json_schema ("This response_format type is
        unavailable now"), which failed every /analyze at planning (#328)."""
        cfg = LLMConfig(
            provider="DeepSeek API",
            model_name="deepseek-flash",
            api_key="fake",
            response_format={"type": "object", "properties": {}},
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert kwargs["response_format"] == {"type": "json_object"}


class TestLMStudioKwargs:
    def test_placeholder_api_key_when_none_configured(self):
        """LM Studio routes through the `openai/` prefix, and the OpenAI SDK
        refuses to build a client without an api_key — even for localhost. A
        missing key must become a placeholder rather than None, or every call
        dies with "The api_key client option must be set" (issue #159)."""
        cfg = LLMConfig(
            provider="LM Studio Server",
            model_name="google/gemma-4-e4b",
            api_key="",
            api_base="http://localhost:1234",
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert kwargs["api_key"] == "not-needed"
        assert kwargs["model"] == "openai/google/gemma-4-e4b"
        assert kwargs["api_base"] == "http://localhost:1234/v1"

    def test_real_key_preserved_when_server_requires_auth(self):
        """LM Studio Server can be put behind auth, so an explicit key wins."""
        cfg = LLMConfig(
            provider="LM Studio Server",
            model_name="google/gemma-4-e4b",
            api_key="sk-user-supplied",
            api_base="http://localhost:1234",
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert kwargs["api_key"] == "sk-user-supplied"

    def test_cloud_provider_without_key_still_passes_none(self):
        """The placeholder is scoped to non-authenticating providers — a cloud
        provider with no key must not be handed a bogus one, which would turn a
        clear auth error into a confusing 401 from the provider."""
        cfg = LLMConfig(provider="OpenAI API", model_name="gpt-5.5", api_key="")
        kwargs = _build_litellm_kwargs(cfg)
        assert kwargs["api_key"] is None


class TestSchemaResponseFormat:
    def test_other_providers_keep_json_schema(self):
        """Only DeepSeek downgrades a schema; Gemini still gets it enforced."""
        schema = {"type": "object", "properties": {}}
        cfg = LLMConfig(
            provider="Google AI API",
            model_name="gemini-3.8-flash",
            api_key="fake",
            response_format=schema,
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert kwargs["response_format"] == {
            "type": "json_schema",
            "json_schema": {"name": "response", "schema": schema},
        }
