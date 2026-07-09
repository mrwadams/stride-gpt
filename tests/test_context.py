"""Tests for stride_gpt.agent.context — token counting and compression."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from stride_gpt.agent.context import (
    COMPRESSION_THRESHOLD,
    DEFAULT_LIMITS,
    KEEP_RECENT,
    ContextManager,
)
from stride_gpt.core.schemas import LLMConfig, LLMResponse


def _make_config(model: str = "claude-sonnet-4-5-20250929") -> LLMConfig:
    return LLMConfig(provider="Anthropic API", model_name=model, api_key="test")


@pytest.fixture
def ctx():
    return ContextManager(config=_make_config())


@pytest.fixture
def ctx_small():
    """Context manager with a tiny limit so compression triggers easily."""
    return ContextManager(config=_make_config(), context_window=100)


# ---------------------------------------------------------------------------
# _infer_limit
# ---------------------------------------------------------------------------


class TestResolveLimit:
    def test_registered_claude_model(self):
        from stride_gpt.models import get_model

        ctx = ContextManager(config=_make_config("claude-sonnet-4-6"))
        expected = get_model("Anthropic API", "claude-sonnet-4-6").max_tokens
        assert ctx.context_window == expected

    def test_registered_gemini_model(self):
        from stride_gpt.models import get_model

        cfg = LLMConfig(provider="Google AI API", model_name="gemini-3.1-pro-preview", api_key="test")
        ctx = ContextManager(config=cfg)
        expected = get_model("Google AI API", "gemini-3.1-pro-preview").max_tokens
        assert ctx.context_window == expected

    def test_unregistered_claude_falls_back_to_name_inference(self):
        # Old/custom Claude model not in the registry → keyword match wins
        ctx = ContextManager(config=_make_config("claude-sonnet-4-5-20250929"))
        assert ctx.context_window == DEFAULT_LIMITS["claude"]

    def test_unknown_model(self):
        ctx = ContextManager(config=_make_config("some-obscure-model"))
        assert ctx.context_window == DEFAULT_LIMITS["default"]

    def test_explicit_override(self):
        ctx = ContextManager(config=_make_config(), context_window=50_000)
        assert ctx.context_window == 50_000


# ---------------------------------------------------------------------------
# count_tokens
# ---------------------------------------------------------------------------


class TestCountTokens:
    @patch("stride_gpt.agent.context.litellm")
    def test_fallback_on_error(self, mock_litellm, ctx):
        mock_litellm.token_counter.side_effect = Exception("boom")
        msgs = [{"role": "user", "content": "a" * 400}]
        result = ctx.count_tokens(msgs)
        assert result == 100  # 400 chars / 4


# ---------------------------------------------------------------------------
# needs_compression
# ---------------------------------------------------------------------------


class TestNeedsCompression:
    @patch("stride_gpt.agent.context.litellm")
    def test_under_threshold(self, mock_litellm, ctx):
        mock_litellm.token_counter.return_value = 10
        assert ctx.needs_compression([{"role": "user", "content": "hi"}]) is False

    @patch("stride_gpt.agent.context.litellm")
    def test_over_threshold(self, mock_litellm, ctx):
        threshold = int(ctx.context_window * COMPRESSION_THRESHOLD) + 1
        mock_litellm.token_counter.return_value = threshold
        assert ctx.needs_compression([{"role": "user", "content": "hi"}]) is True


# ---------------------------------------------------------------------------
# compress
# ---------------------------------------------------------------------------


class TestCompress:
    def test_noop_when_few_messages(self, ctx_small, llm_config):
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hello"},
        ]
        result = ctx_small.compress(llm_config, msgs)
        assert result == msgs

    @patch("stride_gpt.agent.context.call_llm")
    def test_compresses_old_messages(self, mock_call_llm, ctx_small, llm_config):
        mock_call_llm.return_value = LLMResponse(
            content="Summary: found auth issues in auth.py",
            thinking=None,
            reasoning=None,
            model="test",
        )
        # Build enough messages to trigger compression
        msgs = [{"role": "system", "content": "system prompt"}]
        msgs.extend(
            {"role": "user" if i % 2 == 0 else "assistant", "content": f"msg {i}"}
            for i in range(12)
        )

        result = ctx_small.compress(llm_config, msgs)

        # Should have: system + summary + KEEP_RECENT recent messages
        assert len(result) == 1 + 1 + KEEP_RECENT
        assert result[0]["role"] == "system"
        assert "Summary" in result[1]["content"]
        mock_call_llm.assert_called_once()

    @patch("stride_gpt.agent.context.call_llm")
    def test_preserves_system_messages(self, mock_call_llm, ctx_small, llm_config):
        mock_call_llm.return_value = LLMResponse(
            content="compressed", thinking=None, reasoning=None, model="test"
        )
        msgs = [{"role": "system", "content": "important system prompt"}]
        msgs.extend({"role": "user", "content": f"msg {i}"} for i in range(12))

        result = ctx_small.compress(llm_config, msgs)
        assert result[0]["role"] == "system"
        assert result[0]["content"] == "important system prompt"
