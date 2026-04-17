"""Tests for stride_gpt.agent.context — token counting and compression."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

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
    return ContextManager(config=_make_config(), max_tokens=100)


# ---------------------------------------------------------------------------
# _infer_limit
# ---------------------------------------------------------------------------


class TestInferLimit:
    def test_claude_model(self):
        ctx = ContextManager(config=_make_config("claude-sonnet-4-5-20250929"))
        assert ctx.max_tokens == DEFAULT_LIMITS["claude"]

    def test_gpt_model(self):
        ctx = ContextManager(config=_make_config("gpt-5.2"))
        assert ctx.max_tokens == DEFAULT_LIMITS["gpt"]

    def test_gemini_model(self):
        ctx = ContextManager(config=_make_config("gemini-2.5-pro"))
        assert ctx.max_tokens == DEFAULT_LIMITS["gemini"]

    def test_unknown_model(self):
        ctx = ContextManager(config=_make_config("some-obscure-model"))
        assert ctx.max_tokens == DEFAULT_LIMITS["default"]

    def test_explicit_override(self):
        ctx = ContextManager(config=_make_config(), max_tokens=50_000)
        assert ctx.max_tokens == 50_000


# ---------------------------------------------------------------------------
# count_tokens
# ---------------------------------------------------------------------------


class TestCountTokens:
    @patch("stride_gpt.agent.context.litellm")
    def test_uses_litellm_counter(self, mock_litellm, ctx):
        mock_litellm.token_counter.return_value = 42
        msgs = [{"role": "user", "content": "hello"}]
        assert ctx.count_tokens(msgs) == 42
        mock_litellm.token_counter.assert_called_once()

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
        threshold = int(ctx.max_tokens * COMPRESSION_THRESHOLD) + 1
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
        for i in range(12):
            msgs.append({"role": "user" if i % 2 == 0 else "assistant", "content": f"msg {i}"})

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
        for i in range(12):
            msgs.append({"role": "user", "content": f"msg {i}"})

        result = ctx_small.compress(llm_config, msgs)
        assert result[0]["role"] == "system"
        assert result[0]["content"] == "important system prompt"
