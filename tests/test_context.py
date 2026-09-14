"""Tests for stride_gpt.agent.context — token counting and compression."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from stride_gpt.agent.context import (
    COMPRESSION_THRESHOLD,
    DEFAULT_LIMITS,
    SUMMARY_HEADER,
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


def _summary(text: str) -> LLMResponse:
    return LLMResponse(content=text, thinking=None, reasoning=None, model="test")


def _agent_history(turns: int, calls_per_turn: int, prefix: str = "t") -> list[dict]:
    """System + task, then ``turns`` assistant turns with their tool results."""
    msgs: list[dict] = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "analyse the auth subsystem"},
    ]
    for i in range(turns):
        ids = [f"{prefix}{i}-{k}" for k in range(calls_per_turn)]
        msgs.append({
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"id": tc_id, "type": "function",
                 "function": {"name": "read_file", "arguments": "{}"}}
                for tc_id in ids
            ],
        })
        msgs.extend(
            {"role": "tool", "tool_call_id": tc_id, "name": "read_file",
             "content": f"contents of file {tc_id}"}
            for tc_id in ids
        )
    return msgs


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
        mock_call_llm.return_value = _summary("Summary: found auth issues in auth.py")
        msgs = _agent_history(turns=6, calls_per_turn=1)

        result = ctx_small.compress(llm_config, msgs)

        assert len(result) < len(msgs)
        assert result[0] == msgs[0]
        # The task survives, with the summary appended to it
        assert result[1]["role"] == "user"
        assert result[1]["content"].startswith("analyse the auth subsystem")
        assert f"{SUMMARY_HEADER}\nSummary: found auth issues" in result[1]["content"]
        # The kept tail is the end of the original history
        assert result[2:] == msgs[-len(result) + 2:]
        mock_call_llm.assert_called_once()

    @pytest.mark.parametrize("calls_per_turn", [1, 2, 3, 4])
    @pytest.mark.parametrize("window", [100, 300, 1000])
    @patch("stride_gpt.agent.context.call_llm")
    def test_never_orphans_tool_results(
        self, mock_call_llm, llm_config, calls_per_turn, window
    ):
        mock_call_llm.return_value = _summary("s")
        ctx = ContextManager(config=_make_config(), context_window=window)
        msgs = _agent_history(turns=8, calls_per_turn=calls_per_turn)

        result = ctx.compress(llm_config, msgs)

        seen_ids: set[str] = set()
        for msg in result:
            if msg["role"] == "assistant":
                seen_ids.update(tc["id"] for tc in msg.get("tool_calls", []))
            elif msg["role"] == "tool":
                assert msg["tool_call_id"] in seen_ids, [m["role"] for m in result]
        # Every kept assistant message still has all of its results
        tool_ids = {m["tool_call_id"] for m in result if m["role"] == "tool"}
        assert seen_ids == tool_ids

    @patch("stride_gpt.agent.context.call_llm")
    def test_newest_turn_kept_even_when_over_budget(
        self, mock_call_llm, ctx_small, llm_config
    ):
        mock_call_llm.return_value = _summary("s")
        msgs = _agent_history(turns=3, calls_per_turn=2)
        msgs[-1]["content"] = "x" * 5000  # far beyond 25% of a 100-token window

        result = ctx_small.compress(llm_config, msgs)

        assert result[2:] == msgs[-3:]

    @patch("stride_gpt.agent.context.call_llm")
    def test_recompression_keeps_earlier_summary(self, mock_call_llm, ctx_small, llm_config):
        mock_call_llm.side_effect = [_summary("first findings"), _summary("second findings")]
        msgs = _agent_history(turns=6, calls_per_turn=1)

        once = ctx_small.compress(llm_config, msgs)
        once.extend(_agent_history(turns=6, calls_per_turn=1, prefix="later")[2:])
        twice = ctx_small.compress(llm_config, once)

        # The earlier summary was fed to the second summarisation...
        second_input = mock_call_llm.call_args_list[1].args[1][1]["content"]
        assert "first findings" in second_input
        # ...and replaced, not stacked, in the task message
        task = twice[1]["content"]
        assert task.startswith("analyse the auth subsystem")
        assert task.count(SUMMARY_HEADER) == 1
        assert "second findings" in task and "first findings" not in task

    @pytest.mark.parametrize(
        "outcome", [RuntimeError("provider down"), _summary(""), _summary("  \n")]
    )
    @patch("stride_gpt.agent.context.call_llm")
    def test_failed_summary_returns_original(
        self, mock_call_llm, ctx_small, llm_config, outcome
    ):
        if isinstance(outcome, Exception):
            mock_call_llm.side_effect = outcome
        else:
            mock_call_llm.return_value = outcome
        msgs = _agent_history(turns=6, calls_per_turn=2)

        assert ctx_small.compress(llm_config, msgs) is msgs

    @patch("stride_gpt.agent.context.call_llm")
    def test_summary_prompt_requests_fixed_sections(
        self, mock_call_llm, ctx_small, llm_config
    ):
        mock_call_llm.return_value = _summary("s")
        ctx_small.compress(llm_config, _agent_history(turns=6, calls_per_turn=1))

        prompt = mock_call_llm.call_args.args[1][0]["content"]
        headings = [
            "## Threats identified so far",
            "## Files examined and conclusions",
            "## Pending work",
            "## Current focus",
        ]
        positions = [prompt.index(h) for h in headings]
        assert positions == sorted(positions)
        assert '"none"' in prompt

    @patch("stride_gpt.agent.context.call_llm")
    def test_summary_input_includes_tool_calls(self, mock_call_llm, ctx_small, llm_config):
        mock_call_llm.return_value = _summary("s")
        msgs = _agent_history(turns=6, calls_per_turn=2)
        msgs[2]["tool_calls"][0]["function"]["arguments"] = '{"path": "auth.py"}'

        ctx_small.compress(llm_config, msgs)

        conversation = mock_call_llm.call_args.args[1][1]["content"]
        assert '[assistant] Called: read_file({"path": "auth.py"}), read_file({})' in conversation

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
