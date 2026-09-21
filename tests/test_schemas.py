"""Tests for stride_gpt.core.schemas — TokenUsage accounting."""

from __future__ import annotations

from stride_gpt.core.schemas import LLMResponse, TokenUsage


class TestTokenUsage:
    def test_unavailable_by_default(self):
        usage = TokenUsage()
        assert usage.available is False
        assert usage.total_tokens is None

    def test_record_folds_in_a_response(self):
        usage = TokenUsage()
        usage.record(LLMResponse(content="", prompt_tokens=100, completion_tokens=50))
        assert usage.available is True
        assert usage.prompt_tokens == 100
        assert usage.completion_tokens == 50
        assert usage.total_tokens == 150

    def test_record_accumulates_across_calls(self):
        usage = TokenUsage()
        usage.record(LLMResponse(content="", prompt_tokens=100, completion_tokens=50))
        usage.record(LLMResponse(content="", prompt_tokens=10, completion_tokens=5))
        assert usage.prompt_tokens == 110
        assert usage.completion_tokens == 55
        assert usage.total_tokens == 165

    def test_record_ignores_a_response_with_no_usage(self):
        """A response that reported nothing must not flip ``available`` on,
        or coerce the running total's None into a real number."""
        usage = TokenUsage()
        usage.record(LLMResponse(content=""))
        assert usage.available is False
        assert usage.prompt_tokens is None
        assert usage.completion_tokens is None

    def test_record_after_unavailable_response_still_works(self):
        usage = TokenUsage()
        usage.record(LLMResponse(content=""))
        usage.record(LLMResponse(content="", prompt_tokens=20, completion_tokens=10))
        assert usage.available is True
        assert usage.total_tokens == 30

    def test_merge_folds_another_aggregate_in(self):
        a = TokenUsage(prompt_tokens=100, completion_tokens=50)
        b = TokenUsage(prompt_tokens=10, completion_tokens=5)
        a.merge(b)
        assert a.prompt_tokens == 110
        assert a.completion_tokens == 55

    def test_merge_of_unavailable_is_a_noop(self):
        a = TokenUsage(prompt_tokens=100, completion_tokens=50)
        a.merge(TokenUsage())
        assert a.prompt_tokens == 100
        assert a.completion_tokens == 50

    def test_merge_into_unavailable_becomes_available(self):
        a = TokenUsage()
        a.merge(TokenUsage(prompt_tokens=5, completion_tokens=5))
        assert a.available is True
        assert a.total_tokens == 10

    def test_model_dump_round_trips(self):
        usage = TokenUsage(prompt_tokens=42, completion_tokens=8)
        dumped = usage.model_dump()
        assert TokenUsage(**dumped) == usage
