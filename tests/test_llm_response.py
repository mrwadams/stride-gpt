"""Tests for the pure response-parsing helpers in stride_gpt.core.llm.

extract_deepseek_reasoning and process_groq_response are deterministic string
transforms with no external deps — they split reasoning from the answer and
route a Groq/DeepSeek response to JSON, Mermaid, or raw text.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from stride_gpt.core.llm import (
    _call_litellm,
    _call_litellm_with_tools,
    _parse_tool_arguments,
    extract_deepseek_reasoning,
    process_groq_response,
)


class TestExtractDeepseekReasoning:
    def test_splits_reasoning_from_answer(self):
        text = "<think>weighing options</think>Final answer here."
        reasoning, answer = extract_deepseek_reasoning(text)
        assert reasoning == "weighing options"
        assert answer == "Final answer here."

    def test_no_tags_returns_none_reasoning_and_original_text(self):
        reasoning, answer = extract_deepseek_reasoning("just an answer")
        assert reasoning is None
        assert answer == "just an answer"

    def test_multiline_reasoning_across_tags(self):
        text = "<think>line one\nline two</think>\n{\"ok\": true}"
        reasoning, answer = extract_deepseek_reasoning(text)
        assert reasoning == "line one\nline two"
        assert answer == '{"ok": true}'

    def test_reasoning_is_stripped(self):
        reasoning, _ = extract_deepseek_reasoning("<think>  padded  </think>answer")
        assert reasoning == "padded"


class TestProcessGroqResponse:
    def test_valid_json_is_parsed_to_dict(self):
        reasoning, output = process_groq_response('{"a": 1}', "some-model", expect_json=True)
        assert reasoning is None
        assert output == {"a": 1}

    def test_invalid_json_falls_back_to_raw_text(self):
        reasoning, output = process_groq_response("not json", "some-model", expect_json=True)
        assert reasoning is None
        assert output == "not json"

    def test_deepseek_model_extracts_reasoning_before_json(self):
        text = '<think>reasoning</think>{"a": 1}'
        reasoning, output = process_groq_response(
            text, "deepseek-r1-distill-llama-70b", expect_json=True
        )
        assert reasoning == "reasoning"
        assert output == {"a": 1}

    def test_non_json_mermaid_response_is_extracted(self):
        text = "```mermaid\ngraph TD\n  a-->b\n```"
        reasoning, output = process_groq_response(text, "some-model", expect_json=False)
        assert reasoning is None
        assert output.startswith("graph")

    def test_non_json_plain_text_passthrough(self):
        reasoning, output = process_groq_response(
            "just prose, no graph", "some-model", expect_json=False
        )
        assert reasoning is None
        assert output == "just prose, no graph"


class TestToolArgumentParsing:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ('{"path": "app.py"}', {"path": "app.py"}),
            ({"path": "app.py"}, {"path": "app.py"}),
            (None, {}),
            ("", {}),
            ("  \n", {}),
        ],
    )
    def test_accepts(self, raw, expected):
        assert _parse_tool_arguments(raw) == (expected, None)

    @pytest.mark.parametrize(
        ("raw", "message"),
        [
            ('{"pattern": "a"b"}', "arguments were not valid JSON (Expecting ',' delimiter"),
            ('{"path": "app.', "arguments were not valid JSON (Unterminated string"),
            ('["app.py"]', "arguments must be a JSON object, not list"),
            ("42", "arguments must be a JSON object, not int"),
        ],
    )
    def test_rejects_without_raising(self, raw, message):
        arguments, error = _parse_tool_arguments(raw)
        assert arguments == {}
        assert error.startswith(message)

    @patch("stride_gpt.core.llm.litellm.completion")
    def test_bad_call_does_not_fail_the_response(self, mock_completion, llm_config):
        def tool_call(tc_id, name, arguments):
            return SimpleNamespace(
                id=tc_id, function=SimpleNamespace(name=name, arguments=arguments)
            )

        message = SimpleNamespace(
            content="",
            tool_calls=[
                tool_call("a", "grep_content", '{"pattern": "x'),
                tool_call("b", "read_file", '{"path": "app.py"}'),
            ],
        )
        mock_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=message)]
        )

        response = _call_litellm_with_tools(llm_config, [], [])

        bad, good = response.tool_calls
        assert (bad.id, bad.arguments) == ("a", {})
        assert bad.parse_error.startswith("arguments were not valid JSON")
        assert (good.arguments, good.parse_error) == ({"path": "app.py"}, None)


class TestUsageExtraction:
    """A provider's usage lands on LLMResponse; a provider with none leaves
    it None, never 0 — a caller must be able to tell "unknown" from "free"."""

    @patch("stride_gpt.core.llm.litellm.completion")
    def test_call_llm_records_usage_when_reported(self, mock_completion, llm_config):
        message = SimpleNamespace(content="hello", tool_calls=None)
        mock_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=message)],
            usage=SimpleNamespace(prompt_tokens=120, completion_tokens=30),
        )

        response = _call_litellm(llm_config, [])

        assert response.prompt_tokens == 120
        assert response.completion_tokens == 30

    @patch("stride_gpt.core.llm.litellm.completion")
    def test_call_llm_leaves_usage_none_when_absent(self, mock_completion, llm_config):
        message = SimpleNamespace(content="hello", tool_calls=None)
        mock_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=message)]
        )

        response = _call_litellm(llm_config, [])

        assert response.prompt_tokens is None
        assert response.completion_tokens is None

    @patch("stride_gpt.core.llm.litellm.completion")
    def test_call_llm_with_tools_records_usage_when_reported(self, mock_completion, llm_config):
        message = SimpleNamespace(content="", tool_calls=None)
        mock_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=message)],
            usage=SimpleNamespace(prompt_tokens=999, completion_tokens=1),
        )

        response = _call_litellm_with_tools(llm_config, [], [])

        assert response.prompt_tokens == 999
        assert response.completion_tokens == 1

    @patch("stride_gpt.core.llm.litellm.completion")
    def test_call_llm_with_tools_leaves_usage_none_when_absent(self, mock_completion, llm_config):
        message = SimpleNamespace(content="", tool_calls=None)
        mock_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=message)]
        )

        response = _call_litellm_with_tools(llm_config, [], [])

        assert response.prompt_tokens is None
        assert response.completion_tokens is None

    @patch("stride_gpt.core.llm.litellm.completion")
    def test_a_usage_object_missing_one_field_leaves_only_that_one_none(
        self, mock_completion, llm_config
    ):
        """Some providers report only one side of the pair via LiteLLM's
        normalized usage object — each field is read independently."""
        message = SimpleNamespace(content="hi", tool_calls=None)
        mock_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=message)],
            usage=SimpleNamespace(prompt_tokens=42),
        )

        response = _call_litellm(llm_config, [])

        assert response.prompt_tokens == 42
        assert response.completion_tokens is None
