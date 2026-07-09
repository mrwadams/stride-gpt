"""Tests for the pure response-parsing helpers in stride_gpt.core.llm.

extract_deepseek_reasoning and process_groq_response are deterministic string
transforms with no external deps — they split reasoning from the answer and
route a Groq/DeepSeek response to JSON, Mermaid, or raw text.
"""

from __future__ import annotations

from stride_gpt.core.llm import extract_deepseek_reasoning, process_groq_response


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
