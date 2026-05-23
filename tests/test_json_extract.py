"""Tests for stride_gpt.core.json_extract — shared JSON-from-LLM extractor."""

from __future__ import annotations

from stride_gpt.core.json_extract import extract_json_object


class TestExtractJsonObject:
    def test_clean_json(self):
        assert extract_json_object('{"a": 1}') == {"a": 1}

    def test_markdown_fence(self):
        content = '```json\n{"a": 1}\n```'
        assert extract_json_object(content) == {"a": 1}

    def test_fence_without_lang_tag(self):
        content = '```\n{"a": 1}\n```'
        assert extract_json_object(content) == {"a": 1}

    def test_embedded_in_prose(self):
        content = 'Here is the answer:\n{"a": 1, "b": [1, 2]}\nLet me know.'
        result = extract_json_object(content)
        assert result == {"a": 1, "b": [1, 2]}

    def test_invalid_text_returns_none(self):
        assert extract_json_object("Sorry, I cannot produce JSON right now.") is None

    def test_empty_returns_none(self):
        assert extract_json_object("") is None

    def test_array_returns_none(self):
        assert extract_json_object("[1, 2, 3]") is None

    def test_scalar_returns_none(self):
        assert extract_json_object("42") is None
