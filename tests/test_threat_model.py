"""Tests for stride_gpt.core.threat_model parsing helpers.

Focus on the resilience path: local models frequently emit prose or
fence-wrapped JSON instead of a clean object, so the parser must clean common
noise and, on genuine failure, return a well-formed ThreatModelOutput carrying
a structured error rather than raising into the caller.
"""

from __future__ import annotations

from stride_gpt.core.threat_model import (
    _clean_json_content,
    _parse_threat_model_response,
)


class TestParseThreatModelResponse:
    def test_parses_valid_json(self):
        content = (
            '{"threat_model": [{"Threat Type": "Spoofing", "Scenario": "s", '
            '"Potential Impact": "i"}], "improvement_suggestions": ["fix it"]}'
        )
        parsed = _parse_threat_model_response(content)
        assert parsed.threat_model[0]["Threat Type"] == "Spoofing"
        assert parsed.improvement_suggestions == ["fix it"]

    def test_malformed_json_yields_structured_error(self):
        parsed = _parse_threat_model_response("the model rambled instead {{{")
        assert len(parsed.threat_model) == 1
        assert parsed.threat_model[0]["Threat Type"] == "Error"
        assert "Failed to parse" in parsed.threat_model[0]["Scenario"]

    def test_error_fallback_includes_raw_snippet(self):
        parsed = _parse_threat_model_response("not json <b>hi</b>")
        joined = " ".join(parsed.improvement_suggestions)
        assert "JSON parse error" in joined
        assert "not json" in joined

    def test_error_snippet_escapes_pipes_for_markdown_table(self):
        # The snippet lands in a markdown table cell; unescaped pipes would
        # break the table layout.
        parsed = _parse_threat_model_response("a | b | c not json {{{")
        joined = " ".join(parsed.improvement_suggestions)
        assert "\\|" in joined

    def test_empty_response_reports_empty_placeholder(self):
        parsed = _parse_threat_model_response("")
        joined = " ".join(parsed.improvement_suggestions)
        assert "(empty response)" in joined

    def test_long_snippet_is_truncated(self):
        parsed = _parse_threat_model_response("x" * 1000 + " not json {{{")
        joined = " ".join(parsed.improvement_suggestions)
        assert "..." in joined

    def test_missing_keys_default_to_empty_lists(self):
        parsed = _parse_threat_model_response('{"threat_model": []}')
        assert parsed.threat_model == []
        assert parsed.improvement_suggestions == []


class TestCleanJsonContent:
    def test_strips_json_fence(self):
        assert _clean_json_content('```json\n{"a": 1}\n```') == '{"a": 1}'

    def test_strips_bare_fence(self):
        assert _clean_json_content('```\n{"a": 1}\n```') == '{"a": 1}'

    def test_removes_line_comments(self):
        cleaned = _clean_json_content('{"a": 1} // a comment\n')
        assert "//" not in cleaned

    def test_repairs_trailing_comma_before_bracket(self):
        cleaned = _clean_json_content('{"x": [1,\n]}')
        assert ",\n]" not in cleaned

    def test_fenced_json_with_comment_becomes_parseable(self):
        import json

        raw = '```json\n{"threat_model": [], // note\n"improvement_suggestions": []}\n```'
        cleaned = _clean_json_content(raw)
        assert json.loads(cleaned) == {
            "threat_model": [],
            "improvement_suggestions": [],
        }
