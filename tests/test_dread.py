"""Tests for stride_gpt.core.dread — DREAD risk scoring, table rendering, and
response parsing. These are pure functions (no LLM calls) and carry the core
DREAD business logic, so they're worth pinning precisely."""

from __future__ import annotations

from stride_gpt.core.dread import (
    _clean_json_content,
    _parse_dread_response,
    dread_json_to_markdown,
)

# ---------------------------------------------------------------------------
# dread_json_to_markdown — risk-score arithmetic + table rendering
# ---------------------------------------------------------------------------


class TestDreadJsonToMarkdown:
    def test_risk_score_is_average_of_five_categories(self):
        """Risk Score = mean of the five DREAD categories, to 2 decimals.
        (10+8+6+4+2)/5 = 6.00 — pins the divisor and the formatting."""
        assessment = {
            "Risk Assessment": [
                {
                    "Threat Type": "Spoofing",
                    "Scenario": "Credential stuffing",
                    "Damage Potential": 10,
                    "Reproducibility": 8,
                    "Exploitability": 6,
                    "Affected Users": 4,
                    "Discoverability": 2,
                }
            ]
        }
        md = dread_json_to_markdown(assessment)
        assert "| 6.00 |" in md
        assert "Spoofing" in md
        assert "Credential stuffing" in md

    def test_empty_assessment_emits_placeholder_row(self):
        md = dread_json_to_markdown({"Risk Assessment": []})
        assert "No threats found" in md

    def test_missing_key_treated_as_empty(self):
        """A payload with no 'Risk Assessment' key is the same as no threats."""
        md = dread_json_to_markdown({})
        assert "No threats found" in md

    def test_non_dict_entry_emits_invalid_row(self):
        md = dread_json_to_markdown({"Risk Assessment": ["not-a-dict"]})
        assert "Invalid threat" in md

    def test_missing_scores_default_to_zero(self):
        """A threat dict with no numeric scores must not crash; missing scores
        default to 0 so the score is 0.00 rather than a KeyError."""
        md = dread_json_to_markdown(
            {"Risk Assessment": [{"Threat Type": "Tampering", "Scenario": "x"}]}
        )
        assert "| 0.00 |" in md

    def test_pipe_in_text_is_escaped(self):
        """Pipes in LLM text would break the markdown table; they're escaped."""
        md = dread_json_to_markdown(
            {
                "Risk Assessment": [
                    {
                        "Threat Type": "A|B",
                        "Scenario": "uses | pipe",
                        "Damage Potential": 1,
                        "Reproducibility": 1,
                        "Exploitability": 1,
                        "Affected Users": 1,
                        "Discoverability": 1,
                    }
                ]
            }
        )
        assert "A\\|B" in md
        assert "uses \\| pipe" in md

    def test_newlines_stripped_from_scenario(self):
        """Newlines in the scenario would break table row formatting."""
        md = dread_json_to_markdown(
            {
                "Risk Assessment": [
                    {
                        "Threat Type": "Tampering",
                        "Scenario": "line one\nline two\r\nline three",
                        "Damage Potential": 2,
                        "Reproducibility": 2,
                        "Exploitability": 2,
                        "Affected Users": 2,
                        "Discoverability": 2,
                    }
                ]
            }
        )
        assert "line one line two line three" in md
        # No literal newline survives inside the rendered scenario.
        assert "line one\nline two" not in md

    def test_malformed_input_returns_error_row_not_exception(self):
        """A non-iterable under 'Risk Assessment' hits the blanket except and
        yields an error row instead of raising."""
        md = dread_json_to_markdown({"Risk Assessment": 42})
        assert "Error" in md


# ---------------------------------------------------------------------------
# _parse_dread_response / _clean_json_content
# ---------------------------------------------------------------------------


class TestParseDreadResponse:
    def test_parses_plain_json(self):
        parsed = _parse_dread_response('{"Risk Assessment": []}')
        assert parsed == {"Risk Assessment": []}

    def test_parses_fenced_json(self):
        content = '```json\n{"Risk Assessment": [{"Threat Type": "X"}]}\n```'
        parsed = _parse_dread_response(content)
        assert parsed["Risk Assessment"][0]["Threat Type"] == "X"

    def test_unparseable_returns_error_fallback(self):
        """A response that can't be parsed yields the structured error fallback
        so downstream rendering still has the expected shape."""
        parsed = _parse_dread_response("not json at all {{{")
        assert parsed["Risk Assessment"][0]["Threat Type"] == "Error"
        assert "Failed to parse" in parsed["Risk Assessment"][0]["Scenario"]


class TestCleanJsonContent:
    def test_strips_json_fence(self):
        assert _clean_json_content('```json\n{"a": 1}\n```') == '{"a": 1}'

    def test_strips_bare_fence(self):
        assert _clean_json_content('```\n{"a": 1}\n```') == '{"a": 1}'

    def test_strips_line_comments(self):
        cleaned = _clean_json_content('{"a": 1} // trailing comment\n')
        assert "//" not in cleaned

    def test_fixes_trailing_comma_before_bracket(self):
        cleaned = _clean_json_content('{"x": [1,\n  ]}')
        assert ",\n  ]" not in cleaned
