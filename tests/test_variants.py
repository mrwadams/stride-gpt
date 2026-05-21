"""Tests for stride_gpt.core.prompts.variants — reference-card loader."""

from __future__ import annotations

import pytest

from stride_gpt.core.prompts.variants import (
    base_system_prompt,
    coerce_app_type,
    load_reference,
)


class TestBaseSystemPrompt:
    def test_contains_stride_framing(self):
        text = base_system_prompt()
        for keyword in ("Spoofing", "Tampering", "Repudiation",
                        "Information Disclosure", "Denial of Service",
                        "Elevation of Privilege"):
            assert keyword in text

    def test_advertises_reference_cards(self):
        """The base prompt must point the agent at both reference cards so the
        progressive-disclosure pattern actually works."""
        text = base_system_prompt()
        assert "load_reference" in text
        assert 'name="genai"' in text or 'name=\'genai\'' in text
        assert 'name="agentic"' in text or 'name=\'agentic\'' in text

    def test_includes_output_schema(self):
        text = base_system_prompt()
        assert "threats" in text
        assert "Threat Type" in text
        assert "improvement_suggestions" in text


class TestLoadReference:
    def test_genai_card_has_llm_content(self):
        text = load_reference("genai")
        for code in ("LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
                     "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"):
            assert code in text

    def test_genai_card_specifies_schema_addition(self):
        text = load_reference("genai")
        assert "OWASP_LLM" in text

    def test_agentic_card_has_asi_content(self):
        text = load_reference("agentic")
        for code in ("ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
                     "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"):
            assert code in text

    def test_agentic_card_specifies_schema_addition(self):
        text = load_reference("agentic")
        assert "OWASP_ASI" in text

    def test_unknown_card_returns_error_message(self):
        # The agent receives this string as a tool result; it must not raise.
        result = load_reference("nope")
        assert "Error" in result
        assert "nope" in result

    def test_unknown_card_lists_available_options(self):
        result = load_reference("nope")
        assert "genai" in result
        assert "agentic" in result


class TestCoerceAppType:
    @pytest.mark.parametrize("value,expected", [
        ("web", "web"),
        ("genai", "genai"),
        ("agentic", "agentic"),
        ("Web application", "web"),
        ("Generative AI application", "genai"),
        ("Agentic AI application", "agentic"),
        ("AGENTIC", "agentic"),
        ("  genai  ", "genai"),
        ("Gen AI", "genai"),
        ("unknown thing", "web"),
        ("", "web"),
        (None, "web"),
    ])
    def test_coercion(self, value, expected):
        assert coerce_app_type(value) == expected


class TestLegacyHelpersUseMarkdown:
    """The legacy single-shot path's section helpers must source content from
    the same markdown files as the agent's reference cards — otherwise the two
    paths drift apart."""

    def test_llm_section_matches_genai_card(self):
        from stride_gpt.core.prompts import create_llm_stride_prompt_section

        section = create_llm_stride_prompt_section()
        card = load_reference("genai")
        # Section is the card with a leading newline (legacy callers concat
        # without a separator).
        assert card in section

    def test_agentic_section_matches_agentic_card(self):
        from stride_gpt.core.prompts import create_agentic_stride_prompt_section

        section = create_agentic_stride_prompt_section()
        card = load_reference("agentic")
        assert card in section
