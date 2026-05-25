"""Tests for stride_gpt.core.prompts.variants — reference-card loader."""

from __future__ import annotations

import pytest

from stride_gpt.core.prompts.variants import (
    base_system_prompt,
    coerce_app_type,
    list_references,
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
        """The base prompt must point the agent at the discovery tool
        (`list_references`) and the loader (`load_reference`) so the
        progressive-disclosure pattern actually works. The per-card names
        now live in card frontmatter and reach the agent via list_references,
        so the prompt itself no longer hardcodes them."""
        text = base_system_prompt()
        assert "list_references" in text
        assert "load_reference" in text

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

    def test_insider_threat_card_has_categories(self):
        text = load_reference("insider_threat")
        for cat in (
            "Credential Compromise",
            "Supply Chain Sabotage",
            "Data Exfiltration",
            "Infrastructure Sabotage",
            "Deception & Evasion",
        ):
            assert cat in text

    def test_insider_threat_card_has_concrete_scenarios(self):
        """The 23 STRIDE-mapped scenarios are the meat of the framework — if
        they're not present the card is the abstract version, not the useful
        one."""
        text = load_reference("insider_threat")
        for code in ("S1", "S2", "S3", "S4", "T1", "T2", "T3", "T4",
                     "R1", "R2", "R3", "I1", "I2", "I3", "I4",
                     "D1", "D2", "D3", "D4", "E1", "E2", "E3", "E4"):
            assert f"**{code}**" in text, f"missing scenario {code}"

    def test_insider_threat_card_attribution(self):
        """Source must be credited — the card content is distilled from
        ai-insider-threat.matt-adams.co.uk."""
        text = load_reference("insider_threat")
        assert "ai-insider-threat.matt-adams.co.uk" in text

    def test_insider_threat_card_specifies_schema_addition(self):
        text = load_reference("insider_threat")
        assert "INSIDER_CATEGORY" in text

    def test_unknown_card_returns_error_message(self):
        # The agent receives this string as a tool result; it must not raise.
        result = load_reference("nope")
        assert "Error" in result
        assert "nope" in result

    def test_unknown_card_lists_available_options(self):
        result = load_reference("nope")
        assert "genai" in result
        assert "agentic" in result

    def test_body_excludes_frontmatter(self):
        """Frontmatter is metadata, not card content. If it leaked into the
        body, the legacy single-shot prompt would carry YAML headers into the
        LLM context."""
        for name in ("genai", "agentic", "insider_threat"):
            body = load_reference(name)
            assert not body.startswith("---"), f"{name} body starts with frontmatter"
            # Body must start with the card's own H1.
            assert body.lstrip().startswith("#"), f"{name} body has no H1"


class TestListReferences:
    def test_lists_all_cards(self):
        catalogue = list_references()
        names = {entry["name"] for entry in catalogue}
        assert names == {"genai", "agentic", "insider_threat"}

    def test_entries_carry_trigger_metadata(self):
        """Each entry must describe when it applies and what fields it adds
        — that's what makes cheap discovery cheap."""
        for entry in list_references():
            assert entry["when_to_load"], f"{entry['name']} missing when_to_load"
            assert entry["adds_fields"], f"{entry['name']} missing adds_fields"
            assert entry["title"], f"{entry['name']} missing title"
            assert entry["version"], f"{entry['name']} missing version"

    def test_insider_threat_adds_expected_fields(self):
        entry = next(e for e in list_references() if e["name"] == "insider_threat")
        assert "INSIDER_CATEGORY" in entry["adds_fields"]


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

    def test_insider_section_matches_insider_card(self):
        from stride_gpt.core.prompts import create_insider_threat_prompt_section

        section = create_insider_threat_prompt_section()
        card = load_reference("insider_threat")
        assert card in section


class TestLegacyAgenticPath:
    """The legacy create_threat_model_prompt path must include the insider-
    threat section for agentic apps — and only for agentic apps."""

    def test_agentic_app_includes_insider_section(self):
        from stride_gpt.core.prompts import create_threat_model_prompt

        prompt = create_threat_model_prompt(
            app_type="Agentic AI application",
            authentication="oauth",
            internet_facing="yes",
            sensitive_data="high",
            app_input="A LangGraph multi-agent app",
        )
        assert "INSIDER_CATEGORY" in prompt
        assert "Credential Compromise" in prompt

    def test_genai_app_excludes_insider_section(self):
        """A pure GenAI app (no agent loop) shouldn't get the insider lens —
        it's not autonomous enough to be the threat actor."""
        from stride_gpt.core.prompts import create_threat_model_prompt

        prompt = create_threat_model_prompt(
            app_type="Generative AI application",
            authentication="oauth",
            internet_facing="yes",
            sensitive_data="high",
            app_input="A RAG-backed chatbot",
        )
        assert "INSIDER_CATEGORY" not in prompt

    def test_web_app_excludes_insider_section(self):
        from stride_gpt.core.prompts import create_threat_model_prompt

        prompt = create_threat_model_prompt(
            app_type="Web application",
            authentication="oauth",
            internet_facing="yes",
            sensitive_data="medium",
            app_input="A Flask CRUD app",
        )
        assert "INSIDER_CATEGORY" not in prompt
