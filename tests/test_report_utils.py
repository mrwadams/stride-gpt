"""Tests for stride_gpt.core.report_utils — shared table-rendering helpers."""

from __future__ import annotations

from stride_gpt.core.report_utils import (
    detect_extra_columns,
    threat_table_header,
    threat_table_row,
)


class TestDetectExtraColumns:
    def test_all_absent(self):
        threats = [{"Threat Type": "T", "Scenario": "s", "Potential Impact": "i"}]
        assert detect_extra_columns(threats) == (False, False, False)

    def test_only_llm(self):
        threats = [{"OWASP_LLM": "LLM01"}]
        assert detect_extra_columns(threats) == (True, False, False)

    def test_all_three(self):
        threats = [{
            "OWASP_LLM": "LLM01",
            "OWASP_ASI": "ASI06",
            "INSIDER_CATEGORY": "Data Exfiltration",
        }]
        assert detect_extra_columns(threats) == (True, True, True)

    def test_null_treated_as_absent(self):
        """A None value for an OWASP field must not count as "present" —
        otherwise web reports get unwanted columns full of empty cells."""
        threats = [{"OWASP_LLM": None, "INSIDER_CATEGORY": None}]
        assert detect_extra_columns(threats) == (False, False, False)

    def test_aggregates_across_threats(self):
        """Column shown if ANY threat carries the field, even if most don't."""
        threats = [
            {"Threat Type": "A"},
            {"OWASP_LLM": "LLM01"},
            {"Threat Type": "C"},
        ]
        assert detect_extra_columns(threats) == (True, False, False)


class TestThreatTableHeader:
    def test_base_columns_only(self):
        header, sep = threat_table_header(False, False, False)
        assert header == "| Threat Type | Scenario | Potential Impact |"
        assert sep.count("|") == 4  # 3 cols + 2 edges = 4 separators

    def test_all_optional_columns(self):
        header, _ = threat_table_header(True, True, True)
        assert "OWASP LLM" in header
        assert "OWASP ASI" in header
        assert "Insider Category" in header

    def test_cross_cutting_adds_affected(self):
        header, _ = threat_table_header(False, False, False, cross_cutting=True)
        assert "Affected Subsystems" in header

    def test_column_order_is_fixed(self):
        """Column order matters for downstream consumers — LLM before ASI
        before Insider, Affected Subsystems always last."""
        header, _ = threat_table_header(True, True, True, cross_cutting=True)
        llm_idx = header.index("OWASP LLM")
        asi_idx = header.index("OWASP ASI")
        insider_idx = header.index("Insider Category")
        affected_idx = header.index("Affected Subsystems")
        assert llm_idx < asi_idx < insider_idx < affected_idx


class TestThreatTableRow:
    def test_base_row(self):
        threat = {"Threat Type": "Spoofing", "Scenario": "a", "Potential Impact": "b"}
        row = threat_table_row(threat, False, False, False)
        assert row == "| Spoofing | a | b |"

    def test_pipes_escaped(self):
        threat = {"Threat Type": "T", "Scenario": "a | b", "Potential Impact": "c"}
        row = threat_table_row(threat, False, False, False)
        assert "a \\| b" in row

    def test_null_optional_cells_blank(self):
        """A null OWASP field must render as an empty cell, not "None"."""
        threat = {"Threat Type": "T", "Scenario": "s", "Potential Impact": "i",
                  "OWASP_LLM": "LLM01", "OWASP_ASI": None}
        row = threat_table_row(threat, True, True, False)
        assert "None" not in row
        assert "| LLM01 |  |" in row  # ASI cell empty


class TestLegacyJsonToMarkdownInsider:
    """The legacy /quick renderer (core/threat_model.py:json_to_markdown) uses
    the same shared helpers, so it should surface INSIDER_CATEGORY columns the
    same way the agentic renderer does."""

    def test_insider_column_appears(self):
        from stride_gpt.core.threat_model import json_to_markdown

        threats = [{
            "Threat Type": "Information Disclosure",
            "Scenario": "Agent harvests credentials",
            "Potential Impact": "Lateral movement",
            "INSIDER_CATEGORY": "Credential Compromise",
        }]
        md = json_to_markdown(threats, [])
        assert "Insider Category" in md
        assert "Credential Compromise" in md

    def test_three_lenses_all_render(self):
        from stride_gpt.core.threat_model import json_to_markdown

        threats = [{
            "Threat Type": "Information Disclosure",
            "Scenario": "RAG leaks PII",
            "Potential Impact": "Mass disclosure",
            "OWASP_LLM": "LLM02",
            "OWASP_ASI": "ASI06",
            "INSIDER_CATEGORY": "Data Exfiltration",
        }]
        md = json_to_markdown(threats, [])
        assert "OWASP LLM" in md
        assert "OWASP ASI" in md
        assert "Insider Category" in md
        assert "LLM02" in md
        assert "ASI06" in md
        assert "Data Exfiltration" in md

    def test_no_extra_columns_for_web(self):
        from stride_gpt.core.threat_model import json_to_markdown

        threats = [{"Threat Type": "Spoofing", "Scenario": "s", "Potential Impact": "i"}]
        md = json_to_markdown(threats, [])
        assert "OWASP" not in md
        assert "Insider Category" not in md
