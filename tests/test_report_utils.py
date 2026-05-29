"""Tests for stride_gpt.core.report_utils — shared table-rendering helpers."""

from __future__ import annotations

from stride_gpt.core.report_utils import (
    detect_extra_columns,
    format_mitre_cell,
    mitre_url,
    threat_table_header,
    threat_table_row,
)


class TestDetectExtraColumns:
    def test_all_absent(self):
        threats = [{"Threat Type": "T", "Scenario": "s", "Potential Impact": "i"}]
        assert detect_extra_columns(threats) == (False, False, False, False)

    def test_only_llm(self):
        threats = [{"OWASP_LLM": "LLM01"}]
        assert detect_extra_columns(threats) == (True, False, False, False)

    def test_all_four(self):
        threats = [{
            "OWASP_LLM": "LLM01",
            "OWASP_ASI": "ASI06",
            "INSIDER_CATEGORY": "Data Exfiltration",
            "MITRE_ATTACK": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
        }]
        assert detect_extra_columns(threats) == (True, True, True, True)

    def test_null_treated_as_absent(self):
        """A None / empty value must not count as "present" — otherwise web
        reports get unwanted columns full of empty cells."""
        threats = [{"OWASP_LLM": None, "INSIDER_CATEGORY": None, "MITRE_ATTACK": []}]
        assert detect_extra_columns(threats) == (False, False, False, False)

    def test_aggregates_across_threats(self):
        """Column shown if ANY threat carries the field, even if most don't."""
        threats = [
            {"Threat Type": "A"},
            {"OWASP_LLM": "LLM01"},
            {"Threat Type": "C", "MITRE_ATTACK": [{"id": "T1078", "name": "Valid Accounts"}]},
        ]
        assert detect_extra_columns(threats) == (True, False, False, True)

    def test_named_attribute_access(self):
        """The return value exposes positional unpacking AND named attributes
        so call sites can use whichever reads better."""
        threats = [{"MITRE_ATTACK": [{"id": "T1190", "name": "Exploit Public-Facing Application"}]}]
        cols = detect_extra_columns(threats)
        assert cols.show_mitre is True
        assert cols.show_llm is False


class TestThreatTableHeader:
    def test_base_columns_only(self):
        header, sep = threat_table_header(False, False, False, False)
        assert header == "| Threat Type | Scenario | Potential Impact |"
        assert sep.count("|") == 4  # 3 cols + 2 edges = 4 separators

    def test_all_optional_columns(self):
        header, _ = threat_table_header(True, True, True, True)
        assert "OWASP LLM" in header
        assert "OWASP ASI" in header
        assert "Insider Category" in header
        assert "MITRE ATT&CK" in header

    def test_cross_cutting_adds_affected(self):
        header, _ = threat_table_header(False, False, False, False, cross_cutting=True)
        assert "Affected Subsystems" in header

    def test_column_order_is_fixed(self):
        """Column order matters for downstream consumers — LLM before ASI
        before Insider before MITRE, Affected Subsystems always last."""
        header, _ = threat_table_header(True, True, True, True, cross_cutting=True)
        llm_idx = header.index("OWASP LLM")
        asi_idx = header.index("OWASP ASI")
        insider_idx = header.index("Insider Category")
        mitre_idx = header.index("MITRE ATT&CK")
        affected_idx = header.index("Affected Subsystems")
        assert llm_idx < asi_idx < insider_idx < mitre_idx < affected_idx


class TestThreatTableRow:
    def test_base_row(self):
        threat = {"Threat Type": "Spoofing", "Scenario": "a", "Potential Impact": "b"}
        row = threat_table_row(threat, False, False, False, False)
        assert row == "| Spoofing | a | b |"

    def test_pipes_escaped(self):
        threat = {"Threat Type": "T", "Scenario": "a | b", "Potential Impact": "c"}
        row = threat_table_row(threat, False, False, False, False)
        assert "a \\| b" in row

    def test_null_optional_cells_blank(self):
        """A null OWASP field must render as an empty cell, not "None"."""
        threat = {"Threat Type": "T", "Scenario": "s", "Potential Impact": "i",
                  "OWASP_LLM": "LLM01", "OWASP_ASI": None}
        row = threat_table_row(threat, True, True, False, False)
        assert "None" not in row
        assert "| LLM01 |  |" in row  # ASI cell empty

    def test_mitre_cell_renders_ids_and_names(self):
        threat = {
            "Threat Type": "Spoofing",
            "Scenario": "s",
            "Potential Impact": "i",
            "MITRE_ATTACK": [
                {"id": "T1190", "name": "Exploit Public-Facing Application"},
                {"id": "AML.T0051", "name": "LLM Prompt Injection"},
            ],
        }
        row = threat_table_row(threat, False, False, False, True)
        assert "T1190 (Exploit Public-Facing Application)" in row
        assert "AML.T0051 (LLM Prompt Injection)" in row

    def test_mitre_cell_empty_when_field_absent(self):
        threat = {"Threat Type": "T", "Scenario": "s", "Potential Impact": "i"}
        row = threat_table_row(threat, False, False, False, True)
        # Last cell should be empty before the trailing pipe.
        assert row.endswith("|  |")


class TestFormatMitreCell:
    def test_object_form(self):
        techs = [{"id": "T1190", "name": "Exploit Public-Facing Application"}]
        assert format_mitre_cell(techs) == "T1190 (Exploit Public-Facing Application)"

    def test_string_form_falls_back_to_id_only(self):
        assert format_mitre_cell(["T1190", "T1078"]) == "T1190, T1078"

    def test_missing_id_skipped(self):
        techs = [{"id": "T1190", "name": "A"}, {"name": "no id"}, {"id": "T1078", "name": "B"}]
        assert format_mitre_cell(techs) == "T1190 (A), T1078 (B)"

    def test_empty_or_invalid_yields_empty_string(self):
        assert format_mitre_cell(None) == ""
        assert format_mitre_cell([]) == ""
        assert format_mitre_cell("not a list") == ""

    def test_pipes_inside_names_escaped(self):
        techs = [{"id": "T1", "name": "foo | bar"}]
        assert format_mitre_cell(techs) == "T1 (foo \\| bar)"


class TestMitreUrl:
    def test_enterprise_top_level(self):
        assert mitre_url("T1190") == "https://attack.mitre.org/techniques/T1190/"

    def test_enterprise_subtechnique(self):
        assert mitre_url("T1078.004") == "https://attack.mitre.org/techniques/T1078/004/"

    def test_atlas_id(self):
        assert mitre_url("AML.T0051") == "https://atlas.mitre.org/techniques/AML.T0051/"

    def test_unknown_pattern_yields_empty(self):
        assert mitre_url("not-a-technique") == ""
        assert mitre_url("") == ""


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
