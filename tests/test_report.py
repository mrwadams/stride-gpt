"""Tests for stride_gpt.agent.report — markdown, JSON, and SARIF rendering."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stride_gpt.agent.report import (
    render_json,
    render_markdown,
    render_sarif,
    render_markdown_from_json,
    render_sarif_from_json,
    save_report,
    load_report,
    list_reports,
)
from stride_gpt.core.schemas import AnalysisReport


# ---------------------------------------------------------------------------
# render_markdown
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    def test_contains_title(self, sample_report: AnalysisReport):
        md = render_markdown(sample_report)
        assert "# STRIDE Threat Model:" in md

    def test_contains_threats_table(self, sample_report: AnalysisReport):
        md = render_markdown(sample_report)
        assert "| Threat Type |" in md
        assert "Spoofing" in md
        assert "brute-force" in md

    def test_contains_cross_cutting(self, sample_report: AnalysisReport):
        md = render_markdown(sample_report)
        assert "Cross-Cutting Threats" in md
        assert "CSRF" in md

    def test_contains_recommendations(self, sample_report: AnalysisReport):
        md = render_markdown(sample_report)
        assert "rate limiting" in md

    def test_contains_summary(self, sample_report: AnalysisReport):
        md = render_markdown(sample_report)
        assert "Total threats identified" in md
        assert "LLM calls" in md

    def test_pipe_escaping(self, sample_plan):
        """Pipes in threat text shouldn't break markdown tables."""
        from stride_gpt.core.schemas import SubsystemFinding

        finding = SubsystemFinding(
            subsystem="Test",
            threats=[{
                "Threat Type": "Tampering",
                "Scenario": "Input contains | pipe chars",
                "Potential Impact": "Table | breaks",
            }],
        )
        report = AnalysisReport(plan=sample_plan, findings=[finding], metadata={})
        md = render_markdown(report)
        assert "\\|" in md


# ---------------------------------------------------------------------------
# render_json
# ---------------------------------------------------------------------------


class TestRenderJson:
    def test_structure(self, sample_report: AnalysisReport):
        data = render_json(sample_report)
        assert data["version"] == "1.0"
        assert "generated_at" in data
        assert len(data["subsystems"]) == 1
        assert len(data["cross_cutting_threats"]) == 1

    def test_metadata_preserved(self, sample_report: AnalysisReport):
        data = render_json(sample_report)
        assert data["metadata"]["llm_calls"] == 5


# ---------------------------------------------------------------------------
# render_sarif
# ---------------------------------------------------------------------------


class TestRenderSarif:
    def test_sarif_schema(self, sample_report: AnalysisReport):
        sarif = render_sarif(sample_report)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_rules(self, sample_report: AnalysisReport):
        sarif = render_sarif(sample_report)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "STRIDE/SPOOFING" in rule_ids

    def test_sarif_results(self, sample_report: AnalysisReport):
        sarif = render_sarif(sample_report)
        results = sarif["runs"][0]["results"]
        # 2 subsystem threats + 1 cross-cutting
        assert len(results) == 3

    def test_sarif_locations(self, sample_report: AnalysisReport):
        sarif = render_sarif(sample_report)
        results = sarif["runs"][0]["results"]
        subsystem_results = [r for r in results if r["properties"]["subsystem"] != "cross-cutting"]
        for r in subsystem_results:
            assert "locations" in r

    def test_cross_cutting_marked(self, sample_report: AnalysisReport):
        sarif = render_sarif(sample_report)
        results = sarif["runs"][0]["results"]
        cc = [r for r in results if r["properties"]["subsystem"] == "cross-cutting"]
        assert len(cc) == 1
        assert "[Cross-cutting]" in cc[0]["message"]["text"]


# ---------------------------------------------------------------------------
# render_*_from_json (round-trip)
# ---------------------------------------------------------------------------


class TestFromJsonRenderers:
    def test_markdown_roundtrip(self, sample_report: AnalysisReport):
        data = render_json(sample_report)
        md = render_markdown_from_json(data)
        assert "Spoofing" in md
        assert "Cross-Cutting" in md

    def test_sarif_roundtrip(self, sample_report: AnalysisReport):
        data = render_json(sample_report)
        sarif = render_sarif_from_json(data)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 3


# ---------------------------------------------------------------------------
# save / load / list reports
# ---------------------------------------------------------------------------


class TestReportPersistence:
    def test_save_and_load(self, sample_report: AnalysisReport, tmp_path: Path):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)
            path = save_report(sample_report)
            assert path.exists()
            data = load_report(path)
            assert data["version"] == "1.0"
            assert len(data["subsystems"]) == 1

    def test_list_reports(self, sample_report: AnalysisReport, tmp_path: Path):
        from unittest.mock import patch
        from datetime import datetime, timezone

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)

            # Use different timestamps so filenames don't collide
            t1 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
            t2 = datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
            with patch("stride_gpt.agent.report.datetime") as mock_dt:
                mock_dt.now.return_value = t1
                mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
                save_report(sample_report)
                mock_dt.now.return_value = t2
                save_report(sample_report)

            reports = list_reports(limit=5)
            assert len(reports) == 2
            _, _, summary = reports[0]
            assert summary["threat_count"] == 3  # 2 subsystem + 1 cross-cutting


# ---------------------------------------------------------------------------
# OWASP column rendering — appears only when threats carry the codes
# ---------------------------------------------------------------------------


def _report_with_owasp(sample_plan, *, owasp_llm: str | None = None, owasp_asi: str | None = None):
    from stride_gpt.core.schemas import SubsystemFinding

    threat: dict = {
        "Threat Type": "Tampering",
        "Scenario": "Prompt injection via uploaded doc",
        "Potential Impact": "Compromised analysis",
    }
    if owasp_llm is not None:
        threat["OWASP_LLM"] = owasp_llm
    if owasp_asi is not None:
        threat["OWASP_ASI"] = owasp_asi
    return AnalysisReport(
        plan=sample_plan,
        findings=[SubsystemFinding(subsystem="Auth", threats=[threat])],
        metadata={},
    )


class TestOwaspColumns:
    def test_columns_appear_when_codes_present(self, sample_plan):
        report = _report_with_owasp(sample_plan, owasp_llm="LLM01", owasp_asi="ASI01")
        md = render_markdown(report)
        assert "OWASP LLM" in md
        assert "OWASP ASI" in md
        assert "LLM01" in md
        assert "ASI01" in md

    def test_only_llm_column_when_no_asi(self, sample_plan):
        report = _report_with_owasp(sample_plan, owasp_llm="LLM05", owasp_asi=None)
        md = render_markdown(report)
        assert "OWASP LLM" in md
        assert "OWASP ASI" not in md
        assert "LLM05" in md

    def test_columns_absent_for_web_report(self, sample_report):
        """The default sample_report fixture is a web app — no OWASP codes."""
        md = render_markdown(sample_report)
        assert "OWASP LLM" not in md
        assert "OWASP ASI" not in md
        assert "Spoofing" in md  # smoke check the body still renders

    def test_null_owasp_renders_as_empty_cell(self, sample_plan):
        """A null OWASP_ASI on one threat alongside a non-null on another
        must render as a blank cell, not the literal 'None'."""
        from stride_gpt.core.schemas import SubsystemFinding

        report = AnalysisReport(
            plan=sample_plan,
            findings=[SubsystemFinding(subsystem="X", threats=[
                {"Threat Type": "T", "Scenario": "s", "Potential Impact": "i",
                 "OWASP_LLM": "LLM01", "OWASP_ASI": "ASI01"},
                {"Threat Type": "T", "Scenario": "s2", "Potential Impact": "i2",
                 "OWASP_LLM": "LLM02", "OWASP_ASI": None},
            ])],
            metadata={},
        )
        md = render_markdown(report)
        assert "None" not in md.split("Threats")[-1].split("## ")[0]

    def test_cross_cutting_table_includes_owasp(self, sample_plan):
        from stride_gpt.core.schemas import SubsystemFinding

        report = AnalysisReport(
            plan=sample_plan,
            findings=[SubsystemFinding(
                subsystem="X",
                threats=[{"Threat Type": "T", "Scenario": "s", "Potential Impact": "i",
                          "OWASP_LLM": "LLM01"}],
            )],
            cross_cutting_threats=[{
                "Threat Type": "Tampering",
                "Scenario": "cc",
                "Potential Impact": "cc impact",
                "Affected Subsystems": ["X"],
                "OWASP_LLM": "LLM01",
            }],
            metadata={},
        )
        md = render_markdown(report)
        cc_section = md.split("Cross-Cutting Threats")[1]
        assert "OWASP LLM" in cc_section
        assert "Affected Subsystems" in cc_section

    def test_from_json_renderer_picks_up_owasp(self, sample_plan):
        """The disk-replay path (rendering a saved JSON report) must also
        surface OWASP columns — that's the path /reports uses."""
        report = _report_with_owasp(sample_plan, owasp_llm="LLM01", owasp_asi="ASI06")
        data = render_json(report)
        md = render_markdown_from_json(data)
        assert "OWASP LLM" in md
        assert "OWASP ASI" in md
        assert "ASI06" in md

    def test_sarif_properties_include_owasp(self, sample_plan):
        report = _report_with_owasp(sample_plan, owasp_llm="LLM01", owasp_asi="ASI01")
        sarif = render_sarif(report)
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["owasp_llm"] == "LLM01"
        assert result["properties"]["owasp_asi"] == "ASI01"

    def test_sarif_omits_owasp_when_null(self, sample_plan):
        report = _report_with_owasp(sample_plan, owasp_llm="LLM01", owasp_asi=None)
        sarif = render_sarif(report)
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["owasp_llm"] == "LLM01"
        assert "owasp_asi" not in result["properties"]


class TestInsiderCategoryColumn:
    """The insider-threat lens adds an INSIDER_CATEGORY field to threats.
    Conditional column, same pattern as OWASP_LLM / OWASP_ASI."""

    def _report_with_insider(self, sample_plan, category):
        from stride_gpt.core.schemas import SubsystemFinding

        threat = {
            "Threat Type": "Information Disclosure",
            "Scenario": "Agent harvests credentials from env vars",
            "Potential Impact": "Lateral movement",
            "INSIDER_CATEGORY": category,
        }
        return AnalysisReport(
            plan=sample_plan,
            findings=[SubsystemFinding(subsystem="Agent", threats=[threat])],
            metadata={},
        )

    def test_column_appears_when_insider_present(self, sample_plan):
        report = self._report_with_insider(sample_plan, "Credential Compromise")
        md = render_markdown(report)
        assert "Insider Category" in md
        assert "Credential Compromise" in md

    def test_column_absent_when_no_insider(self, sample_report):
        md = render_markdown(sample_report)
        assert "Insider Category" not in md

    def test_three_lenses_render_together(self, sample_plan):
        """A threat can carry all three lenses (LLM + ASI + Insider) — the
        renderer must include all three columns."""
        from stride_gpt.core.schemas import SubsystemFinding

        report = AnalysisReport(
            plan=sample_plan,
            findings=[SubsystemFinding(subsystem="Agent", threats=[{
                "Threat Type": "Information Disclosure",
                "Scenario": "RAG leaks PII via exfiltration",
                "Potential Impact": "Mass disclosure",
                "OWASP_LLM": "LLM02",
                "OWASP_ASI": "ASI06",
                "INSIDER_CATEGORY": "Data Exfiltration",
            }])],
            metadata={},
        )
        md = render_markdown(report)
        assert "OWASP LLM" in md
        assert "OWASP ASI" in md
        assert "Insider Category" in md
        # And all values render in the same row
        assert "LLM02" in md
        assert "ASI06" in md
        assert "Data Exfiltration" in md

    def test_sarif_properties_carry_insider_category(self, sample_plan):
        report = self._report_with_insider(sample_plan, "Data Exfiltration")
        sarif = render_sarif(report)
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["insider_category"] == "Data Exfiltration"

    def test_sarif_omits_insider_when_null(self, sample_plan):
        from stride_gpt.core.schemas import SubsystemFinding

        report = AnalysisReport(
            plan=sample_plan,
            findings=[SubsystemFinding(subsystem="X", threats=[{
                "Threat Type": "T", "Scenario": "s", "Potential Impact": "i",
                "INSIDER_CATEGORY": None,
            }])],
            metadata={},
        )
        sarif = render_sarif(report)
        result = sarif["runs"][0]["results"][0]
        assert "insider_category" not in result["properties"]

    def test_from_json_renderer_picks_up_insider(self, sample_plan):
        from stride_gpt.agent.report import render_json
        report = self._report_with_insider(sample_plan, "Infrastructure Sabotage")
        data = render_json(report)
        md = render_markdown_from_json(data)
        assert "Insider Category" in md
        assert "Infrastructure Sabotage" in md
