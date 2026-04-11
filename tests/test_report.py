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
