"""Tests for report assembly and rendering."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscope.config import Weights
from vulnscope.parsers.findings import parse_findings
from vulnscope.parsers.threat_model import parse_threat_model
from vulnscope.report import (
    build_report,
    render_console_summary,
    render_markdown,
    score_band,
)
from vulnscope.scorer import score_findings, synthesize_summary

FIXTURES = Path(__file__).parent / "fixtures"


def _report():
    tm = parse_threat_model(FIXTURES / "sample_threat_model.json")
    findings = parse_findings(FIXTURES / "sample_findings.json")
    scored = score_findings(findings, tm, weights=Weights(), client=None)
    summary = synthesize_summary(scored, tm, client=None)
    return build_report(scored, tm, summary), tm


class TestScoreBand:
    def test_bands(self):
        assert score_band(9.0) == "CRITICAL"
        assert score_band(6.5) == "HIGH"
        assert score_band(4.0) == "MEDIUM"
        assert score_band(1.0) == "LOW"


class TestBuildReport:
    def test_metadata(self):
        report, _ = _report()
        assert report["metadata"]["application"] == "PaymentAPI"
        assert report["metadata"]["findings_count"] == 4
        assert report["metadata"]["tool"] == "VulnScope"

    def test_prioritised_findings_have_required_fields(self):
        report, _ = _report()
        for f in report["prioritised_findings"]:
            assert {"finding_id", "title", "composite_score", "classification", "scores",
                    "reasoning", "original_finding"} <= set(f)
            assert f["reasoning"].strip()

    def test_gaps_capture_novel_and_out_of_scope(self):
        report, _ = _report()
        gap_classes = {g["classification"] for g in report["threat_model_gaps"]}
        assert "OUT_OF_SCOPE" in gap_classes
        assert "NOVEL" in gap_classes

    def test_json_is_serialisable(self):
        report, _ = _report()
        # Round-trips cleanly (CI/CD consumption).
        assert json.loads(json.dumps(report)) == report


class TestRenderMarkdown:
    def test_contains_key_sections(self):
        report, _ = _report()
        md = render_markdown(report)
        assert "# VulnScope Report: PaymentAPI" in md
        assert "## Executive Summary" in md
        assert "## Top Findings" in md
        assert "## Threat Model Gaps" in md
        assert "## Recommended Threat Model Updates" in md

    def test_every_finding_reasoning_cites_named_element(self):
        # Acceptance criterion #5: each reasoning cites a named threat model
        # element (component name, threat id, or STRIDE category).
        report, tm = _report()
        names = tm.component_names() | {t.threat_id for t in tm.threats}
        categories = {t.stride_category for t in tm.threats}
        tokens = names | categories
        for f in report["prioritised_findings"]:
            assert any(tok and tok in f["reasoning"] for tok in tokens), f["reasoning"]

    def test_table_cells_escape_pipes(self):
        report, _ = _report()
        # Inject a pipe to confirm escaping keeps the table well-formed.
        report["prioritised_findings"][0]["title"] = "a | b"
        md = render_markdown(report)
        assert "a \\| b" in md


class TestConsoleSummary:
    def test_summary_lists_bands_and_classes(self):
        report, _ = _report()
        out = render_console_summary(report, "report.md")
        assert "VulnScope" in out
        assert "CRITICAL" in out
        assert "Corroborated:" in out
        assert "Report written to: report.md" in out
