"""Tests for stride_gpt.agent.report — markdown, JSON, and SARIF rendering."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stride_gpt.agent.html_report import render_html, render_html_from_json
from stride_gpt.agent.report import (
    render_json,
    render_markdown,
    render_sarif,
    render_markdown_from_json,
    render_sarif_from_json,
    save_report,
    save_quick_report,
    load_report,
    list_reports,
)
from stride_gpt.core.schemas import AnalysisReport, ThreatModelOutput


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


# ---------------------------------------------------------------------------
# Report persistence — separate folders for /analyze and /quick
# ---------------------------------------------------------------------------


class TestRenderHtml:
    """The HTML renderer is the human-facing companion to the JSON report.
    Tests assert on shape and key fragments, not whole-document bytes — the
    Tailwind class soup will churn often, but the structural anchors won't."""

    def test_doctype_and_scaffold(self, sample_report: AnalysisReport):
        html = render_html(sample_report)
        assert html.startswith("<!doctype html>")
        assert "tailwindcss.com" in html  # Tailwind CDN present
        assert "<title>STRIDE Threat Model" in html

    def test_target_name_in_header(self, sample_report: AnalysisReport):
        html = render_html(sample_report)
        # plan.target_path = "/tmp/test-app" → name "test-app"
        assert "test-app" in html

    def test_renders_stride_badges_for_threats(self, sample_report: AnalysisReport):
        html = render_html(sample_report)
        # Each threat should appear in a card; the Spoofing badge class is the
        # canonical "category coding works" smoke check.
        assert "Spoofing" in html
        assert "bg-indigo-100" in html
        assert "brute-force" in html

    def test_renders_cross_cutting_section(self, sample_report: AnalysisReport):
        html = render_html(sample_report)
        assert "Cross-cutting threats" in html
        assert "CSRF" in html
        # Affected subsystems should appear as pills, not a comma-joined string
        assert ">Auth<" in html
        assert ">API<" in html

    def test_renders_recommendations(self, sample_report: AnalysisReport):
        html = render_html(sample_report)
        assert "Recommendations" in html
        assert "rate limiting" in html

    def test_renders_files_analyzed(self, sample_report: AnalysisReport):
        html = render_html(sample_report)
        assert "Files analyzed" in html
        assert "auth.py" in html
        assert "font-mono" in html

    def test_summary_chips_present(self, sample_report: AnalysisReport):
        html = render_html(sample_report)
        # 2 subsystem threats + 1 cross-cutting = 3
        assert "3 threats" in html
        assert "1 cross-cutting" in html

    def test_escapes_hostile_threat_text(self, sample_plan):
        """A threat carrying <script> must not render as a live tag.
        The renderer is for human review of analysis output, but treat any
        LLM-produced text as untrusted on the way to a browser."""
        from stride_gpt.core.schemas import SubsystemFinding

        report = AnalysisReport(
            plan=sample_plan,
            findings=[SubsystemFinding(
                subsystem="Auth",
                threats=[{
                    "Threat Type": "Tampering",
                    "Scenario": "<script>alert('xss')</script>",
                    "Potential Impact": "User session hijack via </body><script>x</script>",
                }],
            )],
            metadata={},
        )
        html = render_html(report)
        assert "<script>alert" not in html
        assert "&lt;script&gt;alert" in html

    def test_owasp_pills_appear_when_codes_present(self, sample_plan):
        report = _report_with_owasp(sample_plan, owasp_llm="LLM01", owasp_asi="ASI06")
        html = render_html(report)
        assert "OWASP LLM01" in html
        assert "ASI ASI06" in html

    def test_owasp_pills_absent_when_codes_missing(self, sample_report: AnalysisReport):
        """A standard web app has no OWASP_LLM/ASI; pills must not appear at all
        (not even as empty containers)."""
        html = render_html(sample_report)
        assert "OWASP " not in html
        assert "ASI " not in html

    def test_insider_category_pill(self, sample_plan):
        from stride_gpt.core.schemas import SubsystemFinding

        report = AnalysisReport(
            plan=sample_plan,
            findings=[SubsystemFinding(
                subsystem="Agent",
                threats=[{
                    "Threat Type": "Information Disclosure",
                    "Scenario": "Agent harvests env vars",
                    "Potential Impact": "Lateral movement",
                    "INSIDER_CATEGORY": "Data Exfiltration",
                }],
            )],
            metadata={},
        )
        html = render_html(report)
        assert "Insider: Data Exfiltration" in html

    def test_quick_report_renders_with_single_subsystem(self, sample_plan):
        """The /quick path saves a synthetic 'Application' subsystem with no
        files_analyzed and an empty overview — the renderer must handle that
        gracefully (no orphan headers, no empty Files-analyzed block)."""
        quick_data = {
            "version": "1.0",
            "kind": "quick",
            "generated_at": "2026-01-15T12:00:00+00:00",
            "target": "my-saas-app",
            "overview": "",
            "subsystems": [{
                "name": "Application",
                "threats": [{
                    "Threat Type": "Spoofing",
                    "Scenario": "Weak password policy",
                    "Potential Impact": "Account takeover",
                }],
                "improvement_suggestions": ["Require MFA"],
                "files_analyzed": [],
            }],
            "cross_cutting_threats": [],
            "metadata": {"kind": "quick"},
        }
        html = render_html_from_json(quick_data)
        assert "my-saas-app" in html
        assert "Application" in html
        assert "Files analyzed" not in html
        assert "Cross-cutting" not in html
        # Subsystem count chip suppressed for /quick (only one subsystem)
        assert "1 subsystems" not in html

    def test_round_trip_via_saved_json(self, sample_report: AnalysisReport, tmp_path):
        """The disk-replay path must produce byte-identical HTML to a live
        render — /analyze and /reports share rendering."""
        live = render_html(sample_report)
        replay = render_html_from_json(render_json(sample_report))
        # generated_at is computed at render time from data["generated_at"]
        # which is set by render_json, so the two should match.
        assert live == replay

    def test_unknown_stride_category_falls_back(self, sample_plan):
        """An unrecognised Threat Type must still render — fall back to the
        neutral badge rather than KeyError."""
        from stride_gpt.core.schemas import SubsystemFinding

        report = AnalysisReport(
            plan=sample_plan,
            findings=[SubsystemFinding(
                subsystem="X",
                threats=[{
                    "Threat Type": "Some Future Category",
                    "Scenario": "s",
                    "Potential Impact": "i",
                }],
            )],
            metadata={},
        )
        html = render_html(report)
        assert "Some Future Category" in html

    def test_auto_save_writes_html_companion(
        self, sample_report: AnalysisReport, tmp_path
    ):
        """save_report() must write a .html sibling alongside the .json so
        users get a browser-viewable report for free."""
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)
            json_path = save_report(sample_report)
            html_path = json_path.with_suffix(".html")
            assert html_path.exists()
            content = html_path.read_text()
            assert content.startswith("<!doctype html>")
            assert "Spoofing" in content

    def test_quick_auto_save_writes_html_companion(self, tmp_path, model_pair):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)
            output = ThreatModelOutput(
                threat_model=[{
                    "Threat Type": "Spoofing",
                    "Scenario": "x",
                    "Potential Impact": "y",
                }],
                improvement_suggestions=["test"],
            )
            json_path = save_quick_report(output, "atlas", models=model_pair)
            html_path = json_path.with_suffix(".html")
            assert html_path.exists()
            assert "atlas" in html_path.read_text()


class TestSplitReportFolders:
    """/analyze and /quick reports must live in separate subdirectories so a
    coding agent pointed at the 'analyze' folder doesn't see unrelated
    description-based analyses mixed in."""

    def test_analyze_saves_to_analyze_subdir(self, sample_report, tmp_path):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)
            path = save_report(sample_report)
            assert path.parent == tmp_path / "analyze"
            assert path.exists()

    def test_quick_saves_to_quick_subdir(self, tmp_path, model_pair):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)
            output = ThreatModelOutput(
                threat_model=[{"Threat Type": "S", "Scenario": "x", "Potential Impact": "y"}],
                improvement_suggestions=["test"],
            )
            path = save_quick_report(output, "atlas", models=model_pair)
            assert path.parent == tmp_path / "quick"
            assert path.exists()
            # The saved JSON must be loadable and carry the kind marker so
            # downstream tools can tell quick from analyze reports.
            data = load_report(path)
            assert data["kind"] == "quick"
            assert data["metadata"]["kind"] == "quick"
            assert data["metadata"]["worker_model"] == model_pair.worker.model_name
            assert data["metadata"]["architect_model"] is None

    def test_quick_metadata_records_call_counts(self, tmp_path, model_pair):
        """Call counts and the per-tool breakdown must reach the saved JSON.
        Diagnoses the discovery-skip case: `tool_calls: 0` or a `tools_used`
        without `load_reference` means the agent never loaded any cards."""
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)
            output = ThreatModelOutput(
                threat_model=[],
                improvement_suggestions=[],
                llm_calls=3,
                tool_calls=2,
                tools_used={"list_references": 1, "load_reference": 1},
            )
            path = save_quick_report(output, "atlas", models=model_pair)
            data = load_report(path)
            assert data["metadata"]["llm_calls"] == 3
            assert data["metadata"]["tool_calls"] == 2
            assert data["metadata"]["tools_used"] == {
                "list_references": 1, "load_reference": 1,
            }

    def test_list_reports_defaults_to_analyze(self, sample_report, tmp_path):
        """The default /reports behaviour is the analyze-only view — quick
        reports must not bleed in unless --quick or --all is passed."""
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)
            save_report(sample_report)
            save_quick_report(
                ThreatModelOutput(threat_model=[], improvement_suggestions=[]),
                "atlas",
            )
            analyze_only = list_reports(limit=10)
            assert len(analyze_only) == 1
            assert analyze_only[0][2]["kind"] == "analyze"

    def test_list_reports_quick_filter(self, sample_report, tmp_path):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)
            save_report(sample_report)
            save_quick_report(
                ThreatModelOutput(threat_model=[], improvement_suggestions=[]),
                "atlas",
            )
            quick_only = list_reports(limit=10, kind="quick")
            assert len(quick_only) == 1
            assert quick_only[0][2]["kind"] == "quick"

    def test_list_reports_all(self, sample_report, tmp_path):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)
            save_report(sample_report)
            save_quick_report(
                ThreatModelOutput(threat_model=[], improvement_suggestions=[]),
                "atlas",
            )
            both = list_reports(limit=10, kind="all")
            assert {r[2]["kind"] for r in both} == {"analyze", "quick"}

    def test_legacy_root_reports_still_surfaced(self, sample_report, tmp_path):
        """Reports saved before the split (sitting in reports/ root) must
        still appear in the listing — tagged 'legacy' — so users can find
        old work without manual migration."""
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("stride_gpt.config.REPORTS_DIR", tmp_path)
            tmp_path.mkdir(parents=True, exist_ok=True)
            (tmp_path / "old_report.json").write_text(json.dumps({
                "version": "1.0",
                "generated_at": "2026-01-01T00:00:00Z",
                "target": "/some/old/path",
                "subsystems": [{"threats": [{}]}],
                "cross_cutting_threats": [],
                "metadata": {},
            }))
            save_report(sample_report)
            all_reports = list_reports(limit=10)
            kinds = {r[2]["kind"] for r in all_reports}
            assert "legacy" in kinds
            assert "analyze" in kinds
