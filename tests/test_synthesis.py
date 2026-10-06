"""Synthesis splits aggregations (observations) from emergent threats (threats)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from stride_gpt.agent.html_report import render_html
from stride_gpt.agent.loop import assign_threat_ids, classify_synthesis, run_analysis
from stride_gpt.agent.report import (
    render_json,
    render_markdown,
    render_markdown_from_json,
    render_sarif,
)
from stride_gpt.core.schemas import AnalysisPlan, Subsystem, SubsystemFinding
from tests.fakes import ScriptedLLM, reply
from tests.test_loop import _DFD, _finish, _report, _tool_turn

_NAMES = ("Frontend", "MCP Server", "Orchestration")
_SNIPPET = "app = Flask(__name__)"
_EVIDENCE = [{"path": "app.py", "snippet": _SNIPPET}]


def _plan(target) -> AnalysisPlan:
    return AnalysisPlan(
        target_path=str(target),
        overall_description="app",
        subsystems=[
            Subsystem(name=n, description="d", key_files=[], focus_areas=[]) for n in _NAMES
        ],
    )


def _run(model_pair, target, synthesis_items):
    """Three subsystems that each report the same missing-auth weakness."""
    steps = [
        _tool_turn(
            _report(f"r{i}", scenario="No authentication on any endpoint", evidence=_EVIDENCE),
            _finish(f"f{i}"),
        )
        for i in range(3)
    ]
    steps += [reply(json.dumps({"cross_cutting_threats": synthesis_items})), _DFD]
    with ScriptedLLM(steps) as fake:
        report = run_analysis(model_pair, target, plan=_plan(target), progress=MagicMock())
    return report, fake


_AGGREGATION = {
    "Classification": "aggregation",
    "Threat Type": "Spoofing",
    "Scenario": "No authentication anywhere in the system",
    "Potential Impact": "Anyone can act as any user",
    "Affected Subsystems": list(_NAMES),
    "Related Threats": ["frontend-T1", "mcp-server-T1", "orchestration-T1"],
}


class TestAggregationRegression:
    """Every subsystem reports the same weakness: one aggregation, not a fourth threat."""

    def test_links_to_every_subsystem_threat_and_is_not_a_threat(self, model_pair, sandbox_dir):
        report, _ = _run(model_pair, sandbox_dir, [_AGGREGATION])

        assert report.cross_cutting_threats == []
        (observation,) = report.systemic_observations
        assert observation["Related Threats"] == [
            "frontend-T1", "mcp-server-T1", "orchestration-T1",
        ]
        ids = [t["id"] for f in report.findings for t in f.threats]
        assert ids == observation["Related Threats"]

    def test_not_counted_and_not_in_sarif(self, model_pair, sandbox_dir):
        report, _ = _run(model_pair, sandbox_dir, [_AGGREGATION])

        assert len(render_sarif(report)["runs"][0]["results"]) == 3
        assert "Total threats identified**: 3" in render_markdown(report)

    def test_architect_is_shown_ids_and_evidence(self, model_pair, sandbox_dir):
        _, fake = _run(model_pair, sandbox_dir, [_AGGREGATION])

        synthesis = next(r for r in fake.requests if r.messages[0]["content"].startswith("You are a security architect"))
        shown = json.loads(synthesis.messages[1]["content"].split("\n", 1)[1])
        threat = shown[0]["threats"][0]
        assert threat["id"] == "frontend-T1"
        assert threat["evidence"][0]["snippet"] == _SNIPPET

    def test_renders_in_its_own_section(self, model_pair, sandbox_dir):
        report, _ = _run(model_pair, sandbox_dir, [_AGGREGATION])

        for markdown in (render_markdown(report), render_markdown_from_json(render_json(report))):
            assert "## Systemic Observations" in markdown
            assert "## Cross-Cutting Threats" not in markdown
            assert "`mcp-server-T1` (MCP Server: Spoofing)" in markdown
            assert "**Systemic observations**: 1" in markdown
        html = render_html(report)
        assert 'id="systemic-observations"' in html
        assert 'id="cross-cutting"' not in html
        assert "3 threats" in html


class TestEmergentThreat:
    def _emergent(self, evidence):
        return {
            "Classification": "emergent",
            "Threat Type": "Information Disclosure",
            "Scenario": "Frontend sends the key to the server in cleartext",
            "Potential Impact": "Key theft",
            "Affected Subsystems": ["Frontend", "MCP Server"],
            "evidence": evidence,
        }

    def test_stays_a_threat_and_is_verified_against_the_code(self, model_pair, sandbox_dir):
        lie = {"path": "app.py", "snippet": "verified = True  # trust me", "verified": True}
        report, _ = _run(
            model_pair, sandbox_dir,
            [self._emergent([*_EVIDENCE, lie])],
        )

        assert report.systemic_observations == []
        (threat,) = report.cross_cutting_threats
        assert threat["Classification"] == "emergent"
        real, fabricated = threat["evidence"]
        assert real["verified"] is True and real["start_line"] == 2
        # The architect's own "verified" flag is not trusted.
        assert fabricated["verified"] is False
        assert "Total threats identified**: 4" in render_markdown(report)
        assert len(render_sarif(report)["runs"][0]["results"]) == 4

    def test_without_evidence_is_dropped(self, model_pair, sandbox_dir):
        report, _ = _run(model_pair, sandbox_dir, [self._emergent([])])

        assert report.cross_cutting_threats == []
        assert report.systemic_observations == []


class TestClassifySynthesis:
    def _findings(self):
        findings = [
            SubsystemFinding(subsystem="Auth", threats=[{"Threat Type": "Spoofing"}]),
            SubsystemFinding(subsystem="API", threats=[{"Threat Type": "Tampering"}]),
        ]
        assign_threat_ids(findings)
        return findings

    def test_aggregation_with_unknown_links_is_dropped(self, tmp_path):
        raw = [
            {"Classification": "aggregation", "Threat Type": "Spoofing", "Scenario": "s",
             "Related Threats": ["nope-T9"]},
            {"Classification": "aggregation", "Threat Type": "Spoofing", "Scenario": "s"},
        ]
        assert classify_synthesis(raw, self._findings(), tmp_path) == ([], [])

    def test_aggregation_keeps_only_real_links_and_no_evidence(self, tmp_path):
        raw = [{
            "Classification": "Aggregation", "Threat Type": "Spoofing", "Scenario": "s",
            "Related Threats": ["auth-T1", "nope-T9", "auth-T1"],
            "evidence": [{"path": "app.py", "snippet": "x"}],
        }]
        emergent, aggregations = classify_synthesis(raw, self._findings(), tmp_path)
        assert emergent == []
        assert aggregations[0]["Related Threats"] == ["auth-T1"]
        assert aggregations[0]["Classification"] == "aggregation"
        assert "evidence" not in aggregations[0]

    def test_object_shaped_links_are_dropped_not_fatal(self, tmp_path):
        """An unhashable link used to raise out of the `in known_ids` test."""
        raw = [{
            "Classification": "aggregation", "Threat Type": "Spoofing", "Scenario": "s",
            "Related Threats": [{"id": "auth-T1"}, "auth-T1", 7],
        }]
        emergent, aggregations = classify_synthesis(raw, self._findings(), tmp_path)
        assert emergent == []
        assert aggregations[0]["Related Threats"] == ["auth-T1"]

    def test_object_shaped_links_alone_drop_the_aggregation(self, tmp_path):
        raw = [{
            "Classification": "aggregation", "Threat Type": "Spoofing", "Scenario": "s",
            "Related Threats": [{"id": "auth-T1"}],
        }]
        assert classify_synthesis(raw, self._findings(), tmp_path) == ([], [])

    def test_emergent_keeps_a_link_given_as_a_bare_string(self, tmp_path):
        raw = [{
            "Classification": "emergent", "Threat Type": "Tampering", "Scenario": "s",
            "Related Threats": "auth-T1",
            "evidence": [{"path": "app.py", "snippet": "x"}],
        }]
        emergent, aggregations = classify_synthesis(raw, self._findings(), tmp_path)
        assert aggregations == []
        assert emergent[0]["Related Threats"] == ["auth-T1"]

    def test_emergent_drops_links_that_name_nothing(self, tmp_path):
        raw = [{
            "Classification": "emergent", "Threat Type": "Tampering", "Scenario": "s",
            "Related Threats": ["nope-T9", {"id": "auth-T1"}],
            "evidence": [{"path": "app.py", "snippet": "x"}],
        }]
        emergent, _ = classify_synthesis(raw, self._findings(), tmp_path)
        assert "Related Threats" not in emergent[0]

    def test_output_that_is_not_a_list_is_dropped_not_fatal(self, tmp_path):
        """Phase 3 must not throw away the subsystem findings it just collected."""
        for raw in (5, "cross-cutting threats: none", {"Classification": "aggregation"}, None):
            assert classify_synthesis(raw, self._findings(), tmp_path) == ([], [])

    def test_unhashable_threat_id_on_a_finding_is_ignored(self, tmp_path):
        findings = [SubsystemFinding(subsystem="Auth", threats=[{"id": ["auth-T1"]}])]
        assert classify_synthesis(
            [{"Classification": "aggregation", "Threat Type": "Spoofing",
              "Scenario": "s", "Related Threats": ["auth-T1"]}],
            findings, tmp_path,
        ) == ([], [])

    def test_unclassified_and_malformed_items_are_dropped(self, tmp_path):
        raw = [
            {"Threat Type": "Spoofing", "Scenario": "no classification"},
            {"Classification": "maybe", "Threat Type": "Spoofing", "Scenario": "s"},
            "not a dict",
        ]
        assert classify_synthesis(raw, self._findings(), tmp_path) == ([], [])


class TestAssignThreatIds:
    def test_ids_are_unique_stable_and_preserved(self):
        findings = [
            SubsystemFinding(subsystem="API Server", threats=[{"a": 1}, {"a": 2, "id": "keep"}]),
            SubsystemFinding(subsystem="api server", threats=[{"a": 3}]),
        ]
        assign_threat_ids(findings)
        assert [t["id"] for t in findings[0].threats] == ["api-server-T1", "keep"]
        assert findings[1].threats[0]["id"] == "api-server-2-T1"

        assign_threat_ids(findings)  # idempotent
        assert [t["id"] for t in findings[0].threats] == ["api-server-T1", "keep"]
