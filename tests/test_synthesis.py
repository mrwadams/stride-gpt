"""Synthesis splits aggregations (observations) from emergent threats (threats)."""

from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock

import litellm

from stride_gpt.agent.html_report import render_html
from stride_gpt.agent.loop import (
    assign_threat_ids,
    classify_synthesis,
    make_threat_id,
    run_analysis,
)
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
_SCENARIO = "No authentication on any endpoint"
_IDS = [make_threat_id(n, "Spoofing", _SCENARIO) for n in _NAMES]
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
            _report(f"r{i}", scenario=_SCENARIO, evidence=_EVIDENCE),
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
    "Related Threats": _IDS,
}

_AUTH = make_threat_id("Auth", "Spoofing", "")


class TestAggregationRegression:
    """Every subsystem reports the same weakness: one aggregation, not a fourth threat."""

    def test_links_to_every_subsystem_threat_and_is_not_a_threat(self, model_pair, sandbox_dir):
        report, _ = _run(model_pair, sandbox_dir, [_AGGREGATION])

        assert report.cross_cutting_threats == []
        (observation,) = report.systemic_observations
        assert observation["Related Threats"] == _IDS
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
        assert threat["id"] == _IDS[0]
        assert threat["evidence"][0]["snippet"] == _SNIPPET

    def test_renders_in_its_own_section(self, model_pair, sandbox_dir):
        report, _ = _run(model_pair, sandbox_dir, [_AGGREGATION])

        for markdown in (render_markdown(report), render_markdown_from_json(render_json(report))):
            assert "## Systemic Observations" in markdown
            assert "## Cross-Cutting Threats" not in markdown
            assert f"`{_IDS[1]}` (MCP Server: Spoofing)" in markdown
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

    def test_with_no_verified_evidence_is_dropped(self, model_pair, sandbox_dir, caplog):
        invented = {"path": "does/not/exist.py", "snippet": _SNIPPET}
        altered = {"path": "app.py", "snippet": "app = Flask(name)"}
        with caplog.at_level(logging.WARNING):
            report, _ = _run(model_pair, sandbox_dir, [self._emergent([invented, altered])])

        assert report.cross_cutting_threats == []
        assert "Total threats identified**: 3" in render_markdown(report)
        assert len(render_sarif(report)["runs"][0]["results"]) == 3
        assert "none of its evidence verifies" in caplog.text
        assert "stripped" not in caplog.text

    def test_dropped_when_evidence_was_stripped_to_fit_context(
        self, model_pair, sandbox_dir, monkeypatch, caplog
    ):
        """With no snippets to quote, the architect's citation cannot verify."""

        def token_counter(*, model, messages):
            # Only the summary without evidence fits the architect's window.
            return 1 if '"evidence"' not in messages[0]["content"] else 10**9

        monkeypatch.setattr(litellm, "token_counter", token_counter)
        paraphrase = {"path": "app.py", "snippet": "app = Flask(app_name)"}
        with caplog.at_level(logging.WARNING):
            report, fake = _run(model_pair, sandbox_dir, [self._emergent([paraphrase])])

        synthesis = next(r for r in fake.requests if r.messages[0]["content"].startswith("You are a security architect"))
        assert _SNIPPET not in synthesis.messages[1]["content"]
        assert report.cross_cutting_threats == []
        assert "evidence stripped to fit context" in caplog.text


class TestClassifySynthesis:
    def _findings(self):
        findings = [
            SubsystemFinding(subsystem="Auth", threats=[{"Threat Type": "Spoofing"}]),
            SubsystemFinding(subsystem="API", threats=[{"Threat Type": "Tampering"}]),
        ]
        assign_threat_ids(findings, [])
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
            "Related Threats": [_AUTH, "nope-T9", _AUTH],
            "evidence": [{"path": "app.py", "snippet": "x"}],
        }]
        emergent, aggregations = classify_synthesis(raw, self._findings(), tmp_path)
        assert emergent == []
        assert aggregations[0]["Related Threats"] == [_AUTH]
        assert aggregations[0]["Classification"] == "aggregation"
        assert "evidence" not in aggregations[0]

    def test_object_shaped_links_are_dropped_not_fatal(self, tmp_path):
        """An unhashable link used to raise out of the `in known_ids` test."""
        raw = [{
            "Classification": "aggregation", "Threat Type": "Spoofing", "Scenario": "s",
            "Related Threats": [{"id": _AUTH}, _AUTH, 7],
        }]
        emergent, aggregations = classify_synthesis(raw, self._findings(), tmp_path)
        assert emergent == []
        assert aggregations[0]["Related Threats"] == [_AUTH]

    def test_object_shaped_links_alone_drop_the_aggregation(self, tmp_path):
        raw = [{
            "Classification": "aggregation", "Threat Type": "Spoofing", "Scenario": "s",
            "Related Threats": [{"id": _AUTH}],
        }]
        assert classify_synthesis(raw, self._findings(), tmp_path) == ([], [])

    def test_emergent_keeps_a_link_given_as_a_bare_string(self, tmp_path):
        raw = [{
            "Classification": "emergent", "Threat Type": "Tampering", "Scenario": "s",
            "Related Threats": _AUTH,
            "evidence": [{"path": "app.py", "snippet": "x"}],
        }]
        (tmp_path / "app.py").write_text("x\n")
        emergent, aggregations = classify_synthesis(raw, self._findings(), tmp_path)
        assert aggregations == []
        assert emergent[0]["Related Threats"] == [_AUTH]

    def test_emergent_drops_links_that_name_nothing(self, tmp_path):
        raw = [{
            "Classification": "emergent", "Threat Type": "Tampering", "Scenario": "s",
            "Related Threats": ["nope-T9", {"id": _AUTH}],
            "evidence": [{"path": "app.py", "snippet": "x"}],
        }]
        (tmp_path / "app.py").write_text("x\n")
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
              "Scenario": "s", "Related Threats": [_AUTH]}],
            findings, tmp_path,
        ) == ([], [])

    def test_emergent_with_no_verified_evidence_is_dropped(self, tmp_path):
        (tmp_path / "app.py").write_text("x\n")
        raw = [{
            "Classification": "emergent", "Threat Type": "Tampering", "Scenario": "s",
            "evidence": [
                {"path": "does/not/exist.py", "snippet": "x"},
                {"path": "app.py", "snippet": "y"},
                {"path": "app.py"},
            ],
        }]
        dropped: list[dict[str, str]] = []
        assert classify_synthesis(raw, self._findings(), tmp_path, dropped=dropped) == ([], [])
        assert dropped == [
            {"item": "emergent threat 'Tampering'", "reason": "none of its evidence verifies"}
        ]

    def test_emergent_with_some_verified_evidence_is_kept(self, tmp_path):
        (tmp_path / "app.py").write_text("x\n")
        raw = [{
            "Classification": "emergent", "Threat Type": "Tampering", "Scenario": "s",
            "evidence": [
                {"path": "does/not/exist.py", "snippet": "x"},
                {"path": "app.py", "snippet": "x"},
            ],
        }]
        (threat,), _ = classify_synthesis(raw, self._findings(), tmp_path)
        assert [e["verified"] for e in threat["evidence"]] == [False, True]

    def test_unclassified_and_malformed_items_are_dropped(self, tmp_path):
        raw = [
            {"Threat Type": "Spoofing", "Scenario": "no classification"},
            {"Classification": "maybe", "Threat Type": "Spoofing", "Scenario": "s"},
            "not a dict",
        ]
        assert classify_synthesis(raw, self._findings(), tmp_path) == ([], [])

    def test_dropped_items_are_recorded_with_reasons(self, tmp_path):
        raw = [
            {"Threat Type": "Spoofing", "Scenario": "no classification"},
            {"Classification": "aggregation", "Threat Type": "Tampering", "Scenario": "s"},
            {"Classification": "emergent", "Threat Type": "Repudiation", "Scenario": "s"},
            "not a dict",
        ]
        dropped: list[dict[str, str]] = []
        assert classify_synthesis(raw, self._findings(), tmp_path, dropped=dropped) == ([], [])
        assert [d["item"] for d in dropped] == [
            "synthesis item 'Spoofing'",
            "aggregation 'Tampering'",
            "emergent threat 'Repudiation'",
            "synthesis item",
        ]
        assert "neither" in dropped[0]["reason"]
        assert dropped[1]["reason"] == "it links to no known threat id"
        assert dropped[2]["reason"] == "it cites no evidence"
        assert "str" in dropped[3]["reason"]

    def test_output_that_is_not_a_list_is_recorded_as_dropped(self, tmp_path):
        dropped: list[dict[str, str]] = []
        classify_synthesis("none", self._findings(), tmp_path, dropped=dropped)
        assert dropped == [{"item": "synthesis output", "reason": "expected a list of items, got str"}]


_PRE_209 = {"Threat Type": "Spoofing", "Scenario": "old shape, no Classification"}


class TestDroppedSynthesisReporting:
    """Every item dropped must not read the same as synthesis finding nothing (#252)."""

    def test_all_dropped_is_recorded_in_metadata_and_summaries(self, model_pair, sandbox_dir):
        report, _ = _run(model_pair, sandbox_dir, [_PRE_209, _PRE_209])

        assert report.cross_cutting_threats == []
        dropped = report.metadata["synthesis_dropped"]
        assert len(dropped) == 2
        assert all("neither" in d["reason"] for d in dropped)
        for markdown in (render_markdown(report), render_markdown_from_json(render_json(report))):
            assert "**Synthesis items dropped**: 2" in markdown
        assert "2 synthesis items dropped" in render_html(report)

    def test_empty_synthesis_says_nothing_about_drops(self, model_pair, sandbox_dir):
        report, _ = _run(model_pair, sandbox_dir, [])

        assert report.metadata["synthesis_dropped"] == []
        for markdown in (render_markdown(report), render_markdown_from_json(render_json(report))):
            assert "Synthesis items dropped" not in markdown
        assert "synthesis items dropped" not in render_html(report)
