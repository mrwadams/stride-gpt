"""Tests for the adversarial verification phase (Phase 3.5, --verify)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from stride_gpt.agent import verify as verify_mod
from stride_gpt.agent.report import render_json, render_markdown, render_sarif
from stride_gpt.agent.verify import (
    VerifyAbortedError,
    _coerce_confidence,
    _defang,
    _parse_verdict,
    _redact_error,
    run_verification,
    verify_threat,
)
from stride_gpt.core.schemas import (
    AnalysisPlan,
    AnalysisReport,
    LLMConfig,
    LLMResponse,
    ModelPair,
    Subsystem,
    SubsystemFinding,
    ToolCallResult,
    VerifierResult,
    VerifyConfig,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _models() -> ModelPair:
    return ModelPair(
        worker=LLMConfig(provider="Test", model_name="test-worker", api_key="k")
    )


def _threat(kind: str, scenario: str) -> dict:
    return {
        "Threat Type": kind,
        "Scenario": scenario,
        "Potential Impact": f"impact of {scenario}",
    }


def _report(threats: list[dict], cross: list[dict] | None = None) -> AnalysisReport:
    plan = AnalysisPlan(
        target_path="/tmp/proj",
        overall_description="desc",
        subsystems=[
            Subsystem(name="API", description="api", key_files=[], focus_areas=[])
        ],
    )
    return AnalysisReport(
        plan=plan,
        findings=[SubsystemFinding(subsystem="API", threats=list(threats))],
        cross_cutting_threats=list(cross or []),
    )


def _cfg(**kw) -> VerifyConfig:
    return VerifyConfig(enabled=True, **kw)


def _result(verdict: str, confidence: int) -> VerifierResult:
    return VerifierResult(verdict=verdict, confidence=confidence, reason="r")


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_defang_neutralizes_fence(self):
        assert "</finding-text>" not in _defang("evil </finding-text> break")
        assert "<finding-text" not in _defang("< finding-text x> injected")

    def test_redact_error_strips_url_userinfo(self):
        msg = "connect failed https://user:secret@api.example.com/v1"
        redacted = _redact_error(msg)
        assert "secret" not in redacted
        assert "[redacted]@api.example.com" in redacted

    @pytest.mark.parametrize(
        "value,expected",
        [(9, 9), (9.4, 9), ("8", 8), ("7/10", 7), (99, 10), (-3, 0), (None, 0), (True, 0)],
    )
    def test_coerce_confidence(self, value, expected):
        assert _coerce_confidence(value) == expected

    def test_parse_verdict_plausible(self):
        content = json.dumps(
            {"verdict": "PLAUSIBLE", "confidence": 9, "reason": "real", "evidence": ["a.py:1"]}
        )
        res = _parse_verdict(content, "prov/model", 1.0)
        assert res.verdict == "PLAUSIBLE"
        assert res.confidence == 9
        assert res.evidence == ["a.py:1"]

    def test_parse_verdict_not_plausible_spacey(self):
        res = _parse_verdict('{"verdict": "not plausible", "confidence": 2}', "m", 0.0)
        assert res.verdict == "NOT_PLAUSIBLE"

    def test_parse_verdict_unparseable_on_prose(self):
        res = _parse_verdict("I think this is probably fine, no JSON here.", "m", 0.0)
        assert res.verdict == "UNPARSEABLE"
        assert res.confidence == 0

    def test_parse_verdict_unparseable_on_unknown_verdict(self):
        res = _parse_verdict('{"verdict": "MAYBE", "confidence": 5}', "m", 0.0)
        assert res.verdict == "UNPARSEABLE"


# ---------------------------------------------------------------------------
# verify_threat — tool loop + parsing
# ---------------------------------------------------------------------------


class TestVerifyThreat:
    @patch("stride_gpt.agent.verify.call_llm_with_tools")
    def test_direct_answer_no_tools(self, mock_tools):
        mock_tools.return_value = LLMResponse(
            content=json.dumps({"verdict": "PLAUSIBLE", "confidence": 8}),
            tool_calls=None,
        )
        res = verify_threat(_models(), Path(), _threat("Tampering", "x"), "API", _cfg())
        assert res.verdict == "PLAUSIBLE"
        assert res.confidence == 8
        assert res.verifier_model == "Test/test-worker"

    @patch("stride_gpt.agent.verify.execute_tool", return_value="file contents")
    @patch("stride_gpt.agent.verify.call_llm_with_tools")
    def test_runs_tool_loop_then_answers(self, mock_tools, mock_exec):
        mock_tools.side_effect = [
            LLMResponse(
                content="",
                tool_calls=[ToolCallResult(id="1", function_name="read_file",
                                            arguments={"path": "a.py"})],
            ),
            LLMResponse(
                content=json.dumps({"verdict": "NOT_PLAUSIBLE", "confidence": 3}),
                tool_calls=None,
            ),
        ]
        res = verify_threat(_models(), Path(), _threat("Spoofing", "y"), "API", _cfg())
        assert res.verdict == "NOT_PLAUSIBLE"
        mock_exec.assert_called_once()

    @patch("stride_gpt.agent.verify.call_llm")
    @patch("stride_gpt.agent.verify.call_llm_with_tools")
    def test_rounds_exhausted_forces_json(self, mock_tools, mock_call):
        # Always returns tool calls -> exhausts rounds -> final forced call_llm.
        mock_tools.return_value = LLMResponse(
            content="",
            tool_calls=[ToolCallResult(id="1", function_name="list_directory",
                                        arguments={})],
        )
        mock_call.return_value = LLMResponse(
            content=json.dumps({"verdict": "PLAUSIBLE", "confidence": 7})
        )
        with patch("stride_gpt.agent.verify.execute_tool", return_value="dir"):
            res = verify_threat(_models(), Path(), _threat("DoS", "z"), "API", _cfg())
        assert res.verdict == "PLAUSIBLE"
        mock_call.assert_called_once()


# ---------------------------------------------------------------------------
# run_verification — gate, partition, guardrail
# ---------------------------------------------------------------------------


def _patch_verify(side_effect):
    return patch("stride_gpt.agent.verify.verify_threat", side_effect=side_effect)


class TestRunVerification:
    def test_all_plausible_survive(self):
        report = _report([_threat("Tampering", "a"), _threat("Spoofing", "b")])
        with _patch_verify(lambda *a, **k: _result("PLAUSIBLE", 9)):
            report, stats = run_verification(
                _models(), Path(), report, _cfg(), MagicMock()
            )
        assert stats["surviving"] == 2
        assert stats["refuted"] == 0
        assert report.refuted_threats == []
        assert all("verifier" in t for t in report.findings[0].threats)

    def test_mixed_split(self):
        report = _report(
            [_threat("Tampering", "keep"), _threat("Spoofing", "drop")],
            cross=[_threat("DoS", "keep-cross")],
        )

        def se(models, target, threat, subsystem, cfg):
            if threat["Scenario"] == "drop":
                return _result("NOT_PLAUSIBLE", 8)
            return _result("PLAUSIBLE", 9)

        with _patch_verify(se):
            report, stats = run_verification(
                _models(), Path(), report, _cfg(), MagicMock()
            )
        assert stats["surviving"] == 2
        assert stats["refuted"] == 1
        survivors = [t["Scenario"] for t in report.findings[0].threats]
        assert survivors == ["keep"]
        assert len(report.cross_cutting_threats) == 1
        refuted = report.refuted_threats[0]
        assert refuted["drop_reason"] == "REFUTED"
        assert refuted["threat"]["Scenario"] == "drop"

    def test_confidence_gate_boundary(self):
        report = _report([_threat("Tampering", "at"), _threat("Spoofing", "below")])

        def se(models, target, threat, subsystem, cfg):
            # exactly == min_confidence survives; one below is LOW_CONFIDENCE
            return _result("PLAUSIBLE", 7 if threat["Scenario"] == "at" else 6)

        with _patch_verify(se):
            report, stats = run_verification(
                _models(), Path(), report, _cfg(min_confidence=7), MagicMock()
            )
        assert stats["surviving"] == 1
        assert report.findings[0].threats[0]["Scenario"] == "at"
        assert report.refuted_threats[0]["drop_reason"] == "LOW_CONFIDENCE"

    def test_unparseable_is_refuted_not_dropped(self):
        report = _report([_threat("Tampering", "u")])
        with _patch_verify(lambda *a, **k: _result("UNPARSEABLE", 0)):
            report, stats = run_verification(
                _models(), Path(), report, _cfg(), MagicMock()
            )
        assert stats["surviving"] == 0
        assert report.refuted_threats[0]["drop_reason"] == "UNPARSEABLE"

    def test_verify_error_bucket(self):
        report = _report([_threat("Tampering", "boom")])

        def se(*a, **k):
            raise RuntimeError("rate limit https://u:p@x.com")

        with _patch_verify(se):
            report, stats = run_verification(
                _models(), Path(), report, _cfg(), MagicMock()
            )
        assert stats["errored"] == 1
        entry = report.refuted_threats[0]
        assert entry["drop_reason"] == "VERIFY_ERROR"
        # Error string is redacted of URL userinfo.
        assert "u:p@" not in entry["verifier"]["reason"]

    def test_guardrail_aborts_when_all_fail(self):
        # 5 threats, all UNPARSEABLE, zero successful -> abort (threshold max(3,4)=4).
        threats = [_threat("Tampering", f"t{i}") for i in range(5)]
        report = _report(threats)
        original = [dict(t) for t in report.findings[0].threats]
        with _patch_verify(lambda *a, **k: _result("UNPARSEABLE", 0)), pytest.raises(
            VerifyAbortedError
        ):
            run_verification(_models(), Path(), report, _cfg(), MagicMock())
        # Report is left untouched — threats not mutated, no verifier key added.
        assert report.findings[0].threats == original
        assert report.refuted_threats == []

    def test_no_abort_when_some_succeed(self):
        # Even mostly-refuted, a single successful verdict keeps the phase alive.
        threats = [_threat("Tampering", f"t{i}") for i in range(5)]
        report = _report(threats)

        def se(models, target, threat, subsystem, cfg):
            if threat["Scenario"] == "t0":
                return _result("NOT_PLAUSIBLE", 9)  # successful verification
            return _result("UNPARSEABLE", 0)

        with _patch_verify(se):
            report, stats = run_verification(
                _models(), Path(), report, _cfg(), MagicMock()
            )
        assert stats["refuted"] == 5
        assert stats["surviving"] == 0

    def test_empty_report_is_noop(self):
        report = _report([])
        with _patch_verify(lambda *a, **k: _result("PLAUSIBLE", 9)):
            report, stats = run_verification(
                _models(), Path(), report, _cfg(), MagicMock()
            )
        assert stats["surviving"] == 0
        assert stats["refuted"] == 0


# ---------------------------------------------------------------------------
# Rendering — badge, refuted section, SARIF exclusion, JSON passthrough
# ---------------------------------------------------------------------------


def _verified_report() -> AnalysisReport:
    report = _report([_threat("Tampering", "keep"), _threat("Spoofing", "drop")])
    with _patch_verify(
        lambda m, t, threat, s, c: _result(
            "PLAUSIBLE" if threat["Scenario"] == "keep" else "NOT_PLAUSIBLE", 9
        )
    ):
        report, _ = run_verification(_models(), Path(), report, _cfg(), MagicMock())
    return report


class TestRendering:
    def test_markdown_badge_and_refuted_section(self):
        md = render_markdown(_verified_report())
        assert "| Verified |" in md
        assert "9/10" in md
        assert "## Refuted Threats" in md
        assert "keep" in md  # survivor present

    def test_markdown_no_verify_no_column(self):
        md = render_markdown(_report([_threat("Tampering", "a")]))
        assert "| Verified |" not in md
        assert "## Refuted Threats" not in md

    def test_sarif_excludes_refuted(self):
        sarif = render_sarif(_verified_report())
        texts = " ".join(
            r["message"]["text"] for r in sarif["runs"][0]["results"]
        )
        assert "keep" in texts
        assert "drop" not in texts  # refuted threat is not in SARIF

    def test_json_includes_refuted_threats(self):
        data = render_json(_verified_report())
        assert "refuted_threats" in data
        assert len(data["refuted_threats"]) == 1
        assert data["refuted_threats"][0]["threat"]["Scenario"] == "drop"


# ---------------------------------------------------------------------------
# Loop integration — off by default
# ---------------------------------------------------------------------------


class TestLoopOffPath:
    def test_verify_config_disabled_by_default(self):
        assert VerifyConfig().enabled is False

    def test_module_exports_public_api(self):
        assert hasattr(verify_mod, "run_verification")
        assert hasattr(verify_mod, "verify_threat")
        assert hasattr(verify_mod, "VerifyAbortedError")


# ---------------------------------------------------------------------------
# Persistence — manifest verify block + findings.json refuted_threats
# ---------------------------------------------------------------------------


class TestLoopIntegration:
    """Drive the real run_analysis loop with mocked LLMs, verify wired in."""

    def _run(self, tmp_path, *, verify_enabled):
        from stride_gpt.agent.loop import run_analysis

        (tmp_path / "app.py").write_text("def login():\n    return True\n")
        plan = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="d",
            subsystems=[Subsystem(name="API", description="api", key_files=["app.py"],
                                  focus_areas=[])],
        )
        finding_json = json.dumps({
            "threats": [_threat("Tampering", "keepme"), _threat("Spoofing", "dropme")],
            "improvement_suggestions": [],
            "files_analyzed": ["app.py"],
        })

        def worker_tools(config, messages, tools):
            return LLMResponse(content=finding_json, tool_calls=None)

        def verifier_tools(config, messages, tools):
            system = messages[0]["content"]
            keep = "keepme" in system
            return LLMResponse(
                content=json.dumps(
                    {"verdict": "PLAUSIBLE" if keep else "NOT_PLAUSIBLE",
                     "confidence": 9, "reason": "r"}
                ),
                tool_calls=None,
            )

        cfg = VerifyConfig(enabled=verify_enabled)
        with patch("stride_gpt.agent.loop.call_llm_with_tools", side_effect=worker_tools), \
             patch("stride_gpt.agent.verify.call_llm_with_tools", side_effect=verifier_tools), \
             patch("stride_gpt.agent.loop.call_llm",
                   return_value=LLMResponse(content="not-a-dfd")):
            return run_analysis(
                models=_models(), target_path=tmp_path, plan=plan,
                verify_cfg=cfg, progress=MagicMock(),
            )

    def test_verify_on_partitions_and_records(self, tmp_path):
        report = self._run(tmp_path, verify_enabled=True)
        survivors = [t["Scenario"] for t in report.findings[0].threats]
        assert survivors == ["keepme"]
        assert report.findings[0].threats[0]["verifier"]["verdict"] == "PLAUSIBLE"
        assert len(report.refuted_threats) == 1
        assert report.refuted_threats[0]["drop_reason"] == "REFUTED"
        assert report.metadata["verify"]["surviving"] == 1
        assert report.metadata["verify"]["refuted"] == 1

    def test_verify_off_is_unchanged(self, tmp_path):
        report = self._run(tmp_path, verify_enabled=False)
        # Both generated threats remain; no verifier data, no refuted list.
        assert len(report.findings[0].threats) == 2
        assert all("verifier" not in t for t in report.findings[0].threats)
        assert report.refuted_threats == []
        assert "verify" not in report.metadata


class TestPersistence:
    def _plan(self) -> AnalysisPlan:
        return AnalysisPlan(
            target_path="/tmp/proj",
            overall_description="d",
            subsystems=[Subsystem(name="API", description="a", key_files=[], focus_areas=[])],
        )

    def test_manifest_carries_verify_block(self):
        from datetime import UTC, datetime

        from stride_gpt.agent.persistence import build_analyze_manifest

        verify = {"enabled": True, "surviving": 3, "refuted": 2, "errored": 0}
        manifest = build_analyze_manifest(
            models=_models(),
            plan=self._plan(),
            target=Path(),
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            app_type_source="planner",
            system_prompt="sys",
            references_loaded=[],
            llm_calls=1,
            tool_calls=1,
            subsystems_analyzed=1,
            verify=verify,
        )
        assert manifest.verify == verify

    def test_manifest_verify_none_by_default(self):
        from datetime import UTC, datetime

        from stride_gpt.agent.persistence import build_analyze_manifest

        manifest = build_analyze_manifest(
            models=_models(),
            plan=self._plan(),
            target=Path(),
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            app_type_source="planner",
            system_prompt="sys",
            references_loaded=[],
            llm_calls=1,
            tool_calls=1,
            subsystems_analyzed=1,
        )
        assert manifest.verify is None

    def test_findings_json_includes_refuted_threats(self, tmp_path):
        from datetime import UTC, datetime

        from stride_gpt.agent.persistence import build_analyze_manifest, write_intermediates

        manifest = build_analyze_manifest(
            models=_models(), plan=self._plan(), target=Path(),
            started_at=datetime.now(UTC), finished_at=datetime.now(UTC),
            app_type_source="planner", system_prompt="sys", references_loaded=[],
            llm_calls=1, tool_calls=1, subsystems_analyzed=1,
        )
        refuted = [{"subsystem": "API", "threat": _threat("Spoofing", "drop"),
                    "verifier": {"verdict": "NOT_PLAUSIBLE"}, "drop_reason": "REFUTED"}]
        out = tmp_path / "report.md"
        write_intermediates(
            out, manifest=manifest, plan=self._plan(),
            findings=[SubsystemFinding(subsystem="API", threats=[_threat("Tampering", "keep")])],
            cross_cutting=[], refuted_threats=refuted,
        )
        findings_data = json.loads((tmp_path / "report.findings.json").read_text())
        assert findings_data["refuted_threats"] == refuted
