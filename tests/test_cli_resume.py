"""CLI-level tests for `stride-gpt analyze --resume` (issue #197)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from stride_gpt import cli
from stride_gpt.agent.persistence import build_checkpoint, write_checkpoint
from stride_gpt.core.schemas import AnalysisPlan, LLMConfig, ModelPair, Subsystem, SubsystemFinding
from tests.fakes import SUBSYSTEM_TOOL_NAMES, ScriptedLLM, reply

runner = CliRunner()

_DFD = reply("```mermaid\nflowchart LR\n  A --> B\n```")


@pytest.fixture(autouse=True)
def no_saved_config(monkeypatch):
    """Ignore the developer's own ~/.stride-gpt/config.json.

    Every test here passes its models on the command line. A saved config
    would add an architect tier the checkpoint was never built with, so the
    run refuses on ``config_hash changed`` before reaching the branch under
    test — passing in CI and failing on any machine with a saved config.
    """
    monkeypatch.setattr(cli, "load_config", lambda: None)


def _plan(target: Path) -> AnalysisPlan:
    return AnalysisPlan(
        target_path=str(target),
        overall_description="d",
        subsystems=[Subsystem(name="Auth", description="d", key_files=[], focus_areas=[])],
    )


def _write_checkpoint_for(
    target: Path, path: Path, *, model_name: str = "claude-x", findings=None
) -> None:
    models = ModelPair(
        worker=LLMConfig(provider="Anthropic API", model_name=model_name, api_key="sk-x")
    )
    checkpoint = build_checkpoint(
        plan=_plan(target),
        findings=findings or [],
        target=target,
        models=models,
        app_type_source="planner",
        started_at=datetime.now(UTC),
    )
    write_checkpoint(path, checkpoint)


class TestResumeFlag:
    def test_missing_checkpoint_exits_1(self, tmp_path):
        result = runner.invoke(cli.app, [
            "analyze", str(tmp_path),
            "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
            "--resume", str(tmp_path / "missing.checkpoint.json"),
        ])
        assert result.exit_code == 1
        assert "Checkpoint not found" in result.stdout

    def test_config_hash_mismatch_refuses_with_clear_reason(self, tmp_path):
        checkpoint_path = tmp_path / "report.checkpoint.json"
        _write_checkpoint_for(tmp_path, checkpoint_path, model_name="claude-old")

        result = runner.invoke(cli.app, [
            "analyze", str(tmp_path),
            "--worker-model", "anthropic/claude-new", "--worker-api-key", "sk-test",
            "--resume", str(checkpoint_path),
        ])
        assert result.exit_code == 1
        assert "Cannot resume" in result.stdout
        assert "config_hash changed" in result.stdout

    def test_missing_git_sha_refuses_without_force(self, tmp_path):
        # tmp_path is never a git checkout, so target_git_sha is None both
        # times — the refusal comes from the "no discoverable SHA" branch,
        # not a SHA mismatch.
        checkpoint_path = tmp_path / "report.checkpoint.json"
        _write_checkpoint_for(tmp_path, checkpoint_path, model_name="claude-x")

        result = runner.invoke(cli.app, [
            "analyze", str(tmp_path),
            "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
            "--resume", str(checkpoint_path),
        ])
        assert result.exit_code == 1
        assert "no discoverable git SHA" in result.stdout

    def test_successful_resume_reuses_finding_and_records_it_in_the_manifest(self, tmp_path):
        checkpoint_path = tmp_path / "report.checkpoint.json"
        reused_finding = SubsystemFinding(
            subsystem="Auth",
            threats=[{"Threat Type": "Spoofing", "Scenario": "s", "Potential Impact": "i"}],
            outcome="completed",
        )
        _write_checkpoint_for(tmp_path, checkpoint_path, findings=[reused_finding])

        output_path = tmp_path / "report.md"
        with ScriptedLLM([_DFD]):
            result = runner.invoke(cli.app, [
                "analyze", str(tmp_path),
                "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
                "--resume", str(checkpoint_path), "--force",
                "-o", str(output_path),
            ])

        assert result.exit_code == 0, result.stdout
        assert "Resuming from" in result.stdout
        assert output_path.exists()

        manifest = json.loads((tmp_path / "report.run.json").read_text())
        assert manifest["run_summary"]["resumed_subsystems"] == ["Auth"]
        assert manifest["run_summary"]["rerun_subsystems"] == []

        findings = json.loads((tmp_path / "report.findings.json").read_text())
        assert [f["subsystem"] for f in findings["findings"]] == ["Auth"]
        assert findings["findings"][0]["threats"][0]["Threat Type"] == "Spoofing"


class TestResumedRunLooksLikeAnUninterruptedOne:
    """The checkpoint stores redacted paths; the report renders live ones. A
    resumed run used to hand the redacted copies straight to the report, so
    reused subsystems printed ``./src/a.py`` beside ``src/a.py`` for re-run
    ones and ``analyze .`` lost its project name from the title."""

    def test_reused_finding_paths_match_a_fresh_run_s(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "auth.py").write_text("PASSWORD = 'x'\n")
        checkpoint_path = tmp_path / "report.checkpoint.json"
        reused_finding = SubsystemFinding(
            subsystem="Auth",
            threats=[{
                "Threat Type": "Spoofing", "Scenario": "s", "Potential Impact": "i",
                "evidence": [{"path": "src/auth.py", "snippet": "PASSWORD = 'x'", "verified": True}],
            }],
            files_analyzed=["src/auth.py"],
            outcome="completed",
        )
        _write_checkpoint_for(tmp_path, checkpoint_path, findings=[reused_finding])
        # The stored checkpoint really is redacted — otherwise this test would
        # pass for the wrong reason.
        stored = json.loads(checkpoint_path.read_text())
        assert stored["findings"][0]["files_analyzed"] == ["./src/auth.py"]

        output_path = tmp_path / "report.md"
        with ScriptedLLM([_DFD]):
            result = runner.invoke(cli.app, [
                "analyze", str(tmp_path),
                "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
                "--resume", str(checkpoint_path), "--force",
                "-o", str(output_path),
            ])

        assert result.exit_code == 0, result.stdout
        report = output_path.read_text()
        assert "`src/auth.py`" in report
        assert "./src/auth.py" not in report
        # And the title still names the project, as an uninterrupted run does.
        assert f"# STRIDE Threat Model: {tmp_path.name}" in report

    def test_unreadable_checkpoint_refuses_instead_of_raising(self, tmp_path):
        checkpoint_path = tmp_path / "report.checkpoint.json"
        checkpoint_path.write_text('{"stride_gpt_version": "0.1.0", "plan": {')

        result = runner.invoke(cli.app, [
            "analyze", str(tmp_path),
            "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
            "--resume", str(checkpoint_path),
        ])
        assert result.exit_code == 1
        assert "Cannot resume" in result.stdout
        assert result.exception is None or isinstance(result.exception, SystemExit)


class TestAppTypeProvenance:
    def test_explicit_app_type_is_recorded_as_an_override_even_when_it_agrees(self, tmp_path):
        """``--app-type web`` is the user's choice whether or not the planner
        would have said ``web`` on its own, and the manifest has to say so."""
        plan_json = json.dumps({
            "detected_app_type": "web",
            "overall_description": "d",
            "subsystems": [
                {"name": "Auth", "description": "d", "key_files": [], "focus_areas": []}
            ],
        })
        finding_json = json.dumps({
            "threats": [], "improvement_suggestions": [], "files_analyzed": [],
        })
        output_path = tmp_path / "report.md"
        with ScriptedLLM([
            reply(plan_json),
            reply(finding_json, tools=SUBSYSTEM_TOOL_NAMES),
            _DFD,
        ]):
            result = runner.invoke(cli.app, [
                "analyze", str(tmp_path),
                "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
                "--app-type", "web", "-y", "-o", str(output_path),
            ])

        assert result.exit_code == 0, result.stdout
        manifest = json.loads((tmp_path / "report.run.json").read_text())
        assert manifest["app_type_source"] == "override:web"
        assert manifest["detected_app_type"] == "web"
