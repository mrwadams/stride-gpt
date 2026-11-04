"""CLI-level tests for `stride-gpt analyze --resume` (issue #197)."""

from __future__ import annotations

import json
import shlex
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from stride_gpt import cli
from stride_gpt.agent.loop import run_analysis
from stride_gpt.agent.persistence import build_checkpoint, write_checkpoint
from stride_gpt.core.schemas import (
    AnalysisPlan,
    LLMConfig,
    ModelPair,
    Subsystem,
    SubsystemFinding,
    ToolCallResult,
)
from tests.fakes import SUBSYSTEM_TOOL_NAMES, ScriptedLLM, call_tools, fail, reply

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
    target: Path, path: Path, *, model_name: str = "claude-x", findings=None, plan=None
) -> None:
    models = ModelPair(
        worker=LLMConfig(provider="Anthropic API", model_name=model_name, api_key="sk-x")
    )
    checkpoint = build_checkpoint(
        plan=plan or _plan(target),
        findings=findings or [],
        target=target,
        output=path.with_name("report.md"),
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


class TestResumeRefusesAnotherTarget:
    def test_sibling_directory_is_refused_before_any_llm_call(self, git_repo):
        checkpoint_path = git_repo / "report.checkpoint.json"
        _write_checkpoint_for(git_repo / "svc_a", checkpoint_path)

        with ScriptedLLM([]) as fake:
            result = runner.invoke(cli.app, [
                "analyze", str(git_repo / "svc_b"),
                "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
                "--resume", str(checkpoint_path), "--force",
            ])

        assert result.exit_code == 1
        assert "Cannot resume" in result.stdout
        assert fake.requests == []


_FINISH = call_tools(
    ToolCallResult(id="f", function_name="finish", arguments={}), tools=SUBSYSTEM_TOOL_NAMES,
)


def _four_subsystem_plan(target: Path) -> AnalysisPlan:
    return AnalysisPlan(
        target_path=str(target),
        overall_description="d",
        subsystems=[
            Subsystem(name=name, description="d", key_files=[], focus_areas=[])
            for name in ("A", "B", "C", "D")
        ],
    )


def _finding(name: str, outcome: str) -> SubsystemFinding:
    return SubsystemFinding(subsystem=name, threats=[], outcome=outcome)


class TestResumeKeepsFindingsNotYetReached:
    """A failed, B completed, C failed, D completed. Rerunning A used to
    rewrite the checkpoint as [A], so a kill before D lost a paid-for finding."""

    def test_every_write_keeps_resumed_findings_ahead_of_the_loop(self, tmp_path, model_pair):
        resumed = {name: _finding(name, "completed") for name in ("B", "D")}
        writes: list[list[str]] = []

        with ScriptedLLM([
            _FINISH,
            fail(RuntimeError("boom"), tools=SUBSYSTEM_TOOL_NAMES),
            reply(json.dumps({"cross_cutting_threats": []})),
            _DFD,
        ]):
            run_analysis(
                model_pair, tmp_path,
                plan=_four_subsystem_plan(tmp_path),
                progress=MagicMock(),
                resume_findings=resumed,
                on_checkpoint=lambda findings: writes.append([f.subsystem for f in findings]),
            )

        assert len(writes) == 4
        for names in writes:
            assert {"B", "D"} <= set(names)
            assert len(names) == len(set(names))
        assert writes[-1] == ["A", "B", "C", "D"]

    def test_a_run_killed_mid_rerun_leaves_the_later_finding_on_disk(self, tmp_path):
        checkpoint_path = tmp_path / "report.checkpoint.json"
        _write_checkpoint_for(
            tmp_path, checkpoint_path,
            plan=_four_subsystem_plan(tmp_path),
            findings=[
                _finding("A", "error"), _finding("B", "completed"),
                _finding("C", "error"), _finding("D", "completed"),
            ],
        )

        with ScriptedLLM([
            _FINISH,
            fail(KeyboardInterrupt(), tools=SUBSYSTEM_TOOL_NAMES),
        ]):
            result = runner.invoke(cli.app, [
                "analyze", str(tmp_path),
                "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
                "--resume", str(checkpoint_path), "--force",
                "-o", str(tmp_path / "report.md"),
            ])

        assert result.exit_code != 0
        stored = json.loads(checkpoint_path.read_text())
        completed = {f["subsystem"] for f in stored["findings"] if f["outcome"] == "completed"}
        assert completed == {"A", "B", "D"}


class TestInterruptPrintsResumeCommand:
    """Ctrl-C used to leave a checkpoint without saying where it was (#303)."""

    _PLAN = reply(json.dumps({
        "detected_app_type": "web",
        "overall_description": "d",
        "subsystems": [
            {"name": "Auth", "description": "d", "key_files": [], "focus_areas": []}
        ],
    }))

    def test_fresh_run_names_its_checkpoint_and_the_resume_command(self, tmp_path, monkeypatch):
        output = tmp_path / "out" / "report.json"
        args = [
            "analyze", str(tmp_path), "-y", "-f", "json", "-o", str(output),
            "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-secret",
        ]
        monkeypatch.setattr("sys.argv", ["/usr/bin/stride-gpt", *args])

        with ScriptedLLM([self._PLAN, fail(KeyboardInterrupt(), tools=SUBSYSTEM_TOOL_NAMES)]):
            result = runner.invoke(cli.app, args)

        assert result.exit_code != 0
        checkpoint = tmp_path / "out" / "report.checkpoint.json"
        assert checkpoint.is_file()
        assert str(checkpoint) in result.stdout

        command = next(
            line for line in result.stdout.splitlines()
            if line.startswith("Resume with:")
        )
        expected = "Resume with: " + shlex.join([
            "stride-gpt",
            "analyze",
            str(tmp_path),
            "-y",
            "-f",
            "json",
            "-o",
            str(output),
            "--worker-model",
            "anthropic/claude-x",
            "--worker-api-key",
            "<api-key>",
            "--resume",
            str(checkpoint),
        ])
        assert command == expected
        assert "sk-secret" not in result.stdout

    def test_resumed_run_replaces_its_resume_flag(self, tmp_path, monkeypatch):
        checkpoint = tmp_path / "report.checkpoint.json"
        _write_checkpoint_for(tmp_path, checkpoint)
        args = [
            "analyze", str(tmp_path), f"--resume={checkpoint}", "--force",
            "--worker-model", "anthropic/claude-x", "--worker-api-key=sk-secret",
            "-o", str(tmp_path / "report.md"),
        ]
        monkeypatch.setattr("sys.argv", ["stride-gpt", *args])

        with ScriptedLLM([fail(KeyboardInterrupt(), tools=SUBSYSTEM_TOOL_NAMES)]):
            result = runner.invoke(cli.app, args)

        assert result.exit_code != 0
        command = next(line for line in result.stdout.splitlines() if line.startswith("Resume with:"))
        assert command.count("--resume") == 1
        assert command.endswith(shlex.join(["--resume", str(checkpoint)]))
        assert "sk-secret" not in result.stdout

    def test_run_without_output_has_no_checkpoint_to_name(self, tmp_path, monkeypatch):
        args = [
            "analyze", str(tmp_path), "-y",
            "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
        ]
        monkeypatch.setattr("sys.argv", ["stride-gpt", *args])

        with ScriptedLLM([self._PLAN, fail(KeyboardInterrupt(), tools=SUBSYSTEM_TOOL_NAMES)]):
            result = runner.invoke(cli.app, args)

        assert result.exit_code != 0
        assert "Resume with" not in result.stdout

    def test_repl_prints_the_slash_command(self, tmp_path, monkeypatch):
        output = tmp_path / "report.md"
        config = {"worker": {"provider": "Anthropic API", "model": "claude-x", "api_key": "sk-test"}}
        monkeypatch.setattr(cli, "config_to_model_pair", lambda _c: ModelPair(
            worker=LLMConfig(provider="Anthropic API", model_name="claude-x", api_key="sk-test"),
        ))
        monkeypatch.setattr(cli, "_check_tier_api_keys", lambda *_a: True)

        with (
            ScriptedLLM([self._PLAN, fail(KeyboardInterrupt(), tools=SUBSYSTEM_TOOL_NAMES)]),
            cli.console.capture() as captured,
            pytest.raises(KeyboardInterrupt),
        ):
            cli._handle_analyze(config, f"{tmp_path} -y -o {output}")

        checkpoint = tmp_path / "report.checkpoint.json"
        expected = "/analyze " + shlex.join([
            str(tmp_path),
            "-y",
            "-o",
            str(output),
            "--resume",
            str(checkpoint),
        ])
        assert f"Resume with: {expected}" in captured.get()


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
        output_path = tmp_path / "report.md"
        with ScriptedLLM([
            reply(plan_json),
            _FINISH,
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
