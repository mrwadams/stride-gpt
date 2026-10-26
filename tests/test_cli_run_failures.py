"""Runs that fail for reasons outside stride-gpt end with one message and the right exit code."""

from __future__ import annotations

import json

import litellm
import pytest
from typer.testing import CliRunner

from stride_gpt import cli
from tests.fakes import QUICK_TOOL_NAMES, SUBSYSTEM_TOOL_NAMES, ScriptedLLM, fail, reply

runner = CliRunner()

_PLAN = reply(json.dumps({
    "detected_app_type": "web",
    "overall_description": "d",
    "subsystems": [{"name": "Auth", "description": "d", "key_files": [], "focus_areas": []}],
}))
_FINDING = reply(
    json.dumps({"threats": [], "improvement_suggestions": [], "files_analyzed": []}),
    tools=SUBSYSTEM_TOOL_NAMES,
)
_DFD = reply("```mermaid\nflowchart LR\n  A --> B\n```")
_MODEL_ARGS = ["--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test"]


@pytest.fixture(autouse=True)
def no_saved_config(monkeypatch):
    """Ignore the developer's own ~/.stride-gpt/config.json."""
    monkeypatch.setattr(cli, "load_config", lambda: None)


def test_output_into_a_missing_directory_creates_it(tmp_path):
    output = tmp_path / "out" / "nested" / "report.json"
    with ScriptedLLM([_PLAN, _FINDING, _DFD]):
        result = runner.invoke(cli.app, [
            "analyze", str(tmp_path), "--yes", "-f", "json", "-o", str(output), *_MODEL_ARGS,
        ])
    assert result.exit_code == 0, result.stdout
    assert output.exists()
    assert (output.parent / "report.checkpoint.json").exists()


def test_unreachable_provider_prints_one_message(tmp_path):
    connection_error = litellm.InternalServerError(
        message="OpenAIException - Connection error.", model="gpt-x", llm_provider="openai"
    )
    with ScriptedLLM([fail(connection_error)]):
        result = runner.invoke(cli.app, ["analyze", str(tmp_path), "--yes", *_MODEL_ARGS])
    assert result.exit_code == 1
    assert "provider call failed" in result.stdout
    assert "Connection error" in result.stdout
    assert "Traceback" not in result.stdout


def test_run_where_no_subsystem_is_analysed_exits_1(tmp_path):
    auth_error = litellm.AuthenticationError(
        message="Incorrect API key provided", model="claude-x", llm_provider="anthropic"
    )
    with ScriptedLLM([_PLAN, fail(auth_error, tools=SUBSYSTEM_TOOL_NAMES), _DFD]):
        result = runner.invoke(cli.app, ["analyze", str(tmp_path), "--yes", *_MODEL_ARGS])
    assert result.exit_code == 1, result.stdout
    assert "No subsystem was analysed" in result.stdout


_QUICK = reply(
    json.dumps({"threat_model": [], "improvement_suggestions": []}),
    tools=QUICK_TOOL_NAMES,
)


@pytest.fixture
def description(tmp_path, monkeypatch):
    monkeypatch.setattr("stride_gpt.config.REPORTS_DIR", tmp_path / "reports")
    path = tmp_path / "app.txt"
    path.write_text("A web app with a login form.")
    return path


def test_quick_output_into_a_missing_directory_creates_it(tmp_path, description):
    output = tmp_path / "out" / "nested" / "quick.md"
    with ScriptedLLM([_QUICK]):
        result = runner.invoke(cli.app, ["quick", "-i", str(description), "-o", str(output), *_MODEL_ARGS])
    assert result.exit_code == 0, result.stdout
    assert output.exists()


def test_reports_export_into_a_missing_directory_creates_it(tmp_path, description):
    with ScriptedLLM([_QUICK]):
        assert runner.invoke(cli.app, ["quick", "-i", str(description), *_MODEL_ARGS]).exit_code == 0
    output = tmp_path / "out" / "nested" / "export.md"
    result = runner.invoke(cli.app, ["reports", "1", "--quick", "-o", str(output)])
    assert result.exit_code == 0, result.stdout
    assert output.exists()
