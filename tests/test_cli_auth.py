"""A rejected API key ends the run with one message, not a traceback (issue #255)."""

from __future__ import annotations

import litellm
import pytest
from typer.testing import CliRunner

from stride_gpt import cli
from tests.fakes import QUICK_TOOL_NAMES, ScriptedLLM, fail

runner = CliRunner()


@pytest.fixture(autouse=True)
def no_saved_config(monkeypatch):
    """Ignore the developer's own ~/.stride-gpt/config.json."""
    monkeypatch.setattr(cli, "load_config", lambda: None)


def _auth_error():
    return litellm.AuthenticationError(
        message="Incorrect API key provided", model="claude-x", llm_provider="anthropic"
    )


def test_analyze_with_bad_key_prints_auth_failure(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    with ScriptedLLM([fail(_auth_error())]):
        result = runner.invoke(cli.app, [
            "analyze", str(tmp_path), "--yes",
            "--worker-model", "anthropic/claude-x", "--worker-api-key", "invalid",
        ])
    assert result.exit_code == 1
    assert "Authentication failed" in result.stdout
    assert "Traceback" not in result.stdout


def test_quick_with_bad_key_prints_auth_failure(tmp_path):
    description = tmp_path / "app.txt"
    description.write_text("A web app with a login form.")
    with ScriptedLLM([fail(_auth_error(), tools=QUICK_TOOL_NAMES)]):
        result = runner.invoke(cli.app, [
            "quick", "-i", str(description),
            "--worker-model", "anthropic/claude-x", "--worker-api-key", "invalid",
        ])
    assert result.exit_code == 1
    assert "Authentication failed" in result.stdout
    assert "Traceback" not in result.stdout


def test_other_planning_errors_still_raise(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    with ScriptedLLM([fail(RuntimeError("boom"))]):
        result = runner.invoke(cli.app, [
            "analyze", str(tmp_path), "--yes",
            "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
        ])
    assert isinstance(result.exception, RuntimeError)
