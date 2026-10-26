"""What a user types at the setup wizard and the REPL does what the screen says."""

from __future__ import annotations

import io
import re

import pytest
from rich.console import Console
from rich.prompt import PromptBase

from stride_gpt import cli, config
from stride_gpt.core.schemas import LLMConfig, ModelPair

_DEEPSEEK = "6"


def _recording_console() -> Console:
    return Console(file=io.StringIO(), width=200, color_system=None)


def _answer(monkeypatch, answers: list[str]) -> None:
    """Feed setup prompts from a list instead of stdin."""
    pending = list(answers)
    monkeypatch.setattr(
        PromptBase, "get_input", classmethod(lambda *_a, **_k: pending.pop(0))
    )


# ---------------------------------------------------------------------------
# Setup: q cancels at yes/no prompts too
# ---------------------------------------------------------------------------


def test_q_at_the_missing_key_prompt_cancels_setup(monkeypatch):
    console = _recording_console()
    _answer(monkeypatch, [_DEEPSEEK, "1", "q"])
    assert config.run_setup(console) is None
    assert "Setup cancelled." in console.file.getvalue()


def test_q_at_the_architect_prompt_cancels_setup(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(config, "save_config", lambda _c: pytest.fail("setup saved after q"))
    console = _recording_console()
    _answer(monkeypatch, [_DEEPSEEK, "1", "q"])
    assert config.run_setup(console) is None
    assert "Setup cancelled." in console.file.getvalue()


def test_q_at_the_keep_architect_prompt_cancels_setup(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(config, "save_config", lambda _c: pytest.fail("setup saved after q"))
    existing = {"architect_provider": "DeepSeek", "architect_model": "deepseek-pro"}
    console = _recording_console()
    _answer(monkeypatch, [_DEEPSEEK, "1", "q"])
    assert config.run_setup(console, existing) is None
    assert "Setup cancelled." in console.file.getvalue()


# ---------------------------------------------------------------------------
# /help
# ---------------------------------------------------------------------------


def test_help_commands_render_in_aligned_columns():
    console = _recording_console()
    console.print(cli.HELP_TEXT)
    lines = console.file.getvalue().splitlines()
    start = lines.index("Commands:") + 1
    commands = lines[start:start + 6]
    assert "/analyze [path]" in commands[0]
    columns = {re.search(r"/\S+(?: \[path\])?\s+", line).end() for line in commands}
    assert len(columns) == 1, commands


# ---------------------------------------------------------------------------
# /analyze and /quick arguments
# ---------------------------------------------------------------------------


@pytest.fixture
def repl(monkeypatch):
    """Stub everything /analyze does after parsing, and capture what it decides."""
    seen: dict = {}

    def fake_resolve(*_a, auto_approve, **_k):
        """Record the decision, then decline the plan (an implicit None)."""
        seen["auto_approve"] = auto_approve

    models = ModelPair(worker=LLMConfig(provider="OpenAI API", model_name="m", api_key="k"))
    monkeypatch.setattr(cli, "config_to_model_pair", lambda _c: models)
    monkeypatch.setattr(cli, "_check_tier_api_keys", lambda *_a, **_k: True)
    monkeypatch.setattr(cli, "_check_lm_studio_context_for", lambda *_a, **_k: None)
    monkeypatch.setattr(cli, "_resolve_analysis_plan", fake_resolve)
    console = _recording_console()
    monkeypatch.setattr(cli, "console", console)
    seen["output"] = console.file
    return seen


def test_repl_analyze_rejects_a_flag_it_does_not_support(repl, tmp_path):
    cli._handle_analyze({}, f"{tmp_path} --max-llm-calls 5")
    out = repl["output"].getvalue()
    assert "auto_approve" not in repl, "planning ran despite the unsupported flag"
    assert "--max-llm-calls" in out
    assert "stride-gpt analyze" in out


def test_repl_quick_rejects_a_flag_it_does_not_support(repl, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "stride_gpt.agent.quick.run_quick_analysis",
        lambda *_a, **_k: pytest.fail("quick ran despite the unsupported flag"),
    )
    desc = tmp_path / "desc.txt"
    desc.write_text("A web app.")
    cli._handle_quick({}, f"-i {desc} --max-llm-calls 5")
    assert "--max-llm-calls" in repl["output"].getvalue()


def test_repl_analyze_only_auto_approves_on_the_flag(repl, tmp_path):
    target = tmp_path / "my-yard"
    target.mkdir()
    cli._handle_analyze({}, str(target))
    assert repl["auto_approve"] is False


def test_repl_analyze_expands_home(repl, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "app").mkdir()
    cli._handle_analyze({}, "~/app")
    assert "not a directory" not in repl["output"].getvalue()
    assert "auto_approve" in repl


def test_repl_quick_output_into_a_missing_directory_creates_it(repl, tmp_path, monkeypatch):
    from stride_gpt.core.schemas import ThreatModelOutput

    monkeypatch.setattr("stride_gpt.config.REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(
        "stride_gpt.agent.quick.run_quick_analysis",
        lambda *_a, **_k: ThreatModelOutput(threat_model=[], improvement_suggestions=[]),
    )
    desc = tmp_path / "desc.txt"
    desc.write_text("A web app.")
    output = tmp_path / "out" / "nested" / "quick.md"
    cli._handle_quick({}, f"-i {desc} -o {output}")
    assert output.exists()


def test_repl_reports_export_into_a_missing_directory_creates_it(repl, tmp_path, monkeypatch):
    from stride_gpt.agent.report import save_quick_report
    from stride_gpt.core.schemas import ThreatModelOutput

    monkeypatch.setattr("stride_gpt.config.REPORTS_DIR", tmp_path / "reports")
    save_quick_report(ThreatModelOutput(threat_model=[], improvement_suggestions=[]), "app")
    output = tmp_path / "out" / "nested" / "export.md"
    cli._handle_reports(f"1 --quick -o {output}")
    assert output.exists()
