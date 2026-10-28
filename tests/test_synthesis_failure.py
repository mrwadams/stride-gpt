"""A failed synthesis must not discard completed subsystem findings."""

import json
from unittest.mock import MagicMock

import litellm
import pytest
from typer.testing import CliRunner

from stride_gpt import cli
from stride_gpt.agent.html_report import render_html, render_html_from_json
from stride_gpt.agent.loop import run_analysis
from stride_gpt.agent.report import render_json, render_markdown, render_markdown_from_json
from tests.fakes import ScriptedLLM, fail, reply
from tests.test_loop import _DFD, _finish, _report, _tool_turn
from tests.test_synthesis import _EVIDENCE, _NAMES, _SCENARIO, _plan, _run


@pytest.mark.parametrize("retry", [False, True])
def test_failed_synthesis_preserves_findings_and_marks_reports(model_pair, sandbox_dir, retry):
    steps = [
        _tool_turn(
            _report(f"r{i}", scenario=_SCENARIO, evidence=_EVIDENCE),
            _finish(f"f{i}"),
        )
        for i in range(len(_NAMES))
    ]
    if retry:
        steps.append(reply("not JSON"))
    steps.extend([
        fail(litellm.AuthenticationError(
            message="secret provider detail", model="fake", llm_provider="anthropic"
        )),
        _DFD,
    ])
    progress = MagicMock()
    with ScriptedLLM(steps):
        report = run_analysis(model_pair, sandbox_dir, plan=_plan(sandbox_dir), progress=progress)

    assert [finding.subsystem for finding in report.findings] == list(_NAMES)
    assert all(len(finding.threats) == 1 for finding in report.findings)
    assert report.cross_cutting_threats == []
    assert report.systemic_observations == []
    assert report.data_flow_diagram
    assert report.metadata["synthesis_error_class"] == "AuthenticationError"
    assert report.metadata["llm_calls"] == len(_NAMES) + int(retry) + 1
    progress.synthesis_done.assert_not_called()
    data = render_json(report)
    for rendered in (
        render_markdown(report),
        render_markdown_from_json(data),
        render_html(report),
        render_html_from_json(data),
    ):
        assert "Synthesis failed" in rendered
        assert "AuthenticationError" in rendered
        assert "secret provider detail" not in rendered


def test_empty_successful_synthesis_is_not_reported_as_failure(model_pair, sandbox_dir):
    report, _ = _run(model_pair, sandbox_dir, [])
    assert "synthesis_error_class" not in report.metadata
    assert "Synthesis failed" not in render_markdown(report)
    assert "Synthesis failed" not in render_html(report)


def test_cli_writes_partial_report_and_manifest_after_synthesis_error(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "load_config", lambda: None)
    monkeypatch.setattr("stride_gpt.config.REPORTS_DIR", tmp_path / "saved")
    plan = reply(json.dumps({
        "detected_app_type": "web",
        "overall_description": "app",
        "subsystems": [
            {"name": name, "description": "d", "key_files": [], "focus_areas": []}
            for name in _NAMES
        ],
    }))
    steps = [plan]
    steps.extend(
        _tool_turn(
            _report(f"r{i}", scenario=_SCENARIO, evidence=[]),
            _finish(f"f{i}"),
        )
        for i in range(len(_NAMES))
    )
    steps.extend([
        fail(litellm.AuthenticationError(
            message="secret provider detail", model="fake", llm_provider="anthropic"
        )),
        _DFD,
    ])
    output = tmp_path / "report.json"
    with ScriptedLLM(steps):
        result = CliRunner().invoke(cli.app, [
            "analyze", str(tmp_path), "--yes", "-f", "json", "-o", str(output),
            "--worker-model", "anthropic/claude-x", "--worker-api-key", "sk-test",
        ])

    assert result.exit_code == 0, result.stdout
    report = json.loads(output.read_text(encoding="utf-8"))
    assert len(report["subsystems"]) == len(_NAMES)
    assert all(len(subsystem["threats"]) == 1 for subsystem in report["subsystems"])
    assert report["metadata"]["synthesis_error_class"] == "AuthenticationError"
    html = output.with_suffix(".html").read_text(encoding="utf-8")
    assert "Synthesis failed (AuthenticationError)" in html
    manifest = json.loads((tmp_path / "report.run.json").read_text(encoding="utf-8"))
    assert manifest["run_summary"]["status"] == "partial"
    assert manifest["run_summary"]["synthesis_error_class"] == "AuthenticationError"
    assert "secret provider detail" not in json.dumps(report)
    assert "secret provider detail" not in json.dumps(manifest)


def test_saved_report_html_escapes_failure_class(model_pair, sandbox_dir):
    report, _ = _run(model_pair, sandbox_dir, [])
    report.metadata["synthesis_error_class"] = "<script>"
    html = render_html_from_json(render_json(report))
    assert "Synthesis failed (&lt;script&gt;)" in html
    assert "Synthesis failed (<script>)" not in html
