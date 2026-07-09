"""Tests for the intermediate persistence layer (issue #122)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from stride_gpt.agent.persistence import (
    ModelDescriptor,
    RunManifest,
    RunSummary,
    build_analyze_manifest,
    build_quick_manifest,
    compute_config_hash,
    redact_path,
    write_intermediates,
)
from stride_gpt.core.schemas import (
    LLMConfig,
    ModelPair,
    SubsystemFinding,
)

# ---------------------------------------------------------------------------
# redact_path
# ---------------------------------------------------------------------------


def test_redact_path_under_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    nested = tmp_path / "services" / "auth"
    nested.mkdir(parents=True)
    assert redact_path(nested) == "./services/auth"


def test_redact_path_cwd_itself(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert redact_path(tmp_path) == "./"


def test_redact_path_under_home_outside_cwd(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(cwd)
    target = home / "code" / "acme"
    target.mkdir(parents=True)
    assert redact_path(target) == "~/code/acme"


def test_redact_path_outside_cwd_and_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(cwd)
    # Not under cwd, not under HOME — falls through to absolute path.
    assert redact_path(other) == str(other.resolve())


# ---------------------------------------------------------------------------
# compute_config_hash
# ---------------------------------------------------------------------------


def _make_pair(
    worker_model: str = "claude-sonnet-4-5",
    api_key: str = "sk-test",
) -> ModelPair:
    return ModelPair(
        worker=LLMConfig(
            provider="Anthropic API", model_name=worker_model, api_key=api_key,
        ),
    )


def test_config_hash_is_deterministic():
    pair = _make_pair()
    a = compute_config_hash(system_prompt="P", models=pair, references=["genai"])
    b = compute_config_hash(system_prompt="P", models=pair, references=["genai"])
    assert a == b


def test_config_hash_changes_with_prompt():
    pair = _make_pair()
    a = compute_config_hash(system_prompt="P", models=pair, references=[])
    b = compute_config_hash(system_prompt="P2", models=pair, references=[])
    assert a != b


def test_config_hash_changes_with_model():
    a = compute_config_hash(
        system_prompt="P", models=_make_pair("claude-sonnet-4-5"), references=[],
    )
    b = compute_config_hash(
        system_prompt="P", models=_make_pair("claude-opus-4-7"), references=[],
    )
    assert a != b


def test_config_hash_changes_with_references():
    pair = _make_pair()
    a = compute_config_hash(system_prompt="P", models=pair, references=["genai"])
    b = compute_config_hash(system_prompt="P", models=pair, references=["agentic"])
    assert a != b


def test_config_hash_ignores_api_key():
    # Two runs against the same model with different BYOK keys should share
    # a hash — the key is deployment noise, not behaviour.
    a = compute_config_hash(
        system_prompt="P", models=_make_pair(api_key="key-A"), references=[],
    )
    b = compute_config_hash(
        system_prompt="P", models=_make_pair(api_key="key-B"), references=[],
    )
    assert a == b


def test_config_hash_reference_order_insensitive():
    pair = _make_pair()
    a = compute_config_hash(
        system_prompt="P", models=pair, references=["genai", "agentic"],
    )
    b = compute_config_hash(
        system_prompt="P", models=pair, references=["agentic", "genai"],
    )
    assert a == b


# ---------------------------------------------------------------------------
# write_intermediates — analyze run
# ---------------------------------------------------------------------------


def _make_analyze_manifest(tmp_path: Path) -> RunManifest:
    return RunManifest(
        stride_gpt_version="0.0.0-test",
        python_version="3.12.0",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        architect=ModelDescriptor(provider="A", model_name="m1"),
        worker=ModelDescriptor(provider="A", model_name="m2"),
        detected_app_type="web",
        app_type_source="planner",
        target_path="./",
        target_git_sha=None,
        config_hash="0" * 64,
        references_loaded=["genai"],
        run_summary=RunSummary(
            status="completed",
            subsystems_planned=2,
            subsystems_analyzed=2,
            llm_calls=5,
            tool_calls=12,
        ),
        mode="analyze",
    )


def test_write_intermediates_analyze_emits_three_siblings(
    tmp_path, sample_plan, sample_finding, sample_report,
):
    output = tmp_path / "report.md"
    output.write_text("# placeholder report\n")

    paths = write_intermediates(
        output,
        manifest=_make_analyze_manifest(tmp_path),
        plan=sample_plan,
        findings=sample_report.findings,
        cross_cutting=sample_report.cross_cutting_threats,
        data_flow_diagram=sample_report.data_flow_diagram,
    )

    plan_path = tmp_path / "report.plan.json"
    findings_path = tmp_path / "report.findings.json"
    run_path = tmp_path / "report.run.json"

    assert set(paths) == {plan_path, findings_path, run_path}
    for p in paths:
        assert p.is_file()


def test_write_intermediates_analyze_files_parse_as_models(
    tmp_path, sample_plan, sample_report,
):
    output = tmp_path / "audit.sarif"
    output.write_text("{}")
    write_intermediates(
        output,
        manifest=_make_analyze_manifest(tmp_path),
        plan=sample_plan,
        findings=sample_report.findings,
        cross_cutting=sample_report.cross_cutting_threats,
        data_flow_diagram=sample_report.data_flow_diagram,
    )

    from stride_gpt.core.schemas import AnalysisPlan

    plan_data = json.loads((tmp_path / "audit.plan.json").read_text())
    AnalysisPlan(**plan_data)  # round-trip via pydantic

    findings_data = json.loads((tmp_path / "audit.findings.json").read_text())
    assert "findings" in findings_data
    assert "cross_cutting_threats" in findings_data
    assert "data_flow_diagram" in findings_data
    for f in findings_data["findings"]:
        SubsystemFinding(**f)

    run_data = json.loads((tmp_path / "audit.run.json").read_text())
    RunManifest(**run_data)


def test_write_intermediates_format_flag_does_not_change_sibling_extensions(
    tmp_path, sample_plan, sample_report,
):
    # Three different report formats — same three sibling filenames.
    for ext in (".md", ".sarif", ".json", ".html"):
        sub = tmp_path / ext.lstrip(".")
        sub.mkdir()
        output = sub / f"r{ext}"
        output.write_text("ignored")
        write_intermediates(
            output,
            manifest=_make_analyze_manifest(tmp_path),
            plan=sample_plan,
            findings=sample_report.findings,
            cross_cutting=sample_report.cross_cutting_threats,
            data_flow_diagram=sample_report.data_flow_diagram,
        )
        assert (sub / "r.plan.json").is_file()
        assert (sub / "r.findings.json").is_file()
        assert (sub / "r.run.json").is_file()


# ---------------------------------------------------------------------------
# write_intermediates — quick run
# ---------------------------------------------------------------------------


def _make_quick_manifest() -> RunManifest:
    return RunManifest(
        stride_gpt_version="0.0.0-test",
        python_version="3.12.0",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        architect=ModelDescriptor(provider="A", model_name="m1"),
        worker=ModelDescriptor(provider="A", model_name="m2"),
        detected_app_type="genai",
        app_type_source="hint:genai",
        target_path="stdin",
        target_git_sha=None,
        config_hash="f" * 64,
        references_loaded=[],
        run_summary=RunSummary(
            status="completed",
            subsystems_planned=None,
            subsystems_analyzed=None,
            llm_calls=3,
            tool_calls=1,
        ),
        mode="quick",
    )


def test_write_intermediates_quick_only_emits_run_json(tmp_path):
    output = tmp_path / "quick.md"
    output.write_text("# placeholder")

    paths = write_intermediates(output, manifest=_make_quick_manifest())

    assert paths == [tmp_path / "quick.run.json"]
    assert not (tmp_path / "quick.plan.json").exists()
    assert not (tmp_path / "quick.findings.json").exists()


# ---------------------------------------------------------------------------
# Path redaction inside findings.json
# ---------------------------------------------------------------------------


def test_findings_paths_are_redacted_on_disk(tmp_path, monkeypatch, sample_plan):
    monkeypatch.chdir(tmp_path)
    inside_cwd = tmp_path / "src" / "auth.py"
    inside_cwd.parent.mkdir(parents=True)
    inside_cwd.write_text("# auth")

    finding = SubsystemFinding(
        subsystem="Auth",
        threats=[],
        improvement_suggestions=[],
        files_analyzed=[str(inside_cwd.resolve())],
    )

    output = tmp_path / "report.md"
    output.write_text("ignored")
    write_intermediates(
        output,
        manifest=_make_analyze_manifest(tmp_path),
        plan=sample_plan,
        findings=[finding],
        cross_cutting=[],
        data_flow_diagram=None,
    )

    findings_data = json.loads((tmp_path / "report.findings.json").read_text())
    on_disk = findings_data["findings"][0]["files_analyzed"][0]
    assert on_disk == "./src/auth.py"

    # The original finding wasn't mutated.
    assert finding.files_analyzed[0] == str(inside_cwd.resolve())


# ---------------------------------------------------------------------------
# RunManifest round-trip
# ---------------------------------------------------------------------------


def test_run_manifest_round_trip():
    original = RunManifest(
        stride_gpt_version="1.2.3",
        python_version="3.12.0",
        started_at=datetime(2026, 6, 15, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 6, 15, 12, 5, tzinfo=UTC),
        architect=ModelDescriptor(provider="Anthropic API", model_name="opus"),
        worker=ModelDescriptor(provider="Anthropic API", model_name="sonnet"),
        detected_app_type="agentic",
        app_type_source="override:agentic",
        target_path="./",
        target_git_sha="abc123",
        config_hash="a" * 64,
        references_loaded=["agentic", "genai"],
        run_summary=RunSummary(
            status="partial",
            subsystems_planned=5,
            subsystems_analyzed=1,
            llm_calls=8,
            tool_calls=8,
        ),
        mode="analyze",
    )
    # JSON round-trip: model_dump_json → load → RunManifest(**) reproduces.
    rehydrated = RunManifest(**json.loads(original.model_dump_json()))
    assert rehydrated == original


# ---------------------------------------------------------------------------
# Manifest builders
# ---------------------------------------------------------------------------


def test_build_analyze_manifest_populates_expected_fields(
    tmp_path, monkeypatch, sample_plan, model_pair,
):
    monkeypatch.chdir(tmp_path)
    started = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    finished = datetime(2026, 6, 15, 12, 5, tzinfo=UTC)

    manifest = build_analyze_manifest(
        models=model_pair,
        plan=sample_plan,
        target=tmp_path,
        started_at=started,
        finished_at=finished,
        app_type_source="planner",
        system_prompt="hello",
        references_loaded=["genai"],
        llm_calls=5,
        tool_calls=12,
        subsystems_analyzed=len(sample_plan.subsystems),
    )

    assert manifest.mode == "analyze"
    assert manifest.detected_app_type == sample_plan.detected_app_type
    assert manifest.app_type_source == "planner"
    assert manifest.target_path == "./"
    assert manifest.references_loaded == ["genai"]
    assert manifest.worker.provider == model_pair.worker.provider
    assert manifest.worker.model_name == model_pair.worker.model_name
    assert manifest.started_at == started
    assert manifest.finished_at == finished
    # 64-char sha256 hex.
    assert len(manifest.config_hash) == 64
    int(manifest.config_hash, 16)


def test_build_analyze_manifest_status_completed_when_all_subsystems_analyzed(
    tmp_path, monkeypatch, sample_plan, model_pair,
):
    monkeypatch.chdir(tmp_path)
    manifest = build_analyze_manifest(
        models=model_pair,
        plan=sample_plan,
        target=tmp_path,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        app_type_source="planner",
        system_prompt="hello",
        references_loaded=[],
        llm_calls=5,
        tool_calls=12,
        subsystems_analyzed=len(sample_plan.subsystems),
    )

    assert manifest.run_summary.status == "completed"
    assert manifest.run_summary.subsystems_planned == len(sample_plan.subsystems)
    assert manifest.run_summary.subsystems_analyzed == len(sample_plan.subsystems)
    assert manifest.run_summary.llm_calls == 5
    assert manifest.run_summary.tool_calls == 12


def test_build_analyze_manifest_status_partial_when_cap_truncates(
    tmp_path, monkeypatch, sample_plan, model_pair,
):
    # A call cap stopped analysis after 1 of the plan's 2 subsystems.
    monkeypatch.chdir(tmp_path)
    manifest = build_analyze_manifest(
        models=model_pair,
        plan=sample_plan,
        target=tmp_path,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        app_type_source="planner",
        system_prompt="hello",
        references_loaded=[],
        llm_calls=8,
        tool_calls=8,
        subsystems_analyzed=1,
    )

    assert manifest.run_summary.status == "partial"
    assert manifest.run_summary.subsystems_planned == 2
    assert manifest.run_summary.subsystems_analyzed == 1


def test_build_quick_manifest_uses_target_label_verbatim(model_pair):
    manifest = build_quick_manifest(
        models=model_pair,
        target_label="my-app.md",
        detected_app_type="genai",
        app_type_source="hint:genai",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        system_prompt="quick prompt",
        references_loaded=["genai", "agentic"],
        llm_calls=3,
        tool_calls=1,
    )

    assert manifest.mode == "quick"
    assert manifest.target_path == "my-app.md"
    assert manifest.target_git_sha is None
    # references_loaded is sorted by the builder.
    assert manifest.references_loaded == ["agentic", "genai"]


def test_build_quick_manifest_run_summary_completed_with_null_subsystems(model_pair):
    # /quick is single-shot: always "completed", no subsystem counts.
    manifest = build_quick_manifest(
        models=model_pair,
        target_label="stdin",
        detected_app_type="web",
        app_type_source="default",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        system_prompt="quick prompt",
        references_loaded=[],
        llm_calls=4,
        tool_calls=2,
    )

    assert manifest.run_summary.status == "completed"
    assert manifest.run_summary.subsystems_planned is None
    assert manifest.run_summary.subsystems_analyzed is None
    assert manifest.run_summary.llm_calls == 4
    assert manifest.run_summary.tool_calls == 2
