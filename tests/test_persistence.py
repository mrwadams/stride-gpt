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
    TokenUsage,
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


def test_redact_path_null_byte_does_not_raise():
    # Path.resolve() raises ValueError (not OSError) on an embedded null
    # byte, e.g. one decoded from model output, so redact_path must catch
    # broadly rather than propagate it (issue #208).
    malformed = "a" + chr(0) + "b.py"
    assert redact_path(malformed) == malformed


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
        assert f["outcome"] == "completed"
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


def _findings_for(plan) -> list[SubsystemFinding]:
    """One completed finding per planned subsystem — the all-clear baseline."""
    return [
        SubsystemFinding(subsystem=s.name, threats=[]) for s in plan.subsystems
    ]


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
        findings=_findings_for(sample_plan),
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


def test_build_analyze_manifest_defaults_to_unavailable_usage(
    tmp_path, monkeypatch, sample_plan, model_pair,
):
    """No ``token_usage_by_phase`` given (or no response in the run reported
    usage) reads as unavailable, not a silent zero."""
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
        findings=_findings_for(sample_plan),
    )

    assert manifest.run_summary.token_usage_total.available is False
    assert manifest.run_summary.token_usage_total.total_tokens is None
    assert manifest.run_summary.token_usage_by_phase == {}


def test_build_analyze_manifest_records_token_usage_by_phase_and_subsystem(
    tmp_path, monkeypatch, sample_plan, model_pair,
):
    monkeypatch.chdir(tmp_path)
    findings = [
        SubsystemFinding(
            subsystem=sample_plan.subsystems[0].name, threats=[],
            token_usage=TokenUsage(prompt_tokens=100, completion_tokens=10),
        ),
        SubsystemFinding(
            subsystem=sample_plan.subsystems[1].name, threats=[],
            token_usage=TokenUsage(prompt_tokens=200, completion_tokens=20),
        ),
    ]

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
        findings=findings,
        token_usage_by_phase={
            "exploration": {"prompt_tokens": 300, "completion_tokens": 30},
            "synthesis": {"prompt_tokens": 50, "completion_tokens": 5},
            "planning": {"prompt_tokens": None, "completion_tokens": None},
        },
    )

    summary = manifest.run_summary
    assert summary.token_usage_total.available is True
    assert summary.token_usage_total.prompt_tokens == 350
    assert summary.token_usage_total.completion_tokens == 35
    assert summary.token_usage_by_phase["exploration"] == TokenUsage(
        prompt_tokens=300, completion_tokens=30,
    )
    assert summary.token_usage_by_phase["planning"].available is False
    assert summary.token_usage_by_subsystem[sample_plan.subsystems[0].name].total_tokens == 110
    assert summary.token_usage_by_subsystem[sample_plan.subsystems[1].name].total_tokens == 220


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
        findings=_findings_for(sample_plan),
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
    findings = _findings_for(sample_plan)
    findings[1] = findings[1].model_copy(update={"outcome": "skipped"})
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
        findings=findings,
    )

    assert manifest.run_summary.status == "partial"
    assert manifest.run_summary.subsystems_planned == 2
    assert manifest.run_summary.subsystems_analyzed == 1
    assert manifest.run_summary.subsystem_outcomes == {"completed": 1, "skipped": 1}


def test_build_analyze_manifest_is_completed_when_a_subsystem_took_the_grace_round(
    tmp_path, monkeypatch, sample_plan, model_pair,
):
    """A final round still analysed the code, so the run isn't partial."""
    monkeypatch.chdir(tmp_path)
    findings = _findings_for(sample_plan)
    findings[0] = findings[0].model_copy(update={"outcome": "budget_exhausted"})

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
        findings=findings,
    )

    assert manifest.run_summary.status == "completed"
    assert manifest.run_summary.subsystems_analyzed == 2
    assert manifest.run_summary.subsystem_outcomes == {
        "budget_exhausted": 1, "completed": 1,
    }


def test_build_analyze_manifest_is_partial_when_a_subsystem_crashed(
    tmp_path, monkeypatch, sample_plan, model_pair,
):
    """The count used to be of findings recorded, so a crash read as complete."""
    monkeypatch.chdir(tmp_path)
    findings = _findings_for(sample_plan)
    findings[0] = findings[0].model_copy(
        update={"outcome": "error", "error_class": "context_overflow"}
    )

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
        findings=findings,
    )

    assert manifest.run_summary.status == "partial"
    assert manifest.run_summary.subsystems_analyzed == 1
    assert manifest.run_summary.subsystem_outcomes == {"completed": 1, "error": 1}


def test_findings_json_written_before_outcomes_existed_still_loads():
    """Pre-change files have no outcome key; they had reached the subsystem."""
    legacy = {
        "subsystem": "Auth",
        "threats": [{"Threat Type": "Spoofing"}],
        "improvement_suggestions": [],
        "files_analyzed": ["./auth.py"],
    }

    finding = SubsystemFinding(**legacy)

    assert finding.outcome == "completed"
    assert finding.error_class is None


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


def test_evidence_paths_are_redacted_without_mutating_the_report(
    tmp_path, monkeypatch, sample_plan
):
    """The -o siblings redact; the auto-saved archive keeps verbatim values.

    model_copy is shallow, so redacting a path nested inside a threat dict
    in place would corrupt the report still held in memory.
    """
    monkeypatch.chdir(tmp_path)
    cited = tmp_path / "src" / "auth.py"
    cited.parent.mkdir(parents=True)
    cited.write_text("# auth")
    absolute = str(cited.resolve())

    threat = {
        "Threat Type": "Spoofing",
        "Scenario": "s",
        "Potential Impact": "i",
        "evidence": [
            {"path": absolute, "snippet": "# auth", "verified": True,
             "start_line": 1, "end_line": 1}
        ],
    }
    finding = SubsystemFinding(subsystem="Auth", threats=[threat], files_analyzed=[absolute])

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

    on_disk = json.loads((tmp_path / "report.findings.json").read_text())
    assert on_disk["findings"][0]["threats"][0]["evidence"][0]["path"] == "./src/auth.py"
    assert threat["evidence"][0]["path"] == absolute


def test_threats_without_evidence_pass_through_redaction(tmp_path, monkeypatch, sample_plan):
    monkeypatch.chdir(tmp_path)
    threat = {"Threat Type": "Spoofing", "Scenario": "s", "Potential Impact": "i"}
    output = tmp_path / "report.md"
    output.write_text("ignored")
    write_intermediates(
        output,
        manifest=_make_analyze_manifest(tmp_path),
        plan=sample_plan,
        findings=[SubsystemFinding(subsystem="Auth", threats=[threat])],
        cross_cutting=[],
        data_flow_diagram=None,
    )
    on_disk = json.loads((tmp_path / "report.findings.json").read_text())
    assert on_disk["findings"][0]["threats"] == [threat]
