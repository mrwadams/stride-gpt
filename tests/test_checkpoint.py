"""Tests for checkpointing an /analyze run and resuming it (issue #197)."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stride_gpt.agent import persistence
from stride_gpt.agent.persistence import (
    Checkpoint,
    CheckpointValidationError,
    build_checkpoint,
    checkpoint_path_for,
    compute_checkpoint_config_hash,
    is_git_dirty,
    load_checkpoint,
    restore_checkpoint_paths,
    validate_checkpoint_for_resume,
    write_checkpoint,
    write_intermediates,
)
from stride_gpt.core.schemas import AnalysisPlan, LLMConfig, ModelPair, Subsystem, SubsystemFinding

# ---------------------------------------------------------------------------
# compute_checkpoint_config_hash
# ---------------------------------------------------------------------------


def _pair(model_name: str = "claude-sonnet-4-5", api_key: str = "sk-test") -> ModelPair:
    return ModelPair(
        worker=LLMConfig(provider="Anthropic API", model_name=model_name, api_key=api_key),
    )


class TestComputeCheckpointConfigHash:
    def test_deterministic(self):
        pair = _pair()
        assert compute_checkpoint_config_hash(pair) == compute_checkpoint_config_hash(pair)

    def test_changes_with_model(self):
        a = compute_checkpoint_config_hash(_pair("claude-sonnet-4-5"))
        b = compute_checkpoint_config_hash(_pair("claude-opus-4-7"))
        assert a != b

    def test_ignores_api_key(self):
        a = compute_checkpoint_config_hash(_pair(api_key="key-A"))
        b = compute_checkpoint_config_hash(_pair(api_key="key-B"))
        assert a == b

    def test_independent_of_references_loaded_so_far(self):
        """The hash must not depend on runtime reference-card discovery —
        otherwise a checkpoint could never validate against itself as more
        subsystems load more cards mid-run."""
        # There's no `references` parameter to vary — the point of this test
        # is that the function signature doesn't accept one at all, so a
        # caller can't accidentally fold in the progressively-discovered set.
        import inspect

        params = inspect.signature(compute_checkpoint_config_hash).parameters
        assert "references" not in params


# ---------------------------------------------------------------------------
# build_checkpoint / write_checkpoint / load_checkpoint
# ---------------------------------------------------------------------------


class TestBuildAndWriteCheckpoint:
    def test_round_trips_through_disk(self, tmp_path, monkeypatch, sample_plan, sample_finding, model_pair):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: "abc123")

        checkpoint = build_checkpoint(
            plan=sample_plan,
            findings=[sample_finding],
            target=tmp_path,
            output=tmp_path / "report.md",
            models=model_pair,
            app_type_source="planner",
            started_at=datetime(2026, 6, 15, 12, 0, tzinfo=UTC),
        )
        path = tmp_path / "report.checkpoint.json"
        write_checkpoint(path, checkpoint)

        assert path.is_file()
        loaded = load_checkpoint(path)
        assert loaded == checkpoint
        assert loaded.target_git_sha == "abc123"
        assert loaded.findings[0].subsystem == sample_finding.subsystem

    def test_write_is_atomic_no_leftover_tmp_file(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: None)

        checkpoint = build_checkpoint(
            plan=sample_plan, findings=[], target=tmp_path, output=tmp_path / "report.md",
            models=model_pair,
            app_type_source="planner", started_at=datetime.now(UTC),
        )
        path = tmp_path / "out.checkpoint.json"
        write_checkpoint(path, checkpoint)

        assert path.is_file()
        assert not (tmp_path / "out.checkpoint.json.tmp").exists()

    def test_overwrite_replaces_previous_checkpoint(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: None)
        path = tmp_path / "out.checkpoint.json"

        first = build_checkpoint(
            plan=sample_plan, findings=[], target=tmp_path, output=tmp_path / "report.md",
            models=model_pair,
            app_type_source="planner", started_at=datetime.now(UTC),
        )
        write_checkpoint(path, first)

        second_finding = SubsystemFinding(subsystem="Auth", threats=[])
        second = build_checkpoint(
            plan=sample_plan, findings=[second_finding], target=tmp_path, output=tmp_path / "report.md",
            models=model_pair,
            app_type_source="planner", started_at=datetime.now(UTC),
        )
        write_checkpoint(path, second)

        loaded = load_checkpoint(path)
        assert len(loaded.findings) == 1
        assert loaded.findings[0].subsystem == "Auth"

    def test_findings_are_redacted_without_mutating_the_originals(
        self, tmp_path, monkeypatch, sample_plan, model_pair
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: None)
        cited = tmp_path / "src" / "auth.py"
        cited.parent.mkdir(parents=True)
        cited.write_text("# auth")
        absolute = str(cited.resolve())

        finding = SubsystemFinding(subsystem="Auth", threats=[], files_analyzed=[absolute])
        checkpoint = build_checkpoint(
            plan=sample_plan, findings=[finding], target=tmp_path, output=tmp_path / "report.md",
            models=model_pair,
            app_type_source="planner", started_at=datetime.now(UTC),
        )

        assert checkpoint.findings[0].files_analyzed[0] == "./src/auth.py"
        # The in-memory finding passed in is untouched.
        assert finding.files_analyzed[0] == absolute

    def test_plan_target_path_is_redacted(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: None)
        checkpoint = build_checkpoint(
            plan=sample_plan, findings=[], target=tmp_path, output=tmp_path / "report.md",
            models=model_pair,
            app_type_source="planner", started_at=datetime.now(UTC),
        )
        # sample_plan.target_path is "/tmp/test-app", outside tmp_path/HOME,
        # so it falls through to the absolute form — but it must have gone
        # through redact_path, not been copied verbatim, and the original
        # plan object must be untouched.
        assert checkpoint.plan.target_path == persistence.redact_path(sample_plan.target_path)
        assert sample_plan.target_path == "/tmp/test-app"


class TestCheckpointPathFor:
    def test_sibling_naming_matches_intermediates_convention(self, tmp_path):
        assert checkpoint_path_for(tmp_path / "report.md") == tmp_path / "report.checkpoint.json"
        assert checkpoint_path_for(tmp_path / "report.json") == tmp_path / "report.checkpoint.json"
        assert checkpoint_path_for(tmp_path / "report") == tmp_path / "report.checkpoint.json"


# ---------------------------------------------------------------------------
# validate_checkpoint_for_resume
# ---------------------------------------------------------------------------


def _checkpoint(*, target_git_sha: str | None, config_hash: str, sample_plan) -> Checkpoint:
    return Checkpoint(
        stride_gpt_version="0.0.0-test",
        started_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        target_path="./",
        target_git_sha=target_git_sha,
        target_repo_path=None,
        report_name="report.md",
        config_hash=config_hash,
        app_type_source="planner",
        plan=sample_plan,
        findings=[],
    )


class TestValidateCheckpointForResume:
    def test_matching_sha_and_hash_with_clean_tree_passes(
        self, tmp_path, monkeypatch, sample_plan, model_pair
    ):
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: "sha1")
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target, **kw: False)
        checkpoint = _checkpoint(
            target_git_sha="sha1",
            config_hash=compute_checkpoint_config_hash(model_pair),
            sample_plan=sample_plan,
        )
        # No exception raised.
        validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=False)

    def test_sha_changed_refuses_even_with_force(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: "sha-new")
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target, **kw: False)
        checkpoint = _checkpoint(
            target_git_sha="sha-old",
            config_hash=compute_checkpoint_config_hash(model_pair),
            sample_plan=sample_plan,
        )
        for force in (False, True):
            with pytest.raises(CheckpointValidationError, match="target_git_sha changed"):
                validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=force)

    def test_config_hash_changed_refuses_even_with_force(
        self, tmp_path, monkeypatch, sample_plan, model_pair
    ):
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: "sha1")
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target, **kw: False)
        different_model_pair = _pair("a-different-model")
        checkpoint = _checkpoint(
            target_git_sha="sha1",
            config_hash=compute_checkpoint_config_hash(different_model_pair),
            sample_plan=sample_plan,
        )
        for force in (False, True):
            with pytest.raises(CheckpointValidationError, match="config_hash changed"):
                validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=force)

    def test_missing_git_sha_refuses_without_force(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: None)
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target, **kw: False)
        checkpoint = _checkpoint(
            target_git_sha=None,
            config_hash=compute_checkpoint_config_hash(model_pair),
            sample_plan=sample_plan,
        )
        with pytest.raises(CheckpointValidationError, match="no discoverable git SHA"):
            validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=False)

    def test_missing_git_sha_passes_with_force(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: None)
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target, **kw: False)
        checkpoint = _checkpoint(
            target_git_sha=None,
            config_hash=compute_checkpoint_config_hash(model_pair),
            sample_plan=sample_plan,
        )
        validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=True)

    def test_dirty_tree_refuses_without_force(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: "sha1")
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target, **kw: True)
        checkpoint = _checkpoint(
            target_git_sha="sha1",
            config_hash=compute_checkpoint_config_hash(model_pair),
            sample_plan=sample_plan,
        )
        with pytest.raises(CheckpointValidationError, match="uncommitted changes"):
            validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=False)

    def test_dirty_tree_passes_with_force(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: "sha1")
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target, **kw: True)
        checkpoint = _checkpoint(
            target_git_sha="sha1",
            config_hash=compute_checkpoint_config_hash(model_pair),
            sample_plan=sample_plan,
        )
        validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=True)


# ---------------------------------------------------------------------------
# is_git_dirty — best-effort behaviour
# ---------------------------------------------------------------------------


class TestIsGitDirty:
    def test_clean_tree_is_not_dirty(self, tmp_path, monkeypatch):
        class _Result:
            returncode = 0
            stdout = ""

        monkeypatch.setattr(persistence.subprocess, "run", lambda *a, **k: _Result())
        assert is_git_dirty(tmp_path) is False

    def test_uncommitted_changes_are_dirty(self, tmp_path, monkeypatch):
        class _Result:
            returncode = 0
            stdout = " M some_file.py\n"

        monkeypatch.setattr(persistence.subprocess, "run", lambda *a, **k: _Result())
        assert is_git_dirty(tmp_path) is True

    def test_git_missing_is_treated_as_dirty(self, tmp_path, monkeypatch):
        def _raise(*a, **k):
            raise FileNotFoundError

        monkeypatch.setattr(persistence.subprocess, "run", _raise)
        assert is_git_dirty(tmp_path) is True

    def test_nonzero_returncode_is_treated_as_dirty(self, tmp_path, monkeypatch):
        class _Result:
            returncode = 128
            stdout = ""

        monkeypatch.setattr(persistence.subprocess, "run", lambda *a, **k: _Result())
        assert is_git_dirty(tmp_path) is True


# ---------------------------------------------------------------------------
# load_checkpoint — an unreadable checkpoint refuses, it doesn't crash
# ---------------------------------------------------------------------------


class TestLoadCheckpointRejectsBadInput:
    """A run killed mid-write is the normal way to meet a bad checkpoint, so
    "cannot resume" has to come back as a refusal. An unhandled
    JSONDecodeError takes the interactive session down with it."""

    def test_truncated_json_refuses(self, tmp_path):
        path = tmp_path / "report.checkpoint.json"
        path.write_text('{"stride_gpt_version": "0.1.0", "plan": {')
        with pytest.raises(CheckpointValidationError, match="could not be read as JSON"):
            load_checkpoint(path)

    def test_valid_json_wrong_shape_refuses(self, tmp_path):
        path = tmp_path / "report.checkpoint.json"
        path.write_text('{"stride_gpt_version": "0.1.0"}')
        with pytest.raises(CheckpointValidationError, match="not a checkpoint this version can read"):
            load_checkpoint(path)

    def test_not_a_json_object_refuses(self, tmp_path):
        path = tmp_path / "report.checkpoint.json"
        path.write_text("[1, 2, 3]")
        with pytest.raises(CheckpointValidationError):
            load_checkpoint(path)


# ---------------------------------------------------------------------------
# restore_checkpoint_paths — redaction is undone before the run reports from it
# ---------------------------------------------------------------------------


class TestRestoreCheckpointPaths:
    def _checkpoint_with_paths(self, tmp_path, monkeypatch, model_pair):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: "abc123")
        plan = AnalysisPlan(
            target_path=str(tmp_path / "app"),
            overall_description="d",
            subsystems=[
                Subsystem(name="Auth", description="d", key_files=["app/auth.py"], focus_areas=[])
            ],
        )
        finding = SubsystemFinding(
            subsystem="Auth",
            threats=[{
                "Threat Type": "Spoofing",
                "Scenario": "s",
                "evidence": [{"path": "app/auth.py", "snippet": "x", "verified": True}],
            }],
            files_analyzed=["app/auth.py"],
            outcome="completed",
        )
        return build_checkpoint(
            plan=plan,
            findings=[finding],
            target=tmp_path / "app",
            output=tmp_path / "report.md",
            models=model_pair,
            app_type_source="planner",
            started_at=datetime.now(UTC),
        )

    def test_redaction_is_visible_in_the_stored_checkpoint(self, tmp_path, monkeypatch, model_pair):
        checkpoint = self._checkpoint_with_paths(tmp_path, monkeypatch, model_pair)
        assert checkpoint.findings[0].files_analyzed == ["./app/auth.py"]
        assert checkpoint.plan.subsystems[0].key_files == ["./app/auth.py"]
        assert checkpoint.plan.target_path == "./app"

    def test_restore_gives_back_the_report_s_own_path_form(self, tmp_path, monkeypatch, model_pair):
        checkpoint = self._checkpoint_with_paths(tmp_path, monkeypatch, model_pair)
        restored = restore_checkpoint_paths(checkpoint, target=tmp_path / "app")

        # Exactly what an uninterrupted run holds in memory: no "./" prefix,
        # and a target path the report can take a project name from.
        assert restored.findings[0].files_analyzed == ["app/auth.py"]
        assert restored.findings[0].threats[0]["evidence"][0]["path"] == "app/auth.py"
        assert restored.plan.subsystems[0].key_files == ["app/auth.py"]
        assert restored.plan.target_path == str(tmp_path / "app")

    def test_restore_leaves_the_stored_checkpoint_alone(self, tmp_path, monkeypatch, model_pair):
        checkpoint = self._checkpoint_with_paths(tmp_path, monkeypatch, model_pair)
        restore_checkpoint_paths(checkpoint, target=tmp_path / "app")
        assert checkpoint.findings[0].files_analyzed == ["./app/auth.py"]
        assert checkpoint.findings[0].threats[0]["evidence"][0]["path"] == "./app/auth.py"


# ---------------------------------------------------------------------------
# is_git_dirty — the run's own checkpoint is not a change to the code
# ---------------------------------------------------------------------------


class TestIsGitDirtyIgnoresTheCheckpoint:
    """``analyze . -o report.md`` writes the checkpoint inside the repository
    it is analysing. Counting it as a working-tree change means the file that
    makes resume possible is the file that makes resume refuse."""

    def _stub_git(self, monkeypatch, tmp_path, porcelain):
        def _run(cmd, **kwargs):
            class _Result:
                returncode = 0
                stdout = str(tmp_path) + "\n" if "--show-toplevel" in cmd else porcelain

            return _Result()

        monkeypatch.setattr(persistence.subprocess, "run", _run)

    def test_only_the_checkpoint_untracked_is_not_dirty(self, tmp_path, monkeypatch):
        self._stub_git(monkeypatch, tmp_path, "?? report.checkpoint.json\n")
        assert is_git_dirty(tmp_path, ignore={tmp_path / "report.checkpoint.json"}) is False

    def test_a_real_change_beside_the_checkpoint_is_still_dirty(self, tmp_path, monkeypatch):
        self._stub_git(monkeypatch, tmp_path, "?? report.checkpoint.json\n M src/auth.py\n")
        assert is_git_dirty(tmp_path, ignore={tmp_path / "report.checkpoint.json"}) is True

    def test_without_ignore_the_checkpoint_still_counts(self, tmp_path, monkeypatch):
        self._stub_git(monkeypatch, tmp_path, "?? report.checkpoint.json\n")
        assert is_git_dirty(tmp_path) is True

    def test_a_checkpoint_outside_the_repo_changes_nothing(self, tmp_path, monkeypatch):
        self._stub_git(monkeypatch, tmp_path, " M src/auth.py\n")
        assert is_git_dirty(tmp_path, ignore={tmp_path.parent / "elsewhere.checkpoint.json"}) is True


# ---------------------------------------------------------------------------
# Resume against the wrong target
# ---------------------------------------------------------------------------


def _checkpoint_for(target: Path, output: Path, sample_plan, model_pair) -> Checkpoint:
    return build_checkpoint(
        plan=sample_plan, findings=[], target=target, output=output, models=model_pair,
        app_type_source="planner", started_at=datetime.now(UTC),
    )


class TestResumeTargetMustMatch:
    """A git SHA and a config hash are the same for every directory in a
    repository, so neither can tell ``analyze svc_a`` from ``analyze svc_b``."""

    @pytest.mark.parametrize("force", [False, True])
    def test_another_directory_of_the_same_repo_refuses(
        self, git_repo, sample_plan, model_pair, force
    ):
        checkpoint = _checkpoint_for(git_repo / "svc_a", git_repo / "r.md", sample_plan, model_pair)
        with pytest.raises(CheckpointValidationError, match="target changed"):
            validate_checkpoint_for_resume(
                checkpoint, target=git_repo / "svc_b", models=model_pair, force=force
            )

    def test_the_same_target_from_another_working_directory_passes(
        self, git_repo, monkeypatch, sample_plan, model_pair
    ):
        monkeypatch.chdir(git_repo)
        checkpoint = _checkpoint_for(Path("svc_a"), git_repo / "r.md", sample_plan, model_pair)
        monkeypatch.chdir(git_repo / "svc_a")
        validate_checkpoint_for_resume(checkpoint, target=Path(), models=model_pair, force=False)

    def test_the_same_target_in_a_moved_repository_passes(
        self, git_repo, tmp_path, sample_plan, model_pair
    ):
        checkpoint = _checkpoint_for(git_repo / "svc_a", git_repo / "r.md", sample_plan, model_pair)
        moved = tmp_path / "moved"
        shutil.move(git_repo, moved)
        validate_checkpoint_for_resume(
            checkpoint, target=moved / "svc_a", models=model_pair, force=False
        )

    def test_outside_git_another_path_refuses_until_forced(
        self, tmp_path, sample_plan, model_pair
    ):
        """Without git the redacted path is the only evidence, and it depends
        on the working directory, so ``--force`` can override it."""
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        checkpoint = _checkpoint_for(tmp_path / "a", tmp_path / "r.md", sample_plan, model_pair)

        with pytest.raises(CheckpointValidationError, match="target changed"):
            validate_checkpoint_for_resume(
                checkpoint, target=tmp_path / "b", models=model_pair, force=False
            )
        validate_checkpoint_for_resume(
            checkpoint, target=tmp_path / "b", models=model_pair, force=True
        )


# ---------------------------------------------------------------------------
# Sibling file names
# ---------------------------------------------------------------------------


class TestSiblingNamesKeepTheWholeStem:
    def test_versioned_reports_do_not_share_siblings(self, tmp_path, monkeypatch, sample_plan, sample_finding):
        monkeypatch.chdir(tmp_path)
        manifest = persistence.RunManifest.model_validate(_MANIFEST)
        first = write_intermediates(
            tmp_path / "report.v1.md", manifest=manifest, plan=sample_plan, findings=[sample_finding]
        )
        second = write_intermediates(
            tmp_path / "report.v2.md", manifest=manifest, plan=sample_plan, findings=[sample_finding]
        )
        assert len(first) == 3
        assert not set(first) & set(second)

    def test_every_suffix_follows_the_report_name(self, tmp_path, monkeypatch, sample_plan, sample_finding):
        monkeypatch.chdir(tmp_path)
        written = write_intermediates(
            tmp_path / "threat-model.2026.md",
            manifest=persistence.RunManifest.model_validate(_MANIFEST),
            plan=sample_plan,
            findings=[sample_finding],
        )
        assert {p.name for p in written} == {
            "threat-model.2026.plan.json",
            "threat-model.2026.findings.json",
            "threat-model.2026.run.json",
        }

    def test_checkpoints_do_not_collide(self, tmp_path):
        v1 = checkpoint_path_for(tmp_path / "report.v1.md")
        v2 = checkpoint_path_for(tmp_path / "report.v2.md")
        assert v1 != v2
        assert v1.name == "report.v1.checkpoint.json"


_MANIFEST = {
    "stride_gpt_version": "0.0.0-test",
    "python_version": "3.12.0",
    "started_at": "2026-06-15T12:00:00Z",
    "finished_at": "2026-06-15T12:01:00Z",
    "architect": {"provider": "Anthropic API", "model_name": "claude-x"},
    "worker": {"provider": "Anthropic API", "model_name": "claude-x"},
    "detected_app_type": "web",
    "app_type_source": "planner",
    "target_path": "./",
    "target_git_sha": None,
    "config_hash": "0" * 64,
    "references_loaded": [],
    "run_summary": {"status": "completed", "llm_calls": 1, "tool_calls": 0},
    "mode": "analyze",
}


# ---------------------------------------------------------------------------
# Dirtiness against a real repository
# ---------------------------------------------------------------------------


class TestRunOutputsAreNotDirtiness:
    """``git status`` collapses a new directory to ``?? out/``, so an exact
    match on the checkpoint file misses it, and a finished run leaves its
    report and siblings behind too."""

    def _resumable(self, repo, output, sample_plan, model_pair):
        output.parent.mkdir(exist_ok=True)
        checkpoint = _checkpoint_for(repo, output, sample_plan, model_pair)
        path = checkpoint_path_for(output)
        write_checkpoint(path, checkpoint)
        return checkpoint, path

    def _validate(self, checkpoint, path, repo, model_pair):
        validate_checkpoint_for_resume(
            checkpoint, target=repo, models=model_pair, force=False, checkpoint_path=path
        )

    def test_checkpoint_in_a_new_directory(self, git_repo, sample_plan, model_pair):
        checkpoint, path = self._resumable(git_repo, git_repo / "out" / "r.md", sample_plan, model_pair)
        self._validate(checkpoint, path, git_repo, model_pair)

    def test_everything_a_finished_run_left_behind(self, git_repo, sample_plan, model_pair):
        output = git_repo / "out" / "r.v1.json"
        checkpoint, path = self._resumable(git_repo, output, sample_plan, model_pair)
        for name in (
            "r.v1.json", "r.v1.html", "r.v1.plan.json", "r.v1.findings.json", "r.v1.run.json",
            "r.v1.checkpoint.json.tmp",
        ):
            (output.parent / name).write_text("{}")
        self._validate(checkpoint, path, git_repo, model_pair)

    def test_outputs_beside_the_repo_root(self, git_repo, sample_plan, model_pair):
        output = git_repo / "r.md"
        checkpoint, path = self._resumable(git_repo, output, sample_plan, model_pair)
        output.write_text("# report")
        self._validate(checkpoint, path, git_repo, model_pair)

    @pytest.mark.parametrize("name", ["evil.py", "r.py"])
    def test_a_new_source_file_in_the_output_directory_still_counts(
        self, git_repo, sample_plan, model_pair, name
    ):
        output = git_repo / "out" / "r.md"
        checkpoint, path = self._resumable(git_repo, output, sample_plan, model_pair)
        (output.parent / name).write_text("print('new')\n")
        with pytest.raises(CheckpointValidationError, match="uncommitted"):
            self._validate(checkpoint, path, git_repo, model_pair)

    def test_a_changed_tracked_file_still_counts(self, git_repo, sample_plan, model_pair):
        output = git_repo / "out" / "r.md"
        checkpoint, path = self._resumable(git_repo, output, sample_plan, model_pair)
        (git_repo / "svc_a" / "app.py").write_text("print('changed')\n")
        with pytest.raises(CheckpointValidationError, match="uncommitted"):
            self._validate(checkpoint, path, git_repo, model_pair)
