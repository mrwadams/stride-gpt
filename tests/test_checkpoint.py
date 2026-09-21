"""Tests for checkpointing an /analyze run and resuming it (issue #197)."""

from __future__ import annotations

from datetime import UTC, datetime

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
    validate_checkpoint_for_resume,
    write_checkpoint,
)
from stride_gpt.core.schemas import LLMConfig, ModelPair, SubsystemFinding

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
            plan=sample_plan, findings=[], target=tmp_path, models=model_pair,
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
            plan=sample_plan, findings=[], target=tmp_path, models=model_pair,
            app_type_source="planner", started_at=datetime.now(UTC),
        )
        write_checkpoint(path, first)

        second_finding = SubsystemFinding(subsystem="Auth", threats=[])
        second = build_checkpoint(
            plan=sample_plan, findings=[second_finding], target=tmp_path, models=model_pair,
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
            plan=sample_plan, findings=[finding], target=tmp_path, models=model_pair,
            app_type_source="planner", started_at=datetime.now(UTC),
        )

        assert checkpoint.findings[0].files_analyzed[0] == "./src/auth.py"
        # The in-memory finding passed in is untouched.
        assert finding.files_analyzed[0] == absolute

    def test_plan_target_path_is_redacted(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: None)
        checkpoint = build_checkpoint(
            plan=sample_plan, findings=[], target=tmp_path, models=model_pair,
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
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target: False)
        checkpoint = _checkpoint(
            target_git_sha="sha1",
            config_hash=compute_checkpoint_config_hash(model_pair),
            sample_plan=sample_plan,
        )
        # No exception raised.
        validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=False)

    def test_sha_changed_refuses_even_with_force(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: "sha-new")
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target: False)
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
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target: False)
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
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: None)
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target: False)
        checkpoint = _checkpoint(
            target_git_sha=None,
            config_hash=compute_checkpoint_config_hash(model_pair),
            sample_plan=sample_plan,
        )
        with pytest.raises(CheckpointValidationError, match="no discoverable git SHA"):
            validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=False)

    def test_missing_git_sha_passes_with_force(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: None)
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target: False)
        checkpoint = _checkpoint(
            target_git_sha=None,
            config_hash=compute_checkpoint_config_hash(model_pair),
            sample_plan=sample_plan,
        )
        validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=True)

    def test_dirty_tree_refuses_without_force(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: "sha1")
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target: True)
        checkpoint = _checkpoint(
            target_git_sha="sha1",
            config_hash=compute_checkpoint_config_hash(model_pair),
            sample_plan=sample_plan,
        )
        with pytest.raises(CheckpointValidationError, match="uncommitted changes"):
            validate_checkpoint_for_resume(checkpoint, target=tmp_path, models=model_pair, force=False)

    def test_dirty_tree_passes_with_force(self, tmp_path, monkeypatch, sample_plan, model_pair):
        monkeypatch.setattr(persistence, "discover_git_sha", lambda target: "sha1")
        monkeypatch.setattr(persistence, "is_git_dirty", lambda target: True)
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
