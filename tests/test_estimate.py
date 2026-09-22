"""Tests for the plan cost estimate shown at approval (issue #198).

The estimate is the only thing standing between a user and a multi-million
token run they didn't ask for, so what matters here is that it matches history
to the right target, never to a subsystem name, and never presents a default
as a measurement.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stride_gpt.agent.estimate import (
    DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE,
    estimate_from_manifests,
    estimate_plan_cost,
    format_plan_estimate,
    format_tokens,
    matches_target,
    subsystem_costs,
)
from stride_gpt.agent.persistence import (
    ModelDescriptor,
    RunManifest,
    RunSummary,
    load_run_manifests,
    target_identity,
)
from stride_gpt.core.schemas import TokenUsage

TARGET_ID = target_identity("/tmp/project-a")
OTHER_ID = target_identity("/tmp/project-b")


def _manifest(
    *,
    target_id: str | None = TARGET_ID,
    target_path: str = "./",
    git_sha: str | None = "84c8a0f",
    finished: datetime | None = None,
    by_subsystem: dict[str, TokenUsage] | None = None,
    mode: str = "analyze",
) -> RunManifest:
    """A manifest with only the fields history matching actually reads."""
    if by_subsystem is None:
        by_subsystem = {"Auth": TokenUsage(prompt_tokens=90_000, completion_tokens=10_000)}
    finished = finished or datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    return RunManifest(
        stride_gpt_version="0.19.0",
        python_version="3.12.0",
        started_at=finished,
        finished_at=finished,
        architect=ModelDescriptor(provider="Anthropic API", model_name="opus"),
        worker=ModelDescriptor(provider="Anthropic API", model_name="sonnet"),
        detected_app_type="agentic",
        app_type_source="planner",
        target_path=target_path,
        target_git_sha=git_sha,
        target_id=target_id,
        config_hash="a" * 64,
        references_loaded=[],
        run_summary=RunSummary(
            status="completed",
            subsystems_planned=len(by_subsystem),
            subsystems_analyzed=len(by_subsystem),
            llm_calls=10,
            tool_calls=20,
            token_usage_by_subsystem=by_subsystem,
        ),
        mode=mode,
    )


def _estimate(manifests, *, subsystem_count=5, git_sha="84c8a0f"):
    return estimate_from_manifests(
        subsystem_count=subsystem_count,
        manifests=manifests,
        target_id=TARGET_ID,
        target_path="./",
        target_git_sha=git_sha,
    )


# ---------------------------------------------------------------------------
# The default
# ---------------------------------------------------------------------------


class TestDefault:
    def test_default_is_not_the_disproven_fifty_thousand(self):
        """50,000 was measured to be ~9x low — the cheapest completed
        subsystem observed cost 108,640 tokens."""
        assert DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE != 50_000
        assert DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE >= 108_640

    def test_no_history_falls_back_to_the_default(self):
        estimate = _estimate([])
        assert estimate.source == "default"
        assert estimate.per_subsystem_tokens == DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE
        assert estimate.total_tokens == 5 * DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE
        assert estimate.sample_size == 0
        assert not estimate.from_history

    def test_history_without_usable_usage_falls_back(self):
        """A provider that never reports usage (LM Studio / Ollama) records
        unavailable — it must not read as a free run."""
        unusable = _manifest(by_subsystem={"Auth": TokenUsage(), "API": TokenUsage()})
        assert _estimate([unusable]).source == "default"


# ---------------------------------------------------------------------------
# Matching a prior run
# ---------------------------------------------------------------------------


class TestMatching:
    def test_same_commit_is_preferred(self):
        older_same_commit = _manifest(
            git_sha="84c8a0f",
            finished=datetime(2026, 6, 1, tzinfo=UTC),
            by_subsystem={"A": TokenUsage(prompt_tokens=200_000, completion_tokens=0)},
        )
        newer_other_commit = _manifest(
            git_sha="deadbee",
            finished=datetime(2026, 6, 20, tzinfo=UTC),
            by_subsystem={"B": TokenUsage(prompt_tokens=900_000, completion_tokens=0)},
        )
        estimate = _estimate([newer_other_commit, older_same_commit])
        assert estimate.source == "history-same-commit"
        assert estimate.per_subsystem_tokens == 200_000
        assert estimate.matched_git_sha == "84c8a0f"

    def test_falls_back_to_most_recent_run_at_another_commit(self):
        older = _manifest(
            git_sha="1111111",
            finished=datetime(2026, 6, 1, tzinfo=UTC),
            by_subsystem={"A": TokenUsage(prompt_tokens=100_000, completion_tokens=0)},
        )
        newer = _manifest(
            git_sha="2222222",
            finished=datetime(2026, 6, 20, tzinfo=UTC),
            by_subsystem={"B": TokenUsage(prompt_tokens=300_000, completion_tokens=0)},
        )
        estimate = _estimate([older, newer])
        assert estimate.source == "history-other-commit"
        assert estimate.per_subsystem_tokens == 300_000
        assert estimate.matched_git_sha == "2222222"

    def test_another_repositorys_history_never_matches(self):
        """Two repos analysed from their own roots both record ``"./"``. The
        target id is what keeps one from costing the other."""
        other_repo = _manifest(
            target_id=OTHER_ID,
            target_path="./",
            by_subsystem={"X": TokenUsage(prompt_tokens=999_999, completion_tokens=0)},
        )
        assert _estimate([other_repo]).source == "default"

    def test_legacy_manifest_with_bare_dot_slash_is_not_matched(self):
        """Manifests predating ``target_id`` can only be matched on their
        redacted path, and ``"./"`` identifies no repository in particular."""
        legacy = _manifest(target_id=None, target_path="./")
        assert _estimate([legacy]).source == "default"

    def test_legacy_manifest_with_a_named_path_still_matches(self):
        legacy = _manifest(
            target_id=None,
            target_path="~/code/project-a",
            by_subsystem={"A": TokenUsage(prompt_tokens=150_000, completion_tokens=0)},
        )
        estimate = estimate_from_manifests(
            subsystem_count=3,
            manifests=[legacy],
            target_id=TARGET_ID,
            target_path="~/code/project-a",
            target_git_sha="84c8a0f",
        )
        assert estimate.source == "history-same-commit"
        assert estimate.per_subsystem_tokens == 150_000

    def test_quick_runs_are_not_history_for_analyze(self):
        quick = _manifest(mode="quick")
        assert _estimate([quick]).source == "default"

    def test_target_id_wins_over_a_changed_path(self):
        """A target analysed from a parent directory records a different
        ``target_path``; it's still the same target."""
        moved = _manifest(target_path="./sub/project-a")
        assert matches_target(moved, target_id=TARGET_ID, target_path="./")

    def test_untracked_target_matches_only_on_target(self):
        """No git sha at all still matches the target's history — just never
        as a same-commit estimate."""
        history = _manifest(git_sha=None)
        estimate = _estimate([history], git_sha=None)
        assert estimate.source == "history-other-commit"


# ---------------------------------------------------------------------------
# The mean
# ---------------------------------------------------------------------------


class TestPerSubsystemMean:
    def test_mean_over_measured_subsystems_times_plan_size(self):
        history = _manifest(
            by_subsystem={
                "A": TokenUsage(prompt_tokens=100_000, completion_tokens=0),
                "B": TokenUsage(prompt_tokens=200_000, completion_tokens=0),
            }
        )
        estimate = _estimate([history], subsystem_count=4)
        assert estimate.per_subsystem_tokens == 150_000
        assert estimate.sample_size == 2
        assert estimate.total_tokens == 600_000

    def test_partial_run_still_yields_a_usable_figure(self):
        """1 of 5 subsystems completed — the one that finished is the
        measurement, the four that never started are not zeros."""
        history = _manifest(
            by_subsystem={
                "A": TokenUsage(prompt_tokens=108_640, completion_tokens=0),
                "B": TokenUsage(),
                "C": TokenUsage(),
                "D": TokenUsage(),
                "E": TokenUsage(),
            }
        )
        estimate = _estimate([history])
        assert estimate.sample_size == 1
        assert estimate.per_subsystem_tokens == 108_640

    def test_prompt_and_completion_tokens_both_count(self):
        history = _manifest(
            by_subsystem={"A": TokenUsage(prompt_tokens=90_000, completion_tokens=10_000)}
        )
        assert _estimate([history]).per_subsystem_tokens == 100_000

    def test_subsystem_costs_drops_unavailable_and_zero(self):
        manifest = _manifest(
            by_subsystem={
                "A": TokenUsage(prompt_tokens=120_000, completion_tokens=0),
                "B": TokenUsage(),
                "C": TokenUsage(prompt_tokens=0, completion_tokens=0),
            }
        )
        assert subsystem_costs(manifest) == [120_000]

    def test_subsystem_names_are_never_the_key(self):
        """The planner renames subsystems every run, so history matched by
        name would miss even against a perfect record of the same target."""
        history = _manifest(
            by_subsystem={
                "Agent Execution & Orchestration": TokenUsage(
                    prompt_tokens=300_000, completion_tokens=0
                )
            }
        )
        # Nothing in the plan under approval shares that name.
        estimate = _estimate([history], subsystem_count=5)
        assert estimate.source == "history-same-commit"
        assert estimate.total_tokens == 1_500_000


# ---------------------------------------------------------------------------
# Reading manifests off disk
# ---------------------------------------------------------------------------


class TestLoadRunManifests:
    def test_missing_directory_is_no_history(self, tmp_path):
        assert load_run_manifests(tmp_path / "nope") == []

    def test_reads_manifests_newest_first_and_skips_junk(self, tmp_path):
        old = _manifest(finished=datetime(2026, 1, 1, tzinfo=UTC))
        new = _manifest(finished=datetime(2026, 9, 1, tzinfo=UTC))
        (tmp_path / "a.run.json").write_text(old.model_dump_json())
        (tmp_path / "b.run.json").write_text(new.model_dump_json())
        (tmp_path / "broken.run.json").write_text("{not json")
        (tmp_path / "wrong-schema.run.json").write_text('{"hello": 1}')
        # A saved report is not a manifest and must not be parsed as one.
        (tmp_path / "report.json").write_text('{"version": "1.0"}')

        loaded = load_run_manifests(tmp_path)
        assert [m.finished_at for m in loaded] == [new.finished_at, old.finished_at]

    def test_estimate_plan_cost_reads_the_reports_directory(
        self, tmp_path, monkeypatch
    ):
        reports = tmp_path / "reports"
        (reports / "analyze").mkdir(parents=True)
        target = tmp_path / "project"
        target.mkdir()
        history = _manifest(
            target_id=target_identity(target),
            git_sha=None,
            by_subsystem={"A": TokenUsage(prompt_tokens=250_000, completion_tokens=0)},
        )
        (reports / "analyze" / "x.run.json").write_text(history.model_dump_json())

        monkeypatch.setattr("stride_gpt.config.REPORTS_DIR", reports)
        monkeypatch.setattr(
            "stride_gpt.agent.estimate.discover_git_sha", lambda _target: None
        )

        estimate = estimate_plan_cost(subsystem_count=2, target=target)
        assert estimate.source == "history-other-commit"
        assert estimate.total_tokens == 500_000

    def test_estimate_plan_cost_with_no_history_is_the_default(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("stride_gpt.config.REPORTS_DIR", tmp_path / "empty")
        estimate = estimate_plan_cost(subsystem_count=3, target=tmp_path)
        assert estimate.source == "default"
        assert estimate.total_tokens == 3 * DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------


class TestFormatting:
    @pytest.mark.parametrize(
        "count, expected",
        [(950, "950"), (12_500, "12k"), (1_400_000, "1.4M"), (2_300_000, "2.3M")],
    )
    def test_format_tokens(self, count, expected):
        assert format_tokens(count) == expected

    def test_default_estimate_says_it_is_a_default(self):
        text = format_plan_estimate(_estimate([]))
        assert "default" in text.lower()
        assert "not a measurement" in text.lower()
        assert f"{DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE:,}" in text

    def test_same_commit_estimate_says_so(self):
        history = _manifest(git_sha="84c8a0fdeadbeef")
        text = format_plan_estimate(_estimate([history], git_sha="84c8a0fdeadbeef"))
        assert "recorded history" in text.lower()
        assert "this commit" in text.lower()
        # Shown short, like git does.
        assert "(84c8a0f)" in text

    def test_other_commit_estimate_says_so(self):
        history = _manifest(git_sha="1111111222222")
        text = format_plan_estimate(_estimate([history], git_sha="84c8a0f"))
        assert "different commit" in text.lower()
        assert "1111111" in text

    def test_headline_shows_total_and_per_subsystem(self):
        text = format_plan_estimate(_estimate([], subsystem_count=5))
        assert f"~{format_tokens(5 * DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE)} tokens" in text
        assert "5 subsystems" in text

    def test_says_it_is_an_order_of_magnitude(self):
        assert "order of magnitude" in format_plan_estimate(_estimate([])).lower()


# ---------------------------------------------------------------------------
# target_identity
# ---------------------------------------------------------------------------


class TestTargetIdentity:
    def test_stable_for_the_same_path(self, tmp_path):
        assert target_identity(tmp_path) == target_identity(Path(str(tmp_path)))

    def test_differs_between_targets(self, tmp_path):
        a = tmp_path / "a"
        b = tmp_path / "b"
        assert target_identity(a) != target_identity(b)

    def test_does_not_leak_the_path(self, tmp_path):
        identity = target_identity(tmp_path)
        assert tmp_path.name not in identity
        int(identity, 16)

    def test_relative_and_absolute_forms_agree(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert target_identity(Path()) == target_identity(tmp_path)


def test_manifest_json_round_trip_keeps_target_id():
    original = _manifest()
    rehydrated = RunManifest(**json.loads(original.model_dump_json()))
    assert rehydrated.target_id == TARGET_ID
