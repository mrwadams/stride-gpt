"""Tests for the pure / branchy helpers in stride_gpt.cli.

These functions decide which model and API key actually drive a run, so a
regression here silently runs the wrong tier or slips past a missing key.
They're tested in isolation (no Typer command invocation, no LLM calls) by
mocking the config layer.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from stride_gpt import cli
from stride_gpt.core.schemas import LLMConfig, ModelPair

# ---------------------------------------------------------------------------
# _resolve_provider — pure prefix routing
# ---------------------------------------------------------------------------


class TestResolveProvider:
    @pytest.mark.parametrize(
        "model, expected_provider, expected_name",
        [
            ("anthropic/claude-x", "Anthropic API", "claude-x"),
            ("mistral/large", "Mistral API", "large"),
            ("groq/llama", "Groq API", "llama"),
            ("openai/gpt-x", "OpenAI API", "gpt-x"),
            ("google/gemini-x", "Google AI API", "gemini-x"),
            ("deepseek/deepseek-v4-pro", "DeepSeek API", "deepseek-v4-pro"),
        ],
    )
    def test_known_prefixes(self, model, expected_provider, expected_name):
        provider, name = cli._resolve_provider(model)
        assert provider == expected_provider
        assert name == expected_name

    def test_unprefixed_defaults_to_openai(self):
        """An unprefixed string defaults to OpenAI with the full name intact —
        the documented catch-all for OpenAI-compatible endpoints."""
        provider, name = cli._resolve_provider("some-local-model")
        assert provider == "OpenAI API"
        assert name == "some-local-model"

    def test_unknown_prefix_is_not_stripped(self):
        provider, name = cli._resolve_provider("cohere/command")
        assert provider == "OpenAI API"
        assert name == "cohere/command"


# ---------------------------------------------------------------------------
# _build_model_pair — flag validation + fallback
# ---------------------------------------------------------------------------


class TestBuildModelPair:
    def test_architect_flag_without_model_exits_2(self, monkeypatch):
        monkeypatch.setattr(cli, "load_config", lambda: None)
        with pytest.raises(typer.Exit) as exc:
            cli._build_model_pair(
                worker_model="anthropic/claude-x",
                worker_api_key="k",
                architect_api_key="only-key-no-model",
            )
        assert exc.value.exit_code == 2

    def test_architect_model_with_no_architect_exits_2(self, monkeypatch):
        monkeypatch.setattr(cli, "load_config", lambda: None)
        with pytest.raises(typer.Exit) as exc:
            cli._build_model_pair(
                worker_model="anthropic/claude-x",
                worker_api_key="k",
                architect_model="anthropic/opus",
                no_architect=True,
            )
        assert exc.value.exit_code == 2

    def test_no_worker_model_and_no_saved_exits_1(self, monkeypatch):
        monkeypatch.setattr(cli, "load_config", lambda: None)
        with pytest.raises(typer.Exit) as exc:
            cli._build_model_pair()
        assert exc.value.exit_code == 1

    def test_missing_worker_key_exits_1(self, monkeypatch):
        monkeypatch.setattr(cli, "load_config", lambda: None)
        monkeypatch.setattr("stride_gpt.config.get_api_key", lambda *a, **k: "")
        with pytest.raises(typer.Exit) as exc:
            cli._build_model_pair(worker_model="anthropic/claude-x")
        assert exc.value.exit_code == 1

    def test_explicit_worker_key_builds_single_tier_pair(self, monkeypatch):
        monkeypatch.setattr(cli, "load_config", lambda: None)
        pair = cli._build_model_pair(
            worker_model="anthropic/claude-x", worker_api_key="sk-worker"
        )
        assert isinstance(pair, ModelPair)
        assert pair.worker.provider == "Anthropic API"
        assert pair.worker.model_name == "claude-x"
        assert pair.worker.api_key == "sk-worker"
        assert pair.architect is None

    def test_lm_studio_worker_allowed_without_key(self, monkeypatch):
        """LM Studio is a local server, so a missing API key must NOT exit —
        the worker is built from saved config with an empty key."""
        saved = {
            "worker_provider_key": "LM Studio Server",
            "worker_model": "local-model",
        }
        monkeypatch.setattr(cli, "load_config", lambda: saved)
        monkeypatch.setattr("stride_gpt.config.get_api_key", lambda *a, **k: "")
        pair = cli._build_model_pair()
        assert pair.worker.provider == "LM Studio Server"
        assert pair.worker.model_name == "local-model"

    def test_worker_falls_back_to_saved_config(self, monkeypatch):
        saved = {
            "worker_provider_key": "Anthropic API",
            "worker_model": "saved-sonnet",
        }
        monkeypatch.setattr(cli, "load_config", lambda: saved)
        monkeypatch.setattr("stride_gpt.config.get_api_key", lambda *a, **k: "sk-saved")
        pair = cli._build_model_pair()
        assert pair.worker.model_name == "saved-sonnet"
        assert pair.worker.api_key == "sk-saved"


# ---------------------------------------------------------------------------
# _check_tier_api_keys — run gating
# ---------------------------------------------------------------------------


def _cfg(provider="Anthropic API", key="sk-x"):
    return LLMConfig(provider=provider, model_name="m", api_key=key)


class TestCheckTierApiKeys:
    def test_worker_missing_key_returns_false(self):
        models = ModelPair(worker=_cfg(key=""))
        assert cli._check_tier_api_keys({}, models) is False

    def test_lm_studio_worker_without_key_ok(self):
        models = ModelPair(worker=_cfg(provider="LM Studio Server", key=""))
        assert cli._check_tier_api_keys({}, models) is True

    def test_tiered_architect_missing_key_returns_false(self):
        models = ModelPair(worker=_cfg(), architect=_cfg(key=""))
        assert cli._check_tier_api_keys({}, models) is False

    def test_both_keys_present_returns_true(self):
        models = ModelPair(worker=_cfg(), architect=_cfg())
        assert cli._check_tier_api_keys({}, models) is True

    def test_single_tier_skips_architect_check(self):
        models = ModelPair(worker=_cfg())
        assert cli._check_tier_api_keys({}, models) is True


# ---------------------------------------------------------------------------
# _panel_models_body — output formatting
# ---------------------------------------------------------------------------


class TestPanelModelsBody:
    def test_tiered_shows_both_lines(self):
        models = ModelPair(worker=_cfg(), architect=_cfg())
        body = cli._panel_models_body(models)
        assert "Architect:" in body
        assert "Worker:" in body

    def test_single_tier_shows_one_model_line(self):
        models = ModelPair(worker=_cfg())
        body = cli._panel_models_body(models)
        assert "Model:" in body
        assert "Architect:" not in body


# ---------------------------------------------------------------------------
# Planning token usage reaches run_analysis on both entry points
# ---------------------------------------------------------------------------


class TestPlanningUsageIsThreaded:
    """Planning runs outside ``run_analysis`` on both the ``analyze`` command
    and the REPL's ``/analyze``. Whichever entry point is used must hand the
    planning call's usage back in, or the run's totals and the manifest's
    ``planning`` phase silently lose it.
    """

    @staticmethod
    def _capture(monkeypatch, entry: str):
        """Run one entry point with everything after planning stubbed out.

        Returns the ``usage`` object handed to ``create_analysis_plan`` and
        the ``planning_usage`` kwarg handed to ``run_analysis``.
        """
        from unittest.mock import MagicMock

        from stride_gpt.core.schemas import AnalysisPlan, AnalysisReport, LLMResponse, Subsystem

        seen: dict = {}
        plan = AnalysisPlan(
            target_path="/tmp", overall_description="d",
            subsystems=[Subsystem(name="A", description="d", key_files=[], focus_areas=[])],
        )

        def fake_create_plan(models, target, *, usage=None):
            seen["create_usage"] = usage
            if usage is not None:
                usage.record(LLMResponse(content="", prompt_tokens=500, completion_tokens=50))
            return plan

        def fake_run_analysis(**kwargs):
            seen["planning_usage"] = kwargs.get("planning_usage")
            return AnalysisReport(plan=plan, findings=[], metadata={})

        monkeypatch.setattr("stride_gpt.agent.loop.create_analysis_plan", fake_create_plan)
        monkeypatch.setattr("stride_gpt.agent.loop.run_analysis", fake_run_analysis)
        monkeypatch.setattr("stride_gpt.agent.report.save_report", lambda *_a, **_k: None)
        monkeypatch.setattr(cli, "console", MagicMock())

        models = ModelPair(worker=LLMConfig(provider="OpenAI API", model_name="m", api_key="k"))
        if entry == "repl":
            monkeypatch.setattr(cli, "config_to_model_pair", lambda _c: models)
            monkeypatch.setattr(cli, "_check_tier_api_keys", lambda *_a, **_k: True)
            monkeypatch.setattr(cli, "_check_lm_studio_context_for", lambda *_a, **_k: None)
            cli._handle_analyze({}, "/tmp -y")
        else:
            monkeypatch.setattr(cli, "_build_model_pair", lambda **_k: models)
            monkeypatch.setattr(cli, "load_config", lambda: {})
            monkeypatch.setattr(cli, "_check_lm_studio_context_for", lambda *_a, **_k: None)
            cli.analyze(path=cli.Path("/tmp"), auto_approve=True)
        return seen

    @pytest.mark.parametrize("entry", ["analyze", "repl"])
    def test_planning_usage_is_collected_and_passed_on(self, monkeypatch, entry):
        seen = self._capture(monkeypatch, entry)
        assert seen["create_usage"] is not None, (
            f"{entry}: create_analysis_plan was called without usage="
        )
        assert seen["planning_usage"] is seen["create_usage"], (
            f"{entry}: run_analysis did not receive the planning usage"
        )
        assert seen["planning_usage"].total_tokens == 550


# ---------------------------------------------------------------------------
# Plan approval — cost estimate and dropping subsystems (issue #198)
# ---------------------------------------------------------------------------


class TestParseSubsystemSelection:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("2", {2}),
            ("2 4", {2, 4}),
            ("2,4", {2, 4}),
            (" 3 , 1 ", {1, 3}),
            ("", set()),
            ("2 2", {2}),
        ],
    )
    def test_valid_selections(self, text, expected):
        chosen, invalid = cli._parse_subsystem_selection(text, 5)
        assert chosen == expected
        assert invalid == []

    @pytest.mark.parametrize("text", ["0", "6", "-1", "x", "two"])
    def test_out_of_range_and_non_numbers_are_reported(self, text):
        chosen, invalid = cli._parse_subsystem_selection(text, 5)
        assert chosen == set()
        assert invalid == [text]


class TestPlanApproval:
    """The approval prompt is where a run's cost becomes the user's choice:
    it has to show what the plan will cost and let them shrink it."""

    @staticmethod
    def _plan():
        from stride_gpt.core.schemas import AnalysisPlan, Subsystem

        return AnalysisPlan(
            target_path="/tmp/app",
            overall_description="d",
            subsystems=[
                Subsystem(name=n, description="d", key_files=[], focus_areas=[])
                for n in ("Auth", "API", "Storage")
            ],
        )

    @staticmethod
    def _console(monkeypatch, tmp_path, answers):
        """Stub the console with scripted answers, and empty cost history."""
        from unittest.mock import MagicMock

        fake = MagicMock()
        fake.input.side_effect = answers
        monkeypatch.setattr(cli, "console", fake)
        monkeypatch.setattr("stride_gpt.config.REPORTS_DIR", tmp_path / "no-reports")
        return fake

    @staticmethod
    def _printed(fake) -> str:
        return "\n".join(str(call.args[0]) for call in fake.print.call_args_list if call.args)

    def test_print_plan_shows_an_estimate(self, monkeypatch, tmp_path):
        fake = self._console(monkeypatch, tmp_path, [])
        cli._print_plan(self._plan(), tmp_path)
        printed = self._printed(fake)
        assert "Estimated cost:" in printed
        assert "3 subsystems" in printed

    def test_yes_approves_the_plan_unchanged(self, monkeypatch, tmp_path):
        self._console(monkeypatch, tmp_path, ["y"])
        plan = self._plan()
        assert cli._approve_plan_interactively(plan, tmp_path) is plan

    @pytest.mark.parametrize("answer", ["n", "q", ""])
    def test_anything_else_cancels(self, monkeypatch, tmp_path, answer):
        self._console(monkeypatch, tmp_path, [answer])
        assert cli._approve_plan_interactively(self._plan(), tmp_path) is None

    def test_dropping_shrinks_the_plan_and_reprints_the_estimate(
        self, monkeypatch, tmp_path
    ):
        fake = self._console(monkeypatch, tmp_path, ["d", "2", "y"])
        approved = cli._approve_plan_interactively(self._plan(), tmp_path)
        assert [s.name for s in approved.subsystems] == ["Auth", "Storage"]
        printed = self._printed(fake)
        assert "Dropped: API" in printed
        # The estimate is re-shown for the smaller plan, or dropping tells the
        # user nothing about what they saved.
        assert "2 subsystems" in printed

    def test_dropping_every_subsystem_is_refused(self, monkeypatch, tmp_path):
        fake = self._console(monkeypatch, tmp_path, ["d", "1 2 3", "y"])
        approved = cli._approve_plan_interactively(self._plan(), tmp_path)
        assert len(approved.subsystems) == 3
        assert "drops every subsystem" in self._printed(fake)

    def test_unrecognised_numbers_are_reported_and_drop_nothing(
        self, monkeypatch, tmp_path
    ):
        fake = self._console(monkeypatch, tmp_path, ["d", "9 banana", "y"])
        approved = cli._approve_plan_interactively(self._plan(), tmp_path)
        assert len(approved.subsystems) == 3
        assert "Not a subsystem number" in self._printed(fake)

    def test_auto_approve_never_prompts_and_runs_the_full_plan(
        self, monkeypatch, tmp_path
    ):
        fake = self._console(monkeypatch, tmp_path, [])
        plan = self._plan()
        monkeypatch.setattr(
            "stride_gpt.agent.loop.create_analysis_plan",
            lambda *_a, **_k: plan,
        )
        from unittest.mock import MagicMock

        resolved = cli._resolve_analysis_plan(
            MagicMock(),
            tmp_path,
            checkpoint=None,
            auto_approve=True,
            progress=MagicMock(),
        )
        assert resolved == (plan, "planner")
        fake.input.assert_not_called()

    def test_the_approved_plan_is_what_reaches_the_run(self, monkeypatch, tmp_path):
        """Dropping at the prompt has to change what gets analysed, not just
        what the estimate says."""
        from unittest.mock import MagicMock

        fake = self._console(monkeypatch, tmp_path, ["d", "1", "y"])
        monkeypatch.setattr(
            "stride_gpt.agent.loop.create_analysis_plan",
            lambda *_a, **_k: self._plan(),
        )
        plan, _ = cli._resolve_analysis_plan(
            MagicMock(),
            tmp_path,
            checkpoint=None,
            auto_approve=False,
            progress=MagicMock(),
        )
        assert [s.name for s in plan.subsystems] == ["API", "Storage"]
        assert fake.input.call_count == 3


class TestArchiveRunManifest:
    """Cost history has to accumulate on its own. A manifest was previously
    written only next to a ``-o`` report, so a user who never passed ``-o``
    would get the default estimate forever (#198)."""

    @staticmethod
    def _report(target: Path):
        from stride_gpt.core.schemas import (
            AnalysisPlan,
            AnalysisReport,
            Subsystem,
            SubsystemFinding,
            TokenUsage,
        )

        plan = AnalysisPlan(
            target_path=str(target),
            overall_description="d",
            subsystems=[
                Subsystem(name=n, description="d", key_files=[], focus_areas=[])
                for n in ("Auth", "API")
            ],
        )
        findings = [
            SubsystemFinding(
                subsystem="Auth",
                threats=[],
                token_usage=TokenUsage(prompt_tokens=100_000, completion_tokens=20_000),
            ),
            SubsystemFinding(
                subsystem="API",
                threats=[],
                token_usage=TokenUsage(prompt_tokens=150_000, completion_tokens=30_000),
            ),
        ]
        return plan, AnalysisReport(plan=plan, findings=findings, metadata={})

    def _run_analyze(self, monkeypatch, tmp_path, reports_dir):
        from unittest.mock import MagicMock

        target = tmp_path / "project"
        target.mkdir()
        plan, report = self._report(target)

        monkeypatch.setattr(
            "stride_gpt.agent.loop.create_analysis_plan", lambda *_a, **_k: plan
        )
        monkeypatch.setattr(
            "stride_gpt.agent.loop.run_analysis", lambda **_k: report
        )
        monkeypatch.setattr("stride_gpt.config.REPORTS_DIR", reports_dir)
        monkeypatch.setattr(cli, "console", MagicMock())
        models = ModelPair(
            worker=LLMConfig(provider="OpenAI API", model_name="m", api_key="k")
        )
        monkeypatch.setattr(cli, "_build_model_pair", lambda **_k: models)
        monkeypatch.setattr(cli, "load_config", lambda: {})
        monkeypatch.setattr(cli, "_check_lm_studio_context_for", lambda *_a, **_k: None)
        cli.analyze(path=target, auto_approve=True)
        return target

    def test_auto_save_writes_a_run_manifest(self, monkeypatch, tmp_path):
        from stride_gpt.agent.persistence import load_run_manifests, target_identity

        reports = tmp_path / "reports"
        target = self._run_analyze(monkeypatch, tmp_path, reports)

        manifests = load_run_manifests(reports / "analyze")
        assert len(manifests) == 1
        assert manifests[0].target_id == target_identity(target)
        assert manifests[0].mode == "analyze"

    def test_the_next_runs_estimate_uses_it(self, monkeypatch, tmp_path):
        """End to end: a finished run's per-subsystem cost is what the next
        run's approval prompt quotes."""
        from stride_gpt.agent.estimate import estimate_plan_cost

        reports = tmp_path / "reports"
        target = self._run_analyze(monkeypatch, tmp_path, reports)

        estimate = estimate_plan_cost(subsystem_count=3, target=target)
        assert estimate.from_history
        assert estimate.sample_size == 2
        # mean(120_000, 180_000) x 3 subsystems
        assert estimate.per_subsystem_tokens == 150_000
        assert estimate.total_tokens == 450_000
