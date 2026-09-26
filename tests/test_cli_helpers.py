"""Tests for the pure / branchy helpers in stride_gpt.cli.

These functions decide which model and API key actually drive a run, so a
regression here silently runs the wrong tier or slips past a missing key.
They're tested in isolation (no Typer command invocation, no LLM calls) by
mocking the config layer.
"""

from __future__ import annotations

from typing import ClassVar

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
            ("openrouter/qwen3-max", "OpenRouter API", "qwen3-max"),
        ],
    )
    def test_known_prefixes(self, model, expected_provider, expected_name):
        provider, name = cli._resolve_provider(model)
        assert provider == expected_provider
        assert name == expected_name

    @pytest.mark.parametrize(
        "model, expected_name",
        [
            ("openrouter/anthropic/claude-opus-5", "anthropic/claude-opus-5"),
            ("openrouter/openai/gpt-5.5", "openai/gpt-5.5"),
            ("openrouter/google/gemini-3.5-flash", "google/gemini-3.5-flash"),
        ],
    )
    def test_openrouter_keeps_inner_vendor_prefix(self, model, expected_name):
        """Only the outer prefix is ours: OpenRouter slugs carry a vendor prefix
        of their own, and stripping it would route to the vendor direct."""
        provider, name = cli._resolve_provider(model)
        assert provider == "OpenRouter API"
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
        # cli.py loads ~/.stride-gpt/.env at import, so the developer's own
        # keys are in os.environ during tests. Clear the one this looks up.
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(typer.Exit) as exc:
            cli._build_model_pair(worker_model="anthropic/claude-x")
        assert exc.value.exit_code == 1

    def test_missing_worker_key_names_the_variable_to_set(self, monkeypatch, capsys):
        """'Set the appropriate env var (e.g. ANTHROPIC_API_KEY)' sent people
        to the wrong variable whenever the provider wasn't Anthropic."""
        monkeypatch.setattr(cli, "load_config", lambda: None)
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        with pytest.raises(typer.Exit):
            cli._build_model_pair(worker_model="deepseek/deepseek-v4-pro")
        printed = capsys.readouterr().out
        assert "DEEPSEEK_API_KEY" in printed
        assert "ANTHROPIC_API_KEY" not in printed

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


class TestWorkerKeyMatchesWorkerProvider:
    """--worker-model can name a provider the saved config doesn't.

    The key must follow the provider the flag names. Resolving it from
    config.json instead sent one provider's endpoint another provider's
    secret, which the fallback chain in ``get_api_key`` could widen to a key
    for a service the command never mentioned.
    """

    SAVED: ClassVar[dict[str, str]] = {
        "worker_provider": "DeepSeek",
        "worker_provider_key": "DeepSeek API",
        "worker_model": "deepseek-v4-pro",
    }

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        for var in (
            "STRIDE_GPT_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
            "GOOGLE_API_KEY", "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
            "MISTRAL_API_KEY", "GROQ_API_KEY",
        ):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setattr(cli, "load_config", lambda: dict(self.SAVED))

    def test_flag_provider_key_is_used_not_the_saved_one(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-saved")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-openrouter")
        pair = cli._build_model_pair(worker_model="openrouter/deepseek/deepseek-v4-pro")
        assert pair.worker.provider == "OpenRouter API"
        assert pair.worker.api_key == "sk-openrouter"

    def test_another_providers_key_is_never_substituted(self, monkeypatch):
        """With no key for the named provider, exit — never reach for
        ANTHROPIC_API_KEY and send it somewhere it doesn't belong."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
        with pytest.raises(typer.Exit) as exc:
            cli._build_model_pair(worker_model="openrouter/deepseek/deepseek-v4-pro")
        assert exc.value.exit_code == 1

    def test_explicit_key_still_wins(self, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-openrouter")
        pair = cli._build_model_pair(
            worker_model="openrouter/deepseek/deepseek-v4-pro", worker_api_key="sk-explicit"
        )
        assert pair.worker.api_key == "sk-explicit"

    def test_saved_config_path_keeps_its_fallback_chain(self, monkeypatch):
        """Without --worker-model nothing changes: the saved provider's key,
        and the legacy generic vars behind it, resolve as they always did."""
        monkeypatch.setenv("STRIDE_GPT_API_KEY", "sk-generic")
        pair = cli._build_model_pair()
        assert pair.worker.provider == "DeepSeek API"
        assert pair.worker.api_key == "sk-generic"

    def test_lm_studio_by_flag_needs_no_key(self, monkeypatch):
        """An unprefixed model is the OpenAI-compatible catch-all, but a saved
        LM Studio tier must still build with an empty key."""
        monkeypatch.setattr(
            cli, "load_config",
            lambda: {"worker_provider_key": "LM Studio Server", "worker_model": "local"},
        )
        pair = cli._build_model_pair()
        assert pair.worker.provider == "LM Studio Server"
        assert pair.worker.api_key == ""


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
