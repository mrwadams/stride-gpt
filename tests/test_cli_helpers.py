"""Tests for the pure / branchy helpers in stride_gpt.cli.

These functions decide which model and API key actually drive a run, so a
regression here silently runs the wrong tier or slips past a missing key.
They're tested in isolation (no Typer command invocation, no LLM calls) by
mocking the config layer.
"""

from __future__ import annotations

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
