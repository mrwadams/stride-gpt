"""Tests for stride_gpt.config — model-pair conversion and API-key resolution."""

from __future__ import annotations

import json

import pytest

from stride_gpt.config import (
    config_to_model_pair,
    get_api_key,
    load_config,
    save_config,
)


@pytest.fixture
def single_tier_config():
    return {
        "worker_provider": "Anthropic",
        "worker_provider_key": "Anthropic API",
        "worker_model": "claude-sonnet-4-6",
        "worker_api_base": None,
        "worker_max_tokens": None,
    }


@pytest.fixture
def tiered_config():
    return {
        "worker_provider": "Anthropic",
        "worker_provider_key": "Anthropic API",
        "worker_model": "claude-sonnet-4-6",
        "worker_api_base": None,
        "worker_max_tokens": None,
        "architect_provider": "OpenAI",
        "architect_provider_key": "OpenAI API",
        "architect_model": "gpt-5",
        "architect_api_base": None,
        "architect_max_tokens": None,
    }


class TestConfigToModelPair:
    def test_returns_none_when_worker_missing(self):
        assert config_to_model_pair({}) is None

    def test_single_tier_yields_no_architect(self, single_tier_config, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-key")
        pair = config_to_model_pair(single_tier_config)
        assert pair is not None
        assert pair.architect is None
        assert pair.tiered is False
        assert pair.worker.model_name == "claude-sonnet-4-6"
        assert pair.worker.api_key == "ant-key"
        assert pair.for_architect() is pair.worker

    def test_tiered_yields_architect(self, tiered_config, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-key")
        monkeypatch.setenv("OPENAI_API_KEY", "oai-key")
        pair = config_to_model_pair(tiered_config)
        assert pair is not None
        assert pair.tiered
        assert pair.architect is not None
        assert pair.architect.model_name == "gpt-5"
        assert pair.architect.api_key == "oai-key"
        assert pair.worker.api_key == "ant-key"

    def test_null_architect_model_treated_as_single_tier(self, tiered_config, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-key")
        tiered_config["architect_model"] = None
        pair = config_to_model_pair(tiered_config)
        assert pair is not None
        assert pair.architect is None
        assert pair.tiered is False


class TestGetApiKey:
    def test_worker_reads_provider_env_var(self, single_tier_config, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "real-key")
        assert get_api_key(single_tier_config, tier="worker") == "real-key"

    def test_architect_reads_own_env_var(self, tiered_config, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-key")
        monkeypatch.setenv("OPENAI_API_KEY", "oai-key")
        assert get_api_key(tiered_config, tier="architect") == "oai-key"

    def test_architect_falls_back_to_worker_only_when_same_provider(self, monkeypatch):
        cfg = {
            "worker_provider": "Anthropic",
            "worker_provider_key": "Anthropic API",
            "architect_provider": "Anthropic",
            "architect_provider_key": "Anthropic API",
        }
        monkeypatch.setenv("ANTHROPIC_API_KEY", "shared-key")
        assert get_api_key(cfg, tier="architect") == "shared-key"

    def test_architect_does_not_reuse_key_across_providers(self, monkeypatch):
        cfg = {
            "worker_provider": "Anthropic",
            "worker_provider_key": "Anthropic API",
            "architect_provider": "OpenAI",
            "architect_provider_key": "OpenAI API",
        }
        monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-key")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        # Architect must NOT receive the Anthropic key.
        assert get_api_key(cfg, tier="architect") == ""


class TestLoadConfig:
    def test_returns_none_when_no_worker_model(self, tmp_path, monkeypatch):
        cfg_dir = tmp_path / ".stride-gpt"
        cfg_dir.mkdir()
        (cfg_dir / "config.json").write_text(json.dumps({"some_other_field": 1}))
        monkeypatch.setattr("stride_gpt.config.CONFIG_FILE", cfg_dir / "config.json")
        assert load_config() is None

    def test_round_trips_two_tier(self, tmp_path, monkeypatch, tiered_config):
        cfg_dir = tmp_path / ".stride-gpt"
        cfg_dir.mkdir()
        cfg_path = cfg_dir / "config.json"
        monkeypatch.setattr("stride_gpt.config.CONFIG_DIR", cfg_dir)
        monkeypatch.setattr("stride_gpt.config.CONFIG_FILE", cfg_path)

        save_config(tiered_config)
        loaded = load_config()
        assert loaded == tiered_config
