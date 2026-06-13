"""Tests for configuration and weight handling."""

from __future__ import annotations

import pytest

from vulnscope.config import Config, Weights


class TestWeights:
    def test_defaults_sum_to_one(self):
        w = Weights()
        total = (
            w.asset_criticality
            + w.threat_alignment
            + w.trust_boundary_exposure
            + w.stride_category_weight
        )
        assert total == pytest.approx(1.0)

    def test_normalised_sums_to_one(self):
        w = Weights(1, 1, 1, 1).normalised()
        assert w.asset_criticality == pytest.approx(0.25)

    def test_zero_weights_fall_back_to_defaults(self):
        w = Weights(0, 0, 0, 0).normalised()
        assert w.asset_criticality == pytest.approx(0.35)


class TestConfigFromEnv:
    def test_reads_env(self, monkeypatch):
        monkeypatch.setenv("VULNSCOPE_MODEL", "claude-test")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setenv("VULNSCOPE_ASSET_WEIGHT", "0.5")
        config = Config.from_env()
        assert config.model == "claude-test"
        assert config.api_key == "sk-test"
        assert config.weights.asset_criticality == 0.5

    def test_overrides_take_precedence(self, monkeypatch):
        monkeypatch.setenv("VULNSCOPE_MODEL", "from-env")
        config = Config.from_env(model="from-flag")
        assert config.model == "from-flag"

    def test_none_overrides_ignored(self, monkeypatch):
        monkeypatch.setenv("VULNSCOPE_MODEL", "from-env")
        config = Config.from_env(model=None)
        assert config.model == "from-env"

    def test_invalid_weight_env_falls_back(self, monkeypatch):
        monkeypatch.setenv("VULNSCOPE_ASSET_WEIGHT", "not-a-number")
        config = Config.from_env()
        assert config.weights.asset_criticality == 0.35
