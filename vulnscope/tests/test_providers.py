"""Tests for multi-provider routing and the build_client credential logic."""

from __future__ import annotations

import pytest

from vulnscope.config import Config
from vulnscope.pipeline import build_client
from vulnscope.providers import (
    DEFAULT_OLLAMA_API_BASE,
    default_api_base,
    infer_provider,
    is_gemini,
    is_local,
    normalise_model,
    resolve_api_key,
)


class TestInferProvider:
    @pytest.mark.parametrize(
        "model,expected",
        [
            ("anthropic/claude-sonnet-4-6", "anthropic"),
            ("openai/gpt-5.4", "openai"),
            ("gemini/gemini-3.1-pro-preview", "gemini"),
            ("groq/llama-3.3-70b-versatile", "groq"),
            ("ollama/llama3.3", "ollama"),
            ("claude-sonnet-4-6", "anthropic"),
            ("gpt-5.4", "openai"),
            ("gemini-3.1-pro-preview", "gemini"),
            ("mistral-large-latest", "mistral"),
            ("some-random-local-model", ""),
        ],
    )
    def test_infer(self, model, expected):
        assert infer_provider(model) == expected


class TestNormaliseModel:
    def test_prefixes_bare_hosted_names(self):
        assert normalise_model("claude-sonnet-4-6") == "anthropic/claude-sonnet-4-6"
        assert normalise_model("gpt-5.4") == "openai/gpt-5.4"

    def test_passes_through_prefixed(self):
        assert normalise_model("groq/llama-3.3-70b-versatile") == "groq/llama-3.3-70b-versatile"

    def test_leaves_unknown_bare_names(self):
        assert normalise_model("my-local-model") == "my-local-model"


class TestResolveApiKey:
    def test_explicit_wins(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
        assert resolve_api_key("claude-sonnet-4-6", "explicit") == "explicit"

    def test_reads_provider_env_var(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
        assert resolve_api_key("openai/gpt-5.4", None) == "sk-openai"

    def test_gemini_accepts_google_key(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("GOOGLE_API_KEY", "g-key")
        assert resolve_api_key("gemini/gemini-3.1-pro-preview", None) == "g-key"

    def test_returns_none_without_key(self, monkeypatch):
        monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
        assert resolve_api_key("mistral/mistral-large-latest", None) is None


class TestLocalAndEndpoint:
    def test_ollama_is_local(self):
        assert is_local("ollama/llama3.3", None) is True

    def test_custom_endpoint_is_local(self):
        assert is_local("openai/local-model", "http://localhost:1234/v1") is True

    def test_hosted_is_not_local(self):
        assert is_local("anthropic/claude-sonnet-4-6", None) is False

    def test_ollama_default_endpoint(self):
        assert default_api_base("ollama/llama3.3", None) == DEFAULT_OLLAMA_API_BASE

    def test_explicit_endpoint_respected(self):
        assert default_api_base("ollama/llama3.3", "http://host:1") == "http://host:1"

    def test_is_gemini(self):
        assert is_gemini("gemini-3.1-pro-preview") is True
        assert is_gemini("openai/gpt-5.4") is False


class TestBuildClient:
    def test_offline_returns_none(self):
        assert build_client(Config(offline=True)) is None

    def test_no_key_for_hosted_returns_none(self, monkeypatch):
        for var in ("ANTHROPIC_API_KEY", "VULNSCOPE_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        assert build_client(Config(model="anthropic/claude-sonnet-4-6")) is None

    def test_local_endpoint_builds_client_without_key(self, monkeypatch):
        # Ollama needs no hosted key; a client should be built. This constructs
        # LiteLLMClient, which imports litellm lazily — skip if unavailable.
        pytest.importorskip("litellm")
        monkeypatch.delenv("VULNSCOPE_API_KEY", raising=False)
        client = build_client(Config(model="ollama/llama3.3"))
        assert client is not None
        assert client.model == "ollama/llama3.3"

    def test_hosted_with_key_builds_client(self, monkeypatch):
        pytest.importorskip("litellm")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        client = build_client(Config(model="claude-sonnet-4-6"))
        assert client is not None
        assert client.model == "anthropic/claude-sonnet-4-6"
