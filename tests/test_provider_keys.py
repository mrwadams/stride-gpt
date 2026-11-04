"""Tripwire tests for the provider -> session-state API-key mapping.

The web UI resolves each provider's API key from ``st.session_state`` via
``apps/web/provider_keys.PROVIDER_API_KEY_STATE`` (used by the sidebar, the DFD
tab, and the guided-draft resolver). If a provider is added to the registry in
``stride_gpt.models`` but not to that map, its guided draft / key lookup would
silently fall back or fail. These tests fail if the two ever drift.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# apps/web isn't a package on the default path; add it so we can import the map.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps" / "web"))

import provider_keys
from provider_keys import PROVIDER_API_KEY_STATE, resolve_active_llm_config

from stride_gpt.models import PROVIDERS


def test_every_api_key_provider_is_mapped():
    """Every registry provider that authenticates with an API key is mapped."""
    for info in PROVIDERS.values():
        # LM Studio authenticates via a custom endpoint (api_base) plus an
        # optional key, and is handled separately by resolve_active_llm_config.
        if info.needs_api_base or not info.needs_api_key:
            continue
        assert info.provider_key in PROVIDER_API_KEY_STATE, (
            f"Provider {info.provider_key!r} is in stride_gpt.models.PROVIDERS but "
            f"missing from PROVIDER_API_KEY_STATE (apps/web/provider_keys.py). "
            f"Add its session-state key."
        )


def test_no_stale_mappings():
    """Every mapped provider still exists in the registry."""
    valid_provider_keys = {info.provider_key for info in PROVIDERS.values()}
    for provider_key in PROVIDER_API_KEY_STATE:
        assert provider_key in valid_provider_keys, (
            f"PROVIDER_API_KEY_STATE maps {provider_key!r}, which is not a known "
            f"provider in stride_gpt.models.PROVIDERS."
        )


@pytest.fixture
def session_state(monkeypatch):
    state: dict = {}
    monkeypatch.setattr(provider_keys, "st", SimpleNamespace(session_state=state))
    return state


@pytest.mark.parametrize("provider, state_key", sorted(PROVIDER_API_KEY_STATE.items()))
def test_resolve_uses_the_providers_key(session_state, provider, state_key):
    session_state.update({"model_provider": provider, "selected_model": "m", state_key: "secret"})
    config = resolve_active_llm_config(response_format="json")
    assert (config.provider, config.model_name, config.api_key, config.api_base) == (
        provider,
        "m",
        "secret",
        None,
    )
    assert config.response_format == "json"


def test_resolve_lm_studio_uses_endpoint_and_optional_key(session_state):
    session_state.update(
        {
            "model_provider": "LM Studio Server",
            "selected_model": "local",
            "lm_studio_endpoint": "http://box:1234",
        }
    )
    config = resolve_active_llm_config()
    assert (config.api_base, config.api_key) == ("http://box:1234", "not-needed")


@pytest.mark.parametrize(
    "state",
    [
        {"model_provider": "OpenAI API", "openai_api_key": "secret"},
        {"model_provider": "OpenAI API", "selected_model": "m"},
        {"model_provider": "Unknown API", "selected_model": "m"},
    ],
    ids=["no-model", "no-key", "unknown-provider"],
)
def test_resolve_returns_none_without_model_or_key(session_state, state):
    session_state.update(state)
    assert resolve_active_llm_config() is None
