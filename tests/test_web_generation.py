"""Tests for the web UI's provider-agnostic generation helpers."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# apps/web isn't a package on the default path; add it so we can import the helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps" / "web"))

import generation

from stride_gpt.core.schemas import LLMConfig, LLMResponse
from tests.fakes import ScriptedLLM, Step

THREAT_MODEL_JSON = json.dumps(
    {
        "threat_model": [{"Threat Type": "Spoofing", "Scenario": "s", "Potential Impact": "i"}],
        "improvement_suggestions": ["Describe the auth flow"],
    }
)


@pytest.fixture
def fake_st(monkeypatch):
    st = MagicMock()
    st.session_state = {}
    monkeypatch.setattr(generation, "st", st)
    return st


def _config(provider: str) -> LLMConfig:
    return LLMConfig(provider=provider, model_name="m", api_key="k")


@pytest.mark.parametrize(
    "provider", ["OpenAI API", "Anthropic API", "Google AI API", "Groq API", "LM Studio Server"]
)
def test_threat_model_output_is_the_same_for_every_provider(fake_st, provider):
    with ScriptedLLM([Step(LLMResponse(content=THREAT_MODEL_JSON))]) as fake:
        output = generation.get_threat_model_output(_config(provider), "describe")

    assert output["threat_model"][0]["Threat Type"] == "Spoofing"
    assert output["improvement_suggestions"] == ["Describe the auth flow"]
    assert fake.requests[0].config.provider == provider
    assert fake.requests[0].messages[-1] == {"role": "user", "content": "describe"}
    assert fake_st.session_state == {}
    fake_st.expander.assert_not_called()


def test_thinking_is_stored_for_the_tab_to_render(fake_st):
    response = LLMResponse(content=THREAT_MODEL_JSON, thinking="weighing threats")
    with ScriptedLLM([Step(response)]):
        generation.get_threat_model_output(_config("Anthropic API"), "describe")

    assert fake_st.session_state["last_thinking_content"] == "weighing threats"
    fake_st.expander.assert_not_called()


def test_reasoning_is_shown_inline(fake_st):
    response = LLMResponse(content=THREAT_MODEL_JSON, reasoning="step by step")
    with ScriptedLLM([Step(response)]):
        generation.get_threat_model_output(_config("Groq API"), "describe")

    fake_st.expander.assert_called_once()
    fake_st.write.assert_called_once_with("step by step")
    assert "last_thinking_content" not in fake_st.session_state
