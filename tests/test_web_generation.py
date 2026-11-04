"""Tests for the web UI's provider-agnostic generation helpers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# apps/web isn't a package on the default path; add it so we can import the helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps" / "web"))

import generation

from stride_gpt.core.schemas import LLMConfig
from tests.fakes import ScriptedLLM, reply

THREAT_MODEL_JSON = json.dumps(
    {
        "threat_model": [{"Threat Type": "Spoofing", "Scenario": "s", "Potential Impact": "i"}],
        "improvement_suggestions": ["Describe the auth flow"],
    }
)


@pytest.mark.parametrize(
    "provider", ["OpenAI API", "Anthropic API", "Google AI API", "Groq API", "LM Studio Server"]
)
def test_threat_model_output_is_the_same_for_every_provider(provider):
    config = LLMConfig(provider=provider, model_name="m", api_key="k")
    with ScriptedLLM([reply(THREAT_MODEL_JSON)]) as fake:
        output = generation.get_threat_model_output(config, "describe")

    assert output == {
        "threat_model": [{"Threat Type": "Spoofing", "Scenario": "s", "Potential Impact": "i"}],
        "improvement_suggestions": ["Describe the auth flow"],
    }
    assert fake.requests[0].config.provider == provider
    assert fake.requests[0].messages[-1] == {"role": "user", "content": "describe"}
