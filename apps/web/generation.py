"""Provider-agnostic generation calls for the web UI.

Each tab builds one ``LLMConfig`` for the active provider (see
``main.resolve_active_llm_config``) and calls the helper here, instead of
dispatching to a per-provider wrapper.
"""

from __future__ import annotations

from stride_gpt.core.schemas import LLMConfig
from stride_gpt.core.threat_model import generate_threat_model


def get_threat_model_output(config: LLMConfig, prompt: str) -> dict:
    """Generate a threat model with the active provider."""
    result, _response = generate_threat_model(config, prompt)
    return {
        "threat_model": result.threat_model,
        "improvement_suggestions": result.improvement_suggestions,
    }
