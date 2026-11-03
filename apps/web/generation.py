"""Provider-agnostic generation calls for the web UI.

Each tab builds one ``LLMConfig`` for the active provider (see
``main.resolve_active_llm_config``) and calls the helper here, instead of
dispatching to a per-provider wrapper. The only thing the wrappers varied was
how a provider's thinking or reasoning output reached the UI, which
``surface_reasoning`` now handles for every provider.
"""

from __future__ import annotations

import streamlit as st

from stride_gpt.core.schemas import LLMConfig, LLMResponse
from stride_gpt.core.threat_model import generate_threat_model


def surface_reasoning(response: LLMResponse) -> None:
    """Show whichever thinking or reasoning output the provider returned.

    Core sets ``thinking`` for Anthropic with extended thinking on and for
    thinking-capable Gemini models. The tab renders it from session state so
    it survives reruns. Core sets ``reasoning`` for Groq's ``<think>`` output,
    which is shown inline.
    """
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    if response.reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(response.reasoning)


def get_threat_model_output(config: LLMConfig, prompt: str) -> dict:
    """Generate a threat model and surface the model's reasoning."""
    result, response = generate_threat_model(config, prompt)
    surface_reasoning(response)
    return {
        "threat_model": result.threat_model,
        "improvement_suggestions": result.improvement_suggestions,
    }
