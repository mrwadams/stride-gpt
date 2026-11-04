"""Provider → Streamlit session-state API-key mapping, and the active config.

Single source of truth for "which session-state key holds this provider's API
key". Shared by the sidebar and ``resolve_active_llm_config``, which every
generation tab uses to build its ``LLMConfig``. Cross-checked against the
provider registry by ``tests/test_provider_keys.py`` so a newly added provider
can't silently miss a mapping.

LM Studio is intentionally absent: it authenticates via a custom endpoint
(``api_base``) plus an optional key, so ``resolve_active_llm_config`` handles it
separately.
"""

from __future__ import annotations

import streamlit as st

from stride_gpt.core.schemas import LLMConfig

# provider_key (LLMConfig.provider) -> st.session_state key holding the API key.
PROVIDER_API_KEY_STATE: dict[str, str] = {
    "OpenAI API": "openai_api_key",
    "Anthropic API": "anthropic_api_key",
    "Google AI API": "google_api_key",
    "Mistral API": "mistral_api_key",
    "Groq API": "groq_api_key",
    "DeepSeek API": "deepseek_api_key",
    "OpenRouter API": "openrouter_api_key",
}


def resolve_active_llm_config(*, response_format="text"):
    """Build an LLMConfig for the provider/model/key currently in session state.

    Reads everything from session state, so any tab can reach the active model.
    Returns ``None`` when no model is selected or no usable key is available,
    letting callers show an error or fall back gracefully.
    """
    provider = st.session_state.get("model_provider", "OpenAI API")
    model_name = st.session_state.get("selected_model", "")
    if not model_name:
        return None

    api_base = None
    if provider == "LM Studio Server":
        api_key = st.session_state.get("lm_studio_api_key", "") or "not-needed"
        api_base = st.session_state.get("lm_studio_endpoint", "http://localhost:1234")
    else:
        state_key = PROVIDER_API_KEY_STATE.get(provider)
        if not state_key:
            return None
        api_key = st.session_state.get(state_key, "")
        if not api_key:
            return None

    return LLMConfig(
        provider=provider,
        model_name=model_name,
        api_key=api_key,
        api_base=api_base,
        response_format=response_format,
    )
