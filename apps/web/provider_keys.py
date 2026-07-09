"""Provider → Streamlit session-state API-key mapping.

Single source of truth for "which session-state key holds this provider's API
key". Shared by the sidebar, the Data Flow Diagram tab, and the guided-draft
resolver in ``main.py``, and cross-checked against the provider registry by
``tests/test_provider_keys.py`` so a newly added provider can't silently miss a
mapping.

LM Studio is intentionally absent: it authenticates via a custom endpoint
(``api_base``) plus an optional key, so it is handled separately by callers.
"""

from __future__ import annotations

# provider_key (LLMConfig.provider) -> st.session_state key holding the API key.
PROVIDER_API_KEY_STATE: dict[str, str] = {
    "OpenAI API": "openai_api_key",
    "Anthropic API": "anthropic_api_key",
    "Google AI API": "google_api_key",
    "Mistral API": "mistral_api_key",
    "Groq API": "groq_api_key",
    "DeepSeek API": "deepseek_api_key",
}
