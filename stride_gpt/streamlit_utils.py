"""Utilities for bridging the Streamlit UI to the agentic analysis engine."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import streamlit as st

from stride_gpt.core.schemas import LLMConfig

_API_KEY_MAP = {
    "OpenAI API": "openai_api_key",
    "Anthropic API": "anthropic_api_key",
    "Google AI API": "google_api_key",
    "Mistral API": "mistral_api_key",
    "Groq API": "groq_api_key",
    "Ollama": None,
    "LM Studio Server": "lm_studio_api_key",
}

_API_BASE_MAP = {
    "Ollama": "ollama_endpoint",
    "LM Studio Server": "lm_studio_endpoint",
}


def build_llm_config_from_session() -> LLMConfig:
    """Build an LLMConfig from Streamlit session state.

    Reads the sidebar selections (provider, model, API key, etc.) and maps
    them into the LLMConfig expected by the agentic analysis engine.
    """
    provider = st.session_state.get("model_provider", "OpenAI API")
    model_name = st.session_state.get("selected_model", "")

    api_key_field = _API_KEY_MAP.get(provider)
    api_key = st.session_state.get(api_key_field, "") if api_key_field else ""

    api_base_field = _API_BASE_MAP.get(provider)
    api_base = st.session_state.get(api_base_field) if api_base_field else None

    use_thinking = st.session_state.get("use_thinking", False) if provider == "Anthropic API" else False

    return LLMConfig(
        provider=provider,
        model_name=model_name,
        api_key=api_key,
        api_base=api_base,
        use_thinking=use_thinking,
    )


def clone_github_repo(url: str) -> Path:
    """Clone a GitHub repository to a temporary directory.

    Returns the path to the cloned repo.
    Raises ValueError on failure.
    """
    tmp_dir = tempfile.mkdtemp(prefix="stride_gpt_")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, tmp_dir],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Failed to clone repository: {e.stderr.strip()}") from e
    except subprocess.TimeoutExpired:
        raise ValueError("Git clone timed out after 120 seconds.")
    return Path(tmp_dir)
