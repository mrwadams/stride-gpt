"""Streamlit-facing provider wrappers for Data Flow Diagram generation.

Mirrors `apps/web/attack_tree.py`: thin per-provider wrappers around the
core `generate_dfd` / `parse_dfd_from_image` functions, with session-state
plumbing for thinking/reasoning displays.
"""

from __future__ import annotations

import streamlit as st

from stride_gpt.core.dfd import generate_dfd, parse_dfd_from_image
from stride_gpt.core.schemas import LLMConfig


__all__ = [
    "get_dfd_anthropic",
    "get_dfd_from_image_anthropic",
    "get_dfd_from_image_google",
    "get_dfd_from_image_openai",
    "get_dfd_google",
    "get_dfd_groq",
    "get_dfd_lm_studio",
    "get_dfd_mistral",
    "get_dfd_openai",
]


# ---------------------------------------------------------------------------
# Generation from a textual description
# ---------------------------------------------------------------------------


def get_dfd_openai(api_key: str, model_name: str, prompt: str) -> str:
    config = LLMConfig(provider="OpenAI API", model_name=model_name, api_key=api_key)
    mermaid, _ = generate_dfd(config, prompt)
    return mermaid


def get_dfd_anthropic(api_key: str, model_name: str, prompt: str) -> str:
    config = LLMConfig(
        provider="Anthropic API",
        model_name=model_name,
        api_key=api_key,
        use_thinking=st.session_state.get("use_thinking", False),
    )
    mermaid, response = generate_dfd(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return mermaid


def get_dfd_google(api_key: str, model_name: str, prompt: str) -> str:
    config = LLMConfig(provider="Google AI API", model_name=model_name, api_key=api_key)
    mermaid, response = generate_dfd(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return mermaid


def get_dfd_groq(api_key: str, model_name: str, prompt: str) -> str:
    config = LLMConfig(provider="Groq API", model_name=model_name, api_key=api_key)
    mermaid, response = generate_dfd(config, prompt)
    if response.reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(response.reasoning)
    return mermaid


def get_dfd_lm_studio(
    lm_studio_endpoint: str, model_name: str, prompt: str, api_key: str = "not-needed"
) -> str:
    config = LLMConfig(
        provider="LM Studio Server",
        model_name=model_name,
        api_key=api_key,
        api_base=lm_studio_endpoint,
    )
    mermaid, _ = generate_dfd(config, prompt)
    return mermaid


def get_dfd_mistral(api_key: str, model_name: str, prompt: str) -> str:
    config = LLMConfig(provider="Mistral API", model_name=model_name, api_key=api_key)
    mermaid, _ = generate_dfd(config, prompt)
    return mermaid


# ---------------------------------------------------------------------------
# Parsing a user-uploaded DFD image
# ---------------------------------------------------------------------------


def get_dfd_from_image_openai(api_key: str, model_name: str, base64_image: str) -> str:
    config = LLMConfig(provider="OpenAI API", model_name=model_name, api_key=api_key)
    mermaid, _ = parse_dfd_from_image(config, base64_image)
    return mermaid


def get_dfd_from_image_anthropic(
    api_key: str, model_name: str, base64_image: str, media_type: str = "image/png"
) -> str:
    config = LLMConfig(provider="Anthropic API", model_name=model_name, api_key=api_key)
    mermaid, _ = parse_dfd_from_image(config, base64_image, media_type=media_type)
    return mermaid


def get_dfd_from_image_google(api_key: str, model_name: str, base64_image: str) -> str:
    config = LLMConfig(provider="Google AI API", model_name=model_name, api_key=api_key)
    mermaid, _ = parse_dfd_from_image(config, base64_image)
    return mermaid
