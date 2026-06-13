"""Provider routing for LiteLLM-backed scoring.

VulnScope follows STRIDE-GPT's pattern: every provider is reached through
LiteLLM, so the model string carries the provider prefix. Examples::

    anthropic/claude-sonnet-4-6
    openai/gpt-5.4
    gemini/gemini-3.1-pro-preview
    groq/llama-3.3-70b-versatile
    mistral/mistral-large-latest
    ollama/llama3.3                  # local, via --api-base
    openai/<model>                   # LM Studio / OpenAI-compatible, via --api-base

Bare names for the major hosted families (``claude-*``, ``gpt-*``,
``gemini-*``, ``mistral-*``) are normalised to their prefixed form so the
common case stays terse.
"""

from __future__ import annotations

import os

# Provider key -> candidate env vars holding its API key (first match wins).
_PROVIDER_ENV_VARS: dict[str, list[str]] = {
    "anthropic": ["ANTHROPIC_API_KEY"],
    "openai": ["OPENAI_API_KEY"],
    "gemini": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
    "groq": ["GROQ_API_KEY"],
    "mistral": ["MISTRAL_API_KEY"],
    "ollama": [],
    "lm_studio": [],
}

# Local providers reach a self-hosted endpoint and need no hosted API key.
LOCAL_PROVIDERS = frozenset({"ollama", "lm_studio"})

DEFAULT_OLLAMA_API_BASE = "http://localhost:11434"

# Gemini blocks security-related content under its default safety settings;
# relax them so vulnerability/threat analysis isn't refused. Mirrors STRIDE-GPT.
GEMINI_SAFETY_SETTINGS = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
]


def infer_provider(model: str) -> str:
    """Infer the LiteLLM provider key from a model string.

    Returns the prefix when one is present, else infers from the model family
    for the major hosted providers. Returns "" when the provider is unknown
    (e.g. a bare local model name).
    """
    m = model.strip().lower()
    if "/" in m:
        return m.split("/", 1)[0]
    if m.startswith("claude"):
        return "anthropic"
    if m.startswith(("gpt-", "gpt", "o1", "o3", "o4")):
        return "openai"
    if m.startswith("gemini"):
        return "gemini"
    if m.startswith(("mistral", "magistral", "ministral", "codestral")):
        return "mistral"
    return ""


def normalise_model(model: str) -> str:
    """Prepend the provider prefix for bare hosted-family names.

    Local models must already carry their prefix (e.g. ``ollama/llama3.3``);
    they are passed through unchanged.
    """
    m = model.strip()
    if "/" in m:
        return m
    provider = infer_provider(m)
    if provider and provider not in LOCAL_PROVIDERS:
        return f"{provider}/{m}"
    return m


def resolve_api_key(model: str, explicit: str | None) -> str | None:
    """Resolve the API key: explicit value first, then the provider's env vars."""
    if explicit:
        return explicit
    provider = infer_provider(model)
    for var in _PROVIDER_ENV_VARS.get(provider, []):
        value = os.environ.get(var)
        if value:
            return value
    return None


def is_local(model: str, api_base: str | None) -> bool:
    """A run is 'local' when it targets a local provider or a custom endpoint."""
    return infer_provider(model) in LOCAL_PROVIDERS or bool(api_base)


def default_api_base(model: str, api_base: str | None) -> str | None:
    """Supply Ollama's default endpoint when none was given."""
    if api_base:
        return api_base
    if infer_provider(model) == "ollama":
        return DEFAULT_OLLAMA_API_BASE
    return None


def is_gemini(model: str) -> bool:
    return infer_provider(model) == "gemini"
