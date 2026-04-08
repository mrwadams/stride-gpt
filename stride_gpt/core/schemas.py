"""Data models for LLM configuration and responses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel


class LLMConfig(BaseModel):
    """Configuration for an LLM call. Constructed by UI layer from session state."""

    provider: str  # "OpenAI API", "Anthropic API", "Google AI API", etc.
    model_name: str  # bare name e.g. "gpt-5.2", "claude-sonnet-4-5-20250929"
    api_key: str  # BYOK key, passed per-call
    api_base: str | None = None  # For Ollama/LM Studio custom endpoints
    timeout: int | None = None  # Request timeout in seconds
    use_thinking: bool = False  # Anthropic extended thinking
    max_tokens: int | None = None  # Override default max tokens
    response_format: str = "text"  # "text" or "json"


@dataclass
class LLMResponse:
    """Normalized response from any LLM provider."""

    content: str  # The main text response
    thinking: str | None = None  # Extended thinking (Anthropic/Google)
    reasoning: str | None = None  # <think> tag reasoning (Groq/DeepSeek)
    model: str = ""  # Model that actually responded


@dataclass
class ThreatModelOutput:
    """Parsed output from threat model generation."""

    threat_model: list[dict[str, Any]] = field(default_factory=list)
    improvement_suggestions: list[str] = field(default_factory=list)
