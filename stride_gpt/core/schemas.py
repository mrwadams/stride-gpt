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
    response_format: str | dict = "text"  # "text", "json", or a JSON schema dict


@dataclass
class ToolCallResult:
    """A single tool call extracted from an LLM response."""

    id: str
    function_name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """Normalized response from any LLM provider."""

    content: str  # The main text response
    thinking: str | None = None  # Extended thinking (Anthropic/Google)
    reasoning: str | None = None  # <think> tag reasoning (Groq/DeepSeek)
    model: str = ""  # Model that actually responded
    tool_calls: list[ToolCallResult] | None = None


@dataclass
class ThreatModelOutput:
    """Parsed output from threat model generation."""

    threat_model: list[dict[str, Any]] = field(default_factory=list)
    improvement_suggestions: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent schemas
# ---------------------------------------------------------------------------


class Subsystem(BaseModel):
    """A subsystem identified for STRIDE analysis."""

    name: str
    description: str
    key_files: list[str]
    focus_areas: list[str]


class AnalysisPlan(BaseModel):
    """Structured plan for agentic codebase analysis."""

    target_path: str
    overall_description: str
    subsystems: list[Subsystem]


class SubsystemFinding(BaseModel):
    """Threat findings for a single subsystem."""

    subsystem: str
    threats: list[dict[str, Any]]
    improvement_suggestions: list[str] = []
    files_analyzed: list[str] = []


class AnalysisReport(BaseModel):
    """Complete analysis report from an agentic run."""

    plan: AnalysisPlan
    findings: list[SubsystemFinding]
    cross_cutting_threats: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
