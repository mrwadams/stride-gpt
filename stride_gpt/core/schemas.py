"""Data models for LLM configuration and responses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel


class LLMConfig(BaseModel):
    """Configuration for an LLM call. Constructed by UI layer from session state."""

    provider: str  # "OpenAI API", "Anthropic API", "Google AI API", etc.
    model_name: str  # bare name e.g. "gpt-5.4", "claude-sonnet-4-6"
    api_key: str  # BYOK key, passed per-call
    api_base: str | None = None  # For LM Studio custom endpoints
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
    # Set when the model's arguments couldn't be parsed into a JSON object.
    # ``arguments`` is then ``{}`` and the call must not be executed.
    parse_error: str | None = None


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
    llm_calls: int = 0
    tool_calls: int = 0
    tools_used: dict[str, int] = field(default_factory=dict)
    # Names of reference cards the agent loaded via ``load_reference``.
    # Populated by the /quick agent loop so the run manifest can record
    # which cards actually shaped the output.
    references_loaded: list[str] = field(default_factory=list)


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
    # Planner-detected application type. The agent uses this as a hint for
    # which OWASP reference cards to load during per-subsystem analysis.
    detected_app_type: Literal["web", "genai", "agentic"] = "web"


# Why a subsystem stopped. A closed set, so a consumer of findings.json can
# tell a clean analysis with nothing to report from one that crashed:
#
# * ``completed`` — the model called ``finish`` (or answered in full).
# * ``budget_exhausted`` — the call/tool budget ran out and the grace round ran.
# * ``parse_failed`` — the model ended on text that carried no usable JSON and
#   nothing had come through the reporting tools, so the finding is empty.
# * ``error`` — the subsystem raised; see ``error_class``.
# * ``skipped`` — the run budget ran out before this subsystem started.
SubsystemOutcome = Literal[
    "completed", "budget_exhausted", "parse_failed", "error", "skipped"
]

# What kind of failure an ``error`` outcome was, classified from the exception
# rather than from its message text. See ``stride_gpt.agent.errors``.
ErrorClass = Literal[
    "context_overflow", "rate_limited", "auth", "provider_error", "unexpected"
]

# Outcomes where the model really did analyse the subsystem. A grace round
# still produces a genuine finding, so it doesn't make a run partial.
ANALYSED_OUTCOMES: frozenset[str] = frozenset({"completed", "budget_exhausted"})


class SubsystemFinding(BaseModel):
    """Threat findings for a single subsystem."""

    subsystem: str
    threats: list[dict[str, Any]]
    improvement_suggestions: list[str] = []
    files_analyzed: list[str] = []
    # Defaults to ``completed`` so a findings.json written before outcomes
    # existed still loads — a run that recorded a finding at all had reached
    # the subsystem.
    outcome: SubsystemOutcome = "completed"
    error_class: ErrorClass | None = None


def count_outcomes(findings: list[SubsystemFinding]) -> dict[str, int]:
    """Per-outcome subsystem counts, omitting outcomes that didn't occur."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.outcome] = counts.get(finding.outcome, 0) + 1
    return counts


def count_analysed(findings: list[SubsystemFinding]) -> int:
    """How many subsystems the model actually analysed."""
    return sum(1 for f in findings if f.outcome in ANALYSED_OUTCOMES)


class AnalysisReport(BaseModel):
    """Complete analysis report from an agentic run."""

    plan: AnalysisPlan
    findings: list[SubsystemFinding]
    cross_cutting_threats: list[dict[str, Any]] = []
    # System-level Data Flow Diagram in Mermaid `flowchart` form. Generated
    # during synthesis from the full set of subsystem findings. None when
    # generation was skipped or failed — DFD is auxiliary, not load-bearing.
    data_flow_diagram: str | None = None
    metadata: dict[str, Any] = {}


class ModelPair(BaseModel):
    """Two-tier model assignment for a single analysis run.

    Worker handles bulk/repetitive calls (per-subsystem agentic iteration,
    JSON-coercion retries). Architect handles reasoning-heavy moments
    (planning, cross-cutting synthesis, context summarization). When
    architect is None, worker is used for everything.
    """

    worker: LLMConfig
    architect: LLMConfig | None = None

    def for_architect(self) -> LLMConfig:
        return self.architect or self.worker

    @property
    def tiered(self) -> bool:
        return self.architect is not None
