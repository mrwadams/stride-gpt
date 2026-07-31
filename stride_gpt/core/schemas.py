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


class SubsystemFinding(BaseModel):
    """Threat findings for a single subsystem."""

    subsystem: str
    threats: list[dict[str, Any]]
    improvement_suggestions: list[str] = []
    files_analyzed: list[str] = []


class VerifierResult(BaseModel):
    """One verifier's adjudication of a single generated threat.

    Attached to a surviving threat under its ``verifier`` key and carried on
    each ``AnalysisReport.refuted_threats`` entry. ``UNPARSEABLE`` is the safe
    undetermined verdict for a verifier reply we could not read as JSON — it is
    never coerced to PLAUSIBLE (which would silently promote an unverified
    threat) nor to NOT_PLAUSIBLE (which would silently drop a real one).
    """

    verdict: Literal["PLAUSIBLE", "NOT_PLAUSIBLE", "UNPARSEABLE"]
    confidence: int = 0  # 0-10; 0 when UNPARSEABLE
    reason: str = ""
    evidence: list[str] = []  # "file:line" refs the verifier opened
    reasoning: str = ""
    verifier_model: str = ""
    elapsed_seconds: float = 0.0


class VerifyConfig(BaseModel):
    """Configuration for the adversarial verification phase (opt-in via --verify)."""

    enabled: bool = False
    min_confidence: int = 7  # PLAUSIBLE below this is dropped (LOW_CONFIDENCE)
    verifier_model: Literal["worker", "architect"] = "worker"
    parallel: int = 4  # ThreadPoolExecutor workers for per-threat verification


class AnalysisReport(BaseModel):
    """Complete analysis report from an agentic run."""

    plan: AnalysisPlan
    findings: list[SubsystemFinding]
    cross_cutting_threats: list[dict[str, Any]] = []
    # Threats that failed verification when --verify was passed. One entry per
    # refuted threat (per-subsystem and cross-cutting), each carrying the
    # original threat, its VerifierResult, and a drop_reason. Survivors stay
    # inline in ``findings[].threats`` / ``cross_cutting_threats``. Empty when
    # verification was not run — so a report without --verify is unchanged.
    refuted_threats: list[dict[str, Any]] = []
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
