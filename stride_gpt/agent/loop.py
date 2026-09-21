"""Core agent loop — plan, explore, analyze, synthesize."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich.console import Console

from stride_gpt.agent.context import ContextManager
from stride_gpt.agent.errors import classify_error
from stride_gpt.agent.evidence import normalise_path, summarise_checks, verify_evidence
from stride_gpt.agent.planner import create_plan, format_plan_for_display
from stride_gpt.agent.progress import ProgressCallback, RichProgress
from stride_gpt.agent.tools import (
    REPORTING_TOOL_NAMES,
    REPORTING_TOOLS,
    SUBSYSTEM_TOOLS,
    THREAT_ARG_TO_FIELD,
    execute_tool,
)
from stride_gpt.core.json_extract import extract_json_object
from stride_gpt.core.llm import call_llm, call_llm_with_tools
from stride_gpt.core.prompts import base_system_prompt
from stride_gpt.core.schemas import (
    ANALYSED_OUTCOMES,
    AnalysisPlan,
    AnalysisReport,
    LLMConfig,
    ModelPair,
    Subsystem,
    SubsystemFinding,
    SubsystemOutcome,
    ToolCallResult,
    count_analysed,
    count_outcomes,
)

logger = logging.getLogger(__name__)

# The agent's system prompt is the packaged `base.md` reference. It points
# the agent at `list_references` for runtime card discovery and
# `load_reference` for on-demand loading — progressive disclosure rather
# than eagerly stacking variant content. The planner's `detected_app_type`
# is still recorded in metadata but no longer hinted in the user prompt;
# the agent decides which cards apply from the catalogue.
AGENT_SYSTEM_PROMPT = base_system_prompt()

SYNTHESIS_PROMPT = """You are a security architect reviewing threat model findings from multiple subsystems.

Below are the per-subsystem STRIDE threat findings. Identify cross-cutting threats that span multiple subsystems — for example:
- Inconsistent authentication across subsystems
- Missing encryption for data flowing between components
- Shared secrets or credentials
- Common input validation gaps

Respond with a JSON object:
{
    "cross_cutting_threats": [
        {
            "Threat Type": "STRIDE category",
            "Scenario": "Cross-cutting threat scenario spanning multiple subsystems",
            "Potential Impact": "Systemic impact",
            "Affected Subsystems": ["subsystem1", "subsystem2"]
        }
    ]
}"""


def create_analysis_plan(models: ModelPair, target_path: Path) -> AnalysisPlan:
    """Run Phase 1 only: scan the codebase and generate an analysis plan.

    This is separated from run_analysis() so callers can inspect/approve
    the plan before committing to the full analysis. Uses the architect
    tier — planning is reasoning-heavy.
    """
    return create_plan(models.for_architect(), target_path)


def run_analysis(
    models: ModelPair,
    target_path: Path,
    *,
    plan: AnalysisPlan | None = None,
    max_llm_calls: int = 0,
    max_tool_calls: int = 0,
    auto_approve: bool = False,
    progress: ProgressCallback | None = None,
    console: Console | None = None,
    resume_findings: dict[str, SubsystemFinding] | None = None,
    on_checkpoint: Callable[[list[SubsystemFinding]], None] | None = None,
) -> AnalysisReport:
    """Run a full agentic threat model analysis on a codebase.

    Args:
        models: Worker + optional architect LLM configuration. Worker drives
            per-subsystem exploration; architect (if set) drives planning,
            cross-cutting synthesis, and context summarization.
        target_path: Path to the codebase root.
        plan: Pre-approved analysis plan. If None, creates one (Phase 1).
        max_llm_calls: Cap on total LLM calls (0 = unlimited). A subsystem
            that reaches it gets one final round on top, to report what it
            found — see ``_grace_round`` — so a run can exceed this by one
            call per subsystem that ran out.
        max_tool_calls: Cap on code exploration (0 = unlimited). Reporting a
            threat doesn't spend it: the cap bounds reading the code, and a
            model mid-report must not be cut off. ``metadata["tool_calls"]``
            still counts every call the model made.
        auto_approve: Skip interactive plan approval (only used when plan is None).
        progress: Progress callback for UI updates. Falls back to Rich console.
        console: Deprecated — use progress instead. Kept for backward compat.
        resume_findings: Subsystem name -> its checkpointed finding, from a
            ``--resume`` run. A subsystem present here is reused verbatim
            (no LLM call) instead of being analysed; every other subsystem
            in the plan runs as normal.
        on_checkpoint: Called with the findings list so far every time it
            changes (a subsystem finished, was skipped, or was reused), so
            the caller can persist a checkpoint. Not called for /quick-style
            callers that don't pass it.

    Returns:
        Complete AnalysisReport.
    """
    if progress is None:
        progress = RichProgress(console or Console())

    ctx = ContextManager(config=models.worker)
    llm_calls = 0
    # Two counters: ``tool_calls`` is what the run reports (every call the
    # model made), ``explore_calls`` is what the tool budget bounds. Letting
    # reporting spend the budget would mean a subsystem that finds more
    # threats leaves less exploration for the next one.
    tool_calls = 0
    explore_calls = 0
    # Names the agent loads via the ``load_reference`` tool. Surfaced on
    # ``report.metadata["references_loaded"]`` so the run manifest can record
    # which cards actually shaped the output.
    loaded_refs: set[str] = set()

    # --- Phase 1: Planning ---
    if plan is None:
        progress.phase_start("Phase 1", "Planning")
        progress.status("Scanning codebase and generating plan...")
        plan = create_plan(models.for_architect(), target_path)
        llm_calls += 1

        progress.status(format_plan_for_display(plan))

        if not auto_approve:  # noqa: SIM102 (trailing comment below belongs to this block)
            # When no plan is provided and auto_approve is False,
            # the caller should have handled approval. For backward compat
            # with CLI, we use Rich console input if available.
            if console is not None:
                response = console.input("[bold yellow]Approve this plan? (y/n/q): [/bold yellow]")
                if response.lower() not in ("y", "yes"):
                    progress.complete("Analysis cancelled.")
                    cancel_meta = _build_metadata(
                        models, plan, llm_calls=llm_calls, tool_calls=tool_calls,
                        findings=[], status="cancelled",
                    )
                    cancel_meta["references_loaded"] = sorted(loaded_refs)
                    return AnalysisReport(
                        plan=plan,
                        findings=[],
                        metadata=cancel_meta,
                    )
            # If no console and not auto_approve, proceed anyway
            # (caller should use the split API for interactive approval)

    # Report token budget so the user knows what context limit is in effect
    progress.token_budget(models.worker.model_name, ctx.context_window, source=ctx.budget_source.value)
    if models.tiered:
        from stride_gpt.config import friendly_provider

        architect = models.architect
        progress.status(
            f"Architect: {friendly_provider(architect.provider)}/{architect.model_name} "
            f"(planning, synthesis, summarization)"
        )

    # --- Phase 2: Per-subsystem analysis ---
    progress.phase_start("Phase 2", "Analyzing Subsystems")
    findings: list[SubsystemFinding] = []
    resumed_names: list[str] = []
    rerun_names: list[str] = []

    for i, subsystem in enumerate(plan.subsystems, 1):
        # A subsystem the checkpoint already completed costs nothing to
        # reuse, so it bypasses the budget checks below entirely — a spent
        # budget shouldn't stop a free reuse.
        if resume_findings and subsystem.name in resume_findings:
            finding = resume_findings[subsystem.name]
            findings.append(finding)
            resumed_names.append(subsystem.name)
            progress.subsystem_start(i, len(plan.subsystems), subsystem.name, subsystem.description)
            progress.status(f"Reusing checkpointed result for {subsystem.name}.")
            progress.subsystem_done(subsystem.name, len(finding.threats), finding.outcome)
            if on_checkpoint:
                on_checkpoint(findings)
            continue

        # A budget that runs out mid-plan used to drop the remaining
        # subsystems entirely, so the run's own N/M counts couldn't see them.
        # Each one is recorded as ``skipped`` instead: findings always match
        # the plan.
        if max_llm_calls and llm_calls >= max_llm_calls - 1:
            progress.limit_reached("LLM call", llm_calls, max_llm_calls)
            findings.extend(_skip_remaining(plan.subsystems[i - 1:], "LLM call", progress))
            if on_checkpoint:
                on_checkpoint(findings)
            break
        if max_tool_calls and explore_calls >= max_tool_calls:
            progress.limit_reached("tool call", explore_calls, max_tool_calls)
            findings.extend(_skip_remaining(plan.subsystems[i - 1:], "tool call", progress))
            if on_checkpoint:
                on_checkpoint(findings)
            break

        progress.subsystem_start(i, len(plan.subsystems), subsystem.name, subsystem.description)
        rerun_names.append(subsystem.name)

        # Pass remaining budget so a single subsystem can't starve later
        # subsystems (or the synthesis pass). 0 still means unlimited.
        remaining_llm = max_llm_calls - llm_calls if max_llm_calls else 0
        remaining_tool = max_tool_calls - explore_calls if max_tool_calls else 0

        try:
            sub_counts: dict[str, int] = {"llm": 0, "tool": 0, "explore": 0}
            finding = _analyze_subsystem(
                models=models,
                target_path=target_path,
                subsystem_name=subsystem.name,
                subsystem_description=subsystem.description,
                key_files=subsystem.key_files,
                focus_areas=subsystem.focus_areas,
                ctx=ctx,
                max_llm_calls=remaining_llm,
                max_tool_calls=remaining_tool,
                progress=progress,
                call_counts=sub_counts,
                loaded_refs=loaded_refs,
            )
            llm_calls += sub_counts["llm"]
            tool_calls += sub_counts["tool"]
            explore_calls += sub_counts["explore"]
            findings.append(finding)
            # Keyed on exploration, not total tool calls: a subsystem that
            # only reported threats still never looked at the code.
            if sub_counts.get("explore", 0) == 0:
                progress.no_tool_use_warning(subsystem.name)
            progress.subsystem_done(subsystem.name, len(finding.threats), finding.outcome)
            if on_checkpoint:
                on_checkpoint(findings)
        except Exception as e:
            partial = e.finding if isinstance(e, SubsystemAbortedError) else None
            # The counts were recorded before the exception escaped.
            llm_calls += sub_counts["llm"]
            tool_calls += sub_counts["tool"]
            explore_calls += sub_counts["explore"]
            error_class, reason = classify_error(
                e.cause if isinstance(e, SubsystemAbortedError) else e
            )
            progress.error(subsystem.name, reason)
            note = f"Analysis stopped early — {reason}"
            findings.append(
                SubsystemFinding(
                    subsystem=subsystem.name,
                    threats=partial.threats if partial else [],
                    improvement_suggestions=[
                        *(partial.improvement_suggestions if partial else []),
                        note,
                    ],
                    files_analyzed=partial.files_analyzed if partial else [],
                    outcome="error",
                    error_class=error_class,
                )
            )
            if on_checkpoint:
                on_checkpoint(findings)

    # Skipped subsystems are placeholders, not findings — synthesis and the
    # DFD must reason about what was actually looked at.
    analysed = [f for f in findings if f.outcome != "skipped"]

    # --- Phase 3: Synthesis ---
    cross_cutting: list[dict[str, Any]] = []
    if len(analysed) > 1 and (not max_llm_calls or llm_calls < max_llm_calls):
        progress.phase_start("Phase 3", "Synthesizing Cross-Cutting Threats")
        progress.status("Identifying cross-cutting threats...")
        cross_cutting = _synthesize(models, analysed)
        llm_calls += 1
        progress.synthesis_done(len(cross_cutting))

    # --- Phase 4: System-level DFD ---
    # Optional pass — gives the report a visual map of components and trust
    # boundaries. Wrapped in try/except so a bad DFD never nukes a good
    # report. Skipped when no findings exist or the call budget is spent.
    data_flow_diagram: str | None = None
    if analysed and (not max_llm_calls or llm_calls < max_llm_calls):
        progress.status("Generating system-level Data Flow Diagram...")
        try:
            data_flow_diagram = _generate_system_dfd(models, plan, analysed)
            llm_calls += 1
        except Exception:
            data_flow_diagram = None

    metadata = _build_metadata(
        models, plan, llm_calls=llm_calls, tool_calls=tool_calls,
        findings=findings, resumed_subsystems=resumed_names, rerun_subsystems=rerun_names,
    )
    metadata["references_loaded"] = sorted(loaded_refs)

    report = AnalysisReport(
        plan=plan,
        findings=findings,
        cross_cutting_threats=cross_cutting,
        data_flow_diagram=data_flow_diagram,
        metadata=metadata,
    )

    progress.complete(_run_summary_text(findings, cross_cutting, llm_calls, tool_calls))
    return report


def _run_summary_text(
    findings: list[SubsystemFinding],
    cross_cutting: list[dict[str, Any]],
    llm_calls: int,
    tool_calls: int,
) -> str:
    """The end-of-run console summary, counted by outcome.

    It used to count a subsystem as succeeded only if it found threats, so a
    clean subsystem with nothing to report was announced as a failure.
    """
    total_threats = sum(len(f.threats) for f in findings) + len(cross_cutting)
    counts = count_outcomes(findings)
    analysed = count_analysed(findings)

    headline = (
        "Analysis complete!" if analysed == len(findings) else "Analysis partially complete"
    )
    lines = [headline, f"Subsystems analyzed: {analysed}/{len(findings)}"]

    unfinished = {o: n for o, n in counts.items() if o not in ANALYSED_OUTCOMES}
    if unfinished:
        lines.append(
            "Not analyzed: "
            + ", ".join(f"{n} {o.replace('_', ' ')}" for o, n in sorted(unfinished.items()))
        )
    lines.append(f"Total threats found: {total_threats}")
    lines.append(f"LLM calls: {llm_calls} | Tool calls: {tool_calls}")
    return "\n".join(lines)


def _skip_remaining(
    subsystems: list[Subsystem], kind: str, progress: ProgressCallback
) -> list[SubsystemFinding]:
    """Record every subsystem the run budget stopped it from starting."""
    note = f"Analysis skipped — the run's {kind} budget ran out before this subsystem."
    progress.subsystems_skipped([s.name for s in subsystems])
    return [
        SubsystemFinding(
            subsystem=s.name,
            threats=[],
            improvement_suggestions=[note],
            outcome="skipped",
        )
        for s in subsystems
    ]


def _build_metadata(
    models: ModelPair,
    plan: AnalysisPlan,
    *,
    llm_calls: int,
    tool_calls: int,
    findings: list[SubsystemFinding],
    status: str | None = None,
    resumed_subsystems: list[str] | None = None,
    rerun_subsystems: list[str] | None = None,
) -> dict[str, Any]:
    """Build the metadata block stored on an AnalysisReport.

    ``subsystems_analyzed`` counts the subsystems the model really analysed,
    not the findings recorded: a crashed or skipped subsystem now has a
    finding too.
    """
    counts = count_outcomes(findings)
    meta: dict[str, Any] = {
        "worker_model": models.worker.model_name,
        "worker_provider": models.worker.provider,
        "architect_model": models.architect.model_name if models.tiered else None,
        "architect_provider": models.architect.provider if models.tiered else None,
        "app_type": plan.detected_app_type,
        "llm_calls": llm_calls,
        "tool_calls": tool_calls,
        "subsystems_analyzed": count_analysed(findings),
        "subsystem_outcomes": counts,
        "resumed_subsystems": resumed_subsystems or [],
        "rerun_subsystems": rerun_subsystems or [],
    }
    if status:
        meta["status"] = status
    return meta


# A subsystem reports through tools, so it needs its own ceiling: the tool
# budget deliberately doesn't gate reporting, and every turn still costs an
# LLM call, but a model that loops on report_threat shouldn't run unbounded.
MAX_THREATS_PER_SUBSYSTEM = 40

GRACE_ROUND_PROMPT = (
    "This is the final round for this subsystem — the call budget is exhausted "
    "and no more exploration is possible. Report every remaining threat you are "
    "confident about with report_threat, then call finish with your improvement "
    "suggestions. Only those two tools are available."
)

NUDGE_PROMPT = (
    "You replied with text but did not call finish. Report each threat you found "
    "with report_threat, then call finish with your improvement suggestions. "
    "Threats written as prose or JSON are not recorded."
)

# Arguments that fill the three always-present threat fields; everything else
# in THREAT_ARG_TO_FIELD is optional and copied across only when the model set
# it, so a threat dict keeps the shape it had before evidence existed.
_REQUIRED_THREAT_ARGS = ("threat_type", "scenario", "potential_impact")


def _threat_arg(args: dict[str, Any], name: str) -> Any:
    """Read one report_threat argument, forgiving the shapes models produce.

    The tool takes snake_case names, but a model with the report's own field
    names in context — from a reference card, or a previous release's prompt —
    will sometimes send those instead. Accepting both costs a dict lookup and
    saves a threat that is otherwise fully formed.
    """
    if name in args:
        return args[name]
    field = THREAT_ARG_TO_FIELD[name]
    if field in args:
        return args[field]
    return args.get(name.replace("_", " ").title())


class SubsystemAbortedError(Exception):
    """A subsystem raised partway through, carrying what it had already found.

    Threats used to exist only in the model's final answer, so a mid-analysis
    failure had nothing to lose. They now accumulate turn by turn, and a rate
    limit or a context overflow on turn 8 would otherwise discard six threats
    the model had already filed — with their verified evidence.
    """

    def __init__(self, cause: BaseException, finding: SubsystemFinding) -> None:
        super().__init__(str(cause))
        self.cause = cause
        self.finding = finding


class _SubsystemRun:
    """State for one subsystem's conversation.

    Threats arrive through ``report_threat`` as the model finds them rather
    than as one JSON blob at the end, so the run has to accumulate them — and
    the tool results it hands back are what tell the model what was recorded.
    """

    def __init__(
        self,
        *,
        target_path: Path,
        subsystem_name: str,
        progress: ProgressCallback,
        max_tool_calls: int,
        loaded_refs: set[str] | None,
    ) -> None:
        self.target_path = target_path
        self.subsystem_name = subsystem_name
        self.progress = progress
        self.max_tool_calls = max_tool_calls
        self.loaded_refs = loaded_refs

        self.threats: list[dict[str, Any]] = []
        self.suggestions: list[str] = []
        self.files_read: list[str] = []
        self.llm_calls = 0
        self.tool_calls = 0
        self.explore_calls = 0
        self.finished = False
        self.reporting_only = False
        # Why the subsystem stopped is derived from these two at the end
        # rather than assigned from each of the loop's several exits.
        self.grace_ran = False
        self.lost_text = False
        self._seen: set[tuple[str, str]] = set()
        self._cache: dict[str, str] = {}

    def clear_tool_cache(self) -> None:
        """Forget cached tool results after compression replaced them."""
        self._cache.clear()

    # -- tool handling ----------------------------------------------------

    def handle(self, tc: ToolCallResult) -> str:
        """Run one tool call and return the result text.

        Always returns a string: every tool call in a batch must get a
        matching ``role: "tool"`` message, or the next request is one a strict
        provider rejects. That matters now that the grace round replays the
        real conversation instead of a stripped copy of it.
        """
        if tc.parse_error:
            # Still a call the model spent a turn on, so it still costs budget.
            self.tool_calls += 1
            if tc.function_name not in REPORTING_TOOL_NAMES:
                self.explore_calls += 1
            return (
                f"Error: {tc.parse_error}. Re-issue the call with a valid JSON object."
            )
        if tc.function_name == "finish":
            return self._handle_finish(tc)
        if tc.function_name == "report_threat":
            return self._handle_report(tc)
        if self.reporting_only:
            return (
                f"Error: {tc.function_name} is not available in the final round. "
                "Use report_threat or finish."
            )
        return self._handle_exploration(tc)

    def _handle_finish(self, tc: ToolCallResult) -> str:
        if self.finished:
            return "Error: finish has already been called for this subsystem."
        self.finished = True
        self.tool_calls += 1
        raw = tc.arguments.get("improvement_suggestions") or []
        if isinstance(raw, str):
            raw = [raw]
        if isinstance(raw, list):
            self.suggestions.extend(
                s.strip() for s in raw if isinstance(s, str) and s.strip()
            )
        self.progress.tool_call("finish", f"suggestions={len(self.suggestions)}", cached=False)
        verified = sum(
            1
            for t in self.threats
            if any(e.get("verified") for e in t.get("evidence", []))
        )
        return (
            f"Subsystem analysis complete: {len(self.threats)} threats recorded "
            f"({verified} with verified evidence), "
            f"{len(self.suggestions)} improvement suggestions. "
            "Stop now — do not call any more tools."
        )

    def _handle_report(self, tc: ToolCallResult) -> str:
        args = tc.arguments
        scenario = str(_threat_arg(args, "scenario") or "").strip()
        if not scenario:
            return (
                "Error: report_threat requires a non-empty 'scenario'. "
                "Nothing was recorded."
            )
        if len(self.threats) >= MAX_THREATS_PER_SUBSYSTEM:
            return (
                f"Error: the per-subsystem limit of {MAX_THREATS_PER_SUBSYSTEM} threats "
                "has been reached. Call finish now."
            )

        threat_type = str(_threat_arg(args, "threat_type") or "Unknown")
        # Compression summarises away the model's own report_threat turns, so
        # it can re-report a threat it already filed. Signature dedupe is
        # cheaper and more reliable than trying to preserve those turns.
        signature = (threat_type.lower(), " ".join(scenario.lower().split())[:200])
        if signature in self._seen:
            return (
                "This threat is already recorded; no duplicate was added. "
                "Report a different threat or call finish."
            )
        self._seen.add(signature)

        threat: dict[str, Any] = {
            "Threat Type": threat_type,
            "Scenario": scenario,
            "Potential Impact": str(_threat_arg(args, "potential_impact") or ""),
        }
        for arg, field in THREAT_ARG_TO_FIELD.items():
            if arg in _REQUIRED_THREAT_ARGS:
                continue
            value = _threat_arg(args, arg)
            if value not in (None, "", []):
                threat[field] = value

        checks = verify_evidence(self.target_path, args.get("evidence"))
        # Omitted rather than empty, so a threat with no evidence is the same
        # dict shape it was before this existed.
        if checks:
            threat["evidence"] = [c.to_dict() for c in checks]
        self.threats.append(threat)
        self.tool_calls += 1

        verified = sum(1 for c in checks if c.verified)
        brief = f"type={threat_type!r}"
        if checks:
            brief += f", evidence={verified}/{len(checks)} verified"
        self.progress.tool_call("report_threat", brief, cached=False)
        return (
            f"Recorded threat #{len(self.threats)} ({threat_type}). "
            + summarise_checks(checks)
        )

    def _handle_exploration(self, tc: ToolCallResult) -> str:
        if self.max_tool_calls and self.explore_calls >= self.max_tool_calls:
            # Answered rather than skipped: a tool call with no result is a
            # malformed conversation, and the grace round sends this history.
            return (
                "Error: the tool budget for this analysis is exhausted; this call was "
                "not executed. Report the threats you already have with report_threat, "
                "then call finish."
            )

        key = tc.function_name + ":" + json.dumps(tc.arguments, sort_keys=True)
        # A call with unparseable arguments isn't the same call as one with no
        # arguments, so keep it out of the cache both ways.
        cached = self._cache.get(key)
        if cached is not None:
            result = (
                "You already have this result from a previous call. "
                "Refer to the earlier tool response instead of requesting it again."
            )
            self.progress.tool_call(tc.function_name, _brief_args(tc.arguments), cached=True)
        else:
            result = execute_tool(self.target_path, tc, loaded_refs=self.loaded_refs)
            self._cache[key] = result
            self.progress.tool_call(tc.function_name, _brief_args(tc.arguments), cached=False)

        self.tool_calls += 1
        self.explore_calls += 1
        if tc.function_name == "read_file" and not result.startswith("Error"):
            self._record_file(tc.arguments.get("path"))
        return result

    def _record_file(self, path: Any) -> None:
        """Record a file the agent really opened.

        ``files_analyzed`` used to be whatever the model claimed at the end.
        Only successful ``read_file`` calls count: a grep hit shows one line,
        not a file the agent studied.
        """
        clean = normalise_path(path)
        if clean and clean not in self.files_read:
            self.files_read.append(clean)

    # -- results ----------------------------------------------------------

    def take_text_fallback(self, content: str) -> bool:
        """Absorb a final plain-text answer. Returns True if it carried JSON.

        Deprecated transition path for models with weak tool calling: threats
        written as JSON prose are still parsed for one release.
        """
        logger.warning(
            "Subsystem %r answered with plain text instead of calling finish; "
            "parsing JSON from the text (deprecated fallback).",
            self.subsystem_name,
        )
        data = extract_json_object(content)
        if data is None:
            self.lost_text = True
            return False
        # Only when nothing came through the tools — a model that does both
        # would otherwise have every threat counted twice.
        if not self.threats:
            threats = data.get("threats")
            if isinstance(threats, list):
                self.threats.extend(t for t in threats if isinstance(t, dict))
        suggestions = data.get("improvement_suggestions")
        if isinstance(suggestions, list):
            self.suggestions.extend(str(s) for s in suggestions if s)
        if not self.files_read:
            claimed = data.get("files_analyzed")
            if isinstance(claimed, list):
                self.files_read.extend(normalise_path(f) for f in claimed if f)
        return True

    def outcome(self) -> SubsystemOutcome:
        """Why this subsystem stopped.

        Checked in this order because an unparseable text answer that left no
        threats is the one case where the finding is empty and untrustworthy —
        that matters more than which budget ran out first.
        """
        if self.lost_text and not self.threats:
            return "parse_failed"
        if self.grace_ran:
            return "budget_exhausted"
        return "completed"

    def finding(self) -> SubsystemFinding:
        return SubsystemFinding(
            subsystem=self.subsystem_name,
            threats=self.threats,
            improvement_suggestions=self.suggestions,
            files_analyzed=self.files_read,
            outcome=self.outcome(),
        )


def _analyze_subsystem(
    models: ModelPair,
    target_path: Path,
    subsystem_name: str,
    subsystem_description: str,
    key_files: list[str],
    focus_areas: list[str],
    ctx: ContextManager,
    max_llm_calls: int,
    max_tool_calls: int,
    progress: ProgressCallback,
    call_counts: dict[str, int],
    loaded_refs: set[str] | None = None,
) -> SubsystemFinding:
    """Analyze a single subsystem using the agent loop.

    The model explores with the filesystem tools and reports each threat
    through ``report_threat`` as it finds it, ending with ``finish``. When the
    budget runs out it gets one final round offering only those two tools, on
    the real conversation — no summarisation, no forced-JSON call on a lossy
    copy of the history.
    """
    user_prompt = f"""Analyze the "{subsystem_name}" subsystem for STRIDE threats.

Description: {subsystem_description}
Key files to examine: {', '.join(key_files) if key_files else 'Discover relevant files using search_files and list_directory'}
Focus areas: {', '.join(focus_areas) if focus_areas else 'All STRIDE categories'}

Start by reading the key files. Use grep to find security-relevant patterns like authentication, authorization, input validation, SQL queries, file operations, secret handling, and network calls. Report each threat with report_threat as you find it, then call finish."""

    messages: list[dict] = [
        {"role": "system", "content": AGENT_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    run = _SubsystemRun(
        target_path=target_path,
        subsystem_name=subsystem_name,
        progress=progress,
        max_tool_calls=max_tool_calls,
        loaded_refs=loaded_refs,
    )
    nudged = False

    try:
        while not run.finished and (not max_llm_calls or run.llm_calls < max_llm_calls):
            progress.status(f"Thinking about {subsystem_name}...")
            response = call_llm_with_tools(models.worker, messages, SUBSYSTEM_TOOLS)
            run.llm_calls += 1

            if not response.tool_calls:
                if run.take_text_fallback(response.content) or run.threats or nudged:
                    return run.finding()
                # One nudge on the real conversation, where _retry_as_json
                # used to spend two calls on a summarised copy of it.
                nudged = True
                messages = _append_user(messages, NUDGE_PROMPT)
                continue

            messages.append({
                "role": "assistant",
                "content": response.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function_name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in response.tool_calls
                ],
            })
            for tc in response.tool_calls:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc.function_name,
                    "content": run.handle(tc),
                })

            if run.finished:
                break
            if _explore_budget_spent(run, max_tool_calls):
                break
            if ctx.needs_compression(messages):
                compressed = ctx.compress(models.for_architect(), messages)
                if compressed is not messages:
                    # The cache points the model at earlier tool responses,
                    # which the summary has just replaced.
                    run.clear_tool_cache()
                    messages = compressed
                run.llm_calls += 1  # Compression uses an LLM call

        if not run.finished and run.llm_calls:
            _grace_round(models, messages, run, progress)
        return run.finding()
    except Exception as e:
        raise SubsystemAbortedError(e, run.finding()) from e
    finally:
        # One place, because the paths out of here multiplied: finish, a text
        # answer, a nudged text answer, and two grace-round outcomes.
        call_counts["llm"] = run.llm_calls
        call_counts["tool"] = run.tool_calls
        call_counts["explore"] = run.explore_calls


def _explore_budget_spent(run: _SubsystemRun, max_tool_calls: int) -> bool:
    """Whether exploration is over, so the model should be asked to wrap up."""
    return bool(max_tool_calls) and run.explore_calls >= max_tool_calls


def _grace_round(
    models: ModelPair,
    messages: list[dict],
    run: _SubsystemRun,
    progress: ProgressCallback,
) -> None:
    """One last call on the real conversation, offering only the two reporting tools.

    This replaces the old cap path, which summarised the conversation and then
    forced JSON out of the summary — two calls, on a copy that had already
    lost the detail the model was about to write up.
    """
    progress.status(f"Final round for {run.subsystem_name}...")
    run.reporting_only = True
    run.grace_ran = True
    grace_msgs = _append_user(messages, GRACE_ROUND_PROMPT)
    response = call_llm_with_tools(models.worker, grace_msgs, REPORTING_TOOLS)
    run.llm_calls += 1

    if not response.tool_calls:
        run.take_text_fallback(response.content)
        return

    grace_msgs.append({
        "role": "assistant",
        "content": response.content or "",
        "tool_calls": [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.function_name, "arguments": json.dumps(tc.arguments)},
            }
            for tc in response.tool_calls
        ],
    })
    for tc in response.tool_calls:
        grace_msgs.append({
            "role": "tool",
            "tool_call_id": tc.id,
            "name": tc.function_name,
            "content": run.handle(tc),
        })


def _threats_without_evidence(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop evidence snippets before sending threats to another model.

    Cross-cutting synthesis and the system DFD reason about what the threats
    are, not the code behind them, and snippets would be the largest thing in
    a payload that already has to be trimmed to fit.
    """
    return [{k: v for k, v in t.items() if k != "evidence"} for t in threats]


def _synthesize(models: ModelPair, findings: list[SubsystemFinding]) -> list[dict[str, Any]]:
    """Identify cross-cutting threats across all subsystem findings.

    Uses the architect tier — synthesis is a cross-cutting reasoning task.
    """
    findings_summary = json.dumps(
        [
            {
                "subsystem": f.subsystem,
                "threats": _threats_without_evidence(f.threats),
                "files_analyzed": f.files_analyzed,
            }
            for f in findings
        ],
        indent=2,
    )

    architect = models.for_architect()

    # Guard against the architect having a smaller context window than the
    # raw findings summary — trim per-finding if so. Worker's window drives
    # the agent loop, but the architect handles the synthesis call.
    findings_summary = _truncate_findings_to_fit(architect, findings, findings_summary)

    json_config = architect.model_copy(update={"response_format": "json"})
    messages: list[dict] = [
        {"role": "system", "content": SYNTHESIS_PROMPT},
        {"role": "user", "content": f"Per-subsystem findings:\n{findings_summary}"},
    ]
    response = call_llm(json_config, messages)
    data = extract_json_object(response.content)

    # Still failed — retry with explicit instruction
    if data is None:
        messages.append({"role": "assistant", "content": response.content})
        messages.append({
            "role": "user",
            "content": "Please respond with ONLY a valid JSON object in the format specified. No other text.",
        })
        response = call_llm(json_config, messages)
        data = extract_json_object(response.content)

    if data is None:
        return []
    return data.get("cross_cutting_threats", [])


def _generate_system_dfd(
    models: ModelPair, plan: AnalysisPlan, findings: list[SubsystemFinding]
) -> str | None:
    """Produce a system-level DFD in Mermaid form, or None on any failure.

    Single architect-tier LLM call. The architect already saw the
    cross-cutting synthesis; this gives it the same finding-level summary
    plus the plan, and asks for a JSON DFD that we render to Mermaid via
    the canonical converter.

    DFD generation is auxiliary — never let it fail the whole report.
    Callers wrap in try/except too as belt-and-braces.
    """
    from stride_gpt.core.dfd import generate_dfd
    from stride_gpt.core.prompts import create_dfd_prompt

    # Build a description that combines the plan overview with the per-
    # subsystem context the agent actually surfaced. Files-analyzed lists
    # are noisy and not useful here.
    description_parts = [plan.overall_description, "", "Subsystems and files identified:"]
    description_parts.extend(f"- {sub.name}: {sub.description}" for sub in plan.subsystems)

    description_parts.append("")
    description_parts.append("Subsystem threat findings (for context only):")
    for finding in findings:
        if not finding.threats:
            continue
        threat_types = sorted({t.get("Threat Type", "") for t in finding.threats if t.get("Threat Type")})
        description_parts.append(f"- {finding.subsystem}: {', '.join(threat_types)}")

    prompt = create_dfd_prompt(
        app_type=plan.detected_app_type,
        authentication="See subsystem details",
        internet_facing="Inferred from findings",
        sensitive_data="Inferred from findings",
        app_input="\n".join(description_parts),
    )

    mermaid, _ = generate_dfd(models.for_architect(), prompt)
    return mermaid or None


def _truncate_findings_to_fit(
    architect: LLMConfig,
    findings: list[SubsystemFinding],
    rendered: str,
) -> str:
    """If the rendered findings JSON exceeds the architect's context window,
    trim per-finding `files_analyzed` lists (cheapest content) until it fits.
    Falls through unchanged on any sizing error — better to send too much
    and let the provider error than crash mid-synthesis here.
    """
    try:
        import litellm
        ctx = ContextManager(config=architect)
        budget = int(ctx.context_window * COMPRESSION_BUDGET)
        messages = [{"role": "user", "content": rendered}]
        if litellm.token_counter(model=architect.model_name, messages=messages) <= budget:
            return rendered

        return json.dumps(
            [
                {
                    "subsystem": f.subsystem,
                    "threats": _threats_without_evidence(f.threats),
                    "files_analyzed": f.files_analyzed[:5],
                }
                for f in findings
            ],
            indent=2,
        )
    except Exception:
        return rendered


COMPRESSION_BUDGET = 0.75  # leave headroom for the system prompt + response


def _append_user(messages: list[dict], text: str) -> list[dict]:
    """Add a user instruction, joining it to a trailing user message if there is one."""
    last = messages[-1] if messages else None
    if last is not None and last.get("role") == "user" and isinstance(last.get("content"), str):
        return [*messages[:-1], {**last, "content": f"{last['content']}\n\n{text}"}]
    return [*messages, {"role": "user", "content": text}]


def _brief_args(args: dict) -> str:
    """Format tool arguments briefly for console display."""
    parts = []
    for k, v in args.items():
        sv = str(v)
        if len(sv) > 40:
            sv = sv[:37] + "..."
        parts.append(f"{k}={sv!r}")
    return ", ".join(parts)
