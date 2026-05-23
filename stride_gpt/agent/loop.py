"""Core agent loop — plan, explore, analyze, synthesize."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

from stride_gpt.agent.context import ContextManager
from stride_gpt.agent.planner import create_plan, format_plan_for_display
from stride_gpt.agent.progress import ProgressCallback, RichProgress
from stride_gpt.agent.tools import AGENT_TOOLS, execute_tool
from stride_gpt.core.json_extract import extract_json_object
from stride_gpt.core.llm import call_llm, call_llm_with_tools
from stride_gpt.core.prompts import base_system_prompt
from stride_gpt.core.schemas import (
    AnalysisPlan,
    AnalysisReport,
    LLMConfig,
    ModelPair,
    SubsystemFinding,
)

# The agent's system prompt is the packaged `base.md` reference. It points to
# optional `genai` and `agentic` reference cards that the agent loads on
# demand via the `load_reference` tool — progressive disclosure rather than
# eagerly stacking variant content.
AGENT_SYSTEM_PROMPT = base_system_prompt()

_APP_TYPE_HINTS = {
    "genai": (
        "The planner classified this codebase as a Generative AI application. "
        "If this subsystem has language-model behaviour in scope, call "
        "`load_reference(name=\"genai\")` to retrieve the OWASP LLM threat reference."
    ),
    "agentic": (
        "The planner classified this codebase as an Agentic AI application. "
        "If this subsystem has language-model behaviour in scope, call "
        "`load_reference(name=\"genai\")` for the OWASP LLM reference. If it "
        "uses agent frameworks, tool-use loops, or persistent agent memory, "
        "also call `load_reference(name=\"agentic\")` for the OWASP Agentic reference."
    ),
}

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
) -> AnalysisReport:
    """Run a full agentic threat model analysis on a codebase.

    Args:
        models: Worker + optional architect LLM configuration. Worker drives
            per-subsystem exploration; architect (if set) drives planning,
            cross-cutting synthesis, and context summarization.
        target_path: Path to the codebase root.
        plan: Pre-approved analysis plan. If None, creates one (Phase 1).
        max_llm_calls: Hard limit on total LLM calls (0 = unlimited).
        max_tool_calls: Hard limit on total tool executions (0 = unlimited).
        auto_approve: Skip interactive plan approval (only used when plan is None).
        progress: Progress callback for UI updates. Falls back to Rich console.
        console: Deprecated — use progress instead. Kept for backward compat.

    Returns:
        Complete AnalysisReport.
    """
    if progress is None:
        progress = RichProgress(console or Console())

    ctx = ContextManager(config=models.worker)
    llm_calls = 0
    tool_calls = 0

    # --- Phase 1: Planning ---
    if plan is None:
        progress.phase_start("Phase 1", "Planning")
        progress.status("Scanning codebase and generating plan...")
        plan = create_plan(models.for_architect(), target_path)
        llm_calls += 1

        progress.status(format_plan_for_display(plan))

        if not auto_approve:
            # When no plan is provided and auto_approve is False,
            # the caller should have handled approval. For backward compat
            # with CLI, we use Rich console input if available.
            if console is not None:
                response = console.input("[bold yellow]Approve this plan? (y/n/q): [/bold yellow]")
                if response.lower() not in ("y", "yes"):
                    progress.complete("Analysis cancelled.")
                    return AnalysisReport(
                        plan=plan,
                        findings=[],
                        metadata=_build_metadata(
                            models, plan, llm_calls=llm_calls, tool_calls=tool_calls,
                            subsystems_analyzed=0, status="cancelled",
                        ),
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

    for i, subsystem in enumerate(plan.subsystems, 1):
        if max_llm_calls and llm_calls >= max_llm_calls - 1:
            progress.limit_reached("LLM call", llm_calls, max_llm_calls)
            break
        if max_tool_calls and tool_calls >= max_tool_calls:
            progress.limit_reached("tool call", tool_calls, max_tool_calls)
            break

        progress.subsystem_start(i, len(plan.subsystems), subsystem.name, subsystem.description)

        # Pass remaining budget so a single subsystem can't starve later
        # subsystems (or the synthesis pass). 0 still means unlimited.
        remaining_llm = max_llm_calls - llm_calls if max_llm_calls else 0
        remaining_tool = max_tool_calls - tool_calls if max_tool_calls else 0

        try:
            sub_counts: dict[str, int] = {"llm": 0, "tool": 0}
            finding = _analyze_subsystem(
                models=models,
                target_path=target_path,
                subsystem_name=subsystem.name,
                subsystem_description=subsystem.description,
                key_files=subsystem.key_files,
                focus_areas=subsystem.focus_areas,
                app_type=plan.detected_app_type,
                ctx=ctx,
                max_llm_calls=remaining_llm,
                max_tool_calls=remaining_tool,
                progress=progress,
                call_counts=sub_counts,
            )
            llm_calls += sub_counts["llm"]
            tool_calls += sub_counts["tool"]
            findings.append(finding)
            if sub_counts["tool"] == 0:
                progress.no_tool_use_warning(subsystem.name)
            progress.subsystem_done(subsystem.name, len(finding.threats))
        except Exception as e:
            err_str = str(e)
            if "n_keep" in err_str and "n_ctx" in err_str:
                reason = "Context window exceeded — model ran out of space for this subsystem."
            elif "crashed" in err_str.lower():
                reason = "The model crashed, likely due to memory constraints."
            else:
                reason = f"Unexpected error: {err_str}"
            progress.error(subsystem.name, reason)
            findings.append(
                SubsystemFinding(
                    subsystem=subsystem.name,
                    threats=[],
                    improvement_suggestions=[f"Analysis skipped — {reason}"],
                )
            )

    # --- Phase 3: Synthesis ---
    cross_cutting: list[dict[str, Any]] = []
    if len(findings) > 1 and (not max_llm_calls or llm_calls < max_llm_calls):
        progress.phase_start("Phase 3", "Synthesizing Cross-Cutting Threats")
        progress.status("Identifying cross-cutting threats...")
        cross_cutting = _synthesize(models, findings)
        llm_calls += 1
        progress.synthesis_done(len(cross_cutting))

    report = AnalysisReport(
        plan=plan,
        findings=findings,
        cross_cutting_threats=cross_cutting,
        metadata=_build_metadata(
            models, plan, llm_calls=llm_calls, tool_calls=tool_calls,
            subsystems_analyzed=len(findings),
        ),
    )

    total_threats = sum(len(f.threats) for f in findings) + len(cross_cutting)
    succeeded = sum(1 for f in findings if f.threats)
    failed = len(findings) - succeeded

    if failed:
        summary = (
            f"Analysis partially complete — {failed}/{len(findings)} subsystems failed\n"
            f"Subsystems analyzed: {succeeded}/{len(findings)}\n"
            f"Total threats found: {total_threats}\n"
            f"LLM calls: {llm_calls} | Tool calls: {tool_calls}"
        )
    else:
        summary = (
            f"Analysis complete!\n"
            f"Subsystems analyzed: {succeeded}/{len(findings)}\n"
            f"Total threats found: {total_threats}\n"
            f"LLM calls: {llm_calls} | Tool calls: {tool_calls}"
        )

    progress.complete(summary)
    return report


def _build_metadata(
    models: ModelPair,
    plan: AnalysisPlan,
    *,
    llm_calls: int,
    tool_calls: int,
    subsystems_analyzed: int,
    status: str | None = None,
) -> dict[str, Any]:
    """Build the metadata block stored on an AnalysisReport."""
    meta: dict[str, Any] = {
        "worker_model": models.worker.model_name,
        "worker_provider": models.worker.provider,
        "architect_model": models.architect.model_name if models.tiered else None,
        "architect_provider": models.architect.provider if models.tiered else None,
        "app_type": plan.detected_app_type,
        "llm_calls": llm_calls,
        "tool_calls": tool_calls,
        "subsystems_analyzed": subsystems_analyzed,
    }
    if status:
        meta["status"] = status
    return meta


def _analyze_subsystem(
    models: ModelPair,
    target_path: Path,
    subsystem_name: str,
    subsystem_description: str,
    key_files: list[str],
    focus_areas: list[str],
    app_type: str,
    ctx: ContextManager,
    max_llm_calls: int,
    max_tool_calls: int,
    progress: ProgressCallback,
    call_counts: dict[str, int],
) -> SubsystemFinding:
    """Analyze a single subsystem using the agent loop."""
    hint = _APP_TYPE_HINTS.get(app_type, "")
    hint_block = f"\n\n{hint}" if hint else ""

    user_prompt = f"""Analyze the "{subsystem_name}" subsystem for STRIDE threats.

Description: {subsystem_description}
Key files to examine: {', '.join(key_files) if key_files else 'Discover relevant files using search_files and list_directory'}
Focus areas: {', '.join(focus_areas) if focus_areas else 'All STRIDE categories'}

Start by reading the key files. Use grep to find security-relevant patterns like authentication, authorization, input validation, SQL queries, file operations, secret handling, encryption, and network calls.{hint_block}"""

    messages: list[dict] = [
        {"role": "system", "content": AGENT_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    llm_calls = 0
    tool_calls = 0
    tool_cache: dict[str, str] = {}

    while (not max_llm_calls or llm_calls < max_llm_calls) and \
          (not max_tool_calls or tool_calls < max_tool_calls):
        progress.status(f"Thinking about {subsystem_name}...")
        response = call_llm_with_tools(models.worker, messages, AGENT_TOOLS)
        llm_calls += 1

        if response.tool_calls:
            # Execute tool calls
            messages.append({"role": "assistant", "content": response.content or "",
                           "tool_calls": [
                               {"id": tc.id, "type": "function",
                                "function": {"name": tc.function_name,
                                             "arguments": json.dumps(tc.arguments)}}
                               for tc in response.tool_calls
                           ]})

            for tc in response.tool_calls:
                if max_tool_calls and tool_calls >= max_tool_calls:
                    break
                cache_key = tc.function_name + ":" + json.dumps(tc.arguments, sort_keys=True)
                cached = tool_cache.get(cache_key)
                if cached is not None:
                    result = (
                        "You already have this result from a previous call. "
                        "Refer to the earlier tool response instead of requesting it again."
                    )
                    progress.tool_call(tc.function_name, _brief_args(tc.arguments), cached=True)
                else:
                    result = execute_tool(target_path, tc)
                    tool_cache[cache_key] = result
                    progress.tool_call(tc.function_name, _brief_args(tc.arguments), cached=False)
                tool_calls += 1
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc.function_name,
                    "content": result,
                })

            # Check context and compress if needed
            if ctx.needs_compression(messages):
                messages = ctx.compress(models.for_architect(), messages)
                llm_calls += 1  # Compression uses an LLM call
        else:
            # No tool calls — the model is done analyzing
            call_counts["llm"] = llm_calls
            call_counts["tool"] = tool_calls
            finding = _parse_subsystem_finding(subsystem_name, response.content)
            if finding is not None:
                return finding
            # JSON parse failed — retry with forced JSON output
            return _retry_as_json(models, messages, subsystem_name, call_counts)

    # Hit limits — summarize findings and ask model to produce final analysis
    clean_msgs = _prepare_for_plain_llm(models.for_architect(), messages)
    llm_calls += 1  # summarization call
    clean_msgs.append({
        "role": "user",
        "content": "You've reached the tool call limit. Please provide your STRIDE threat analysis now based on what you've gathered so far. Respond with the JSON format specified.",
    })
    json_config = models.worker.model_copy(update={"response_format": "json"})
    response = call_llm(json_config, clean_msgs)
    call_counts["llm"] = llm_calls + 1
    call_counts["tool"] = tool_calls
    finding = _parse_subsystem_finding(subsystem_name, response.content)
    if finding is not None:
        return finding
    return SubsystemFinding(
        subsystem=subsystem_name,
        threats=[],
        improvement_suggestions=["Failed to parse model response as JSON"],
    )


def _parse_subsystem_finding(subsystem_name: str, content: str) -> SubsystemFinding | None:
    """Parse an LLM response into a SubsystemFinding.

    Returns None if JSON cannot be extracted, signaling the caller to retry.
    """
    data = extract_json_object(content)
    if data is None:
        return None

    return SubsystemFinding(
        subsystem=subsystem_name,
        threats=data.get("threats", []),
        improvement_suggestions=data.get("improvement_suggestions", []),
        files_analyzed=data.get("files_analyzed", []),
    )


def _retry_as_json(
    models: ModelPair,
    messages: list[dict],
    subsystem_name: str,
    call_counts: dict[str, int],
) -> SubsystemFinding:
    """Retry the final analysis with forced JSON output.

    Summarization uses the architect (a reasoning task). The JSON-forced
    final call uses the worker (it's the same task as the original
    exploration's final-answer call, just with stricter formatting).
    """
    clean_msgs = _prepare_for_plain_llm(models.for_architect(), messages)
    call_counts["llm"] = call_counts.get("llm", 0) + 1  # summarization call
    clean_msgs.append({
        "role": "user",
        "content": "Please respond with ONLY a valid JSON object in the format specified in your instructions. No other text.",
    })
    json_config = models.worker.model_copy(update={"response_format": "json"})
    response = call_llm(json_config, clean_msgs)
    call_counts["llm"] = call_counts.get("llm", 0) + 1

    finding = _parse_subsystem_finding(subsystem_name, response.content)
    if finding is not None:
        return finding
    return SubsystemFinding(
        subsystem=subsystem_name,
        threats=[],
        improvement_suggestions=["Failed to parse model response as JSON after retry"],
    )


def _synthesize(models: ModelPair, findings: list[SubsystemFinding]) -> list[dict[str, Any]]:
    """Identify cross-cutting threats across all subsystem findings.

    Uses the architect tier — synthesis is a cross-cutting reasoning task.
    """
    findings_summary = json.dumps(
        [
            {
                "subsystem": f.subsystem,
                "threats": f.threats,
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

        trimmed = json.dumps(
            [
                {
                    "subsystem": f.subsystem,
                    "threats": f.threats,
                    "files_analyzed": f.files_analyzed[:5],
                }
                for f in findings
            ],
            indent=2,
        )
        return trimmed
    except Exception:
        return rendered


COMPRESSION_BUDGET = 0.75  # leave headroom for the system prompt + response


SUMMARIZE_TRUNCATION = 6_000  # chars per message when building summary input

SUMMARIZE_PROMPT = """You are summarizing the results of a security-focused codebase exploration.

The following is a conversation between a security analyst and their tools. The analyst read files, searched for patterns, and listed directories. Summarize the key findings into a concise briefing that preserves:

- Specific code patterns found (e.g., auth checks, input validation, secret handling)
- File contents and architectural details relevant to STRIDE threat analysis
- Any security weaknesses or concerns already noted
- Enough concrete detail to support writing specific threat scenarios

Be thorough — the analyst needs this summary to produce a final STRIDE threat report without access to the original files."""


def _summarize_for_analysis(config: LLMConfig, messages: list[dict]) -> str:
    """Summarize tool exploration results into a security-focused findings briefing."""
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role", "unknown")
        content = str(msg.get("content", ""))
        if not content.strip():
            continue
        # Tool call metadata: show what was called
        if "tool_calls" in msg:
            tcs = msg.get("tool_calls", [])
            calls = ", ".join(
                f"{tc.get('function', {}).get('name', '?')}({tc.get('function', {}).get('arguments', '')})"
                for tc in tcs
            )
            parts.append(f"[assistant] Called: {calls}")
            continue
        # Truncate long content (file reads can be huge)
        if len(content) > SUMMARIZE_TRUNCATION:
            content = content[:SUMMARIZE_TRUNCATION] + "\n... (truncated)"
        parts.append(f"[{role}] {content}")

    conversation = "\n---\n".join(parts)

    summary_messages = [
        {"role": "system", "content": SUMMARIZE_PROMPT},
        {"role": "user", "content": conversation},
    ]
    response = call_llm(config, summary_messages)
    return response.content


def _prepare_for_plain_llm(config: LLMConfig, messages: list[dict]) -> list[dict]:
    """Prepare messages for a plain (non-tool-use) LLM call.

    Summarizes tool exploration via an LLM call, then builds a clean message
    list with no tool artifacts. Falls back to _strip_tool_calls if the
    summarization call fails.
    """
    # Extract system messages and original user prompt
    system_msgs = []
    user_prompt_msg = None
    for msg in messages:
        if msg.get("role") == "system" and user_prompt_msg is None:
            system_msgs.append(msg)
        elif msg.get("role") == "user" and user_prompt_msg is None:
            user_prompt_msg = msg
            break

    # Check if there are any tool results worth summarizing
    has_tool_results = any(msg.get("role") == "tool" for msg in messages)
    if not has_tool_results:
        return _strip_tool_artifacts(messages)

    try:
        summary = _summarize_for_analysis(config, messages)
    except Exception:
        # Summarization failed — fall back to lossy stripping
        return _strip_tool_artifacts(messages)

    result = list(system_msgs)
    if user_prompt_msg:
        result.append(user_prompt_msg)
    result.append({
        "role": "user",
        "content": f"[Findings from codebase exploration]\n{summary}",
    })

    # Preserve any substantive assistant analysis text
    assistant_parts = []
    for msg in messages:
        if msg.get("role") == "assistant":
            text = (msg.get("content") or "").strip()
            if text and "tool_calls" not in msg:
                assistant_parts.append(text)
    if assistant_parts:
        result.append({"role": "assistant", "content": "\n\n".join(assistant_parts)})

    return result


def _strip_tool_artifacts(messages: list[dict]) -> list[dict]:
    """Remove tool-call metadata from messages so they're valid for plain LLM calls."""
    cleaned: list[dict] = []
    for msg in messages:
        if msg.get("role") == "tool":
            continue
        if "tool_calls" in msg:
            cleaned.append({"role": msg["role"], "content": msg.get("content", "")})
        else:
            cleaned.append(msg)
    return cleaned


def _brief_args(args: dict) -> str:
    """Format tool arguments briefly for console display."""
    parts = []
    for k, v in args.items():
        sv = str(v)
        if len(sv) > 40:
            sv = sv[:37] + "..."
        parts.append(f"{k}={sv!r}")
    return ", ".join(parts)
