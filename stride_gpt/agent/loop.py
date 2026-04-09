"""Core agent loop — plan, explore, analyze, synthesize."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.status import Status

from stride_gpt.agent.context import ContextManager
from stride_gpt.agent.planner import create_plan, format_plan_for_display
from stride_gpt.agent.tools import AGENT_TOOLS, execute_tool
from stride_gpt.core.llm import call_llm, call_llm_with_tools
from stride_gpt.core.schemas import (
    AnalysisPlan,
    AnalysisReport,
    LLMConfig,
    SubsystemFinding,
)

AGENT_SYSTEM_PROMPT = """You are a security expert performing STRIDE threat modeling on a codebase.

You have filesystem tools to explore the code. Your job is to:
1. Read relevant source files for the current subsystem
2. Understand the architecture, data flows, and trust boundaries
3. Identify threats using the STRIDE framework:
   - Spoofing: Can an attacker impersonate a user or component?
   - Tampering: Can data be modified without detection?
   - Repudiation: Can actions be denied without accountability?
   - Information Disclosure: Can sensitive data leak?
   - Denial of Service: Can the service be disrupted?
   - Elevation of Privilege: Can an attacker gain unauthorized access?

When you have gathered enough information, respond with your threat analysis as a JSON object:
{
    "threats": [
        {
            "Threat Type": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
            "Scenario": "Description of the specific attack scenario",
            "Potential Impact": "What damage could result"
        }
    ],
    "improvement_suggestions": ["Actionable recommendation 1", "..."],
    "files_analyzed": ["file1.py", "file2.py"]
}

Be thorough but focused. Read code — don't guess. Use grep to find specific patterns like authentication checks, SQL queries, input validation, secret handling, etc."""

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


def run_analysis(
    config: LLMConfig,
    target_path: Path,
    *,
    max_llm_calls: int = 25,
    max_tool_calls: int = 50,
    auto_approve: bool = False,
    console: Console | None = None,
) -> AnalysisReport:
    """Run a full agentic threat model analysis on a codebase.

    Args:
        config: LLM configuration.
        target_path: Path to the codebase root.
        max_llm_calls: Hard limit on total LLM calls.
        max_tool_calls: Hard limit on total tool executions.
        auto_approve: Skip interactive plan approval.
        console: Rich console for output. Creates one if not provided.

    Returns:
        Complete AnalysisReport.
    """
    console = console or Console()
    ctx = ContextManager(model=config.model_name)
    llm_calls = 0
    tool_calls = 0

    # --- Phase 1: Planning ---
    console.print(Panel("[bold]Phase 1: Planning[/bold]", style="blue"))
    with console.status("Scanning codebase and generating plan..."):
        plan = create_plan(config, target_path)
        llm_calls += 1

    console.print(Panel(format_plan_for_display(plan), title="Analysis Plan", style="cyan"))

    if not auto_approve:
        response = console.input("[bold yellow]Approve this plan? (y/n/q): [/bold yellow]")
        if response.lower() not in ("y", "yes"):
            console.print("[red]Analysis cancelled.[/red]")
            return AnalysisReport(
                plan=plan,
                findings=[],
                metadata={"status": "cancelled"},
            )

    # --- Phase 2: Per-subsystem analysis ---
    console.print(Panel("[bold]Phase 2: Analyzing Subsystems[/bold]", style="blue"))
    findings: list[SubsystemFinding] = []

    for i, subsystem in enumerate(plan.subsystems, 1):
        if llm_calls >= max_llm_calls or tool_calls >= max_tool_calls:
            console.print(
                f"[yellow]Reached call limits (LLM: {llm_calls}/{max_llm_calls}, "
                f"Tools: {tool_calls}/{max_tool_calls}). Stopping early.[/yellow]"
            )
            break

        console.print(
            f"\n[bold cyan]({i}/{len(plan.subsystems)}) Analyzing: {subsystem.name}[/bold cyan]"
        )
        console.print(f"  {subsystem.description}")

        try:
            finding = _analyze_subsystem(
                config=config,
                target_path=target_path,
                subsystem_name=subsystem.name,
                subsystem_description=subsystem.description,
                key_files=subsystem.key_files,
                focus_areas=subsystem.focus_areas,
                ctx=ctx,
                max_llm_calls=max_llm_calls - llm_calls,
                max_tool_calls=max_tool_calls - tool_calls,
                console=console,
                call_counts={"llm": 0, "tool": 0},
            )
            llm_calls += finding.metadata.pop("_llm_calls", 0) if hasattr(finding, "metadata") else 0
            tool_calls += finding.metadata.pop("_tool_calls", 0) if hasattr(finding, "metadata") else 0
            findings.append(finding)
            console.print(
                f"  [green]Found {len(finding.threats)} threats in {subsystem.name}[/green]"
            )
        except Exception as e:
            console.print(f"  [red]Error analyzing {subsystem.name}: {e}[/red]")
            findings.append(
                SubsystemFinding(
                    subsystem=subsystem.name,
                    threats=[],
                    improvement_suggestions=[f"Analysis failed: {e}"],
                )
            )

    # --- Phase 3: Synthesis ---
    cross_cutting: list[dict[str, Any]] = []
    if len(findings) > 1 and llm_calls < max_llm_calls:
        console.print(Panel("[bold]Phase 3: Synthesizing Cross-Cutting Threats[/bold]", style="blue"))
        with console.status("Identifying cross-cutting threats..."):
            cross_cutting = _synthesize(config, findings)
            llm_calls += 1
        console.print(f"  [green]Found {len(cross_cutting)} cross-cutting threats[/green]")

    report = AnalysisReport(
        plan=plan,
        findings=findings,
        cross_cutting_threats=cross_cutting,
        metadata={
            "llm_calls": llm_calls,
            "tool_calls": tool_calls,
            "subsystems_analyzed": len(findings),
        },
    )

    total_threats = sum(len(f.threats) for f in findings) + len(cross_cutting)
    console.print(
        Panel(
            f"[bold green]Analysis complete![/bold green]\n"
            f"Subsystems analyzed: {len(findings)}\n"
            f"Total threats found: {total_threats}\n"
            f"LLM calls: {llm_calls} | Tool calls: {tool_calls}",
            title="Summary",
            style="green",
        )
    )

    return report


def _analyze_subsystem(
    config: LLMConfig,
    target_path: Path,
    subsystem_name: str,
    subsystem_description: str,
    key_files: list[str],
    focus_areas: list[str],
    ctx: ContextManager,
    max_llm_calls: int,
    max_tool_calls: int,
    console: Console,
    call_counts: dict[str, int],
) -> SubsystemFinding:
    """Analyze a single subsystem using the agent loop."""
    user_prompt = f"""Analyze the "{subsystem_name}" subsystem for STRIDE threats.

Description: {subsystem_description}
Key files to examine: {', '.join(key_files) if key_files else 'Discover relevant files using search_files and list_directory'}
Focus areas: {', '.join(focus_areas) if focus_areas else 'All STRIDE categories'}

Start by reading the key files. Use grep to find security-relevant patterns like authentication, authorization, input validation, SQL queries, file operations, secret handling, encryption, and network calls."""

    messages: list[dict] = [
        {"role": "system", "content": AGENT_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    llm_calls = 0
    tool_calls = 0

    while llm_calls < max_llm_calls and tool_calls < max_tool_calls:
        with console.status(f"  Thinking about {subsystem_name}..."):
            response = call_llm_with_tools(config, messages, AGENT_TOOLS)
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
                if tool_calls >= max_tool_calls:
                    break
                result = execute_tool(target_path, tc)
                tool_calls += 1
                console.print(f"    [dim]{tc.function_name}({_brief_args(tc.arguments)})[/dim]")
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc.function_name,
                    "content": result,
                })

            # Check context and compress if needed
            if ctx.needs_compression(messages):
                messages = ctx.compress(config, messages)
                llm_calls += 1  # Compression uses an LLM call
        else:
            # No tool calls — the model is done analyzing
            call_counts["llm"] = llm_calls
            call_counts["tool"] = tool_calls
            return _parse_subsystem_finding(subsystem_name, response.content)

    # Hit limits — ask model to summarize what it has so far
    messages.append({
        "role": "user",
        "content": "You've reached the tool call limit. Please provide your STRIDE threat analysis now based on what you've gathered so far. Respond with the JSON format specified.",
    })
    response = call_llm(config, messages)
    call_counts["llm"] = llm_calls + 1
    call_counts["tool"] = tool_calls
    return _parse_subsystem_finding(subsystem_name, response.content)


def _parse_subsystem_finding(subsystem_name: str, content: str) -> SubsystemFinding:
    """Parse an LLM response into a SubsystemFinding."""
    cleaned = content.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

    try:
        data = json.loads(cleaned)
        return SubsystemFinding(
            subsystem=subsystem_name,
            threats=data.get("threats", []),
            improvement_suggestions=data.get("improvement_suggestions", []),
            files_analyzed=data.get("files_analyzed", []),
        )
    except json.JSONDecodeError:
        # If the response isn't valid JSON, wrap the text as a single finding
        return SubsystemFinding(
            subsystem=subsystem_name,
            threats=[{
                "Threat Type": "Analysis",
                "Scenario": content[:500],
                "Potential Impact": "See scenario for details",
            }],
            improvement_suggestions=["Model returned non-JSON response — consider retrying"],
        )


def _synthesize(config: LLMConfig, findings: list[SubsystemFinding]) -> list[dict[str, Any]]:
    """Identify cross-cutting threats across all subsystem findings."""
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

    json_config = config.model_copy(update={"response_format": "json"})
    messages = [
        {"role": "system", "content": SYNTHESIS_PROMPT},
        {"role": "user", "content": f"Per-subsystem findings:\n{findings_summary}"},
    ]
    response = call_llm(json_config, messages)

    try:
        data = json.loads(response.content)
        return data.get("cross_cutting_threats", [])
    except json.JSONDecodeError:
        return []


def _brief_args(args: dict) -> str:
    """Format tool arguments briefly for console display."""
    parts = []
    for k, v in args.items():
        sv = str(v)
        if len(sv) > 40:
            sv = sv[:37] + "..."
        parts.append(f"{k}={sv!r}")
    return ", ".join(parts)
