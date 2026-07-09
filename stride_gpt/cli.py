"""STRIDE-GPT CLI — interactive threat modeling agent."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Optional

if TYPE_CHECKING:
    from stride_gpt.core.schemas import (
        AnalysisPlan,
        AnalysisReport,
        ModelPair,
        ThreatModelOutput,
    )

from dotenv import load_dotenv

from stride_gpt.config import CONFIG_DIR

load_dotenv(CONFIG_DIR / ".env")  # Load API keys from ~/.stride-gpt/.env

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from stride_gpt.config import (
    config_to_model_pair,
    load_config,
    run_setup,
    show_config,
)

app = typer.Typer(
    name="stride-gpt",
    help="AI-powered threat modeling using the STRIDE methodology.",
    invoke_without_command=True,
)
console = Console()

BANNER = r"""[bold blue]
 _____ _____ _____ _____ ____  _____     _____ _____ _____
|   __|_   _| __  |     |    \|   __|___|   __|  _  |_   _|
|__   | | | |    -|-   -|  |  |   __|___|  |  |   __| | |
|_____| |_| |__|__|_____|____/|_____|   |_____|__|    |_|[/bold blue]

[dim]AI-powered threat modeling agent[/dim]"""

HELP_TEXT = """
[bold]Commands:[/bold]
  [cyan]/analyze[/cyan] [path]        Analyze a codebase for STRIDE threats
  [cyan]/quick[/cyan]               Quick threat model from a text description
  [cyan]/reports[/cyan]              List previous analysis reports
  [cyan]/config[/cyan]              View or change settings
  [cyan]/help[/cyan]                Show this help
  [cyan]/quit[/cyan]                Exit

[bold]Flags[/bold] (for /analyze, /quick, /reports):
  [cyan]-o, --output[/cyan] <path>    Save report to file
  [cyan]-f, --format[/cyan] <fmt>     Output format: markdown (default), json, sarif, html
  [cyan]-y, --yes[/cyan]              Auto-approve the analysis plan

[bold]Examples:[/bold]
  [cyan]/analyze .[/cyan]                          Analyze current directory
  [cyan]/analyze ./my-app[/cyan]                   Analyze a specific path
  [cyan]/analyze . -o report.md[/cyan]             Save report to file
  [cyan]/analyze . -o report.json -f json[/cyan]   Export as JSON (pairs report.html)
  [cyan]/analyze . -o report.html -f html[/cyan]   Export browser-viewable HTML
  [cyan]/quick -i desc.txt -f html -o r.html[/cyan]  Quick model as HTML
  [cyan]/reports[/cyan]                            List recent reports
  [cyan]/reports 1[/cyan]                          View report #1
  [cyan]/reports 1 -o r.md[/cyan]                  Export report #1 to file
"""


class OutputFormat(str, Enum):
    markdown = "markdown"
    json = "json"
    sarif = "sarif"
    html = "html"


class AppTypeOverride(str, Enum):
    """Override for the planner's detected app type. `auto` keeps the planner's choice."""
    auto = "auto"
    web = "web"
    genai = "genai"
    agentic = "agentic"


# ---------------------------------------------------------------------------
# Interactive session
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def interactive(ctx: typer.Context) -> None:
    """Launch interactive session if no subcommand is given."""
    if ctx.invoked_subcommand is not None:
        return

    console.print(BANNER)

    # Load or create config
    config = load_config()
    if config is None:
        config = run_setup(console)
        if config is None:
            console.print("[yellow]Configuration is required to continue. Run stride-gpt again to set up.[/yellow]")
            raise typer.Exit()
    else:
        console.print()
        worker_provider = config.get("worker_provider", "")
        worker_model = config.get("worker_model", "")
        architect_provider = config.get("architect_provider", "")
        architect_model = config.get("architect_model", "")
        if architect_model:
            console.print(
                f"  Architect: [cyan]{architect_provider} / {architect_model}[/cyan]"
            )
            console.print(
                f"  Worker:    [cyan]{worker_provider} / {worker_model}[/cyan]"
            )
        else:
            console.print(f"  Model: [cyan]{worker_provider} / {worker_model}[/cyan]")
        console.print(f"  Type [cyan]/help[/cyan] for commands, [cyan]/config[/cyan] to change settings.")
    console.print()

    # Build interactive prompt session with tab completion, history, status line.
    # The session reads `config` lazily so the bottom toolbar reflects /config changes.
    from stride_gpt.prompt import build_session

    config_box = {"value": config}
    session = build_session(lambda: config_box["value"])

    # Input loop
    while True:
        try:
            user_input = session.prompt().strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        if not user_input:
            continue

        if user_input in ("/quit", "/exit", "/q"):
            console.print("[dim]Goodbye.[/dim]")
            break

        elif user_input == "/help":
            console.print(HELP_TEXT)

        elif user_input == "/config":
            _handle_config(config)
            config = load_config() or config
            config_box["value"] = config

        elif user_input.startswith("/analyze"):
            args = user_input[len("/analyze"):].strip()
            _handle_analyze(config, args)

        elif user_input.startswith("/quick"):
            args = user_input[len("/quick"):].strip()
            _handle_quick(config, args)

        elif user_input.startswith("/reports"):
            args = user_input[len("/reports"):].strip()
            _handle_reports(args)

        elif user_input.startswith("/"):
            console.print(f"[red]Unknown command: {user_input.split()[0]}[/red]")
            console.print("[dim]Type[/dim] [cyan]/help[/cyan] [dim]for available commands.[/dim]")

        else:
            # Bare path — treat as /analyze
            if Path(user_input).is_dir():
                _handle_analyze(config, user_input)
            else:
                console.print("[dim]Type[/dim] [cyan]/help[/cyan] [dim]for available commands, or enter a directory path to analyze.[/dim]")


def _handle_config(config: dict) -> None:
    """Show config and optionally reconfigure."""
    console.print()
    show_config(console, config)
    console.print()
    if Confirm.ask("Reconfigure?", default=False):
        result = run_setup(console, existing=config)
        if result is None:
            console.print("[dim]Keeping existing configuration.[/dim]")


def _persist_analyze_intermediates(
    *,
    output: Path,
    target: Path,
    models: ModelPair,
    plan: AnalysisPlan,
    report: AnalysisReport,
    started_at: datetime,
    finished_at: datetime,
    app_type_source: str,
) -> None:
    """Write plan/findings/run.json siblings next to a /analyze -o report.

    No-op for cancelled runs — matches the existing skip of save_report.
    """
    if report.metadata.get("status") == "cancelled":
        return

    from stride_gpt.agent.persistence import (
        build_analyze_manifest,
        write_intermediates,
    )
    from stride_gpt.core.prompts import base_system_prompt

    refs = report.metadata.get("references_loaded", []) or []
    manifest = build_analyze_manifest(
        models=models,
        plan=plan,
        target=target,
        started_at=started_at,
        finished_at=finished_at,
        app_type_source=app_type_source,
        system_prompt=base_system_prompt(),
        references_loaded=refs,
        llm_calls=report.metadata.get("llm_calls", 0),
        tool_calls=report.metadata.get("tool_calls", 0),
        subsystems_analyzed=report.metadata.get(
            "subsystems_analyzed", len(report.findings)
        ),
    )
    written = write_intermediates(
        output,
        manifest=manifest,
        plan=plan,
        findings=report.findings,
        cross_cutting=report.cross_cutting_threats,
        data_flow_diagram=report.data_flow_diagram,
    )
    for path in written:
        console.print(f"[green]Intermediate written to {path}[/green]")


def _persist_quick_intermediates(
    *,
    output: Path,
    target_label: str,
    models: ModelPair,
    result: ThreatModelOutput,
    started_at: datetime,
    finished_at: datetime,
    hint: str | None,
) -> None:
    """Write the run.json sibling next to a /quick -o report."""
    from stride_gpt.agent.persistence import (
        build_quick_manifest,
        write_intermediates,
    )
    from stride_gpt.core.prompts import coerce_app_type, quick_base_prompt

    detected = coerce_app_type(hint)
    app_type_source = f"hint:{hint}" if hint else "default"
    manifest = build_quick_manifest(
        models=models,
        target_label=target_label,
        detected_app_type=detected,
        app_type_source=app_type_source,
        started_at=started_at,
        finished_at=finished_at,
        system_prompt=quick_base_prompt(),
        references_loaded=result.references_loaded,
        llm_calls=result.llm_calls,
        tool_calls=result.tool_calls,
    )
    written = write_intermediates(output, manifest=manifest)
    for path in written:
        console.print(f"[green]Intermediate written to {path}[/green]")


def _handle_analyze(config: dict, args_str: str) -> None:
    """Run agentic analysis from interactive session."""
    from stride_gpt.agent.html_report import render_html
    from stride_gpt.agent.loop import create_analysis_plan, run_analysis
    from stride_gpt.agent.planner import format_plan_for_display
    from stride_gpt.agent.progress import RichProgress
    from stride_gpt.agent.report import render_json, render_markdown, render_sarif, save_report

    # Parse inline args
    parts = args_str.split() if args_str else ["."]
    target_path = Path(parts[0]).resolve()

    if not target_path.is_dir():
        console.print(f"[red]Error: {parts[0]} is not a directory.[/red]")
        return

    # Check for -o / --output flag
    output_path = None
    output_format = OutputFormat.markdown
    i = 1
    while i < len(parts):
        if parts[i] in ("-o", "--output") and i + 1 < len(parts):
            output_path = Path(parts[i + 1])
            i += 2
        elif parts[i] in ("-f", "--format") and i + 1 < len(parts):
            try:
                output_format = OutputFormat(parts[i + 1])
            except ValueError:
                console.print(f"[red]Invalid format: {parts[i + 1]}. Use markdown, json, sarif, or html.[/red]")
                return
            i += 2
        elif parts[i] in ("-y", "--yes"):
            i += 1  # auto_approve handled below
        else:
            i += 1

    auto_approve = "-y" in args_str or "--yes" in args_str
    models = config_to_model_pair(config)
    if models is None:
        console.print("[red]No model configured. Run /config to set one up.[/red]")
        return

    if not _check_tier_api_keys(config, models):
        return

    _check_lm_studio_context_for(config, models, console)

    console.print(Panel(_panel_target_body(target_path, models), title="[bold]Agentic Analysis[/bold]", style="blue"))

    progress = RichProgress(console)

    # Phase 1: Plan
    started_at = datetime.now(timezone.utc)
    progress.phase_start("Phase 1", "Planning")
    progress.status("Scanning codebase and generating plan...")
    plan = create_analysis_plan(models, target_path)
    console.print(Panel(format_plan_for_display(plan), title="Analysis Plan", style="cyan"))

    if not auto_approve:
        response = console.input("[bold yellow]Approve this plan? (y/n/q): [/bold yellow]")
        if response.lower() not in ("y", "yes"):
            console.print("[red]Analysis cancelled.[/red]")
            return

    # Phases 2+3: Analyze with pre-approved plan
    report = run_analysis(
        models=models,
        target_path=target_path,
        plan=plan,
        progress=progress,
    )
    finished_at = datetime.now(timezone.utc)

    # Auto-save (skip cancelled runs)
    saved_path = None
    if report.metadata.get("status") != "cancelled":
        saved_path = save_report(report)

    # Render
    if output_format == OutputFormat.markdown:
        rendered = render_markdown(report)
    elif output_format == OutputFormat.json:
        rendered = json.dumps(render_json(report), indent=2)
    elif output_format == OutputFormat.sarif:
        rendered = json.dumps(render_sarif(report), indent=2)
    else:  # html
        rendered = render_html(report)

    if output_path:
        output_path.write_text(rendered)
        console.print(f"\n[green]Report written to {output_path}[/green]")
        # JSON output pairs an HTML companion next to it — JSON is the machine
        # artifact, HTML is its human view.
        if output_format == OutputFormat.json:
            html_path = output_path.with_suffix(".html")
            html_path.write_text(render_html(report))
            console.print(f"[green]HTML view written to {html_path}[/green]")
        _persist_analyze_intermediates(
            output=output_path,
            target=target_path,
            models=models,
            plan=plan,
            report=report,
            started_at=started_at,
            finished_at=finished_at,
            app_type_source="planner",
        )
    else:
        console.print()
        if output_format == OutputFormat.markdown:
            console.print(Markdown(rendered))
        elif output_format == OutputFormat.html:
            console.print("[dim]HTML reports must be written to a file with -o.[/dim]")
        else:
            console.print(rendered)

    if saved_path:
        _print_saved_paths(saved_path)
        console.print("[dim]View previous reports with[/dim] [cyan]/reports[/cyan]")


def _handle_reports(args_str: str) -> None:
    """List or view previous analysis reports."""
    from stride_gpt.agent.html_report import render_html_from_json
    from stride_gpt.agent.report import (
        list_reports,
        load_report,
        render_markdown_from_json,
        render_sarif_from_json,
    )

    parts = args_str.split() if args_str else []

    # Pull out --quick / --all kind filters (default: analyze).
    kind = "analyze"
    filtered_parts: list[str] = []
    for tok in parts:
        if tok == "--quick":
            kind = "quick"
        elif tok == "--all":
            kind = "all"
        else:
            filtered_parts.append(tok)
    parts = filtered_parts

    if not parts:
        # List mode
        reports = list_reports(limit=10, kind=kind)
        if not reports:
            console.print("[dim]No saved reports found.[/dim]")
            return

        title_suffix = {"analyze": "", "quick": " (quick)", "all": " (all)"}[kind]
        table = Table(title=f"Recent Reports{title_suffix}", box=None, padding=(0, 2))
        table.add_column("#", style="bold", width=3)
        table.add_column("Date", width=20)
        table.add_column("Kind", style="magenta", width=8)
        table.add_column("Target", style="cyan")
        table.add_column("Threats", justify="right")
        table.add_column("Model", style="dim")

        for idx, _path, summary in reports:
            date_str = summary["generated_at"][:19].replace("T", " ") if summary["generated_at"] else "?"
            target = summary["target"] or "?"
            # /analyze targets are filesystem paths; /quick targets are bare names.
            display_target = Path(target).name if "/" in target or "\\" in target else target
            table.add_row(
                str(idx),
                date_str,
                summary.get("kind", "?"),
                display_target,
                str(summary["threat_count"]),
                summary.get("model", ""),
            )

        console.print()
        console.print(table)
        console.print()
        if kind == "analyze":
            console.print(
                "[dim]View a report:[/dim] [cyan]/reports <number>[/cyan]   "
                "[dim]|[/dim]   [cyan]/reports --quick[/cyan] [dim]to list quick reports[/dim]"
            )
        else:
            console.print("[dim]View a report:[/dim] [cyan]/reports <number>[/cyan]")
        return

    # View/export mode — first arg is the report number
    try:
        report_idx = int(parts[0])
    except ValueError:
        console.print(f"[red]Invalid report number: {parts[0]}[/red]")
        return

    reports = list_reports(limit=max(report_idx, 10), kind=kind)
    match = [r for r in reports if r[0] == report_idx]
    if not match:
        console.print(f"[red]Report #{report_idx} not found.[/red]")
        return

    _, report_path, _ = match[0]
    data = load_report(report_path)

    # Parse optional flags
    output_path = None
    output_format = OutputFormat.markdown
    i = 1
    while i < len(parts):
        if parts[i] in ("-o", "--output") and i + 1 < len(parts):
            output_path = Path(parts[i + 1])
            i += 2
        elif parts[i] in ("-f", "--format") and i + 1 < len(parts):
            try:
                output_format = OutputFormat(parts[i + 1])
            except ValueError:
                console.print(f"[red]Invalid format: {parts[i + 1]}. Use markdown, json, sarif, or html.[/red]")
                return
            i += 2
        else:
            i += 1

    if output_format == OutputFormat.markdown:
        rendered = render_markdown_from_json(data)
    elif output_format == OutputFormat.json:
        rendered = json.dumps(data, indent=2)
    elif output_format == OutputFormat.sarif:
        rendered = json.dumps(render_sarif_from_json(data), indent=2)
    else:  # html
        rendered = render_html_from_json(data)

    if output_path:
        output_path.write_text(rendered)
        console.print(f"[green]Report exported to {output_path}[/green]")
        if output_format == OutputFormat.json:
            html_path = output_path.with_suffix(".html")
            html_path.write_text(render_html_from_json(data))
            console.print(f"[green]HTML view written to {html_path}[/green]")
    else:
        console.print()
        if output_format == OutputFormat.markdown:
            console.print(Markdown(rendered))
        elif output_format == OutputFormat.html:
            console.print("[dim]HTML reports must be written to a file with -o.[/dim]")
        else:
            console.print(rendered)


def _handle_quick(config: dict, args_str: str) -> None:
    """Run quick threat model from a description via the mini agent loop."""
    from stride_gpt.agent.html_report import render_html_from_json
    from stride_gpt.agent.quick import run_quick_analysis
    from stride_gpt.agent.report import save_quick_report
    from stride_gpt.core.threat_model import json_to_markdown

    # Parse flags
    parts = args_str.split() if args_str else []
    input_file: Path | None = None
    output_path: Path | None = None
    hint: str | None = None  # `-t/--type` is now an optional hint, not a switch
    output_format = OutputFormat.markdown

    i = 0
    while i < len(parts):
        if parts[i] in ("-i", "--input") and i + 1 < len(parts):
            input_file = Path(parts[i + 1])
            i += 2
        elif parts[i] in ("-o", "--output") and i + 1 < len(parts):
            output_path = Path(parts[i + 1])
            i += 2
        elif parts[i] in ("-t", "--type") and i + 1 < len(parts):
            hint = parts[i + 1]
            i += 2
        elif parts[i] in ("-f", "--format") and i + 1 < len(parts):
            try:
                output_format = OutputFormat(parts[i + 1])
            except ValueError:
                console.print(
                    f"[red]Invalid format: {parts[i + 1]}. Use markdown or html.[/red]"
                )
                return
            if output_format not in (OutputFormat.markdown, OutputFormat.html):
                console.print(
                    "[red]/quick only supports markdown and html output. "
                    "For JSON or SARIF, see ~/.stride-gpt/reports/quick/.[/red]"
                )
                return
            i += 2
        else:
            i += 1

    # Get app description
    if input_file:
        if not input_file.is_file():
            console.print(f"[red]Error: {input_file} not found.[/red]")
            return
        app_description = input_file.read_text()
        report_name = input_file.stem
    else:
        console.print("[bold]Describe your application[/bold] (press Enter twice to finish):")
        lines: list[str] = []
        empty_count = 0
        while True:
            try:
                line = console.input("[dim]...[/dim] ")
                if not line:
                    empty_count += 1
                    if empty_count >= 1:
                        break
                else:
                    empty_count = 0
                    lines.append(line)
            except (EOFError, KeyboardInterrupt):
                break
        app_description = "\n".join(lines)
        report_name = "quick-analysis"

    if not app_description.strip():
        console.print("[red]Error: Empty app description.[/red]")
        return

    models = config_to_model_pair(config)
    if models is None:
        console.print("[red]No model configured. Run /config to set one up.[/red]")
        return

    if not _check_tier_api_keys(config, models):
        return

    source = str(input_file) if input_file else "typed description"
    console.print(
        Panel(
            f"Source: [cyan]{source}[/cyan]\n{_panel_models_body(models)}"
            + (f"\nType hint: [cyan]{hint}[/cyan]" if hint else ""),
            title="[bold]Quick Threat Model[/bold]",
            style="blue",
        )
    )

    started_at = datetime.now(timezone.utc)
    with console.status("Analysing description..."):
        result = run_quick_analysis(models, app_description, hint=hint)
    finished_at = datetime.now(timezone.utc)

    saved_path = save_quick_report(
        result,
        report_name,
        app_type_hint=hint,
        models=models,
    )

    markdown = json_to_markdown(result.threat_model, result.improvement_suggestions)

    if output_path:
        if output_format == OutputFormat.html:
            # Re-render from the freshly saved JSON so /quick and /reports
            # produce byte-identical HTML for the same analysis.
            from stride_gpt.agent.report import load_report
            html = render_html_from_json(load_report(saved_path))
            output_path.write_text(html)
        else:
            output_path.write_text(markdown)
        console.print(f"[green]Report written to {output_path}[/green]")
        _persist_quick_intermediates(
            output=output_path,
            target_label=str(input_file) if input_file else "stdin",
            models=models,
            result=result,
            started_at=started_at,
            finished_at=finished_at,
            hint=hint,
        )
    else:
        console.print()
        console.print(Markdown(markdown))

    _print_saved_paths(saved_path)
    console.print("[dim]View previous quick reports with[/dim] [cyan]/reports --quick[/cyan]")


# ---------------------------------------------------------------------------
# Non-interactive subcommands (for CI / scripting)
# ---------------------------------------------------------------------------


def _resolve_provider(model: str) -> tuple[str, str]:
    """Infer provider and bare model name from a prefixed model string."""
    prefixes = {
        "anthropic/": "Anthropic API",
        "mistral/": "Mistral API",
        "groq/": "Groq API",
        "openai/": "OpenAI API",
        "google/": "Google AI API",
    }
    for prefix, provider in prefixes.items():
        if model.startswith(prefix):
            return provider, model[len(prefix):]
    return "OpenAI API", model


@app.command()
def analyze(
    path: Annotated[Path, typer.Argument(help="Path to the codebase to analyze.")] = Path("."),
    worker_model: Annotated[Optional[str], typer.Option(help="Worker model — default tier, handles the bulk of calls (e.g. anthropic/claude-sonnet-4-5). A fast, low-cost model usually pays off here. Uses saved config if omitted.")] = None,
    worker_api_key: Annotated[Optional[str], typer.Option(envvar="STRIDE_GPT_API_KEY", help="Worker API key.")] = None,
    worker_api_base: Annotated[Optional[str], typer.Option(help="Worker API base URL (LM Studio).")] = None,
    worker_max_tokens: Annotated[Optional[int], typer.Option(help="Worker per-call output token cap.")] = None,
    architect_model: Annotated[Optional[str], typer.Option(help="Architect model — used only for the reasoning-heavy moments (planning, cross-cutting synthesis, context summarization). Infrequent but high-leverage; a stronger model is worth the cost. Uses saved config if omitted.")] = None,
    architect_api_key: Annotated[Optional[str], typer.Option(help="Architect API key.")] = None,
    architect_api_base: Annotated[Optional[str], typer.Option(help="Architect API base URL.")] = None,
    architect_max_tokens: Annotated[Optional[int], typer.Option(help="Architect per-call output token cap.")] = None,
    no_architect: Annotated[bool, typer.Option("--no-architect", help="Bypass any saved architect tier for this run; worker handles every call.")] = False,
    output: Annotated[Optional[Path], typer.Option("-o", "--output", help="Output file path.")] = None,
    output_format: Annotated[OutputFormat, typer.Option("-f", "--format", help="Output format.")] = OutputFormat.markdown,
    max_llm_calls: Annotated[int, typer.Option(help="Max LLM calls across both tiers (0 = unlimited).")] = 0,
    max_tool_calls: Annotated[int, typer.Option(help="Max tool executions (0 = unlimited).")] = 0,
    auto_approve: Annotated[bool, typer.Option("--yes", "-y", help="Auto-approve the analysis plan.")] = False,
    app_type: Annotated[AppTypeOverride, typer.Option("--app-type", help="Override the planner's app-type classification. 'auto' keeps the planner's choice.")] = AppTypeOverride.auto,
) -> None:
    """Deep agentic analysis of a codebase for STRIDE threats."""
    from stride_gpt.agent.html_report import render_html
    from stride_gpt.agent.loop import create_analysis_plan, run_analysis
    from stride_gpt.agent.planner import format_plan_for_display
    from stride_gpt.agent.progress import RichProgress
    from stride_gpt.agent.report import render_json, render_markdown, render_sarif, save_report

    models = _build_model_pair(
        worker_model=worker_model,
        worker_api_key=worker_api_key,
        worker_api_base=worker_api_base,
        worker_max_tokens=worker_max_tokens,
        architect_model=architect_model,
        architect_api_key=architect_api_key,
        architect_api_base=architect_api_base,
        architect_max_tokens=architect_max_tokens,
        no_architect=no_architect,
    )

    target = path.resolve()
    if not target.is_dir():
        console.print(f"[red]Error: {path} is not a directory.[/red]")
        raise typer.Exit(1)

    _check_lm_studio_context_for(load_config() or {}, models, console, exit_on_fail=True)

    console.print(
        Panel(
            f"[bold]STRIDE-GPT[/bold] Agentic Threat Modeling\n\n"
            f"Target: [cyan]{target}[/cyan]\n"
            f"{_panel_models_body(models)}\n"
            f"Format: [cyan]{output_format.value}[/cyan]",
            style="blue",
        )
    )

    progress = RichProgress(console)

    # Phase 1: Plan
    started_at = datetime.now(timezone.utc)
    progress.phase_start("Phase 1", "Planning")
    progress.status("Scanning codebase and generating plan...")
    plan = create_analysis_plan(models, target)

    # Apply --app-type override, if any.
    if app_type != AppTypeOverride.auto and app_type.value != plan.detected_app_type:
        console.print(
            f"[dim]Overriding detected type "
            f"[yellow]{plan.detected_app_type}[/yellow] → "
            f"[yellow]{app_type.value}[/yellow] (--app-type).[/dim]"
        )
        plan = plan.model_copy(update={"detected_app_type": app_type.value})

    console.print(Panel(format_plan_for_display(plan), title="Analysis Plan", style="cyan"))

    if not auto_approve:
        response = console.input("[bold yellow]Approve this plan? (y/n/q): [/bold yellow]")
        if response.lower() not in ("y", "yes"):
            console.print("[red]Analysis cancelled.[/red]")
            raise typer.Exit(0)

    # Phases 2+3: Analyze with pre-approved plan
    report = run_analysis(
        models=models,
        target_path=target,
        plan=plan,
        max_llm_calls=max_llm_calls,
        max_tool_calls=max_tool_calls,
        progress=progress,
    )
    finished_at = datetime.now(timezone.utc)

    # Auto-save
    saved_path = None
    if report.metadata.get("status") != "cancelled":
        saved_path = save_report(report)

    if output_format == OutputFormat.markdown:
        rendered = render_markdown(report)
    elif output_format == OutputFormat.json:
        rendered = json.dumps(render_json(report), indent=2)
    elif output_format == OutputFormat.sarif:
        rendered = json.dumps(render_sarif(report), indent=2)
    else:  # html
        rendered = render_html(report)

    if output:
        output.write_text(rendered)
        console.print(f"\n[green]Report written to {output}[/green]")
        if output_format == OutputFormat.json:
            html_path = output.with_suffix(".html")
            html_path.write_text(render_html(report))
            console.print(f"[green]HTML view written to {html_path}[/green]")
        app_type_source = (
            f"override:{app_type.value}"
            if app_type != AppTypeOverride.auto
            else "planner"
        )
        _persist_analyze_intermediates(
            output=output,
            target=target,
            models=models,
            plan=plan,
            report=report,
            started_at=started_at,
            finished_at=finished_at,
            app_type_source=app_type_source,
        )
    else:
        console.print()
        if output_format == OutputFormat.markdown:
            console.print(Markdown(rendered))
        elif output_format == OutputFormat.html:
            console.print("[dim]HTML reports must be written to a file with -o.[/dim]")
        else:
            console.print(rendered)

    if saved_path:
        _print_saved_paths(saved_path)
        console.print("[dim]View previous reports with:[/dim] [cyan]stride-gpt reports[/cyan]")


@app.command()
def quick(
    worker_model: Annotated[Optional[str], typer.Option(help="Worker model — default tier, handles fallback / retry calls. A fast, low-cost model is usually fine here. Uses saved config if omitted.")] = None,
    worker_api_key: Annotated[Optional[str], typer.Option(envvar="STRIDE_GPT_API_KEY", help="Worker API key.")] = None,
    worker_api_base: Annotated[Optional[str], typer.Option(help="Worker API base URL (LM Studio).")] = None,
    worker_max_tokens: Annotated[Optional[int], typer.Option(help="Worker per-call output token cap.")] = None,
    architect_model: Annotated[Optional[str], typer.Option(help="Architect model — drives the main single-shot threat-model judgment. A stronger reasoning model is worth the cost here. Uses saved config if omitted.")] = None,
    architect_api_key: Annotated[Optional[str], typer.Option(help="Architect API key.")] = None,
    architect_api_base: Annotated[Optional[str], typer.Option(help="Architect API base URL.")] = None,
    architect_max_tokens: Annotated[Optional[int], typer.Option(help="Architect per-call output token cap.")] = None,
    no_architect: Annotated[bool, typer.Option("--no-architect", help="Bypass any saved architect tier for this run; worker handles every call.")] = False,
    input_file: Annotated[Optional[Path], typer.Option("-i", "--input", help="App description file.")] = None,
    app_type: Annotated[Optional[str], typer.Option(help="Optional hint about the application type (Web / Generative AI / Agentic AI application). Leave unset to let the agent decide which reference cards to load.")] = None,
    output: Annotated[Optional[Path], typer.Option("-o", "--output", help="Output file path.")] = None,
    output_format: Annotated[OutputFormat, typer.Option("-f", "--format", help="Output format: markdown (default) or html.")] = OutputFormat.markdown,
) -> None:
    """Quick threat model from a text description, via the mini agent loop."""
    from stride_gpt.agent.html_report import render_html_from_json
    from stride_gpt.agent.quick import run_quick_analysis
    from stride_gpt.agent.report import load_report, save_quick_report
    from stride_gpt.core.threat_model import json_to_markdown

    if output_format not in (OutputFormat.markdown, OutputFormat.html):
        console.print(
            "[red]/quick only supports markdown and html output. "
            "For JSON or SARIF, see ~/.stride-gpt/reports/quick/.[/red]"
        )
        raise typer.Exit(2)

    models = _build_model_pair(
        worker_model=worker_model,
        worker_api_key=worker_api_key,
        worker_api_base=worker_api_base,
        worker_max_tokens=worker_max_tokens,
        architect_model=architect_model,
        architect_api_key=architect_api_key,
        architect_api_base=architect_api_base,
        architect_max_tokens=architect_max_tokens,
        no_architect=no_architect,
    )

    if input_file:
        if not input_file.is_file():
            console.print(f"[red]Error: {input_file} not found.[/red]")
            raise typer.Exit(1)
        app_description = input_file.read_text()
        report_name = input_file.stem
    else:
        console.print("[dim]Reading app description from stdin (Ctrl+D to finish)...[/dim]")
        app_description = sys.stdin.read()
        report_name = "quick-analysis"

    if not app_description.strip():
        console.print("[red]Error: Empty app description.[/red]")
        raise typer.Exit(1)

    source = str(input_file) if input_file else "stdin"
    console.print(
        Panel(
            f"[bold]STRIDE-GPT[/bold] Quick Threat Model\n\n"
            f"Source: [cyan]{source}[/cyan]\n"
            f"{_panel_models_body(models)}"
            + (f"\nType hint: [cyan]{app_type}[/cyan]" if app_type else ""),
            style="blue",
        )
    )

    started_at = datetime.now(timezone.utc)
    with console.status("Analysing description..."):
        result = run_quick_analysis(models, app_description, hint=app_type)
    finished_at = datetime.now(timezone.utc)

    saved_path = save_quick_report(
        result,
        report_name,
        app_type_hint=app_type,
        models=models,
    )

    markdown = json_to_markdown(result.threat_model, result.improvement_suggestions)

    if output:
        if output_format == OutputFormat.html:
            html = render_html_from_json(load_report(saved_path))
            output.write_text(html)
        else:
            output.write_text(markdown)
        console.print(f"[green]Report written to {output}[/green]")
        _persist_quick_intermediates(
            output=output,
            target_label=str(input_file) if input_file else "stdin",
            models=models,
            result=result,
            started_at=started_at,
            finished_at=finished_at,
            hint=app_type,
        )
    else:
        console.print()
        console.print(Markdown(markdown))

    _print_saved_paths(saved_path)
    console.print("[dim]View previous quick reports with:[/dim] [cyan]stride-gpt reports --quick[/cyan]")


@app.command()
def reports(
    number: Annotated[Optional[int], typer.Argument(help="Report number to view.")] = None,
    output: Annotated[Optional[Path], typer.Option("-o", "--output", help="Export report to file.")] = None,
    output_format: Annotated[OutputFormat, typer.Option("-f", "--format", help="Output format.")] = OutputFormat.markdown,
    limit: Annotated[int, typer.Option("-n", "--limit", help="Number of reports to list.")] = 10,
    quick: Annotated[bool, typer.Option("--quick", help="List description-based /quick reports instead of codebase analyses.")] = False,
    all_kinds: Annotated[bool, typer.Option("--all", help="List both /analyze and /quick reports.")] = False,
) -> None:
    """List or view previous analysis reports."""
    from stride_gpt.agent.html_report import render_html_from_json
    from stride_gpt.agent.report import (
        list_reports,
        load_report,
        render_markdown_from_json,
        render_sarif_from_json,
    )

    kind = "all" if all_kinds else ("quick" if quick else "analyze")

    if number is None:
        # List mode
        report_list = list_reports(limit=limit, kind=kind)
        if not report_list:
            console.print("[dim]No saved reports found.[/dim]")
            raise typer.Exit(0)

        title_suffix = {"analyze": "", "quick": " (quick)", "all": " (all)"}[kind]
        table = Table(title=f"Recent Reports{title_suffix}", box=None, padding=(0, 2))
        table.add_column("#", style="bold", width=3)
        table.add_column("Date", width=20)
        table.add_column("Kind", style="magenta", width=8)
        table.add_column("Target", style="cyan")
        table.add_column("Threats", justify="right")
        table.add_column("Model", style="dim")

        for idx, _path, summary in report_list:
            date_str = summary["generated_at"][:19].replace("T", " ") if summary["generated_at"] else "?"
            target = summary["target"] or "?"
            display_target = Path(target).name if "/" in target or "\\" in target else target
            table.add_row(
                str(idx),
                date_str,
                summary.get("kind", "?"),
                display_target,
                str(summary["threat_count"]),
                summary.get("model", ""),
            )

        console.print()
        console.print(table)
        return

    # View/export mode
    report_list = list_reports(limit=max(number, 10), kind=kind)
    match = [r for r in report_list if r[0] == number]
    if not match:
        console.print(f"[red]Report #{number} not found.[/red]")
        raise typer.Exit(1)

    _, report_path, _ = match[0]
    data = load_report(report_path)

    if output_format == OutputFormat.markdown:
        rendered = render_markdown_from_json(data)
    elif output_format == OutputFormat.json:
        rendered = json.dumps(data, indent=2)
    elif output_format == OutputFormat.sarif:
        rendered = json.dumps(render_sarif_from_json(data), indent=2)
    else:  # html
        rendered = render_html_from_json(data)

    if output:
        output.write_text(rendered)
        console.print(f"[green]Report exported to {output}[/green]")
        if output_format == OutputFormat.json:
            html_path = output.with_suffix(".html")
            html_path.write_text(render_html_from_json(data))
            console.print(f"[green]HTML view written to {html_path}[/green]")
    else:
        console.print()
        if output_format == OutputFormat.markdown:
            console.print(Markdown(rendered))
        elif output_format == OutputFormat.html:
            console.print("[dim]HTML reports must be written to a file with -o.[/dim]")
        else:
            console.print(rendered)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_saved_paths(saved_path: Path) -> None:
    """Tell the user where the auto-saved JSON went, plus the HTML companion.

    The HTML companion is best-effort (see _write_html_companion); we mention
    it only when the sibling actually exists. Paths are coloured rather than
    dimmed — Rich's auto-link styling on dim text becomes near-illegible on
    dark terminal backgrounds.
    """
    console.print(f"\n[dim]A copy of this report has been saved to[/dim] [cyan]{saved_path}[/cyan]")
    html_sibling = saved_path.with_suffix(".html")
    if html_sibling.exists():
        console.print(f"[dim]HTML view:[/dim] [cyan]{html_sibling}[/cyan]")


def _build_model_pair(
    *,
    worker_model: str | None = None,
    worker_api_key: str | None = None,
    worker_api_base: str | None = None,
    worker_max_tokens: int | None = None,
    architect_model: str | None = None,
    architect_api_key: str | None = None,
    architect_api_base: str | None = None,
    architect_max_tokens: int | None = None,
    no_architect: bool = False,
):
    """Build a ModelPair from CLI flags, falling back to saved config + env vars.

    Validations (any failure exits before LLM calls):
      - any --architect-* flag without --architect-model
      - --architect-model with --no-architect
      - missing API key for either tier
    """
    from stride_gpt.config import get_api_key
    from stride_gpt.core.schemas import LLMConfig, ModelPair

    saved = load_config()

    architect_flag_set = any([
        architect_model, architect_api_key, architect_api_base, architect_max_tokens,
    ])
    if architect_flag_set and not architect_model:
        console.print("[red]--architect-* flags require --architect-model.[/red]")
        raise typer.Exit(2)
    if architect_model and no_architect:
        console.print("[red]--architect-model and --no-architect are mutually exclusive.[/red]")
        raise typer.Exit(2)

    # ---- Worker tier ----
    if worker_model:
        worker_provider, worker_model_name = _resolve_provider(worker_model)
    elif saved:
        worker_provider = saved["worker_provider_key"]
        worker_model_name = saved["worker_model"]
    else:
        console.print("[red]No --worker-model specified and no saved config. Run stride-gpt to set up.[/red]")
        raise typer.Exit(1)

    worker_key = worker_api_key or get_api_key(saved or {}, tier="worker")
    if not worker_key and worker_provider != "LM Studio Server":
        console.print("[red]No worker API key found. Set the appropriate env var (e.g. ANTHROPIC_API_KEY) or pass --worker-api-key.[/red]")
        raise typer.Exit(1)

    if worker_api_base is None and saved:
        worker_api_base = saved.get("worker_api_base")
    if worker_max_tokens is None and saved:
        worker_max_tokens = saved.get("worker_max_tokens")

    worker = LLMConfig(
        provider=worker_provider,
        model_name=worker_model_name,
        api_key=worker_key or "",
        api_base=worker_api_base,
        max_tokens=worker_max_tokens,
    )

    # ---- Architect tier ----
    architect: LLMConfig | None = None
    if no_architect:
        architect = None
    elif architect_model:
        a_provider, a_model_name = _resolve_provider(architect_model)
        a_key = architect_api_key or _resolve_explicit_api_key(a_provider) or ""
        if not a_key and a_provider != "LM Studio Server":
            console.print(
                f"[red]Architect API key for {a_provider} could not be resolved. "
                f"Set the provider's env var or pass --architect-api-key.[/red]"
            )
            raise typer.Exit(1)
        architect = LLMConfig(
            provider=a_provider,
            model_name=a_model_name,
            api_key=a_key,
            api_base=architect_api_base,
            max_tokens=architect_max_tokens,
        )
    elif saved and saved.get("architect_model"):
        architect = _tier_to_llm_config_from_saved(saved, "architect")
        if architect is None:
            # Saved architect block present but couldn't be built — usually a missing key.
            architect_provider = saved.get("architect_provider", "")
            console.print(
                f"[red]Saved architect tier ({architect_provider}/{saved['architect_model']}) "
                f"could not be built — API key missing. Set the env var or pass --no-architect.[/red]"
            )
            raise typer.Exit(1)

    return ModelPair(worker=worker, architect=architect)


def _tier_to_llm_config_from_saved(saved: dict, tier: str):
    """Build an LLMConfig for a saved tier; returns None if no API key resolvable."""
    from stride_gpt.config import get_api_key
    from stride_gpt.core.schemas import LLMConfig

    provider = saved.get(f"{tier}_provider_key", "")
    api_key = get_api_key(saved, tier=tier)
    if not api_key and provider != "LM Studio Server":
        return None
    return LLMConfig(
        provider=provider,
        model_name=saved[f"{tier}_model"],
        api_key=api_key,
        api_base=saved.get(f"{tier}_api_base"),
        max_tokens=saved.get(f"{tier}_max_tokens"),
    )


def _resolve_explicit_api_key(provider: str) -> str:
    """Look up an env var key for the given provider, by provider_key."""
    import os

    from stride_gpt.config import PROVIDERS

    for info in PROVIDERS.values():
        if info.provider_key == provider and info.env_var:
            return os.environ.get(info.env_var, "")
    return ""


def _check_tier_api_keys(saved: dict, models) -> bool:
    """For interactive `_handle_*` paths: verify both tiers have keys when needed."""
    if models.worker.provider != "LM Studio Server" and not models.worker.api_key:
        console.print("[red]Worker API key missing. Set the appropriate env var or run /config.[/red]")
        return False
    if models.tiered and models.architect.provider != "LM Studio Server" and not models.architect.api_key:
        console.print("[red]Architect API key missing. Set the appropriate env var or run /config.[/red]")
        return False
    return True


def _check_lm_studio_context_for(saved: dict, models, console_, *, exit_on_fail: bool = False) -> None:
    """Verify LM Studio context window for any LM Studio tier in `models`."""
    from stride_gpt.config import check_lm_studio_context

    for cfg in (models.worker, models.architect):
        if cfg is None:
            continue
        if cfg.provider == "LM Studio Server" and cfg.api_base:
            if not check_lm_studio_context(cfg.api_base, cfg.model_name, console_):
                if exit_on_fail:
                    raise typer.Exit(1)


def _panel_target_body(target_path, models) -> str:
    """Render the body of the interactive analyze panel."""
    return f"Analyzing [cyan]{target_path}[/cyan]\n{_panel_models_body(models)}"


def _panel_models_body(models) -> str:
    """Render model info lines for the analysis panel."""
    from stride_gpt.config import friendly_provider

    if models.tiered:
        a = models.architect
        w = models.worker
        return (
            f"Architect: [cyan]{friendly_provider(a.provider)} / {a.model_name}[/cyan]\n"
            f"Worker:    [cyan]{friendly_provider(w.provider)} / {w.model_name}[/cyan]"
        )
    return (
        f"Model: [cyan]{friendly_provider(models.worker.provider)} / "
        f"{models.worker.model_name}[/cyan]"
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
