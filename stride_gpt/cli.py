"""STRIDE-GPT CLI — interactive threat modeling agent."""

from __future__ import annotations

import json
import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

from dotenv import load_dotenv

from stride_gpt.config import CONFIG_DIR

load_dotenv(CONFIG_DIR / ".env")  # Load API keys from ~/.stride-gpt/.env

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from stride_gpt.config import (
    config_to_llm_config,
    load_config,
    run_setup,
    save_config,
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
  [cyan]/serve[/cyan]               Launch the Streamlit web UI
  [cyan]/help[/cyan]                Show this help
  [cyan]/quit[/cyan]                Exit

[bold]Examples:[/bold]
  [dim]/analyze .[/dim]              Analyze current directory
  [dim]/analyze ./my-app[/dim]       Analyze a specific path
  [dim]/analyze . -o report.md[/dim] Save report to file
  [dim]/quick -i desc.txt[/dim]      Quick model from file
  [dim]/reports[/dim]               List recent reports
  [dim]/reports 1[/dim]             View report #1
  [dim]/reports 1 -o r.md[/dim]     Export report #1 to file
"""


class OutputFormat(str, Enum):
    markdown = "markdown"
    json = "json"
    sarif = "sarif"


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
    else:
        console.print()
        console.print(
            f"  Model: [cyan]{config.get('provider', '')} / {config.get('model', '')}[/cyan]"
        )
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

        elif user_input == "/serve":
            _handle_serve()

        elif user_input.startswith("/"):
            console.print(f"[red]Unknown command: {user_input.split()[0]}[/red]")
            console.print("[dim]Type /help for available commands.[/dim]")

        else:
            # Bare path — treat as /analyze
            if Path(user_input).is_dir():
                _handle_analyze(config, user_input)
            else:
                console.print("[dim]Type /help for available commands, or enter a directory path to analyze.[/dim]")


def _handle_config(config: dict) -> None:
    """Show config and optionally reconfigure."""
    console.print()
    show_config(console, config)
    console.print()
    if Confirm.ask("Reconfigure?", default=False):
        run_setup(console)


def _handle_analyze(config: dict, args_str: str) -> None:
    """Run agentic analysis from interactive session."""
    from stride_gpt.agent.loop import run_analysis
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
                console.print(f"[red]Invalid format: {parts[i + 1]}. Use markdown, json, or sarif.[/red]")
                return
            i += 2
        elif parts[i] in ("-y", "--yes"):
            i += 1  # auto_approve handled below
        else:
            i += 1

    auto_approve = "-y" in args_str or "--yes" in args_str
    llm_config = config_to_llm_config(config)

    if not llm_config.api_key and config.get("provider") not in ("Ollama", "LM Studio"):
        from stride_gpt.config import PROVIDERS

        provider_info = PROVIDERS.get(config.get("provider", ""), {})
        env_var = provider_info.get("env_var", "STRIDE_GPT_API_KEY")
        console.print(f"[red]API key not found. Set {env_var} in your environment.[/red]")
        return

    console.print(
        Panel(
            f"Analyzing [cyan]{target_path}[/cyan]\n"
            f"Model: [cyan]{config.get('provider', '')} / {config.get('model', '')}[/cyan]",
            title="[bold]Agentic Analysis[/bold]",
            style="blue",
        )
    )

    report = run_analysis(
        config=llm_config,
        target_path=target_path,
        auto_approve=auto_approve,
        console=console,
    )

    # Auto-save (skip cancelled runs)
    saved_path = None
    if report.metadata.get("status") != "cancelled":
        saved_path = save_report(report)

    # Render
    if output_format == OutputFormat.markdown:
        rendered = render_markdown(report)
    elif output_format == OutputFormat.json:
        rendered = json.dumps(render_json(report), indent=2)
    else:
        rendered = json.dumps(render_sarif(report), indent=2)

    if output_path:
        output_path.write_text(rendered)
        console.print(f"\n[green]Report written to {output_path}[/green]")
    else:
        console.print()
        if output_format == OutputFormat.markdown:
            console.print(Markdown(rendered))
        else:
            console.print(rendered)

    if saved_path:
        console.print(f"\n[dim]A copy of this report has been saved to {saved_path}[/dim]")
        console.print("[dim]View previous reports with /reports[/dim]")


def _handle_reports(args_str: str) -> None:
    """List or view previous analysis reports."""
    from stride_gpt.agent.report import (
        list_reports,
        load_report,
        render_markdown_from_json,
        render_sarif_from_json,
    )

    parts = args_str.split() if args_str else []

    if not parts:
        # List mode
        reports = list_reports(limit=10)
        if not reports:
            console.print("[dim]No saved reports found.[/dim]")
            return

        table = Table(title="Recent Reports", box=None, padding=(0, 2))
        table.add_column("#", style="bold", width=3)
        table.add_column("Date", width=20)
        table.add_column("Target", style="cyan")
        table.add_column("Threats", justify="right")
        table.add_column("Model", style="dim")

        for idx, _path, summary in reports:
            date_str = summary["generated_at"][:19].replace("T", " ") if summary["generated_at"] else "?"
            table.add_row(
                str(idx),
                date_str,
                Path(summary["target"]).name if summary["target"] else "?",
                str(summary["threat_count"]),
                summary.get("model", ""),
            )

        console.print()
        console.print(table)
        console.print()
        console.print("[dim]View a report: /reports <number>[/dim]")
        return

    # View/export mode — first arg is the report number
    try:
        report_idx = int(parts[0])
    except ValueError:
        console.print(f"[red]Invalid report number: {parts[0]}[/red]")
        return

    reports = list_reports(limit=max(report_idx, 10))
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
                console.print(f"[red]Invalid format: {parts[i + 1]}. Use markdown, json, or sarif.[/red]")
                return
            i += 2
        else:
            i += 1

    if output_format == OutputFormat.markdown:
        rendered = render_markdown_from_json(data)
    elif output_format == OutputFormat.json:
        rendered = json.dumps(data, indent=2)
    else:
        rendered = json.dumps(render_sarif_from_json(data), indent=2)

    if output_path:
        output_path.write_text(rendered)
        console.print(f"[green]Report exported to {output_path}[/green]")
    else:
        console.print()
        if output_format == OutputFormat.markdown:
            console.print(Markdown(rendered))
        else:
            console.print(rendered)


def _handle_quick(config: dict, args_str: str) -> None:
    """Run quick single-shot threat model from interactive session."""
    from stride_gpt.core.threat_model import generate_threat_model, json_to_markdown

    # Parse -i flag
    parts = args_str.split() if args_str else []
    input_file = None
    output_path = None
    app_type = "Web application"

    i = 0
    while i < len(parts):
        if parts[i] in ("-i", "--input") and i + 1 < len(parts):
            input_file = Path(parts[i + 1])
            i += 2
        elif parts[i] in ("-o", "--output") and i + 1 < len(parts):
            output_path = Path(parts[i + 1])
            i += 2
        elif parts[i] in ("-t", "--type") and i + 1 < len(parts):
            app_type = parts[i + 1]
            i += 2
        else:
            i += 1

    # Get app description
    if input_file:
        if not input_file.is_file():
            console.print(f"[red]Error: {input_file} not found.[/red]")
            return
        app_description = input_file.read_text()
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

    if not app_description.strip():
        console.print("[red]Error: Empty app description.[/red]")
        return

    llm_config = config_to_llm_config(config)

    if not llm_config.api_key and config.get("provider") not in ("Ollama", "LM Studio"):
        from stride_gpt.config import PROVIDERS

        provider_info = PROVIDERS.get(config.get("provider", ""), {})
        env_var = provider_info.get("env_var", "STRIDE_GPT_API_KEY")
        console.print(f"[red]API key not found. Set {env_var} in your environment.[/red]")
        return

    # Build prompt
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from threat_model import create_threat_model_prompt

    prompt = create_threat_model_prompt(
        app_type=app_type,
        authentication="Unknown",
        internet_facing="Unknown",
        sensitive_data="Unknown",
        app_input=app_description,
    )

    with console.status("Generating threat model..."):
        result, response = generate_threat_model(llm_config, prompt)

    markdown = json_to_markdown(result.threat_model, result.improvement_suggestions)

    if output_path:
        output_path.write_text(markdown)
        console.print(f"[green]Report written to {output_path}[/green]")
    else:
        console.print()
        console.print(Markdown(markdown))


def _handle_serve() -> None:
    """Launch Streamlit UI."""
    main_py = Path(__file__).resolve().parent.parent / "main.py"
    if not main_py.is_file():
        console.print("[red]Error: main.py not found. Install with [ui] extras.[/red]")
        return

    console.print("[dim]Starting Streamlit...[/dim]")
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(main_py),
         "--server.port=8501", "--server.address=0.0.0.0"],
        check=False,
    )


# ---------------------------------------------------------------------------
# Non-interactive subcommands (for CI / scripting)
# ---------------------------------------------------------------------------


def _resolve_provider(model: str) -> tuple[str, str]:
    """Infer provider and bare model name from a prefixed model string."""
    prefixes = {
        "anthropic/": "Anthropic API",
        "mistral/": "Mistral API",
        "groq/": "Groq API",
        "ollama/": "Ollama",
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
    model: Annotated[Optional[str], typer.Option(help="Model (e.g. anthropic/claude-sonnet-4-5). Uses saved config if omitted.")] = None,
    api_key: Annotated[Optional[str], typer.Option(envvar="STRIDE_GPT_API_KEY", help="API key.")] = None,
    api_base: Annotated[Optional[str], typer.Option(help="Custom API base URL.")] = None,
    output: Annotated[Optional[Path], typer.Option("-o", "--output", help="Output file path.")] = None,
    output_format: Annotated[OutputFormat, typer.Option("-f", "--format", help="Output format.")] = OutputFormat.markdown,
    max_llm_calls: Annotated[int, typer.Option(help="Max LLM calls.")] = 100,
    max_tool_calls: Annotated[int, typer.Option(help="Max tool executions.")] = 200,
    auto_approve: Annotated[bool, typer.Option("--yes", "-y", help="Auto-approve the analysis plan.")] = False,
) -> None:
    """Deep agentic analysis of a codebase for STRIDE threats."""
    from stride_gpt.agent.loop import run_analysis
    from stride_gpt.agent.report import render_json, render_markdown, render_sarif, save_report
    from stride_gpt.core.schemas import LLMConfig

    llm_config = _build_config(model, api_key, api_base)

    target = path.resolve()
    if not target.is_dir():
        console.print(f"[red]Error: {path} is not a directory.[/red]")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"[bold]STRIDE-GPT[/bold] Agentic Threat Modeling\n\n"
            f"Target: [cyan]{target}[/cyan]\n"
            f"Model: [cyan]{llm_config.provider} / {llm_config.model_name}[/cyan]\n"
            f"Format: [cyan]{output_format.value}[/cyan]",
            style="blue",
        )
    )

    report = run_analysis(
        config=llm_config,
        target_path=target,
        max_llm_calls=max_llm_calls,
        max_tool_calls=max_tool_calls,
        auto_approve=auto_approve,
        console=console,
    )

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

    if output:
        output.write_text(rendered)
        console.print(f"\n[green]Report written to {output}[/green]")
    else:
        console.print()
        if output_format == OutputFormat.markdown:
            console.print(Markdown(rendered))
        else:
            console.print(rendered)

    if saved_path:
        console.print(f"\n[dim]A copy of this report has been saved to {saved_path}[/dim]")
        console.print("[dim]View previous reports with: stride-gpt reports[/dim]")


@app.command()
def quick(
    model: Annotated[Optional[str], typer.Option(help="Model. Uses saved config if omitted.")] = None,
    api_key: Annotated[Optional[str], typer.Option(envvar="STRIDE_GPT_API_KEY", help="API key.")] = None,
    input_file: Annotated[Optional[Path], typer.Option("-i", "--input", help="App description file.")] = None,
    app_type: Annotated[str, typer.Option(help="Application type.")] = "Web application",
    output: Annotated[Optional[Path], typer.Option("-o", "--output", help="Output file path.")] = None,
) -> None:
    """Quick single-shot threat model from a text description."""
    from stride_gpt.core.threat_model import generate_threat_model, json_to_markdown

    llm_config = _build_config(model, api_key)

    if input_file:
        if not input_file.is_file():
            console.print(f"[red]Error: {input_file} not found.[/red]")
            raise typer.Exit(1)
        app_description = input_file.read_text()
    else:
        console.print("[dim]Reading app description from stdin (Ctrl+D to finish)...[/dim]")
        app_description = sys.stdin.read()

    if not app_description.strip():
        console.print("[red]Error: Empty app description.[/red]")
        raise typer.Exit(1)

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from threat_model import create_threat_model_prompt

    prompt = create_threat_model_prompt(
        app_type=app_type,
        authentication="Unknown",
        internet_facing="Unknown",
        sensitive_data="Unknown",
        app_input=app_description,
    )

    with console.status("Generating threat model..."):
        result, response = generate_threat_model(llm_config, prompt)

    markdown = json_to_markdown(result.threat_model, result.improvement_suggestions)

    if output:
        output.write_text(markdown)
        console.print(f"[green]Report written to {output}[/green]")
    else:
        console.print()
        console.print(Markdown(markdown))


@app.command()
def reports(
    number: Annotated[Optional[int], typer.Argument(help="Report number to view.")] = None,
    output: Annotated[Optional[Path], typer.Option("-o", "--output", help="Export report to file.")] = None,
    output_format: Annotated[OutputFormat, typer.Option("-f", "--format", help="Output format.")] = OutputFormat.markdown,
    limit: Annotated[int, typer.Option("-n", "--limit", help="Number of reports to list.")] = 10,
) -> None:
    """List or view previous analysis reports."""
    from stride_gpt.agent.report import (
        list_reports,
        load_report,
        render_markdown_from_json,
        render_sarif_from_json,
    )

    if number is None:
        # List mode
        report_list = list_reports(limit=limit)
        if not report_list:
            console.print("[dim]No saved reports found.[/dim]")
            raise typer.Exit(0)

        table = Table(title="Recent Reports", box=None, padding=(0, 2))
        table.add_column("#", style="bold", width=3)
        table.add_column("Date", width=20)
        table.add_column("Target", style="cyan")
        table.add_column("Threats", justify="right")
        table.add_column("Model", style="dim")

        for idx, _path, summary in report_list:
            date_str = summary["generated_at"][:19].replace("T", " ") if summary["generated_at"] else "?"
            table.add_row(
                str(idx),
                date_str,
                Path(summary["target"]).name if summary["target"] else "?",
                str(summary["threat_count"]),
                summary.get("model", ""),
            )

        console.print()
        console.print(table)
        return

    # View/export mode
    report_list = list_reports(limit=max(number, 10))
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
    else:
        rendered = json.dumps(render_sarif_from_json(data), indent=2)

    if output:
        output.write_text(rendered)
        console.print(f"[green]Report exported to {output}[/green]")
    else:
        console.print()
        if output_format == OutputFormat.markdown:
            console.print(Markdown(rendered))
        else:
            console.print(rendered)


@app.command()
def serve(
    port: Annotated[int, typer.Option(help="Port for Streamlit.")] = 8501,
    host: Annotated[str, typer.Option(help="Host to bind to.")] = "0.0.0.0",
) -> None:
    """Launch the Streamlit web UI."""
    main_py = Path(__file__).resolve().parent.parent / "main.py"
    if not main_py.is_file():
        console.print("[red]Error: main.py not found.[/red]")
        raise typer.Exit(1)

    console.print(f"[dim]Starting Streamlit on {host}:{port}...[/dim]")
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(main_py),
         f"--server.port={port}", f"--server.address={host}"],
        check=False,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_config(
    model: str | None = None,
    api_key: str | None = None,
    api_base: str | None = None,
):
    """Build LLMConfig from CLI flags, falling back to saved config + env vars."""
    from stride_gpt.config import get_api_key
    from stride_gpt.core.schemas import LLMConfig

    saved = load_config()

    if model:
        provider, model_name = _resolve_provider(model)
    elif saved:
        provider = saved["provider_key"]
        model_name = saved["model"]
    else:
        console.print("[red]No model specified and no saved config. Run stride-gpt to set up.[/red]")
        raise typer.Exit(1)

    if not api_key:
        api_key = get_api_key(saved or {})

    if not api_key and provider not in ("Ollama", "LM Studio Server"):
        console.print("[red]No API key found in environment. Set the appropriate env var (e.g. ANTHROPIC_API_KEY).[/red]")
        raise typer.Exit(1)

    if not api_base and saved:
        api_base = saved.get("api_base")

    return LLMConfig(
        provider=provider,
        model_name=model_name,
        api_key=api_key or "",
        api_base=api_base,
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
