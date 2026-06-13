"""VulnScope CLI — prioritise vulnerability findings against a threat model.

Usage:
    python cli.py --threat-model tm.json --findings results.sarif
    python cli.py --threat-model tm.json --findings results.json -o out/report

Produces a machine-readable ``.json`` report and a human-readable ``.md``
report, and prints a console summary.
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path
from typing import Annotated, Optional

import typer
from dotenv import load_dotenv

# Make `import vulnscope` work when this file is run directly as `python cli.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent))

load_dotenv()  # Load ANTHROPIC_API_KEY etc. from a local .env if present.

from vulnscope.config import Config, Weights  # noqa: E402
from vulnscope.parsers.findings import Finding, parse_findings  # noqa: E402
from vulnscope.parsers.threat_model import parse_threat_model  # noqa: E402
from vulnscope.pipeline import build_client, run_analysis  # noqa: E402
from vulnscope.report import render_console_summary, render_markdown  # noqa: E402

def main(
    threat_model: Annotated[
        Path,
        typer.Option(
            "--threat-model",
            "-t",
            help="Threat model file (STRIDE-GPT JSON export or minimal JSON schema).",
        ),
    ],
    findings: Annotated[
        Path,
        typer.Option(
            "--findings",
            "-f",
            help="Findings file (SARIF v2.1.0 or a simple JSON array).",
        ),
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output path prefix; '.json' and '.md' are appended. "
            "Defaults to vulnscope_report_<date>.",
        ),
    ] = None,
    model: Annotated[
        Optional[str],
        typer.Option(
            help="LiteLLM model id (default claude-sonnet-4-6). Use a provider "
            "prefix for non-Anthropic models, e.g. openai/gpt-5.4, "
            "gemini/gemini-3.1-pro-preview, groq/llama-3.3-70b-versatile, "
            "mistral/mistral-large-latest, or ollama/llama3.3 (with --api-base)."
        ),
    ] = None,
    api_key: Annotated[
        Optional[str],
        typer.Option(
            help="API key. Defaults to the provider's env var "
            "(ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, GROQ_API_KEY, "
            "MISTRAL_API_KEY)."
        ),
    ] = None,
    api_base: Annotated[
        Optional[str],
        typer.Option(
            help="Custom endpoint for self-hosted models (Ollama, LM Studio)."
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Score with the deterministic heuristic instead of the LLM "
            "(no API key required).",
        ),
    ] = False,
    asset_weight: Annotated[
        Optional[float], typer.Option(help="Asset criticality weight (default 0.35).")
    ] = None,
    align_weight: Annotated[
        Optional[float], typer.Option(help="Threat alignment weight (default 0.30).")
    ] = None,
    boundary_weight: Annotated[
        Optional[float], typer.Option(help="Trust boundary exposure weight (default 0.25).")
    ] = None,
    stride_weight: Annotated[
        Optional[float], typer.Option(help="STRIDE category weight (default 0.10).")
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Suppress per-finding progress output.")
    ] = False,
) -> None:
    """Prioritise findings against a threat model and write JSON + markdown reports."""
    # Resolve weights: any unset flag falls back to env/defaults.
    base = Config.from_env()
    weights = Weights(
        asset_criticality=_or(asset_weight, base.weights.asset_criticality),
        threat_alignment=_or(align_weight, base.weights.threat_alignment),
        trust_boundary_exposure=_or(boundary_weight, base.weights.trust_boundary_exposure),
        stride_category_weight=_or(stride_weight, base.weights.stride_category_weight),
    )
    config = Config.from_env(
        model=model,
        api_key=api_key,
        api_base=api_base,
        offline=offline or None,
        weights=weights,
    )

    # --- Parse inputs ---
    try:
        tm = parse_threat_model(threat_model)
        finding_list = parse_findings(findings)
    except (FileNotFoundError, ValueError) as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc

    if not finding_list:
        typer.secho("No findings to prioritise.", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(1)

    # --- Build LLM client (or fall back to offline heuristic) ---
    try:
        client = build_client(config)
    except RuntimeError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc

    from vulnscope.providers import infer_provider, normalise_model

    mode = "offline heuristic" if client is None else f"LLM ({normalise_model(config.model)})"
    typer.echo(
        f"Scoring {len(finding_list)} finding(s) against '{tm.application_name}' "
        f"using {mode}..."
    )
    if client is None and not offline:
        provider = infer_provider(config.model) or "the chosen provider"
        typer.secho(
            f"  (no API key found for {provider} — using the offline heuristic; set "
            f"the provider's API key for LLM scoring, or pass --offline to silence "
            f"this.)",
            fg=typer.colors.YELLOW,
        )

    def _progress(i: int, total: int, finding: Finding) -> None:
        if not quiet:
            typer.echo(f"  [{i}/{total}] {finding.id}", err=True)

    report = run_analysis(
        tm, finding_list, config, client=client, on_progress=_progress
    )

    # --- Write outputs ---
    prefix = output or Path(f"vulnscope_report_{date.today().isoformat()}")
    json_path = prefix.with_suffix(".json")
    md_path = prefix.with_suffix(".md")
    if json_path.parent and not json_path.parent.exists():
        json_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(json.dumps(report, indent=2) + "\n")
    md_path.write_text(render_markdown(report))

    typer.echo("")
    typer.echo(render_console_summary(report, str(md_path)))
    typer.echo(f"  JSON report:     {json_path}")


def _or(value: Optional[float], default: float) -> float:
    return default if value is None else value


if __name__ == "__main__":
    typer.run(main)
