"""End-to-end pipeline glue shared by the CLI and the Streamlit UI."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from vulnscope.config import Config
from vulnscope.llm import AnthropicClient, LLMClient
from vulnscope.parsers.findings import Finding, parse_findings
from vulnscope.parsers.threat_model import ThreatModel, parse_threat_model
from vulnscope.report import build_report
from vulnscope.scorer import score_findings, synthesize_summary


def build_client(config: Config) -> LLMClient | None:
    """Return an LLM client, or None for offline/heuristic scoring.

    Offline mode is selected explicitly via ``config.offline`` or implicitly
    when no API key is available.
    """
    if config.offline or not config.api_key:
        return None
    return AnthropicClient(
        config.model, config.api_key, max_tokens=config.max_tokens
    )


def run_analysis(
    threat_model: ThreatModel,
    findings: list[Finding],
    config: Config,
    *,
    client: LLMClient | None = None,
    on_progress: Callable[[int, int, Finding], None] | None = None,
) -> dict:
    """Score findings, synthesise a summary, and assemble the report dict."""
    scored = score_findings(
        findings,
        threat_model,
        weights=config.weights,
        client=client,
        on_progress=on_progress,
    )
    summary = synthesize_summary(scored, threat_model, client=client)
    return build_report(scored, threat_model, summary)


def run_from_paths(
    threat_model_path: str | Path,
    findings_path: str | Path,
    config: Config,
    *,
    client: LLMClient | None = None,
    on_progress: Callable[[int, int, Finding], None] | None = None,
) -> dict:
    """Convenience wrapper: parse both inputs from disk, then run the analysis."""
    threat_model = parse_threat_model(threat_model_path)
    findings = parse_findings(findings_path)
    return run_analysis(
        threat_model, findings, config, client=client, on_progress=on_progress
    )
