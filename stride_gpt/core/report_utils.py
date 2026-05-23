"""Shared rendering helpers for threat-model output tables.

Used by both the agentic report renderer (:mod:`stride_gpt.agent.report`) and
the legacy single-shot renderer (:mod:`stride_gpt.core.threat_model`). Each
threat object can optionally carry `OWASP_LLM`, `OWASP_ASI`, and
`INSIDER_CATEGORY` fields — these helpers detect which optional columns are
populated and emit the right header/row shape.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def detect_extra_columns(
    all_threats: Iterable[dict[str, Any]],
) -> tuple[bool, bool, bool]:
    """Decide which optional columns to surface in the rendered tables.

    Returns ``(show_llm, show_asi, show_insider)``. A column is shown only if
    at least one threat carries a non-empty value for it. Compute this once
    at the report level so every table renders with the same shape — partial
    columns per subsystem would look broken.
    """
    threats = list(all_threats)
    show_llm = any(t.get("OWASP_LLM") for t in threats)
    show_asi = any(t.get("OWASP_ASI") for t in threats)
    show_insider = any(t.get("INSIDER_CATEGORY") for t in threats)
    return show_llm, show_asi, show_insider


def threat_table_header(
    show_llm: bool,
    show_asi: bool,
    show_insider: bool,
    *,
    cross_cutting: bool = False,
) -> tuple[str, str]:
    """Return the ``(header_line, separator_line)`` pair for a markdown table.

    The base columns are always ``Threat Type | Scenario | Potential Impact``;
    optional columns are appended in fixed order. ``cross_cutting=True`` adds
    the ``Affected Subsystems`` column used by the synthesis pass.
    """
    cols = ["Threat Type", "Scenario", "Potential Impact"]
    if show_llm:
        cols.append("OWASP LLM")
    if show_asi:
        cols.append("OWASP ASI")
    if show_insider:
        cols.append("Insider Category")
    if cross_cutting:
        cols.append("Affected Subsystems")
    header = "| " + " | ".join(cols) + " |"
    separator = "|" + "|".join("-" * (len(c) + 2) for c in cols) + "|"
    return header, separator


def threat_table_row(
    threat: dict[str, Any],
    show_llm: bool,
    show_asi: bool,
    show_insider: bool,
    *,
    cross_cutting: bool = False,
) -> str:
    """Render a single threat as a markdown table row.

    Pipe characters inside ``Scenario`` / ``Potential Impact`` are escaped so
    they don't break the table. ``null`` / missing optional fields render as
    empty cells (not ``"None"``).
    """
    cells = [
        threat.get("Threat Type", "Unknown"),
        str(threat.get("Scenario", "")).replace("|", "\\|"),
        str(threat.get("Potential Impact", "")).replace("|", "\\|"),
    ]
    if show_llm:
        cells.append(threat.get("OWASP_LLM") or "")
    if show_asi:
        cells.append(threat.get("OWASP_ASI") or "")
    if show_insider:
        cells.append(threat.get("INSIDER_CATEGORY") or "")
    if cross_cutting:
        cells.append(", ".join(threat.get("Affected Subsystems", [])))
    return "| " + " | ".join(cells) + " |"
