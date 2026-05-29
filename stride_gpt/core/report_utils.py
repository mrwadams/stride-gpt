"""Shared rendering helpers for threat-model output tables.

Used by both the agentic report renderer (:mod:`stride_gpt.agent.report`) and
the legacy single-shot renderer (:mod:`stride_gpt.core.threat_model`). Each
threat object can optionally carry `OWASP_LLM`, `OWASP_ASI`,
`INSIDER_CATEGORY`, and `MITRE_ATTACK` fields — these helpers detect which
optional columns are populated and emit the right header/row shape.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, NamedTuple


class ExtraColumns(NamedTuple):
    """Which optional columns to render across a report.

    Tuple-positional for legacy unpacking (``show_llm, show_asi, show_insider,
    show_mitre = detect_extra_columns(...)``); attribute-named for clarity at
    keyword call sites.
    """

    show_llm: bool
    show_asi: bool
    show_insider: bool
    show_mitre: bool


def detect_extra_columns(
    all_threats: Iterable[dict[str, Any]],
) -> ExtraColumns:
    """Decide which optional columns to surface in the rendered tables.

    Returns an :class:`ExtraColumns` 4-tuple. A column is shown only if at
    least one threat carries a non-empty value for it. Compute this once at
    the report level so every table renders with the same shape — partial
    columns per subsystem would look broken.
    """
    threats = list(all_threats)
    return ExtraColumns(
        show_llm=any(t.get("OWASP_LLM") for t in threats),
        show_asi=any(t.get("OWASP_ASI") for t in threats),
        show_insider=any(t.get("INSIDER_CATEGORY") for t in threats),
        show_mitre=any(t.get("MITRE_ATTACK") for t in threats),
    )


def threat_table_header(
    show_llm: bool,
    show_asi: bool,
    show_insider: bool,
    show_mitre: bool,
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
    if show_mitre:
        cols.append("MITRE ATT&CK")
    if cross_cutting:
        cols.append("Affected Subsystems")
    header = "| " + " | ".join(cols) + " |"
    separator = "|" + "|".join("-" * (len(c) + 2) for c in cols) + "|"
    return header, separator


def _escape_md_cell(value: Any) -> str:
    """Make an LLM-supplied value safe to drop into a markdown table cell.

    Escapes ``|`` so it doesn't open a new column, and collapses newlines so a
    malicious value can't break out of the row and inject arbitrary markdown
    below the table.
    """
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def threat_table_row(
    threat: dict[str, Any],
    show_llm: bool,
    show_asi: bool,
    show_insider: bool,
    show_mitre: bool,
    *,
    cross_cutting: bool = False,
) -> str:
    """Render a single threat as a markdown table row.

    Every cell is escaped via :func:`_escape_md_cell` — pipes and newlines in
    LLM output must not be allowed to break the table or inject markdown.
    ``null`` / missing optional fields render as empty cells (not ``"None"``).
    """
    cells = [
        _escape_md_cell(threat.get("Threat Type", "Unknown")),
        _escape_md_cell(threat.get("Scenario", "")),
        _escape_md_cell(threat.get("Potential Impact", "")),
    ]
    if show_llm:
        cells.append(_escape_md_cell(threat.get("OWASP_LLM") or ""))
    if show_asi:
        cells.append(_escape_md_cell(threat.get("OWASP_ASI") or ""))
    if show_insider:
        cells.append(_escape_md_cell(threat.get("INSIDER_CATEGORY") or ""))
    if show_mitre:
        cells.append(format_mitre_cell(threat.get("MITRE_ATTACK")))
    if cross_cutting:
        affected = threat.get("Affected Subsystems", [])
        cells.append(_escape_md_cell(", ".join(str(a) for a in affected)))
    return "| " + " | ".join(cells) + " |"


def format_mitre_cell(value: Any) -> str:
    """Render a ``MITRE_ATTACK`` list as a compact markdown cell.

    Accepts the canonical list-of-objects shape
    (``[{"id": "T1190", "name": "..."}]``) and the simpler list-of-strings
    fallback (``["T1190", "T1078"]``). Pipes and newlines inside names are
    sanitized so the table stays valid even if the model emits unusual
    characters. Empty / missing / non-list input renders as an empty cell.
    """
    if not isinstance(value, list) or not value:
        return ""
    parts: list[str] = []
    for entry in value:
        if isinstance(entry, dict):
            tid = str(entry.get("id") or "").strip()
            name = str(entry.get("name") or "").strip()
            if not tid:
                continue
            parts.append(f"{tid} ({name})" if name else tid)
        elif isinstance(entry, str):
            tid = entry.strip()
            if tid:
                parts.append(tid)
    return _escape_md_cell(", ".join(parts))


def mitre_url(technique_id: str) -> str:
    """Return the canonical ATT&CK or ATLAS URL for a technique ID.

    Enterprise technique IDs follow ``T####`` (with optional ``.###`` sub-
    technique suffix) and resolve to ``attack.mitre.org``. ATLAS IDs carry the
    ``AML.`` prefix and resolve to ``atlas.mitre.org``. Returns an empty
    string for IDs that don't match either pattern — the renderer falls back
    to plain text in that case rather than producing a broken link.
    """
    tid = technique_id.strip()
    if tid.startswith("AML."):
        return f"https://atlas.mitre.org/techniques/{tid}/"
    if tid.startswith("T") and len(tid) > 1 and tid[1].isdigit():
        # Enterprise sub-techniques: T1078.004 → /techniques/T1078/004/
        if "." in tid:
            parent, _, sub = tid.partition(".")
            return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
        return f"https://attack.mitre.org/techniques/{tid}/"
    return ""
