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
        # Use the same normaliser as the cell renderer so the column is shown
        # only when at least one threat yields a technique the cell can render.
        # A truthiness check here would resurface the present-but-blank column
        # bug for values that are truthy but normalize to nothing (e.g. a bare
        # int, or the string shape before it was handled).
        show_mitre=any(normalize_mitre_techniques(t.get("MITRE_ATTACK")) for t in threats),
    )


def threat_table_header(
    show_llm: bool,
    show_asi: bool,
    show_insider: bool,
    show_mitre: bool,
    *,
    cross_cutting: bool = False,
    show_verified: bool = False,
) -> tuple[str, str]:
    """Return the ``(header_line, separator_line)`` pair for a markdown table.

    The base columns are always ``Threat Type | Scenario | Potential Impact``;
    optional columns are appended in fixed order. ``cross_cutting=True`` adds
    the ``Affected Subsystems`` column used by the synthesis pass.
    ``show_verified=True`` appends a trailing ``Verified`` column carrying the
    verifier confidence for survivors of the ``--verify`` pass; it defaults off
    so callers that never verify (including the legacy single-shot renderer)
    are unaffected.
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
    if show_verified:
        cols.append("Verified")
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
    show_verified: bool = False,
) -> str:
    """Render a single threat as a markdown table row.

    Every cell is escaped via :func:`_escape_md_cell` — pipes and newlines in
    LLM output must not be allowed to break the table or inject markdown.
    ``null`` / missing optional fields render as empty cells (not ``"None"``).
    When ``show_verified`` is set, a trailing cell shows the verifier confidence
    (e.g. ``9/10``) for a threat that carries a ``verifier`` record.
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
    if show_verified:
        cells.append(_escape_md_cell(format_verified_cell(threat.get("verifier"))))
    return "| " + " | ".join(cells) + " |"


def format_verified_cell(verifier: Any) -> str:
    """Render a threat's ``verifier`` record as a compact confidence cell.

    Returns ``"N/10"`` for a PLAUSIBLE survivor, or an empty string when the
    threat was never verified or the record is malformed.
    """
    if not isinstance(verifier, dict):
        return ""
    if verifier.get("verdict") != "PLAUSIBLE":
        return ""
    conf = verifier.get("confidence")
    return f"{conf}/10" if isinstance(conf, int) else ""


def has_verified_threats(all_threats: Iterable[dict[str, Any]]) -> bool:
    """Return whether any threat carries a PLAUSIBLE verifier record."""
    return any(
        isinstance(t.get("verifier"), dict)
        and t["verifier"].get("verdict") == "PLAUSIBLE"
        for t in all_threats
    )


def is_mitre_technique_id(value: str) -> bool:
    """Return ``True`` if ``value`` looks like a MITRE technique ID.

    Recognizes the same shapes :func:`mitre_url` links: enterprise ATT&CK
    ``T####`` (with an optional ``.###`` sub-technique suffix) and ATLAS
    ``AML.*``. Used to tell real technique IDs apart from prose when a model
    emits ``MITRE_ATTACK`` as a bare or comma-separated string, so junk like
    ``"see the notes"`` is dropped rather than rendered as a technique.
    """
    tid = value.strip()
    if tid.startswith("AML.") and len(tid) > len("AML."):
        return True
    return tid.startswith("T") and len(tid) > 1 and tid[1].isdigit()


def normalize_mitre_techniques(value: Any) -> list[tuple[str, str]]:
    """Normalize a ``MITRE_ATTACK`` field into ``(id, name)`` pairs.

    Accepts every shape models emit for this field:

    - the canonical list-of-objects (``[{"id": "T1190", "name": "..."}]``),
    - the list-of-strings fallback (``["T1190", "T1078"]``), and
    - the comma-separated-string shape that smaller/cheaper worker models
      often emit instead (``"T1190, T1059, AML.T0053"``).

    Names are only carried by the list-of-objects shape; the other shapes
    yield an empty name. String values (whether the whole field or a single
    list entry) are split on commas so the string shape is recovered rather
    than dropped. Tokens parsed out of a string are kept only when they look
    like MITRE IDs (see :func:`is_mitre_technique_id`), so a prose value never
    turns into a fake technique; ``id``s from the structured object shape are
    trusted as-is. Empty / missing / unrecognized input yields ``[]``.

    This is the single source of truth for interpreting ``MITRE_ATTACK`` so
    the markdown, HTML, and SARIF renderers can never disagree on which
    shapes count as populated.
    """
    if not value:
        return []
    if isinstance(value, str):
        entries: list[Any] = [value]
    elif isinstance(value, list):
        entries = value
    else:
        return []
    techniques: list[tuple[str, str]] = []
    for entry in entries:
        if isinstance(entry, dict):
            tid = str(entry.get("id") or "").strip()
            name = str(entry.get("name") or "").strip()
            if tid:
                techniques.append((tid, name))
        elif isinstance(entry, str):
            for part in entry.split(","):
                tid = part.strip()
                if tid and is_mitre_technique_id(tid):
                    techniques.append((tid, ""))
    return techniques


def format_mitre_cell(value: Any) -> str:
    """Render a ``MITRE_ATTACK`` value as a compact markdown cell.

    Delegates shape handling to :func:`normalize_mitre_techniques`, so the
    canonical list-of-objects, the list-of-strings fallback, and the comma-
    separated-string shape all render. Pipes and newlines inside names are
    sanitized so the table stays valid even if the model emits unusual
    characters. Empty / missing / unrecognized input renders as an empty cell.
    """
    techniques = normalize_mitre_techniques(value)
    if not techniques:
        return ""
    parts = [f"{tid} ({name})" if name else tid for tid, name in techniques]
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
    if not is_mitre_technique_id(tid):
        return ""
    if tid.startswith("AML."):
        return f"https://atlas.mitre.org/techniques/{tid}/"
    # Enterprise sub-techniques: T1078.004 → /techniques/T1078/004/
    if "." in tid:
        parent, _, sub = tid.partition(".")
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"
