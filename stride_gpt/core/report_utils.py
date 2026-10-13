"""Shared rendering helpers for threat-model output tables.

Used by both the agentic report renderer (:mod:`stride_gpt.agent.report`) and
the legacy single-shot renderer (:mod:`stride_gpt.core.threat_model`). Each
threat object can optionally carry `OWASP_LLM`, `OWASP_ASI`,
`INSIDER_CATEGORY`, `MITRE_ATTACK`, and `evidence` fields — these helpers
detect which optional columns are populated and emit the right header/row
shape.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, NamedTuple


class ExtraColumns(NamedTuple):
    """Which optional columns to render across a report.

    Splat it into the header and row helpers (``threat_table_header(*cols)``)
    rather than unpacking it by name — the tuple grows as reference cards add
    fields, and a positional unpack breaks every call site when it does.
    """

    show_llm: bool
    show_asi: bool
    show_insider: bool
    show_mitre: bool
    show_evidence: bool


# Why a subsystem stopped, phrased for a report reader. Keyed by
# ``SubsystemOutcome``; ``completed`` is absent because a completed subsystem
# needs no explanation.
_OUTCOME_NOTES: dict[str, str] = {
    "budget_exhausted": (
        "the analysis budget ran out, so threats were reported in a final round "
        "without further exploration"
    ),
    "parse_failed": (
        "the model's final answer could not be read, so this subsystem may be "
        "incomplete"
    ),
    "error": "the analysis stopped with an error",
    "skipped": "the run budget ran out before this subsystem was analysed",
}

_ERROR_CLASS_NOTES: dict[str, str] = {
    "context_overflow": "the context window was exceeded",
    "rate_limited": "the provider rate-limited the run",
    "auth": "the provider rejected the credentials",
    "provider_error": "the provider failed to answer",
    "unexpected": "an unexpected error",
}


def outcome_note(outcome: str, error_class: str | None = None) -> str | None:
    """A one-line explanation of a subsystem's outcome, or None if it completed.

    Reports that show only threats make a crashed subsystem look like a clean
    one with nothing to report. Markdown and HTML share this wording so they
    can't drift.
    """
    note = _OUTCOME_NOTES.get(outcome)
    if note is None:
        return None
    detail = _ERROR_CLASS_NOTES.get(error_class or "")
    return f"{note} ({detail})" if detail else note


def detect_extra_columns(
    all_threats: Iterable[dict[str, Any]],
) -> ExtraColumns:
    """Decide which optional columns to surface in the rendered tables.

    Returns an :class:`ExtraColumns` tuple. A column is shown only if at
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
        show_evidence=any(evidence_items(t) for t in threats),
    )


def threat_table_header(
    show_llm: bool,
    show_asi: bool,
    show_insider: bool,
    show_mitre: bool,
    show_evidence: bool = False,
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
    if show_evidence:
        cols.append("Evidence")
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
    show_evidence: bool = False,
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
    if show_evidence:
        cells.append(_escape_md_cell(format_evidence_cell(threat)))
    if cross_cutting:
        affected = threat.get("Affected Subsystems", [])
        cells.append(_escape_md_cell(", ".join(str(a) for a in affected)))
    return "| " + " | ".join(cells) + " |"


SYSTEMIC_OBSERVATIONS_NOTE = (
    "These summarise weaknesses already reported in the subsystem sections. "
    "They are not separate threats and are not counted in the totals."
)


def related_threat_labels(
    observation: dict[str, Any],
    subsystems: Iterable[tuple[str, Iterable[dict[str, Any]]]],
) -> list[tuple[str, str]]:
    """``(id, description)`` for each threat a systemic observation links to.

    ``subsystems`` is ``(name, threats)`` pairs. The description says where the
    threat lives — ``Streamlit Frontend: Spoofing`` — because threat ids are not
    shown in the tables. An id that matches no threat (a hand-edited or
    truncated saved report) is kept with an empty description rather than
    dropped, so the link stays visible.
    """
    known: dict[str, str] = {}
    for name, threats in subsystems:
        for threat in threats:
            tid = threat.get("id")
            if isinstance(tid, str) and tid:
                known[tid] = f"{name}: {threat.get('Threat Type', 'Unknown')}"
    related = observation.get("Related Threats")
    if not isinstance(related, list):
        return []
    return [(str(tid), known.get(str(tid), "")) for tid in related]


def systemic_observation_lines(
    observation: dict[str, Any],
    subsystems: Iterable[tuple[str, Iterable[dict[str, Any]]]],
) -> list[str]:
    """One systemic observation as a markdown bullet with its links.

    A list rather than a table row: an observation is prose plus a set of
    links, and none of the threat table's columns describe it. Values go
    through :func:`_escape_md_cell` so LLM text can't start a new block.
    """
    lines = [
        f"- **{_escape_md_cell(observation.get('Threat Type', 'Unknown'))}**: "
        f"{_escape_md_cell(observation.get('Scenario', ''))}"
    ]
    if observation.get("Potential Impact"):
        lines.append(f"  - Impact: {_escape_md_cell(observation['Potential Impact'])}")
    affected = observation.get("Affected Subsystems")
    if isinstance(affected, list) and affected:
        lines.append(f"  - Affects: {_escape_md_cell(', '.join(str(a) for a in affected))}")
    links = related_threat_labels(observation, subsystems)
    if links:
        rendered = "; ".join(
            f"`{_escape_md_cell(tid)}`" + (f" ({_escape_md_cell(label)})" if label else "")
            for tid, label in links
        )
        lines.append(f"  - Summarises: {rendered}")
    return lines


def evidence_items(threat: Any) -> list[dict[str, Any]]:
    """Evidence entries on a threat, or none for a report written before it existed.

    The agent records each threat's evidence as ``{path, snippet, verified,
    start_line, end_line}``; ``/quick`` and pre-change saved reports have
    none, so every renderer has to cope with the key being absent.
    """
    if not isinstance(threat, dict):
        return []
    evidence = threat.get("evidence")
    if not isinstance(evidence, list):
        return []
    return [item for item in evidence if isinstance(item, dict)]


def format_evidence_cell(threat: dict[str, Any]) -> str:
    """Render a threat's evidence as ``src/auth.py:12-18; config.yaml (unverified)``.

    A line range is the verification signal — a snippet we couldn't find in
    the file has no range to show, so it says so instead. A snippet that
    appears more than once says so too: the range is the first match, which
    may not be the one the threat is about.
    """
    parts: list[str] = []
    for item in evidence_items(threat):
        if not item.get("verified"):
            parts.append(f"{evidence_location(item)} (unverified)")
            continue
        occurrences = item.get("occurrences")
        suffix = (
            f" ({occurrences} matches)"
            if isinstance(occurrences, int) and occurrences > 1
            else ""
        )
        parts.append(f"{evidence_location(item)}{suffix}")
    return "; ".join(parts)


def evidence_location(item: dict[str, Any]) -> str:
    """``src/auth.py:12-18`` for a verified item, the bare path otherwise."""
    path = str(item.get("path") or "?")
    if not item.get("verified"):
        return path
    start, end = item.get("start_line"), item.get("end_line")
    if isinstance(start, int) and isinstance(end, int) and start != end:
        return f"{path}:{start}-{end}"
    if isinstance(start, int):
        return f"{path}:{start}"
    return path


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
