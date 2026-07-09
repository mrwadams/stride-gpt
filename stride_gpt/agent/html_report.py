"""HTML report renderer — single-file, Tailwind-styled view of a STRIDE report.

Output is a self-contained HTML document. The only external dependency is
the Tailwind CDN; there is no JavaScript and no app code. Designed as a
human-readable companion to the JSON report — STRIDE category is the primary
visual signal, every threat gets a card, and optional OWASP / Insider lenses
surface as outline pills when present.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from stride_gpt.core.report_utils import mitre_url, normalize_mitre_techniques
from stride_gpt.core.schemas import AnalysisReport

# STRIDE category → Tailwind badge classes. Six categories carry distinct
# hues because category is the dominant visual signal, but each pairs a -50
# fill with a matching ring so chips read as categorized tags rather than
# highlighter marks against the slate chrome.
_STRIDE_BADGE_CLASSES: dict[str, str] = {
    "Spoofing": "bg-indigo-50 text-indigo-800 ring-indigo-200",
    "Tampering": "bg-amber-50 text-amber-800 ring-amber-200",
    "Repudiation": "bg-slate-100 text-slate-800 ring-slate-300",
    "Information Disclosure": "bg-rose-50 text-rose-800 ring-rose-200",
    "Denial of Service": "bg-orange-50 text-orange-800 ring-orange-200",
    "Elevation of Privilege": "bg-red-50 text-red-800 ring-red-200",
}
_DEFAULT_BADGE = "bg-slate-50 text-slate-800 ring-slate-200"
_BADGE_BASE = (
    "inline-flex items-center rounded-full px-3 py-1 text-xs font-medium "
    "ring-1 ring-inset"
)
_PILL_BASE = (
    "inline-flex items-center rounded-full ring-1 ring-inset ring-slate-300 "
    "px-2.5 py-0.5 text-xs font-mono text-slate-700"
)
# MITRE pills lean on a subtle sky tint so they're distinguishable from the
# OWASP / Insider pills without competing with the dominant STRIDE badge.
_MITRE_PILL_BASE = (
    "inline-flex items-center rounded-full ring-1 ring-inset ring-sky-300 "
    "bg-sky-50 px-2.5 py-0.5 text-xs font-mono text-sky-800 hover:bg-sky-100"
)
# Small uppercase captions inside cards — Scenario, Potential impact, etc.
# Mono ties them to the CLI aesthetic without leaning hard on a "terminal" theme.
_CAPTION = "text-[11px] font-mono uppercase tracking-wider text-slate-500"


def render_html(report: AnalysisReport) -> str:
    """Render an in-memory AnalysisReport as a self-contained HTML document.

    Builds the JSON-shape view inline rather than calling `render_json` from
    `agent.report` — that would create an import cycle (report.py
    lazy-imports this module to write the HTML companion).
    """
    data: dict[str, Any] = {
        "version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": report.plan.target_path,
        "overview": report.plan.overall_description,
        "data_flow_diagram": report.data_flow_diagram,
        "subsystems": [
            {
                "name": f.subsystem,
                "threats": f.threats,
                "improvement_suggestions": f.improvement_suggestions,
                "files_analyzed": f.files_analyzed,
            }
            for f in report.findings
        ],
        "cross_cutting_threats": report.cross_cutting_threats,
        "metadata": report.metadata,
    }
    return render_html_from_json(data)


def render_html_from_json(data: dict[str, Any]) -> str:
    """Render a saved JSON report (the disk format) as HTML.

    The two entry points share this implementation so the live `/analyze`
    output and the `/reports` replay path produce byte-identical HTML.
    """
    target = data.get("target") or ""
    target_name = Path(target).name or target or "(unknown target)"
    generated_at = _format_generated_at(data.get("generated_at", ""))
    overview = (data.get("overview") or "").strip()
    dfd_mermaid = (data.get("data_flow_diagram") or "").strip()
    subsystems = data.get("subsystems") or []
    cross_cutting = data.get("cross_cutting_threats") or []
    metadata = data.get("metadata") or {}

    total_threats = sum(len(s.get("threats") or []) for s in subsystems)
    total_threats += len(cross_cutting)

    parts: list[str] = []
    parts.append(_render_header(
        target_name=target_name,
        generated_at=generated_at,
        metadata=metadata,
        total_threats=total_threats,
        subsystem_count=len(subsystems),
        cross_cutting_count=len(cross_cutting),
    ))

    if overview:
        parts.append(_render_overview(overview))

    if dfd_mermaid:
        parts.append(_render_dfd(dfd_mermaid))

    parts.extend(_render_subsystem(sub) for sub in subsystems)

    if cross_cutting:
        parts.append(_render_cross_cutting(cross_cutting))

    parts.append(_render_footer(metadata))

    body = "\n".join(parts)
    return _scaffold(target_name=target_name, body=body)


# ---------------------------------------------------------------------------
# Scaffold + page chrome
# ---------------------------------------------------------------------------


def _scaffold(*, target_name: str, body: str) -> str:
    title = html.escape(f"STRIDE Threat Model — {target_name}")
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{title}</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-slate-50 text-slate-900 font-sans">
    <main class="max-w-5xl mx-auto px-6 py-12 space-y-12">
{body}
    </main>
    <script type="module">
      import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
      mermaid.initialize({{ startOnLoad: true, securityLevel: 'strict' }});
    </script>
  </body>
</html>
"""


def _render_header(
    *,
    target_name: str,
    generated_at: str,
    metadata: dict[str, Any],
    total_threats: int,
    subsystem_count: int,
    cross_cutting_count: int,
) -> str:
    model_line = _format_model_line(metadata)
    chip = (
        "inline-flex items-center rounded-full bg-white ring-1 ring-inset ring-slate-200 "
        "px-3 py-1 text-xs font-mono text-slate-700"
    )

    summary_chips = [
        f'<span class="{chip}">{total_threats} threats</span>',
    ]
    # /quick reports collapse to one synthetic "Application" subsystem; showing
    # "1 subsystem" there would be misleading, so suppress when ≤1.
    if subsystem_count > 1:
        summary_chips.append(f'<span class="{chip}">{subsystem_count} subsystems</span>')
    if cross_cutting_count:
        summary_chips.append(
            f'<span class="{chip}">{cross_cutting_count} cross-cutting</span>'
        )

    meta_line_parts: list[str] = []
    if generated_at:
        meta_line_parts.append(f"Generated {html.escape(generated_at)}")
    if model_line:
        meta_line_parts.append(html.escape(model_line))
    meta_line = " · ".join(meta_line_parts)

    return f"""      <header class="border-b border-slate-200 pb-8 space-y-4">
        <p class="font-mono text-xs tracking-tight text-slate-500">
          <span class="text-slate-400">&rsaquo;</span>
          <span class="text-slate-700">stride-gpt</span>
          <span class="text-slate-400">threat-model</span>
        </p>
        <h1 class="text-3xl font-semibold tracking-tight text-slate-900">{html.escape(target_name)}</h1>
        <p class="text-sm text-slate-600">{meta_line}</p>
        <div class="flex flex-wrap gap-2 pt-2">{"".join(summary_chips)}</div>
      </header>"""


def _render_overview(overview: str) -> str:
    return f"""      <section id="overview" class="space-y-3">
        <h2 class="{_CAPTION}">Overview</h2>
        <p class="text-base leading-relaxed text-slate-800">{html.escape(overview)}</p>
      </section>"""


def _render_dfd(dfd_mermaid: str) -> str:
    """Render the system-level Data Flow Diagram as a Mermaid block.

    Escapes the diagram source — LLM-generated, so treat as untrusted markup
    even though Mermaid would re-escape internally. The CDN-loaded Mermaid
    runtime in the scaffold picks up `.mermaid` blocks on startup.
    """
    return f"""      <section id="data-flow-diagram" class="space-y-3">
        <h2 class="{_CAPTION}">Data Flow Diagram</h2>
        <div class="rounded-lg bg-white ring-1 ring-slate-200 p-4 overflow-auto">
          <pre class="mermaid">{html.escape(dfd_mermaid)}</pre>
        </div>
      </section>"""


def _render_footer(metadata: dict[str, Any]) -> str:
    bits: list[str] = []
    llm_calls = metadata.get("llm_calls")
    tool_calls = metadata.get("tool_calls")
    if llm_calls is not None:
        bits.append(f"{llm_calls} LLM calls")
    if tool_calls is not None:
        bits.append(f"{tool_calls} tool calls")
    model_line = _format_model_line(metadata)
    if model_line:
        bits.append(model_line)
    line = " · ".join(bits)
    return f"""      <footer class="border-t border-slate-200 pt-6 font-mono text-xs text-slate-500">
        <span class="text-slate-400">&rsaquo;</span> generated by stride-gpt{(" · " + html.escape(line)) if line else ""}
      </footer>"""


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _render_subsystem(sub: dict[str, Any]) -> str:
    name = sub.get("name") or "(unnamed)"
    description = (sub.get("description") or "").strip()
    files = sub.get("files_analyzed") or []
    threats = sub.get("threats") or []
    suggestions = sub.get("improvement_suggestions") or []

    parts: list[str] = []
    parts.append(f"""        <header class="space-y-1">
          <h2 class="text-xl font-semibold tracking-tight text-slate-900">{html.escape(name)}</h2>""")
    if description:
        parts.append(
            f'          <p class="text-sm text-slate-600">{html.escape(description)}</p>'
        )
    parts.append("        </header>")

    if files:
        parts.append(_render_files_analyzed(files))

    if threats:
        cards = "\n".join(_render_threat_card(t, cross_cutting=False) for t in threats)
        parts.append(f"""        <div class="space-y-4">
{cards}
        </div>""")
    else:
        parts.append(
            '        <p class="text-sm italic text-slate-500">No threats identified.</p>'
        )

    if suggestions:
        parts.append(_render_recommendations(suggestions))

    body = "\n".join(parts)
    return f"""      <section class="space-y-5">
{body}
      </section>"""


def _render_cross_cutting(threats: list[dict[str, Any]]) -> str:
    cards = "\n".join(_render_threat_card(t, cross_cutting=True) for t in threats)
    return f"""      <section id="cross-cutting" class="space-y-5">
        <header class="space-y-1">
          <h2 class="text-xl font-semibold tracking-tight text-slate-900">Cross-cutting threats</h2>
          <p class="text-sm text-slate-600">Issues that span multiple subsystems.</p>
        </header>
        <div class="space-y-4">
{cards}
        </div>
      </section>"""


def _render_files_analyzed(files: list[str]) -> str:
    items = "\n".join(
        f'            <li class="font-mono text-xs text-slate-700">{html.escape(f)}</li>'
        for f in files
    )
    return f"""        <div>
          <h3 class="{_CAPTION} mb-2">Files analyzed</h3>
          <ul class="space-y-1">
{items}
          </ul>
        </div>"""


def _render_recommendations(suggestions: list[str]) -> str:
    items = "\n".join(
        f'            <li>{html.escape(str(s))}</li>' for s in suggestions
    )
    return f"""        <div class="rounded-lg border border-slate-200 bg-white p-5">
          <h3 class="{_CAPTION} mb-3">Recommendations</h3>
          <ul class="list-disc pl-5 space-y-1 text-sm text-slate-800">
{items}
          </ul>
        </div>"""


# ---------------------------------------------------------------------------
# Threat card
# ---------------------------------------------------------------------------


def _render_threat_card(threat: dict[str, Any], *, cross_cutting: bool) -> str:
    threat_type = threat.get("Threat Type") or "Unknown"
    scenario = str(threat.get("Scenario") or "")
    impact = str(threat.get("Potential Impact") or "")
    owasp_llm = threat.get("OWASP_LLM")
    owasp_asi = threat.get("OWASP_ASI")
    insider = threat.get("INSIDER_CATEGORY")
    mitre = threat.get("MITRE_ATTACK")
    affected = threat.get("Affected Subsystems") or []

    badge_classes = _STRIDE_BADGE_CLASSES.get(threat_type, _DEFAULT_BADGE)

    badges: list[str] = [
        f'<span class="{_BADGE_BASE} {badge_classes}">{html.escape(str(threat_type))}</span>'
    ]
    if owasp_llm:
        badges.append(f'<span class="{_PILL_BASE}">OWASP {html.escape(str(owasp_llm))}</span>')
    if owasp_asi:
        badges.append(f'<span class="{_PILL_BASE}">ASI {html.escape(str(owasp_asi))}</span>')
    if insider:
        badges.append(
            f'<span class="{_PILL_BASE}">Insider: {html.escape(str(insider))}</span>'
        )
    badges.extend(_render_mitre_pills(mitre))

    rows: list[str] = []
    if scenario:
        rows.append(_dl_row("Scenario", html.escape(scenario)))
    if impact:
        rows.append(_dl_row("Potential impact", html.escape(impact)))
    if cross_cutting and affected:
        pills = "".join(
            f'<span class="{_PILL_BASE}">{html.escape(str(a))}</span> '
            for a in affected
        )
        rows.append(_dl_row("Affects", f'<div class="flex flex-wrap gap-1">{pills}</div>'))

    badge_row = "".join(b + " " for b in badges)
    body = "\n".join(rows)
    return f"""          <article class="rounded-lg border border-slate-200 bg-white p-5 space-y-3">
            <div class="flex flex-wrap gap-2">{badge_row}</div>
            <dl class="space-y-3">
{body}
            </dl>
          </article>"""


def _render_mitre_pills(value: Any) -> list[str]:
    """Render MITRE ATT&CK techniques as linked pills.

    Delegates shape handling to
    :func:`stride_gpt.core.report_utils.normalize_mitre_techniques`, so the
    canonical list-of-objects, the list-of-strings fallback, and the comma-
    separated-string shape all render. Each pill links to attack.mitre.org /
    atlas.mitre.org when the ID matches a known prefix; otherwise it renders
    as plain text. Returns an empty list if the field is absent / empty /
    malformed — threat cards without MITRE mappings render exactly as before.
    """
    techniques = normalize_mitre_techniques(value)
    if not techniques:
        return []
    pills: list[str] = []
    for tid, name in techniques:
        label = f"{tid} {name}" if name else tid
        url = mitre_url(tid)
        if url:
            pills.append(
                f'<a class="{_MITRE_PILL_BASE}" href="{html.escape(url)}" '
                f'target="_blank" rel="noopener noreferrer" title="{html.escape(label)}">'
                f'{html.escape(tid)}</a>'
            )
        else:
            pills.append(
                f'<span class="{_MITRE_PILL_BASE}" title="{html.escape(label)}">'
                f'{html.escape(tid)}</span>'
            )
    return pills


def _dl_row(label: str, value_html: str) -> str:
    return f"""              <div>
                <dt class="{_CAPTION}">{label}</dt>
                <dd class="text-sm leading-relaxed text-slate-800">{value_html}</dd>
              </div>"""


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _format_generated_at(raw: str) -> str:
    """Convert ISO-8601 to a humane 'YYYY-MM-DD HH:MM UTC' form.

    Falls back to the raw string if parsing fails — we never want a report
    timestamp to break the renderer.
    """
    if not raw:
        return ""
    try:
        cleaned = raw.rstrip("Z")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return raw


def _format_model_line(metadata: dict[str, Any]) -> str:
    worker = metadata.get("worker_model")
    worker_provider = metadata.get("worker_provider", "")
    architect = metadata.get("architect_model")
    architect_provider = metadata.get("architect_provider", "")
    if architect:
        return (
            f"Architect: {architect_provider}/{architect} · "
            f"Worker: {worker_provider}/{worker}"
        )
    if worker:
        return f"Model: {worker_provider}/{worker}"
    return ""
