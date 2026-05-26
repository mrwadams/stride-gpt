"""HTML report renderer — single-file, Tailwind-styled view of a STRIDE report.

Output is a self-contained HTML document. The only external dependency is
the Tailwind CDN; there is no JavaScript and no app code. Designed as a
human-readable companion to the JSON report — STRIDE category is the primary
visual signal, every threat gets a card, and optional OWASP / Insider lenses
surface as outline pills when present.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stride_gpt.agent.report import render_json
from stride_gpt.core.schemas import AnalysisReport

# STRIDE category → Tailwind badge classes. The six categories carry distinct
# hues because category is the dominant visual signal in a threat model.
_STRIDE_BADGE_CLASSES: dict[str, str] = {
    "Spoofing": "bg-indigo-100 text-indigo-800",
    "Tampering": "bg-amber-100 text-amber-800",
    "Repudiation": "bg-slate-200 text-slate-800",
    "Information Disclosure": "bg-rose-100 text-rose-800",
    "Denial of Service": "bg-orange-100 text-orange-800",
    "Elevation of Privilege": "bg-red-100 text-red-800",
}
_DEFAULT_BADGE = "bg-slate-100 text-slate-800"
_BADGE_BASE = "inline-flex items-center rounded-full px-3 py-1 text-xs font-medium"
_PILL_BASE = (
    "inline-flex items-center rounded-full border border-slate-300 "
    "px-2.5 py-0.5 text-xs font-medium text-slate-700"
)


def render_html(report: AnalysisReport) -> str:
    """Render an in-memory AnalysisReport as a self-contained HTML document."""
    return render_html_from_json(render_json(report))


def render_html_from_json(data: dict[str, Any]) -> str:
    """Render a saved JSON report (the disk format) as HTML.

    The two entry points share this implementation so the live `/analyze`
    output and the `/reports` replay path produce byte-identical HTML.
    """
    target = data.get("target") or ""
    target_name = Path(target).name or target or "(unknown target)"
    generated_at = _format_generated_at(data.get("generated_at", ""))
    overview = (data.get("overview") or "").strip()
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

    for sub in subsystems:
        parts.append(_render_subsystem(sub))

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
  <body class="bg-stone-50 text-slate-900 font-sans">
    <main class="max-w-5xl mx-auto px-6 py-12 space-y-12">
{body}
    </main>
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
        "inline-flex items-center rounded-full bg-white border border-slate-200 "
        "px-3 py-1 text-xs font-medium text-slate-700"
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

    legend_items: list[str] = []
    for stride_type, badge_classes in _STRIDE_BADGE_CLASSES.items():
        legend_items.append(
            f'<span class="{_BADGE_BASE} {badge_classes}">{html.escape(stride_type)}</span>'
        )

    meta_line_parts: list[str] = []
    if generated_at:
        meta_line_parts.append(f"Generated {html.escape(generated_at)}")
    if model_line:
        meta_line_parts.append(html.escape(model_line))
    meta_line = " · ".join(meta_line_parts)

    return f"""      <header class="border-b border-slate-200 pb-8 space-y-4">
        <p class="text-xs uppercase tracking-wider text-slate-500">STRIDE Threat Model</p>
        <h1 class="font-serif text-4xl tracking-tight text-slate-900">{html.escape(target_name)}</h1>
        <p class="text-sm text-slate-600">{meta_line}</p>
        <div class="flex flex-wrap gap-2 pt-2">{"".join(summary_chips)}</div>
        <div class="flex flex-wrap gap-2 pt-2">{"".join(legend_items)}</div>
      </header>"""


def _render_overview(overview: str) -> str:
    return f"""      <section id="overview" class="space-y-3">
        <h2 class="text-xs uppercase tracking-wider text-slate-500">Overview</h2>
        <p class="text-base leading-relaxed text-slate-800">{html.escape(overview)}</p>
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
    return f"""      <footer class="border-t border-slate-200 pt-6 text-xs text-slate-500">
        Generated by STRIDE-GPT{(" · " + html.escape(line)) if line else ""}
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
          <h2 class="font-serif text-2xl tracking-tight text-slate-900">{html.escape(name)}</h2>""")
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
          <h2 class="font-serif text-2xl tracking-tight text-slate-900">Cross-cutting threats</h2>
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
          <h3 class="text-xs uppercase tracking-wider text-slate-500 mb-2">Files analyzed</h3>
          <ul class="space-y-1">
{items}
          </ul>
        </div>"""


def _render_recommendations(suggestions: list[str]) -> str:
    items = "\n".join(
        f'            <li>{html.escape(str(s))}</li>' for s in suggestions
    )
    return f"""        <div class="rounded-lg border border-slate-200 bg-white p-5">
          <h3 class="text-xs uppercase tracking-wider text-slate-500 mb-3">Recommendations</h3>
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


def _dl_row(label: str, value_html: str) -> str:
    return f"""              <div>
                <dt class="text-xs uppercase tracking-wider text-slate-500">{label}</dt>
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
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
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
