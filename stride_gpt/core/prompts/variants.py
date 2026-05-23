"""Threat-model reference cards shipped as packaged markdown.

The agent's base system prompt (`base.md`) points to two optional reference
cards — `genai.md` and `agentic.md` — covering OWASP Top 10 for LLM
Applications and Agentic Applications respectively. The agent loads each card
on-demand via the `load_reference` tool, mirroring the progressive-disclosure
pattern Claude Code skills use.

The same markdown files are the single source of truth for the legacy
single-shot prompt builder in :mod:`stride_gpt.core.prompts.builder`.
"""

from __future__ import annotations

from importlib.resources import files
from typing import Literal

AppType = Literal["web", "genai", "agentic"]
ReferenceName = Literal["genai", "agentic", "insider_threat"]

_PACKAGE = "stride_gpt.core.prompts.threat_model"
_VALID_REFERENCES: tuple[str, ...] = ("genai", "agentic", "insider_threat")


def _read(name: str) -> str:
    return (files(_PACKAGE) / name).read_text(encoding="utf-8")


def base_system_prompt() -> str:
    """Return the agent's always-loaded base system prompt."""
    return _read("base.md")


def load_reference(name: str) -> str:
    """Return the full text of a named OWASP reference card.

    Used by both the agent's `load_reference` tool (on-demand lookup at runtime)
    and the legacy section helpers in :mod:`stride_gpt.core.prompts.builder`.
    """
    if name not in _VALID_REFERENCES:
        valid = ", ".join(_VALID_REFERENCES)
        return f"Error: unknown reference card {name!r}. Available cards: {valid}"
    return _read(f"{name}.md")


def coerce_app_type(value: str | None) -> AppType:
    """Best-effort coercion of free-form app-type strings to the canonical set.

    Accepts the canonical slugs (web/genai/agentic) and the legacy free-text
    labels used by the single-shot path ("Web application", "Generative AI
    application", "Agentic AI application"). Unknown values fall back to "web".
    """
    if not value:
        return "web"
    normalised = value.strip().lower()
    if normalised in ("web", "genai", "agentic"):
        return normalised  # type: ignore[return-value]
    if "agentic" in normalised:
        return "agentic"
    if "generative" in normalised or "genai" in normalised or "gen ai" in normalised:
        return "genai"
    return "web"
