"""Threat-model reference cards shipped as packaged markdown.

Each card in this package starts with a YAML frontmatter block describing
when the agent should load it. The agent discovers cards via
:func:`list_references` (cheap — frontmatter only) and pulls the full body
via :func:`load_reference`. This mirrors the progressive-disclosure pattern
Claude Code skills use.

The same markdown files are the single source of truth for the legacy
single-shot prompt builder in :mod:`stride_gpt.core.prompts.builder`.
"""

from __future__ import annotations

from importlib.resources import files
from typing import Literal

AppType = Literal["web", "genai", "agentic"]

_PACKAGE = "stride_gpt.core.prompts.threat_model"
_NON_CARD_FILES = {"base.md", "quick_base.md"}


# ---------------------------------------------------------------------------
# Frontmatter parsing
# ---------------------------------------------------------------------------


def _split_frontmatter(text: str) -> tuple[str, str]:
    """Split a markdown file into (frontmatter, body).

    Frontmatter is the block between two `---` lines at the very start of the
    file. If absent, returns ("", text).
    """
    if not text.startswith("---\n"):
        return "", text
    end = text.find("\n---\n", 4)
    if end == -1:
        return "", text
    return text[4:end], text[end + 5:].lstrip("\n")


def _parse_frontmatter(block: str) -> dict[str, object]:
    """Parse a minimal YAML subset: scalar values, list-of-scalars, and
    folded-scalar (`|`) blocks. Sufficient for our card metadata; not a
    general-purpose YAML parser.
    """
    result: dict[str, object] = {}
    lines = block.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if ":" not in line:
            i += 1
            continue
        key, _, raw = line.partition(":")
        key = key.strip()
        value = raw.strip()

        # Folded scalar: `key: |` followed by indented lines
        if value == "|":
            collected: list[str] = []
            i += 1
            while i < len(lines) and (lines[i].startswith("  ") or not lines[i].strip()):
                collected.append(lines[i][2:] if lines[i].startswith("  ") else "")
                i += 1
            result[key] = " ".join(s.strip() for s in collected if s.strip())
            continue

        # Inline list: `key: [a, b, c]`
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1]
            result[key] = [_strip_scalar(item) for item in inner.split(",") if item.strip()]
            i += 1
            continue

        # Block list: `key:` followed by `  - item` lines
        if value == "":
            items: list[str] = []
            i += 1
            while i < len(lines) and lines[i].lstrip().startswith("- "):
                items.append(_strip_scalar(lines[i].lstrip()[2:]))
                i += 1
            result[key] = items
            continue

        # Scalar
        result[key] = _strip_scalar(value)
        i += 1
    return result


def _strip_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


# ---------------------------------------------------------------------------
# Card discovery
# ---------------------------------------------------------------------------


def _iter_card_files() -> list[str]:
    """Return the filenames of all reference cards in the package."""
    return sorted(
        f.name
        for f in files(_PACKAGE).iterdir()
        if f.name.endswith(".md") and f.name not in _NON_CARD_FILES
    )


def _read_card(filename: str) -> tuple[dict[str, object], str]:
    """Read a card file, returning (metadata, body)."""
    text = (files(_PACKAGE) / filename).read_text(encoding="utf-8")
    fm, body = _split_frontmatter(text)
    metadata = _parse_frontmatter(fm) if fm else {}
    return metadata, body


def list_references() -> list[dict[str, object]]:
    """Return the catalogue of available reference cards, frontmatter only.

    Cheap discovery — reads each card's frontmatter and skips the body. The
    agent calls this once to find out which cards exist and when to load
    them, then calls :func:`load_reference` for the ones it needs.
    """
    catalogue: list[dict[str, object]] = []
    for filename in _iter_card_files():
        metadata, _ = _read_card(filename)
        if not metadata.get("name"):
            continue
        catalogue.append({
            "name": metadata.get("name"),
            "title": metadata.get("title"),
            "when_to_load": metadata.get("when_to_load"),
            "adds_fields": metadata.get("adds_fields", []),
            "version": metadata.get("version"),
            "source": metadata.get("source"),
        })
    return catalogue


def _card_index() -> dict[str, str]:
    """Map card name -> filename, discovered from the package."""
    index: dict[str, str] = {}
    for filename in _iter_card_files():
        metadata, _ = _read_card(filename)
        name = metadata.get("name")
        if isinstance(name, str):
            index[name] = filename
    return index


# ---------------------------------------------------------------------------
# Public loaders
# ---------------------------------------------------------------------------


def base_system_prompt() -> str:
    """Return the agent's always-loaded base system prompt (codebase mode)."""
    return (files(_PACKAGE) / "base.md").read_text(encoding="utf-8")


def quick_base_prompt() -> str:
    """Return the system prompt for the description-driven `/quick` path.

    Same progressive-disclosure pattern as :func:`base_system_prompt` — points
    at the same reference cards via the ``load_reference`` tool — but framed
    around reasoning from a written description rather than exploring a
    codebase via filesystem tools.
    """
    return (files(_PACKAGE) / "quick_base.md").read_text(encoding="utf-8")


def load_reference(name: str) -> str:
    """Return the body text of a named reference card (frontmatter stripped).

    Used by both the agent's `load_reference` tool (on-demand lookup at runtime)
    and the legacy section helpers in :mod:`stride_gpt.core.prompts.builder`.
    """
    index = _card_index()
    if name not in index:
        valid = ", ".join(sorted(index)) or "(none)"
        return f"Error: unknown reference card {name!r}. Available cards: {valid}"
    _, body = _read_card(index[name])
    return body


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
