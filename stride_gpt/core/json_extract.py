"""JSON extraction from free-form LLM responses."""

from __future__ import annotations

import json


def extract_json_object(content: str) -> dict | None:
    """Parse a JSON object out of an LLM response, robust to fences and prose.

    Strategy:
    1. Strip surrounding whitespace and a leading markdown code fence.
    2. Try ``json.loads`` on the cleaned text.
    3. Fall back to the substring from the first ``{`` to the last ``}`` of the
       original content and try again.

    Returns the parsed dict, or ``None`` if no JSON object can be recovered.
    Non-dict JSON values (lists, scalars) also return ``None``.
    """
    if not content:
        return None

    cleaned = content.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

    data = _try_parse(cleaned)
    if data is not None:
        return data

    start = content.find("{")
    end = content.rfind("}")
    if start != -1 and end > start:
        return _try_parse(content[start : end + 1])

    return None


def _try_parse(text: str) -> dict | None:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None
