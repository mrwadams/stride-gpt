"""Check that a threat's cited code actually exists, without an LLM.

The agent reports each threat through the ``report_threat`` tool and quotes
the code the threat lives in. This module finds that quote in the sandboxed
file and records the line range it matched. Nothing here calls a model: a
snippet either appears in the file or it doesn't.

Matching tolerates whitespace — indentation depth, tabs against spaces,
trailing space, and blank lines the model dropped or added. It deliberately
does not tolerate case, punctuation or smart-quote changes: a model that
rewrote those didn't quote the code, and we want that flagged.

An unverified snippet never loses the threat. It is recorded with
``verified: false`` and a reason written for the model to act on, because the
reason is handed straight back as the tool result.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from itertools import pairwise
from pathlib import Path
from typing import Any

from stride_gpt.agent.tools import resolve_safe_path

# A snippet is meant to be the few lines where the weakness lives. Past these
# bounds we refuse rather than truncate-then-match: a partial match reports a
# line range that is confidently wrong, which is worse than no range at all.
MAX_SNIPPET_CHARS = 2_000
MAX_SNIPPET_LINES = 60

# ``read_file`` caps its *output* at 50 KB but pages, so the model can legally
# cite line 4000 of a 300 KB file. Verification reads whole files and needs
# its own, larger ceiling.
MAX_VERIFY_BYTES = 1_048_576

# Matches the line gutter ``read_file`` writes: ``f"{n:>{width}}\t{line}"``.
_GUTTER_RE = re.compile(r"^ *(\d+)\t")
_FENCE_OPEN_RE = re.compile(r"^\s*```[\w.+-]*\s*$")
_FENCE_CLOSE_RE = re.compile(r"^\s*```\s*$")


@dataclass(frozen=True)
class EvidenceCheck:
    """One ``{path, snippet}`` item the model cited, plus what we found."""

    path: str
    snippet: str
    verified: bool
    start_line: int | None = None  # 1-based inclusive, only when verified
    end_line: int | None = None  # 1-based inclusive, only when verified
    occurrences: int = 0  # >1 means the snippet appears more than once
    reason: str | None = None  # model-facing failure text, only when unverified

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the threat dict, omitting fields that don't apply."""
        out: dict[str, Any] = {
            "path": self.path,
            "snippet": self.snippet,
            "verified": self.verified,
        }
        if self.start_line is not None:
            out["start_line"] = self.start_line
        if self.end_line is not None:
            out["end_line"] = self.end_line
        if self.occurrences > 1:
            out["occurrences"] = self.occurrences
        if self.reason:
            out["reason"] = self.reason
        return out


def normalise_path(value: Any) -> str:
    """Put a model-supplied path into the one form the report uses.

    Forward slashes, no leading ``./`` or ``/``. Evidence paths and
    ``files_analyzed`` both go through this so a file cited and a file read
    are the same string.
    """
    text = str(value or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def verify_evidence(root: Path, raw: Any, *, max_items: int = 5) -> list[EvidenceCheck]:
    """Check every evidence item the model supplied. Never raises.

    ``raw`` is whatever arrived in the tool arguments: a list of dicts if the
    model followed the schema, a JSON-encoded string if it double-encoded, or
    anything at all if it didn't.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []

    checks: list[EvidenceCheck] = []
    for item in raw[:max_items]:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        snippet = item.get("snippet")
        if not isinstance(path, str) or not isinstance(snippet, str):
            checks.append(
                EvidenceCheck(
                    path=normalise_path(path),
                    snippet=snippet if isinstance(snippet, str) else "",
                    verified=False,
                    reason="evidence needs a 'path' string and a 'snippet' string",
                )
            )
            continue
        checks.append(verify_one(root, path, snippet))
    return checks


def verify_one(root: Path, path: str, snippet: str) -> EvidenceCheck:
    """Locate ``snippet`` in ``path`` under ``root``. Never raises."""
    clean_path = normalise_path(path)

    if len(snippet) > MAX_SNIPPET_CHARS or snippet.count("\n") + 1 > MAX_SNIPPET_LINES:
        return _unverified(
            clean_path,
            snippet,
            "snippet is too long — quote only the few lines where the weakness lives",
        )

    try:
        resolved = resolve_safe_path(root, clean_path)
    except ValueError as e:
        return _unverified(clean_path, snippet, str(e))
    except OSError as e:  # symlink loop, unreadable parent
        return _unverified(clean_path, snippet, f"could not resolve {clean_path}: {e}")

    if not resolved.is_file():
        return _unverified(clean_path, snippet, "not a file in the analysed codebase")

    try:
        stat = resolved.stat()
        if stat.st_size > MAX_VERIFY_BYTES:
            return _unverified(clean_path, snippet, "file is too large to verify")
        haystack = _compacted(str(resolved), stat.st_mtime_ns, stat.st_size)
    except OSError as e:
        return _unverified(clean_path, snippet, f"could not read {clean_path}: {e}")

    needle = _compact_snippet(snippet)
    if not needle:
        return _unverified(clean_path, snippet, "snippet is empty")

    match = _find(haystack, needle)
    if match is None:
        return _unverified(
            clean_path,
            snippet,
            "snippet not found in this file — quote the code exactly as read_file "
            "returned it, without the leading line number and tab",
        )
    start, end, occurrences = match
    return EvidenceCheck(
        path=clean_path,
        snippet=snippet,
        verified=True,
        start_line=start,
        end_line=end,
        occurrences=occurrences,
    )


def summarise_checks(checks: Sequence[EvidenceCheck]) -> str:
    """Describe the verification outcome for the model, as the tool result."""
    if not checks:
        return (
            "No evidence was supplied. Prefer citing a snippet whenever the threat "
            "comes from code you read."
        )
    parts: list[str] = []
    for check in checks:
        if check.verified:
            where = (
                f"line {check.start_line}"
                if check.start_line == check.end_line
                else f"lines {check.start_line}-{check.end_line}"
            )
            extra = f" ({check.occurrences} occurrences)" if check.occurrences > 1 else ""
            parts.append(f"{check.path} {where} verified{extra}")
        else:
            parts.append(f"{check.path} NOT verified — {check.reason}")
    summary = "Evidence: " + "; ".join(parts) + "."
    if any(not c.verified for c in checks):
        summary += (
            " The threat has been kept and will be reported as unverified. "
            "Do not re-report this threat."
        )
    return summary


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _unverified(path: str, snippet: str, reason: str) -> EvidenceCheck:
    return EvidenceCheck(path=path, snippet=snippet, verified=False, reason=reason)


def _normalise_line(line: str) -> str:
    """Collapse every whitespace difference; keep everything else."""
    # Argument-less split() splits on all Unicode whitespace, so tabs against
    # spaces, indentation depth, trailing space and NBSP all collapse. NFC
    # fixes decomposed accents in identifiers and string literals.
    return " ".join(unicodedata.normalize("NFC", line).split())


@lru_cache(maxsize=64)
def _compacted(path_str: str, mtime_ns: int, size: int) -> tuple[tuple[str, int], ...]:
    """Normalised non-blank lines of a file, each with its 1-based line number.

    Keyed on mtime and size so an edited file drops out of the cache. Only the
    compacted form is held, never the raw text.

    Splitting with ``splitlines()`` is load-bearing: ``read_file`` and
    ``grep_content`` both use it, so the line numbers reported here are the
    same ones the model saw.
    """
    content = Path(path_str).read_text(errors="replace")
    out = []
    for n, line in enumerate(content.splitlines(), 1):
        norm = _normalise_line(line)
        if norm:
            out.append((norm, n))
    return tuple(out)


def _compact_snippet(snippet: str) -> list[str]:
    """Strip markdown fences and read_file's gutter, then normalise."""
    lines = snippet.splitlines()
    if lines and _FENCE_OPEN_RE.match(lines[0]):
        lines = lines[1:]
        if lines and _FENCE_CLOSE_RE.match(lines[-1]):
            lines = lines[:-1]
    lines = _strip_gutter(lines)
    return [norm for line in lines if (norm := _normalise_line(line))]


def _strip_gutter(lines: list[str]) -> list[str]:
    """Remove ``read_file``'s ``"  42\\t"`` prefix, but only when it's certain.

    Every non-blank line must carry the prefix and, for multi-line snippets,
    the numbers must be strictly consecutive. Both guards are needed so a
    Makefile or a TSV whose lines start with digits isn't mangled. When in
    doubt leave the snippet alone: an unverified snippet is recoverable, a
    silently mis-located one is not.
    """
    body = [line for line in lines if line.strip()]
    if not body:
        return lines
    matches = [_GUTTER_RE.match(line) for line in body]
    if not all(matches):
        return lines
    numbers = [int(m.group(1)) for m in matches if m is not None]
    if len(numbers) > 1 and any(b - a != 1 for a, b in pairwise(numbers)):
        return lines
    return [_GUTTER_RE.sub("", line, count=1) if line.strip() else line for line in lines]


def _find(
    haystack: tuple[tuple[str, int], ...], needle: list[str]
) -> tuple[int, int, int] | None:
    """Return ``(start_line, end_line, occurrences)`` for the first match.

    Both sides have blank lines removed, which is what makes the match
    tolerant of a blank line the model dropped or added. The reported range
    still spans any blanks inside the matched run, which is the right region
    to highlight.
    """
    if not haystack:
        return None

    if len(needle) == 1:
        target = needle[0]
        exact = [n for text, n in haystack if text == target]
        if exact:
            return exact[0], exact[0], len(exact)
        # A fragment quoted out of a longer line, e.g. `eval(user_input)`
        # lifted from `    result = eval(user_input)  # TODO`.
        partial = [n for text, n in haystack if target in text]
        if partial:
            return partial[0], partial[0], len(partial)
        return None

    # Multi-line: equality only. Substring matching across several lines buys
    # ragged quotes at the price of cheap false positives.
    span = len(needle)
    hits: list[tuple[int, int]] = []
    for i in range(len(haystack) - span + 1):
        if haystack[i][0] != needle[0]:
            continue
        if all(haystack[i + j][0] == needle[j] for j in range(1, span)):
            hits.append((haystack[i][1], haystack[i + span - 1][1]))
    if not hits:
        return None
    return hits[0][0], hits[0][1], len(hits)
