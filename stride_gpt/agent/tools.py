"""Filesystem tools for the threat modeling agent.

All paths are sandboxed to the analysis root — no traversal outside it.
Tool definitions use OpenAI function-calling format.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from pathlib import Path
from typing import Any

from stride_gpt.core.schemas import ToolCallResult

MAX_FILE_SIZE = 50 * 1024  # 50 KB
MAX_GREP_RESULTS = 20
MAX_SEARCH_RESULTS = 50
MAX_DIR_ENTRIES = 200

# Caps for LLM-supplied grep patterns. The agent only needs short, common
# patterns; anything longer is much more likely to be a ReDoS attempt than a
# legitimate search. Per-line truncation bounds input so simple polynomial
# patterns can't explode either.
MAX_GREP_PATTERN_LEN = 200
MAX_GREP_LINE_LEN = 1000

# Heuristic for catastrophic backtracking: a quantified inner group followed
# by an outer quantifier — e.g. ``(a+)+``, ``(\w*)+``, ``([0-9]+)*``. Catches
# the textbook ReDoS shape without blocking ordinary patterns like ``(foo)+``.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*[+*?{][^)]*\)\s*[+*]")

# Version-control metadata can hold credentials (actions/checkout v4/v5 writes
# the job token into .git/config; some clones embed a token in the remote URL)
# and says nothing about the system's design, so the agent may not touch it.
VCS_METADATA_DIRS = {".git", ".hg", ".svn"}

# Directories to skip during search/grep
SKIP_DIRS = VCS_METADATA_DIRS | {
    "node_modules", "__pycache__", ".venv", "venv", ".env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
    ".terraform", ".gradle", "target",
}

# ---------------------------------------------------------------------------
# Path sandboxing
# ---------------------------------------------------------------------------


def _sandbox_violation(root_resolved: Path, resolved: Path) -> str | None:
    """Return why a fully resolved path is off-limits, or None if it's allowed."""
    # is_relative_to avoids the classic startswith() prefix bug where
    # `/tmp/project` would falsely match `/tmp/project_secrets/...`.
    if resolved != root_resolved and not resolved.is_relative_to(root_resolved):
        return "Path traversal denied"
    # casefold: on case-insensitive filesystems (macOS, Windows) `.GIT` reaches
    # the same directory as `.git`.
    parts = resolved.relative_to(root_resolved).parts
    if any(part.casefold() in VCS_METADATA_DIRS for part in parts):
        return "Access to version-control metadata denied"
    return None


def _link_target_allowed(root_resolved: Path, path: Path) -> bool:
    """Whether following ``path`` (possibly a symlink) stays inside the sandbox."""
    try:
        target = path.resolve()
    except (OSError, RuntimeError):  # symlink loop
        return False
    return _sandbox_violation(root_resolved, target) is None


def resolve_safe_path(root: Path, user_path: str) -> Path:
    """Resolve a user-provided path relative to root, rejecting traversal.

    Public because evidence verification (:mod:`stride_gpt.agent.evidence`)
    reads files the model cites and must apply exactly the same sandbox rules
    ``read_file`` does.
    """
    # Treat as relative to root even if it looks absolute
    cleaned = user_path.lstrip("/")
    resolved = (root / cleaned).resolve()
    reason = _sandbox_violation(root.resolve(), resolved)
    if reason:
        raise ValueError(f"{reason}: {user_path}")
    return resolved


# Existing call sites in this module use the private name.
_resolve_safe_path = resolve_safe_path


def _should_skip(name: str) -> bool:
    return name in SKIP_DIRS


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def read_file(
    root: Path, path: str, start_line: int | None = None, end_line: int | None = None
) -> str:
    """Read a file as numbered lines, optionally limited to a 1-based inclusive range.

    The output starts with a header giving the file's total line count, the
    exact range shown and whether the byte cap cut the range short. When it
    did, the next line says which ``start_line`` to request to continue, so the
    model can page through files of any size. The numbered body is capped at
    ``MAX_FILE_SIZE`` bytes and cut at a line boundary so the header's range is
    exact; only a single line longer than the cap is itself cut.

    Lines are split the same way as in ``grep_content`` so the two tools agree
    on line numbers. An invalid range returns an error string.
    """
    resolved = _resolve_safe_path(root, path)
    if not resolved.is_file():
        return f"Error: not a file: {path}"
    for name, value in (("start_line", start_line), ("end_line", end_line)):
        if value is None:
            continue
        # bool is an int subclass, but `true` is never a meaningful line number.
        if isinstance(value, bool) or not isinstance(value, int):
            return f"Error: {name} must be an integer, got {value!r}"
        if value < 1:
            return f"Error: {name} must be 1 or greater, got {value}"
    if start_line is not None and end_line is not None and end_line < start_line:
        return f"Error: end_line ({end_line}) is before start_line ({start_line})"
    try:
        content = resolved.read_text(errors="replace")
    except Exception as e:
        return f"Error reading {path}: {e}"

    lines = content.splitlines()
    total = len(lines)
    if start_line is not None and start_line > total:
        return f"Error: start_line {start_line} is past the end of {path} ({total} lines)"
    if total == 0:
        return f"path: {path} | total_lines: 0 | showing: none | truncated: false"

    first = start_line or 1
    # Asking past EOF (e.g. "the rest of the file") is clamped, not an error.
    last = min(end_line or total, total)
    width = len(str(last))
    body: list[str] = []
    used = 0
    shown = first - 1
    cut_line = False
    for n in range(first, last + 1):
        numbered = f"{n:>{width}}\t{lines[n - 1]}"
        size = len(numbered.encode()) + 1  # + newline
        if used + size > MAX_FILE_SIZE:
            if not body:
                # A single line over the cap (e.g. minified JS) would otherwise
                # be unreadable, so show as much of it as fits.
                cut = numbered.encode()[:MAX_FILE_SIZE].decode(errors="ignore")
                body.append(f"{cut}… [line {n} cut at {MAX_FILE_SIZE:,} bytes]")
                shown = n
                cut_line = True
            break
        body.append(numbered)
        used += size
        shown = n

    truncated = cut_line or shown < last
    header = f"path: {path} | total_lines: {total} | showing: {first}-{shown} | truncated: {str(truncated).lower()}"
    # The hint goes at the top: context compression keeps only the start of
    # long tool results.
    if truncated:
        more = f" Call read_file with start_line={shown + 1} to read more." if shown < last else ""
        reason = f"Line {shown} was cut" if cut_line else "Output capped"
        header += f"\n[{reason} at {MAX_FILE_SIZE:,} bytes.{more}]"
    return header + "\n\n" + "\n".join(body)


def list_directory(root: Path, path: str = ".") -> str:
    """List directory entries with type and size."""
    resolved = _resolve_safe_path(root, path)
    if not resolved.is_dir():
        return f"Error: not a directory: {path}"
    root_resolved = root.resolve()
    entries: list[dict[str, Any]] = []
    try:
        for item in sorted(resolved.iterdir()):
            if _should_skip(item.name):
                continue
            entry: dict[str, Any] = {"name": item.name}
            if item.is_symlink() and not _link_target_allowed(root_resolved, item):
                # is_dir() and stat() follow the link, which would reveal
                # whether a path outside the sandbox exists and its size.
                entry["type"] = "symlink"
            elif item.is_dir():
                entry["type"] = "directory"
            else:
                entry["type"] = "file"
                try:
                    entry["size"] = item.stat().st_size
                except OSError:
                    entry["size"] = -1
            entries.append(entry)
            if len(entries) >= MAX_DIR_ENTRIES:
                entries.append({"name": "...", "type": "truncated"})
                break
    except PermissionError:
        return f"Error: permission denied: {path}"
    return json.dumps(entries, indent=2)


def search_files(root: Path, pattern: str, path: str = ".") -> str:
    """Search for files matching a glob pattern."""
    resolved = _resolve_safe_path(root, path)
    if not resolved.is_dir():
        return f"Error: not a directory: {path}"
    matches: list[str] = []
    root_resolved = root.resolve()
    for dirpath, dirnames, filenames in os.walk(resolved):
        # Prune skipped directories
        dirnames[:] = [d for d in dirnames if not _should_skip(d)]
        for filename in filenames:
            if fnmatch.fnmatch(filename, pattern):
                full = Path(dirpath) / filename
                rel = str(full.relative_to(root_resolved))
                matches.append(rel)
                if len(matches) >= MAX_SEARCH_RESULTS:
                    return json.dumps([*matches, f"... (truncated at {MAX_SEARCH_RESULTS})"])
    return json.dumps(matches)


def load_reference(name: str) -> str:
    """Return a packaged reference card body by name.

    Use ``list_references()`` to discover available cards and their trigger
    conditions. The validation is performed by the underlying loader, which
    returns an error string for unknown names rather than raising.
    """
    from stride_gpt.core.prompts.variants import load_reference as _load

    return _load(name)


def list_references() -> str:
    """Return the catalogue of available reference cards as JSON."""
    from stride_gpt.core.prompts.variants import list_references as _list

    return json.dumps(_list(), indent=2)


def grep_content(
    root: Path, pattern: str, path: str = ".", max_results: int = MAX_GREP_RESULTS
) -> str:
    """Search file contents for a regex pattern. Returns matches with context.

    LLM-supplied patterns can trigger catastrophic backtracking, hanging the
    agent loop. Patterns longer than ``MAX_GREP_PATTERN_LEN`` or containing a
    nested-quantifier ReDoS shape are rejected; each line is truncated to
    ``MAX_GREP_LINE_LEN`` before matching to bound input for polynomial
    patterns that slip past the heuristic.
    """
    resolved = _resolve_safe_path(root, path)
    root_resolved = root.resolve()

    if len(pattern) > MAX_GREP_PATTERN_LEN:
        return (
            f"Error: regex pattern too long ({len(pattern)} > "
            f"{MAX_GREP_PATTERN_LEN}). Use a simpler pattern."
        )
    if _NESTED_QUANTIFIER_RE.search(pattern):
        return (
            "Error: regex pattern uses a nested-quantifier shape "
            "(e.g. `(a+)+`) that risks catastrophic backtracking. "
            "Rewrite without quantified groups inside quantified groups."
        )
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return f"Error: invalid regex: {e}"

    results: list[dict[str, Any]] = []

    if resolved.is_file():
        walk_targets = [(str(resolved.parent), [], [resolved.name])]
    else:
        walk_targets = os.walk(resolved)

    for dirpath, dirnames, filenames in walk_targets:
        if hasattr(dirnames, '__delitem__'):
            dirnames[:] = [d for d in dirnames if not _should_skip(d)]
        for filename in filenames:
            full = Path(dirpath) / filename
            # Skip binary-looking files
            if full.suffix in (".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".zip", ".tar", ".gz",
                               ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf"):
                continue
            # os.walk doesn't descend into symlinked directories, but it does
            # list symlinked files — and read_text follows them. Apply the same
            # sandbox check as read_file so a repo can't plant a link to e.g.
            # ~/.aws/credentials or .git/config and have its contents sent to
            # the LLM. The is_file check also skips FIFOs and devices, which
            # would block.
            if not _link_target_allowed(root_resolved, full) or not full.is_file():
                continue
            try:
                text = full.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                # Truncate to bound the input the regex engine has to walk.
                search_line = line if len(line) <= MAX_GREP_LINE_LEN else line[:MAX_GREP_LINE_LEN]
                if compiled.search(search_line):
                    rel = str(full.relative_to(root_resolved))
                    results.append({"file": rel, "line": i, "content": line.strip()[:200]})
                    if len(results) >= max_results:
                        return json.dumps([*results, {"truncated": True, "total_limit": max_results}])
    return json.dumps(results)


# ---------------------------------------------------------------------------
# Tool definitions (OpenAI function-calling format)
# ---------------------------------------------------------------------------

AGENT_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read the contents of a file. Use this to understand code, configuration, or documentation. "
                "Returns line-numbered output under a header giving the file's total_lines and the range shown. "
                "Large files are returned in pages: when the header says truncated: true, call again with the "
                "start_line it suggests. Pass start_line/end_line to read just part of a file."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path relative to the project root.",
                    },
                    "start_line": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "First line to read (1-based, inclusive). Defaults to 1.",
                    },
                    "end_line": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Last line to read (1-based, inclusive). Defaults to the end of the file.",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "List files and subdirectories in a directory. Returns names, types, and sizes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path relative to the project root. Defaults to root.",
                        "default": ".",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "Search for files matching a glob pattern (e.g. '*.py', 'Dockerfile', '*.tf'). Returns matching file paths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern to match filenames (e.g. '*.py', '*.yaml').",
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory to search within. Defaults to project root.",
                        "default": ".",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_references",
            "description": "List available threat reference cards with their trigger conditions and the JSON schema fields each one adds. Call this once at the start of a subsystem analysis to discover which cards apply.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "load_reference",
            "description": "Load the full body of a threat reference card by name. Use list_references first to discover what is available and when to load it. Each card includes the JSON schema additions you must apply to your threat output. Call once per applicable card per subsystem; the content remains in context for the rest of the analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the reference card to load (from list_references).",
                    }
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_content",
            "description": "Search file contents for a regex pattern. Returns matching lines with file paths and line numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for in file contents.",
                    },
                    "path": {
                        "type": "string",
                        "description": "File or directory to search within. Defaults to project root.",
                        "default": ".",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Reporting tools
# ---------------------------------------------------------------------------
#
# These are offered only in the subsystem analysis loop and are handled there,
# not through ``_TOOL_DISPATCH`` — they record loop state rather than reading
# the user's filesystem. Keeping them out of the dispatch table is also what
# lets ``QUICK_TOOLS`` and the dispatch-coverage test stay as they are.

STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]
OWASP_LLM_CODES = [f"LLM{n:02d}" for n in range(1, 11)]
OWASP_ASI_CODES = [f"ASI{n:02d}" for n in range(1, 11)]
INSIDER_CATEGORIES = [
    "Credential Compromise",
    "Supply Chain Sabotage",
    "Data Exfiltration",
    "Infrastructure Sabotage",
    "Deception & Evasion",
]
AUTONOMY_LEVELS = ["L1", "L2", "L3", "L4"]

REPORTING_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "report_threat",
            "description": (
                "Record one STRIDE threat. Call this as soon as you are confident about "
                "a threat — do not wait until the end of the analysis, and do not write "
                "your threats out as prose or JSON. Cite the code the threat lives in "
                "through `evidence`: the snippet is matched against the file and the "
                "line range is recorded for you."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    # snake_case, not the report's "Threat Type" / "Potential
                    # Impact" keys: providers mangle parameter names containing
                    # spaces. DeepSeek truncates them at the space, so
                    # "Threat Type" arrives as a key called "Threat" and the
                    # whole call fails to parse. The loop maps these back.
                    "threat_type": {
                        "type": "string",
                        "enum": STRIDE_CATEGORIES,
                        "description": "The STRIDE category this threat falls under.",
                    },
                    "scenario": {
                        "type": "string",
                        "description": "The specific attack scenario, grounded in this code.",
                    },
                    "potential_impact": {
                        "type": "string",
                        "description": "What damage could result.",
                    },
                    "evidence": {
                        "type": "array",
                        "maxItems": 5,
                        "description": (
                            "Code that demonstrates the threat. Copy the lines verbatim "
                            "from read_file output WITHOUT the leading line number and "
                            "tab, and never write line numbers of your own. Pass an "
                            "empty array for a threat about a missing control that no "
                            "single snippet demonstrates."
                        ),
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": (
                                        "File path relative to the project root, as "
                                        "passed to read_file."
                                    ),
                                },
                                "snippet": {
                                    "type": "string",
                                    "description": (
                                        "A few lines of code copied verbatim from that "
                                        "file — the lines where the weakness lives."
                                    ),
                                },
                            },
                            "required": ["path", "snippet"],
                        },
                    },
                    "owasp_llm": {
                        "type": "string",
                        "enum": OWASP_LLM_CODES,
                        "description": (
                            "OWASP Top 10 for LLM Applications code. Set only when the "
                            "genai reference card is loaded and applies; otherwise omit."
                        ),
                    },
                    "owasp_asi": {
                        "type": "string",
                        "enum": OWASP_ASI_CODES,
                        "description": (
                            "OWASP Top 10 for Agentic Applications code. Set only when "
                            "the agentic card is loaded and applies; otherwise omit."
                        ),
                    },
                    "insider_category": {
                        "type": "string",
                        "enum": INSIDER_CATEGORIES,
                        "description": (
                            "AI Insider Threat category. Set only when the "
                            "insider_threat card is loaded and applies; otherwise omit."
                        ),
                    },
                    "autonomy_level": {
                        "type": "string",
                        "enum": AUTONOMY_LEVELS,
                        "description": (
                            "Deployment archetype from the insider_threat card, L1 "
                            "(human approves every action) to L4 (continuous autonomy)."
                        ),
                    },
                    "mitre_attack": {
                        "type": "array",
                        "description": (
                            "MITRE ATT&CK Enterprise or ATLAS techniques. Set only when "
                            "a MITRE card is loaded and applies; otherwise omit."
                        ),
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {
                                    "type": "string",
                                    "description": "e.g. T1190, T1078.004, AML.T0051.",
                                },
                                "name": {
                                    "type": "string",
                                    "description": "The technique name.",
                                },
                            },
                            "required": ["id"],
                        },
                    },
                },
                "required": ["threat_type", "scenario", "potential_impact", "evidence"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": (
                "End the analysis of this subsystem. Call this once, after you have "
                "reported every threat you found with report_threat. No further tools "
                "will run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "improvement_suggestions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Actionable, specific recommendations for this subsystem. "
                            "May be empty."
                        ),
                    }
                },
                "required": ["improvement_suggestions"],
            },
        },
    },
]

REPORTING_TOOL_NAMES = frozenset(t["function"]["name"] for t in REPORTING_TOOLS)

# report_threat argument -> the key it becomes in the threat dict. The report
# keys are fixed by every downstream consumer (DREAD, mitigations, the HTML
# report, saved JSON); the argument names are snake_case because providers
# mangle parameter names with spaces or, in some cases, change their case.
THREAT_ARG_TO_FIELD = {
    "threat_type": "Threat Type",
    "scenario": "Scenario",
    "potential_impact": "Potential Impact",
    "owasp_llm": "OWASP_LLM",
    "owasp_asi": "OWASP_ASI",
    "insider_category": "INSIDER_CATEGORY",
    "autonomy_level": "autonomy_level",
    "mitre_attack": "MITRE_ATTACK",
}

# What the subsystem loop offers: explore the code, then report what you found.
SUBSYSTEM_TOOLS: list[dict[str, Any]] = [*AGENT_TOOLS, *REPORTING_TOOLS]


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

_TOOL_DISPATCH = {
    "read_file": lambda root, args: read_file(
        root, args["path"], args.get("start_line"), args.get("end_line")
    ),
    "list_directory": lambda root, args: list_directory(root, args.get("path", ".")),
    "search_files": lambda root, args: search_files(
        root, args["pattern"], args.get("path", ".")
    ),
    "grep_content": lambda root, args: grep_content(
        root, args["pattern"], args.get("path", ".")
    ),
    # load_reference / list_references read packaged content, not the user's
    # filesystem — the root parameter is ignored.
    "load_reference": lambda _root, args: load_reference(args["name"]),
    "list_references": lambda _root, _args: list_references(),
}


def execute_tool(
    root: Path,
    tool_call: ToolCallResult,
    *,
    loaded_refs: set[str] | None = None,
) -> str:
    """Execute a tool call and return the result as a string.

    When ``loaded_refs`` is passed, every successful ``load_reference`` call
    appends its ``name`` argument to the set so the run manifest can record
    which cards the agent actually loaded. Failed loads (the loader returns
    a string starting with ``"Error:"``) are not counted.
    """
    if tool_call.parse_error:
        return (
            f"Error: {tool_call.parse_error}. "
            "Re-issue the call with a valid JSON object."
        )
    handler = _TOOL_DISPATCH.get(tool_call.function_name)
    if handler is None:
        return f"Error: unknown tool '{tool_call.function_name}'"
    try:
        result = handler(root, tool_call.arguments)
    except Exception as e:
        return f"Error executing {tool_call.function_name}: {e}"

    if (
        loaded_refs is not None
        and tool_call.function_name == "load_reference"
        and not result.startswith("Error:")
    ):
        name = tool_call.arguments.get("name")
        if isinstance(name, str) and name:
            loaded_refs.add(name)

    return result
