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

# Directories to skip during search/grep
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
    ".terraform", ".gradle", "target",
}

# ---------------------------------------------------------------------------
# Path sandboxing
# ---------------------------------------------------------------------------


def _resolve_safe_path(root: Path, user_path: str) -> Path:
    """Resolve a user-provided path relative to root, rejecting traversal."""
    # Treat as relative to root even if it looks absolute
    cleaned = user_path.lstrip("/")
    resolved = (root / cleaned).resolve()
    root_resolved = root.resolve()
    if not str(resolved).startswith(str(root_resolved)):
        raise ValueError(f"Path traversal denied: {user_path}")
    return resolved


def _should_skip(name: str) -> bool:
    return name in SKIP_DIRS


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def read_file(root: Path, path: str) -> str:
    """Read a file's content, truncating at MAX_FILE_SIZE."""
    resolved = _resolve_safe_path(root, path)
    if not resolved.is_file():
        return f"Error: not a file: {path}"
    size = resolved.stat().st_size
    try:
        content = resolved.read_text(errors="replace")
    except Exception as e:
        return f"Error reading {path}: {e}"
    if size > MAX_FILE_SIZE:
        truncated = content[: MAX_FILE_SIZE]
        return f"{truncated}\n\n[Truncated — file is {size:,} bytes, showing first {MAX_FILE_SIZE:,}]"
    return content


def list_directory(root: Path, path: str = ".") -> str:
    """List directory entries with type and size."""
    resolved = _resolve_safe_path(root, path)
    if not resolved.is_dir():
        return f"Error: not a directory: {path}"
    entries: list[dict[str, Any]] = []
    try:
        for item in sorted(resolved.iterdir()):
            if _should_skip(item.name):
                continue
            entry: dict[str, Any] = {"name": item.name}
            if item.is_dir():
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
                    return json.dumps(matches + [f"... (truncated at {MAX_SEARCH_RESULTS})"])
    return json.dumps(matches)


def grep_content(
    root: Path, pattern: str, path: str = ".", max_results: int = MAX_GREP_RESULTS
) -> str:
    """Search file contents for a regex pattern. Returns matches with context."""
    resolved = _resolve_safe_path(root, path)
    root_resolved = root.resolve()
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
            try:
                text = full.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if compiled.search(line):
                    rel = str(full.relative_to(root_resolved))
                    results.append({"file": rel, "line": i, "content": line.strip()[:200]})
                    if len(results) >= max_results:
                        return json.dumps(results + [{"truncated": True, "total_limit": max_results}])
    return json.dumps(results)


# ---------------------------------------------------------------------------
# Tool definitions (OpenAI function-calling format)
# ---------------------------------------------------------------------------

AGENT_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file. Use this to understand code, configuration, or documentation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path relative to the project root.",
                    }
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
# Tool executor
# ---------------------------------------------------------------------------

_TOOL_DISPATCH = {
    "read_file": lambda root, args: read_file(root, args["path"]),
    "list_directory": lambda root, args: list_directory(root, args.get("path", ".")),
    "search_files": lambda root, args: search_files(
        root, args["pattern"], args.get("path", ".")
    ),
    "grep_content": lambda root, args: grep_content(
        root, args["pattern"], args.get("path", ".")
    ),
}


def execute_tool(root: Path, tool_call: ToolCallResult) -> str:
    """Execute a tool call and return the result as a string."""
    handler = _TOOL_DISPATCH.get(tool_call.function_name)
    if handler is None:
        return f"Error: unknown tool '{tool_call.function_name}'"
    try:
        return handler(root, tool_call.arguments)
    except Exception as e:
        return f"Error executing {tool_call.function_name}: {e}"
