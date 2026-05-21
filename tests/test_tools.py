"""Tests for stride_gpt.agent.tools — filesystem tools with sandboxing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stride_gpt.agent.tools import (
    AGENT_TOOLS,
    MAX_FILE_SIZE,
    execute_tool,
    grep_content,
    list_directory,
    read_file,
    search_files,
)
from stride_gpt.core.schemas import ToolCallResult


# ---------------------------------------------------------------------------
# read_file
# ---------------------------------------------------------------------------


class TestReadFile:
    def test_reads_file(self, sandbox_dir: Path):
        result = read_file(sandbox_dir, "app.py")
        assert "Flask" in result

    def test_nonexistent_file(self, sandbox_dir: Path):
        result = read_file(sandbox_dir, "nope.py")
        assert result.startswith("Error:")

    def test_truncates_large_file(self, sandbox_dir: Path):
        result = read_file(sandbox_dir, "big.txt")
        assert "Truncated" in result
        assert len(result) < 100_000 + 200  # file content + message

    def test_path_traversal_blocked(self, sandbox_dir: Path):
        with pytest.raises(ValueError, match="traversal"):
            read_file(sandbox_dir, "../../etc/passwd")

    def test_reads_nested_file(self, sandbox_dir: Path):
        result = read_file(sandbox_dir, "src/auth.py")
        assert "login" in result


# ---------------------------------------------------------------------------
# list_directory
# ---------------------------------------------------------------------------


class TestListDirectory:
    def test_lists_root(self, sandbox_dir: Path):
        result = json.loads(list_directory(sandbox_dir))
        names = {e["name"] for e in result}
        assert "app.py" in names
        assert "src" in names

    def test_skips_git_and_node_modules(self, sandbox_dir: Path):
        result = json.loads(list_directory(sandbox_dir))
        names = {e["name"] for e in result}
        assert ".git" not in names
        assert "node_modules" not in names

    def test_lists_subdirectory(self, sandbox_dir: Path):
        result = json.loads(list_directory(sandbox_dir, "src"))
        names = {e["name"] for e in result}
        assert "auth.py" in names

    def test_nonexistent_directory(self, sandbox_dir: Path):
        result = list_directory(sandbox_dir, "nonexistent")
        assert result.startswith("Error:")

    def test_includes_types_and_sizes(self, sandbox_dir: Path):
        result = json.loads(list_directory(sandbox_dir))
        files = [e for e in result if e["name"] == "app.py"]
        assert files[0]["type"] == "file"
        assert "size" in files[0]
        dirs = [e for e in result if e["name"] == "src"]
        assert dirs[0]["type"] == "directory"


# ---------------------------------------------------------------------------
# search_files
# ---------------------------------------------------------------------------


class TestSearchFiles:
    def test_finds_python_files(self, sandbox_dir: Path):
        result = json.loads(search_files(sandbox_dir, "*.py"))
        assert any("app.py" in f for f in result)
        assert any("auth.py" in f for f in result)

    def test_finds_yaml(self, sandbox_dir: Path):
        result = json.loads(search_files(sandbox_dir, "*.yaml"))
        assert any("config.yaml" in f for f in result)

    def test_no_matches(self, sandbox_dir: Path):
        result = json.loads(search_files(sandbox_dir, "*.rs"))
        assert result == []

    def test_skips_node_modules(self, sandbox_dir: Path):
        result = json.loads(search_files(sandbox_dir, "*.js"))
        assert not any("node_modules" in f for f in result)


# ---------------------------------------------------------------------------
# grep_content
# ---------------------------------------------------------------------------


class TestGrepContent:
    def test_finds_pattern(self, sandbox_dir: Path):
        result = json.loads(grep_content(sandbox_dir, "Flask"))
        assert len(result) >= 1
        assert result[0]["file"] == "app.py"

    def test_case_insensitive(self, sandbox_dir: Path):
        result = json.loads(grep_content(sandbox_dir, "flask"))
        assert len(result) >= 1

    def test_regex_pattern(self, sandbox_dir: Path):
        result = json.loads(grep_content(sandbox_dir, r"def \w+"))
        assert any("auth.py" in r["file"] for r in result)

    def test_invalid_regex(self, sandbox_dir: Path):
        result = grep_content(sandbox_dir, "[invalid")
        assert "Error" in result

    def test_skips_binary_files(self, sandbox_dir: Path):
        result = json.loads(grep_content(sandbox_dir, "PNG"))
        files = [r.get("file", "") for r in result if isinstance(r, dict)]
        assert not any("image.png" in f for f in files)

    def test_skips_git_dir(self, sandbox_dir: Path):
        result = json.loads(grep_content(sandbox_dir, "refs"))
        files = [r.get("file", "") for r in result if isinstance(r, dict)]
        assert not any(".git" in f for f in files)

    def test_respects_max_results(self, sandbox_dir: Path):
        result = json.loads(grep_content(sandbox_dir, ".", max_results=2))
        # Should have at most 3 entries (2 results + 1 truncation marker)
        assert len(result) <= 3

    def test_grep_in_specific_file(self, sandbox_dir: Path):
        result = json.loads(grep_content(sandbox_dir, "secret_key", path="config.yaml"))
        assert len(result) >= 1
        assert result[0]["file"] == "config.yaml"


# ---------------------------------------------------------------------------
# execute_tool
# ---------------------------------------------------------------------------


class TestExecuteTool:
    def test_dispatches_read_file(self, sandbox_dir: Path):
        tc = ToolCallResult(id="1", function_name="read_file", arguments={"path": "app.py"})
        result = execute_tool(sandbox_dir, tc)
        assert "Flask" in result

    def test_dispatches_list_directory(self, sandbox_dir: Path):
        tc = ToolCallResult(id="2", function_name="list_directory", arguments={})
        result = execute_tool(sandbox_dir, tc)
        entries = json.loads(result)
        assert any(e["name"] == "app.py" for e in entries)

    def test_unknown_tool(self, sandbox_dir: Path):
        tc = ToolCallResult(id="3", function_name="delete_file", arguments={"path": "x"})
        result = execute_tool(sandbox_dir, tc)
        assert "unknown tool" in result.lower()

    def test_dispatches_load_reference(self, sandbox_dir: Path):
        # load_reference is fs-independent — it reads packaged markdown, not
        # the sandbox. Smoke-test both valid and invalid card names.
        tc = ToolCallResult(id="4", function_name="load_reference",
                            arguments={"name": "genai"})
        result = execute_tool(sandbox_dir, tc)
        assert "LLM01" in result

        tc = ToolCallResult(id="5", function_name="load_reference",
                            arguments={"name": "bogus"})
        result = execute_tool(sandbox_dir, tc)
        assert "Error" in result and "bogus" in result


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


class TestToolDefinitions:
    def test_tool_names_match_dispatch(self):
        from stride_gpt.agent.tools import _TOOL_DISPATCH

        tool_names = {t["function"]["name"] for t in AGENT_TOOLS}
        dispatch_names = set(_TOOL_DISPATCH.keys())
        assert tool_names == dispatch_names
