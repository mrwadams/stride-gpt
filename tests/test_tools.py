"""Tests for stride_gpt.agent.tools — filesystem tools with sandboxing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stride_gpt.agent.tools import (
    AGENT_TOOLS,
    MAX_GREP_PATTERN_LEN,
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

    def test_rejects_overlong_pattern(self, sandbox_dir: Path):
        """ReDoS guard: an LLM-supplied pattern longer than the cap is refused
        before it ever reaches re.compile, so it can't hang the agent loop."""
        long_pattern = "a" * (MAX_GREP_PATTERN_LEN + 1)
        result = grep_content(sandbox_dir, long_pattern)
        assert result.startswith("Error:")
        assert "too long" in result

    def test_rejects_nested_quantifier(self, sandbox_dir: Path):
        """ReDoS guard: the textbook catastrophic-backtracking shape `(a+)+`
        is rejected by the heuristic, never compiled and run."""
        result = grep_content(sandbox_dir, "(a+)+")
        assert result.startswith("Error:")
        assert "nested-quantifier" in result

    def test_ordinary_quantified_group_still_allowed(self, sandbox_dir: Path):
        """The guard must not block benign patterns like `(foo)+` — a single
        quantifier on a non-quantified group is fine and should run normally."""
        result = grep_content(sandbox_dir, "(Flask)+")
        # Valid JSON result (a match list), not an Error string.
        assert isinstance(json.loads(result), list)


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

    def test_handler_exception_is_caught(self, sandbox_dir: Path):
        """A handler that raises (here read_file dispatched without its required
        'path' arg -> KeyError) must be turned into an error string, not
        propagated, so one bad tool call can't crash the agent loop."""
        tc = ToolCallResult(id="4", function_name="read_file", arguments={})
        result = execute_tool(sandbox_dir, tc)
        assert result.startswith("Error executing read_file:")

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

    def test_dispatches_load_reference_insider_threat(self, sandbox_dir: Path):
        tc = ToolCallResult(id="6", function_name="load_reference",
                            arguments={"name": "insider_threat"})
        result = execute_tool(sandbox_dir, tc)
        assert "Credential Compromise" in result
        assert "INSIDER_CATEGORY" in result

    def test_load_reference_has_no_hardcoded_enum(self):
        """Card discovery is now runtime — driven by frontmatter in the
        packaged markdown files. A hardcoded enum here would re-introduce
        the drift the migration removed."""
        load_tool = next(
            t for t in AGENT_TOOLS if t["function"]["name"] == "load_reference"
        )
        properties = load_tool["function"]["parameters"]["properties"]
        assert "enum" not in properties["name"]

    def test_list_references_tool_exposed(self):
        """The discovery tool must be in the agent's tool set or the
        progressive-disclosure pattern is unreachable."""
        names = {t["function"]["name"] for t in AGENT_TOOLS}
        assert "list_references" in names

    def test_dispatches_list_references(self, sandbox_dir: Path):
        tc = ToolCallResult(id="7", function_name="list_references", arguments={})
        result = execute_tool(sandbox_dir, tc)
        catalogue = json.loads(result)
        names = {entry["name"] for entry in catalogue}
        assert names == {
            "genai", "agentic", "insider_threat", "mitre_enterprise", "mitre_atlas",
        }
        # Each entry must carry the trigger condition — that's the whole
        # point of cheap discovery.
        for entry in catalogue:
            assert entry["when_to_load"]
            assert entry["adds_fields"]


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


class TestToolDefinitions:
    def test_tool_names_match_dispatch(self):
        from stride_gpt.agent.tools import _TOOL_DISPATCH

        tool_names = {t["function"]["name"] for t in AGENT_TOOLS}
        dispatch_names = set(_TOOL_DISPATCH.keys())
        assert tool_names == dispatch_names
