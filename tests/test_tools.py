"""Tests for stride_gpt.agent.tools — filesystem tools with sandboxing."""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from stride_gpt.agent.tools import (
    AGENT_TOOLS,
    MAX_FILE_SIZE,
    MAX_GREP_PATTERN_LEN,
    REPORTING_TOOL_NAMES,
    REPORTING_TOOLS,
    STRIDE_CATEGORIES,
    SUBSYSTEM_TOOLS,
    THREAT_ARG_TO_FIELD,
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
        """big.txt is a single 100 KB line: it's cut to the cap rather than
        returned as nothing, and the header says so."""
        result = read_file(sandbox_dir, "big.txt")
        header, hint = result.splitlines()[:2]
        assert header == "path: big.txt | total_lines: 1 | showing: 1-1 | truncated: true"
        assert hint == f"[Line 1 was cut at {MAX_FILE_SIZE:,} bytes.]"
        assert "[line 1 cut at" in result
        assert len(result.encode()) < MAX_FILE_SIZE + 300

    def test_header_and_line_numbers(self, sandbox_dir: Path):
        (sandbox_dir / "ten.py").write_text("".join(f"line {i}\n" for i in range(1, 11)))
        result = read_file(sandbox_dir, "ten.py")
        header, blank, *body = result.split("\n")
        assert header == "path: ten.py | total_lines: 10 | showing: 1-10 | truncated: false"
        assert blank == ""
        assert body[0] == " 1\tline 1"
        assert body[-1] == "10\tline 10"
        assert len(body) == 10

    def test_line_range(self, sandbox_dir: Path):
        (sandbox_dir / "ten.py").write_text("".join(f"line {i}\n" for i in range(1, 11)))
        result = read_file(sandbox_dir, "ten.py", start_line=3, end_line=5)
        header, _, *body = result.split("\n")
        assert header == "path: ten.py | total_lines: 10 | showing: 3-5 | truncated: false"
        assert body == ["3\tline 3", "4\tline 4", "5\tline 5"]

    def test_end_line_past_eof_is_clamped(self, sandbox_dir: Path):
        (sandbox_dir / "ten.py").write_text("".join(f"line {i}\n" for i in range(1, 11)))
        for kwargs in ({"start_line": 8, "end_line": 500}, {"start_line": 8}):
            result = read_file(sandbox_dir, "ten.py", **kwargs)
            header, _, *body = result.split("\n")
            assert header == "path: ten.py | total_lines: 10 | showing: 8-10 | truncated: false"
            assert body == [" 8\tline 8", " 9\tline 9", "10\tline 10"]

    def test_pages_through_capped_file(self, sandbox_dir: Path, monkeypatch):
        """Truncation lands on a line boundary, the header's range matches the
        body exactly, and following the hint reads every line exactly once."""
        monkeypatch.setattr("stride_gpt.agent.tools.MAX_FILE_SIZE", 200)
        expected = [f"line {i:03d} " + "y" * 20 for i in range(1, 51)]
        (sandbox_dir / "long.txt").write_text("\n".join(expected) + "\n")

        seen: list[str] = []
        start = None
        for _ in range(50):
            result = read_file(sandbox_dir, "long.txt", start_line=start)
            header = result.split("\n", 1)[0]
            body = result.split("\n\n", 1)[1].split("\n")
            assert len(result.split("\n\n", 1)[1].encode()) <= 200
            match = re.fullmatch(
                r"path: long\.txt \| total_lines: 50 \| showing: (\d+)-(\d+) \| truncated: (true|false)",
                header,
            )
            assert match
            first, last = int(match[1]), int(match[2])
            assert [int(b.split("\t")[0]) for b in body] == list(range(first, last + 1))
            seen.extend(b.split("\t", 1)[1] for b in body)
            if match[3] == "false":
                assert last == 50
                break
            assert f"Call read_file with start_line={last + 1} to read more." in result
            start = last + 1
        assert seen == expected

    def test_oversized_line_in_middle(self, sandbox_dir: Path, monkeypatch):
        monkeypatch.setattr("stride_gpt.agent.tools.MAX_FILE_SIZE", 50)
        (sandbox_dir / "min.js").write_text("a\n" + "z" * 500 + "\nb\n")
        result = read_file(sandbox_dir, "min.js", start_line=2)
        assert result.startswith(
            "path: min.js | total_lines: 3 | showing: 2-2 | truncated: true\n"
            "[Line 2 was cut at 50 bytes. Call read_file with start_line=3 to read more.]\n\n"
        )
        assert "[line 2 cut at 50 bytes]" in result
        # Stops at the long line rather than following it with line 3.
        assert "\tb" not in result

    def test_empty_file(self, sandbox_dir: Path):
        (sandbox_dir / "empty.py").write_text("")
        assert read_file(sandbox_dir, "empty.py") == (
            "path: empty.py | total_lines: 0 | showing: none | truncated: false"
        )
        assert read_file(sandbox_dir, "empty.py", start_line=1).startswith("Error:")

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"start_line": 0},
            {"start_line": -3},
            {"end_line": 0},
            {"start_line": 5, "end_line": 4},
            {"start_line": 11},
            {"start_line": "5"},
            {"end_line": True},
            {"start_line": 1.5},
        ],
    )
    def test_invalid_range_returns_error(self, sandbox_dir: Path, kwargs):
        (sandbox_dir / "ten.py").write_text("".join(f"line {i}\n" for i in range(1, 11)))
        result = read_file(sandbox_dir, "ten.py", **kwargs)
        assert result.startswith("Error:")

    def test_start_past_eof_error_reports_length(self, sandbox_dir: Path):
        (sandbox_dir / "ten.py").write_text("".join(f"line {i}\n" for i in range(1, 11)))
        assert "(10 lines)" in read_file(sandbox_dir, "ten.py", start_line=11)

    def test_sandbox_still_enforced_with_range(self, sandbox_dir: Path):
        with pytest.raises(ValueError, match="traversal"):
            read_file(sandbox_dir, "../../etc/passwd", start_line=1, end_line=5)
        with pytest.raises(ValueError, match="version-control metadata"):
            read_file(sandbox_dir, ".git/HEAD", start_line=1)

    def test_path_traversal_blocked(self, sandbox_dir: Path):
        with pytest.raises(ValueError, match="traversal"):
            read_file(sandbox_dir, "../../etc/passwd")

    def test_reads_nested_file(self, sandbox_dir: Path):
        result = read_file(sandbox_dir, "src/auth.py")
        assert "login" in result

    @pytest.mark.parametrize(
        "path", [".git/HEAD", "src/../.git/HEAD", "./.git", ".GIT/HEAD", ".hg/hgrc"]
    )
    def test_vcs_metadata_blocked(self, sandbox_dir: Path, path: str):
        """.git/config can hold a checkout token, so VCS metadata is refused
        however the path is spelled (including case, for macOS/Windows)."""
        with pytest.raises(ValueError, match="version-control metadata"):
            read_file(sandbox_dir, path)

    def test_symlink_to_vcs_metadata_blocked(self, sandbox_dir: Path):
        """A committed link to .git stays inside the root, so the traversal
        check alone doesn't catch it; the resolved target must be checked."""
        (sandbox_dir / "notes.txt").symlink_to(sandbox_dir / ".git" / "HEAD")
        (sandbox_dir / "meta").symlink_to(sandbox_dir / ".git")
        for path in ("notes.txt", "meta/HEAD"):
            with pytest.raises(ValueError, match="version-control metadata"):
                read_file(sandbox_dir, path)


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

    def test_vcs_metadata_blocked(self, sandbox_dir: Path):
        with pytest.raises(ValueError, match="version-control metadata"):
            list_directory(sandbox_dir, ".git")

    def test_symlink_outside_root_not_followed(self, sandbox_dir: Path, tmp_path_factory):
        """Following the link would leak whether an outside file exists and
        its size, so such links are listed without either."""
        outside = tmp_path_factory.mktemp("outside")
        (outside / "credentials").write_text("x" * 1234)
        (sandbox_dir / "leak.txt").symlink_to(outside / "credentials")
        (sandbox_dir / "leakdir").symlink_to(outside)
        (sandbox_dir / "missing").symlink_to(outside / "nope")
        (sandbox_dir / "head").symlink_to(sandbox_dir / ".git" / "HEAD")
        (sandbox_dir / "app_link.py").symlink_to(sandbox_dir / "app.py")

        entries = {e["name"]: e for e in json.loads(list_directory(sandbox_dir))}
        for name in ("leak.txt", "leakdir", "missing", "head"):
            assert entries[name] == {"name": name, "type": "symlink"}
        # Links that stay inside the root are reported as what they point to.
        assert entries["app_link.py"]["type"] == "file"
        assert entries["app_link.py"]["size"] == (sandbox_dir / "app.py").stat().st_size

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

    def test_symlink_escape_blocked(self, sandbox_dir: Path, tmp_path_factory):
        """A symlinked file pointing outside the root must not be read. read_file
        already refuses it; grep_content must not become a bypass."""
        outside = tmp_path_factory.mktemp("outside") / "credentials"
        outside.write_text("TOP-SECRET-KEY\n")
        (sandbox_dir / "leak.txt").symlink_to(outside)
        (sandbox_dir / "src" / "leak.txt").symlink_to(outside)

        with pytest.raises(ValueError, match="traversal"):
            read_file(sandbox_dir, "leak.txt")
        for path in (".", "src", "leak.txt", "src/leak.txt"):
            try:
                result = grep_content(sandbox_dir, "TOP-SECRET", path=path)
            except ValueError:
                continue  # rejected up front by _resolve_safe_path
            assert "TOP-SECRET" not in result
            assert json.loads(result) == []

    def test_vcs_metadata_not_searched(self, sandbox_dir: Path):
        """Neither pointing grep at .git nor a committed link to it may surface
        its contents (e.g. a token in .git/config)."""
        (sandbox_dir / ".git" / "config").write_text("extraheader = AUTHORIZATION: basic TOKEN\n")
        (sandbox_dir / "notes.txt").symlink_to(sandbox_dir / ".git" / "config")
        (sandbox_dir / "meta").symlink_to(sandbox_dir / ".git")

        result = grep_content(sandbox_dir, "AUTHORIZATION")
        assert json.loads(result) == []
        for path in (".git", ".git/config", "notes.txt", "meta"):
            with pytest.raises(ValueError, match="version-control metadata"):
                grep_content(sandbox_dir, "AUTHORIZATION", path=path)

    def test_symlink_within_root_still_searched(self, sandbox_dir: Path):
        """Links that stay inside the root are harmless and keep working,
        matching read_file's behaviour."""
        (sandbox_dir / "app_link.py").symlink_to(sandbox_dir / "app.py")
        result = json.loads(grep_content(sandbox_dir, "Flask"))
        files = {r["file"] for r in result}
        assert {"app.py", "app_link.py"} <= files


# ---------------------------------------------------------------------------
# execute_tool
# ---------------------------------------------------------------------------


class TestExecuteTool:
    def test_dispatches_read_file(self, sandbox_dir: Path):
        tc = ToolCallResult(id="1", function_name="read_file", arguments={"path": "app.py"})
        result = execute_tool(sandbox_dir, tc)
        assert "Flask" in result

    def test_dispatches_read_file_range(self, sandbox_dir: Path):
        tc = ToolCallResult(
            id="1", function_name="read_file",
            arguments={"path": "app.py", "start_line": 2, "end_line": 2},
        )
        result = execute_tool(sandbox_dir, tc)
        assert result == (
            "path: app.py | total_lines: 2 | showing: 2-2 | truncated: false\n\n"
            "2\tapp = Flask(__name__)"
        )

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

    def test_parse_error_not_executed(self, sandbox_dir: Path):
        tc = ToolCallResult(
            id="4", function_name="load_reference", arguments={},
            parse_error="arguments were not valid JSON (Expecting value)",
        )
        loaded: set[str] = set()
        handler = MagicMock()
        with patch.dict("stride_gpt.agent.tools._TOOL_DISPATCH", {"load_reference": handler}):
            result = execute_tool(sandbox_dir, tc, loaded_refs=loaded)
        handler.assert_not_called()
        assert result == (
            "Error: arguments were not valid JSON (Expecting value). "
            "Re-issue the call with a valid JSON object."
        )
        assert loaded == set()

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


def _reporting(name: str) -> dict:
    return next(t["function"] for t in REPORTING_TOOLS if t["function"]["name"] == name)


class TestToolDefinitions:
    def test_tool_names_match_dispatch(self):
        from stride_gpt.agent.tools import _TOOL_DISPATCH

        tool_names = {t["function"]["name"] for t in AGENT_TOOLS}
        dispatch_names = set(_TOOL_DISPATCH.keys())
        assert tool_names == dispatch_names

    def test_read_file_schema_has_optional_line_range(self):
        read_tool = next(t for t in AGENT_TOOLS if t["function"]["name"] == "read_file")
        params = read_tool["function"]["parameters"]
        assert params["required"] == ["path"]
        for name in ("start_line", "end_line"):
            assert params["properties"][name]["type"] == "integer"
            assert params["properties"][name]["minimum"] == 1


class TestReportingTools:
    """report_threat / finish: offered in the subsystem loop, handled there."""

    def test_not_in_dispatch(self):
        """They record loop state, so execute_tool must never own them.

        Without this, the next reader sees a 'missing' dispatch entry and
        adds one that can't work.
        """
        from stride_gpt.agent.tools import _TOOL_DISPATCH

        assert REPORTING_TOOL_NAMES.isdisjoint(_TOOL_DISPATCH)

    def test_subsystem_tools_is_exploration_plus_reporting(self):
        names = [t["function"]["name"] for t in SUBSYSTEM_TOOLS]
        assert names == [t["function"]["name"] for t in AGENT_TOOLS] + [
            "report_threat",
            "finish",
        ]

    def test_report_threat_requires_the_core_fields_and_evidence(self):
        params = _reporting("report_threat")["parameters"]
        assert params["required"] == [
            "threat_type", "scenario", "potential_impact", "evidence",
        ]

    def test_argument_names_have_no_spaces(self):
        """A parameter name with a space breaks real providers: DeepSeek
        truncates "Threat Type" at the space, so the key arrives as "Threat"
        and the whole call fails to parse. THREAT_ARG_TO_FIELD maps the
        snake_case arguments back to the report's own field names."""
        props = _reporting("report_threat")["parameters"]["properties"]
        assert all(" " not in name for name in props)
        assert set(props) - {"evidence"} == set(THREAT_ARG_TO_FIELD)
        assert THREAT_ARG_TO_FIELD["threat_type"] == "Threat Type"
        assert THREAT_ARG_TO_FIELD["potential_impact"] == "Potential Impact"

    def test_fixed_value_fields_are_enumerated(self):
        """Free-text STRIDE categories degrade the SARIF rule IDs and the
        HTML badge colours, both of which key off the exact strings."""
        props = _reporting("report_threat")["parameters"]["properties"]
        assert props["threat_type"]["enum"] == STRIDE_CATEGORIES
        assert props["owasp_llm"]["enum"][0] == "LLM01"
        assert props["owasp_asi"]["enum"][-1] == "ASI10"
        assert "Data Exfiltration" in props["insider_category"]["enum"]
        assert props["autonomy_level"]["enum"] == ["L1", "L2", "L3", "L4"]

    def test_evidence_items_need_a_path_and_a_snippet(self):
        evidence = _reporting("report_threat")["parameters"]["properties"]["evidence"]
        assert evidence["type"] == "array"
        assert evidence["items"]["required"] == ["path", "snippet"]
        assert evidence["maxItems"] == 5

    def test_evidence_description_forbids_line_numbers(self):
        """The matcher strips read_file's gutter, but the model shouldn't
        rely on that — a snippet is code, not a transcript."""
        evidence = _reporting("report_threat")["parameters"]["properties"]["evidence"]
        assert "WITHOUT the leading line number" in evidence["description"]

    def test_finish_carries_improvement_suggestions(self):
        params = _reporting("finish")["parameters"]
        assert params["required"] == ["improvement_suggestions"]
        assert params["properties"]["improvement_suggestions"]["items"]["type"] == "string"
