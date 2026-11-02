"""Tests for stride_gpt.agent.tools — filesystem tools with sandboxing."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import regex

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

    @pytest.mark.parametrize("name", [".env", "build", "target", "dist"])
    def test_file_named_like_a_skipped_directory_is_listed(self, sandbox_dir: Path, name: str):
        """SKIP_DIRS is about directories. A `.env` file is exactly what a threat
        model should know about."""
        (sandbox_dir / name).write_text("API_KEY=hunter2\n")

        entries = {e["name"]: e for e in json.loads(list_directory(sandbox_dir))}

        assert entries[name] == {"name": name, "type": "file", "size": 16}

    @pytest.mark.parametrize("name", [".env", "venv", "dist"])
    def test_directory_of_a_skipped_name_stays_hidden(self, sandbox_dir: Path, name: str):
        (sandbox_dir / name).mkdir()

        names = {e["name"] for e in json.loads(list_directory(sandbox_dir))}

        assert name not in names

    def test_listing_a_dotenv_file_leaves_its_read_access_unchanged(self, sandbox_dir: Path):
        (sandbox_dir / ".env").write_text("API_KEY=hunter2\n")

        assert "API_KEY=hunter2" in read_file(sandbox_dir, ".env")

    def test_link_out_of_the_sandbox_with_a_skipped_name_reveals_nothing(
        self, sandbox_dir: Path, tmp_path_factory
    ):
        """Hiding only links to directories would say what the target is, so
        such a link is listed the same way whatever it points to."""
        outside = tmp_path_factory.mktemp("outside")
        (outside / "secrets").write_text("x" * 1234)
        (sandbox_dir / ".env").symlink_to(outside / "secrets")
        (sandbox_dir / "venv").symlink_to(outside)

        entries = {e["name"]: e for e in json.loads(list_directory(sandbox_dir))}

        assert entries[".env"] == {"name": ".env", "type": "symlink"}
        assert entries["venv"] == {"name": "venv", "type": "symlink"}


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

    @pytest.mark.parametrize(
        "pattern",
        ["(Flask)+", "(?:Flask)+", "(?:Flask|Django)+", "(?:from|import)+", "(a+)+", "(a+){2,}"],
    )
    def test_quantified_groups_run(self, sandbox_dir: Path, pattern: str):
        """No pattern is refused for its shape: the time limit handles the
        slow ones, so harmless ones like `(?:GET|POST)+` must run."""
        assert isinstance(json.loads(grep_content(sandbox_dir, pattern)), list)

    def test_alternation_under_a_quantifier_finds_matches(self, sandbox_dir: Path):
        (sandbox_dir / "routes.py").write_text("methods = 'GETPOST'\n")
        result = json.loads(grep_content(sandbox_dir, "(?:GET|POST)+", path="routes.py"))
        assert [r["line"] for r in result] == [1]

    @pytest.mark.parametrize("pattern", ["[invalid", "(", ")", "*", "a{2,1}", r"\q", "(?P<n"])
    def test_invalid_pattern_is_reported_not_raised(self, sandbox_dir: Path, pattern: str):
        result = grep_content(sandbox_dir, pattern)
        assert result.startswith("Error:")
        assert "invalid regex" in result

    @pytest.mark.parametrize(
        "pattern",
        [
            "(a{4000}){4000}",
            "((a{1000}){1000}){1000}",
            "((a{2,}){1000}){1000}",
            "((a{1000,2000}){1000}){1000}",
            "a{0}((b{1000}){1000})",
            r"(a\\{1000}){1000}",
        ],
    )
    def test_refuses_repeats_that_exhaust_memory_at_compile_time(
        self, sandbox_dir: Path, pattern: str
    ):
        """`regex` expands counted repeats when compiling, in C, before any
        timeout applies. The patterns are short but need gigabytes."""
        result = grep_content(sandbox_dir, pattern)
        assert result.startswith("Error:")
        assert "repeat" in result

    @pytest.mark.parametrize(
        "pattern",
        [
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            "[A-Za-z0-9]{40}",
            "((a{1,1000}){1,1000}){1,1000}",
            r"\{1000\}\{1000\}",
        ],
    )
    def test_ordinary_counted_repeats_run(self, sandbox_dir: Path, pattern: str):
        assert isinstance(json.loads(grep_content(sandbox_dir, pattern)), list)

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


class TestGrepTimeLimit:
    """`(a|a)+$` on a 41-character line used to hang the whole run."""

    # Under MAX_GREP_LINE_LEN, so truncation can't remove the `!` that forces
    # the backtracking.
    EVIL_LINE = "a" * 500 + "!"

    @pytest.fixture
    def short_deadline(self, monkeypatch):
        monkeypatch.setattr("stride_gpt.agent.tools.GREP_DEADLINE_SECONDS", 0.05)

    @pytest.fixture
    def evil_file(self, sandbox_dir: Path) -> str:
        (sandbox_dir / "evil.txt").write_text(f"{self.EVIL_LINE}\n")
        return "evil.txt"

    @pytest.mark.usefixtures("short_deadline")
    @pytest.mark.parametrize("pattern", ["(a|a)+$", "(a|aa)+$"])
    def test_catastrophic_pattern_is_stopped_and_flagged(
        self, sandbox_dir: Path, evil_file: str, pattern: str
    ):
        result = json.loads(grep_content(sandbox_dir, pattern, path=evil_file))

        assert result[0]["incomplete"] is True
        assert "narrow" in result[0]["warning"].lower()

    @pytest.mark.usefixtures("short_deadline")
    def test_no_matches_yet_does_not_read_as_no_matches(self, sandbox_dir: Path, evil_file: str):
        result = json.loads(grep_content(sandbox_dir, "(a|a)+$", path=evil_file))

        assert result != []
        assert not any("file" in item for item in result)
        warning = result[0]["warning"].lower()
        assert "no matches" in warning
        assert "not" in warning

    @pytest.mark.usefixtures("short_deadline")
    def test_keeps_matches_found_before_the_limit(self, sandbox_dir: Path):
        (sandbox_dir / "mixed.txt").write_text(f"needle\n{self.EVIL_LINE}\nneedle\n")

        result = json.loads(grep_content(sandbox_dir, "needle|(a|a)+$", path="mixed.txt"))

        assert result[0]["incomplete"] is True
        assert [item["line"] for item in result[1:]] == [1]

    @pytest.mark.usefixtures("short_deadline")
    def test_warning_precedes_the_matches(self, sandbox_dir: Path):
        """Context compression keeps only the start of a long tool result, so
        a warning after the matches could be lost and the search would then
        read as complete."""
        body = "".join(f"needle {'x' * 150}\n" for _ in range(15))
        (sandbox_dir / "mixed.txt").write_text(f"{body}{self.EVIL_LINE}\n")

        raw = grep_content(sandbox_dir, "needle|(a|a)+$", path="mixed.txt")

        assert '"incomplete"' in raw[:200]
        assert len(json.loads(raw)) == 16

    def test_one_limit_covers_the_whole_call(self, sandbox_dir: Path, monkeypatch):
        """A per-line limit would spend 0.05s on each of 400 lines, 20 seconds."""
        monkeypatch.setattr("stride_gpt.agent.tools.GREP_DEADLINE_SECONDS", 0.05)
        (sandbox_dir / "evil.txt").write_text(f"{self.EVIL_LINE}\n" * 400)

        started = time.monotonic()
        result = json.loads(grep_content(sandbox_dir, "(a|a)+$", path="evil.txt"))

        assert time.monotonic() - started < 2
        assert result[0]["incomplete"] is True

    def test_limit_spans_files(self, sandbox_dir: Path, monkeypatch):
        monkeypatch.setattr("stride_gpt.agent.tools.GREP_DEADLINE_SECONDS", 0.05)
        for i in range(40):
            (sandbox_dir / f"evil{i}.txt").write_text(f"{self.EVIL_LINE}\n")

        started = time.monotonic()
        result = json.loads(grep_content(sandbox_dir, "(a|a)+$"))

        assert time.monotonic() - started < 1
        assert result[0]["incomplete"] is True

    def test_remaining_time_is_never_negative(self, sandbox_dir: Path, monkeypatch):
        """`regex` treats a negative timeout as no timeout at all, so an
        overrun deadline must reach it as zero. Stubbed because the regression
        this guards against is a hang."""
        monkeypatch.setattr("stride_gpt.agent.tools.GREP_DEADLINE_SECONDS", -1)
        (sandbox_dir / "two.txt").write_text("one\ntwo\n")
        seen: list[float] = []

        class Recorder:
            def search(self, _line: str, timeout: float):
                seen.append(timeout)
                raise TimeoutError

        monkeypatch.setattr("stride_gpt.agent.tools.regex.compile", lambda *_a, **_k: Recorder())

        result = json.loads(grep_content(sandbox_dir, "one", path="two.txt"))

        assert seen == [0]
        assert result[0]["incomplete"] is True

    def test_real_regex_timeout_of_zero_stops_a_catastrophic_match(self, sandbox_dir: Path):
        """Pins the library behaviour the clamp above depends on."""
        with pytest.raises(TimeoutError):
            regex.compile("(a|a)+$").search(self.EVIL_LINE, timeout=0)

    def test_complete_search_carries_no_warning(self, sandbox_dir: Path):
        result = json.loads(grep_content(sandbox_dir, "Flask"))
        assert result
        assert not any("incomplete" in item for item in result)

    def test_tool_description_explains_the_marker(self):
        grep_tool = next(t for t in AGENT_TOOLS if t["function"]["name"] == "grep_content")
        assert "incomplete" in grep_tool["function"]["description"]


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
