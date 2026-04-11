"""Tests for stride_gpt.prompt — slash command and path completion."""

from __future__ import annotations

from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document

from stride_gpt.prompt import COMMANDS, StrideCompleter


def _complete(text: str) -> list[str]:
    """Run the completer and return the completion strings."""
    completer = StrideCompleter()
    doc = Document(text, cursor_position=len(text))
    return [c.text for c in completer.get_completions(doc, CompleteEvent())]


class TestSlashCommandCompletion:
    def test_empty_slash_lists_all(self):
        results = _complete("/")
        # Should suggest every defined command
        all_cmds = {cmd for cmd, _ in COMMANDS}
        assert all_cmds.issubset(set(results))

    def test_partial_slash_filters(self):
        results = _complete("/a")
        assert "/analyze" in results
        assert "/quit" not in results

    def test_no_completion_for_unknown_prefix(self):
        results = _complete("/zzz")
        assert results == []

    def test_no_completion_after_space(self):
        # Once you've typed a command and a space, slash completer is silent.
        # (Path completer takes over for /analyze.)
        results = _complete("/quick ")
        # /quick takes free text, not a path — no completions expected
        assert "/analyze" not in results


class TestPathCompletion:
    def test_path_after_analyze(self, tmp_path):
        # Create some directories to complete against
        (tmp_path / "subdir").mkdir()
        results = _complete(f"/analyze {tmp_path}/")
        # PathCompleter yields directory entries; should include subdir
        assert any("subdir" in r for r in results)

    def test_no_path_completion_for_quick(self, tmp_path):
        (tmp_path / "subdir").mkdir()
        results = _complete(f"/quick {tmp_path}/")
        # /quick is not a path-accepting command for positional args
        assert results == []

    def test_path_after_output_flag(self, tmp_path):
        (tmp_path / "out").mkdir()
        results = _complete(f"/analyze . -o {tmp_path}/")
        assert any("out" in r for r in results)

    def test_path_after_input_flag(self, tmp_path):
        (tmp_path / "desc.txt").write_text("hello")
        results = _complete(f"/quick -i {tmp_path}/")
        assert any("desc.txt" in r for r in results)
