"""Tests for stride_gpt.prompt — slash command and path completion."""

from __future__ import annotations

from prompt_toolkit.application import create_app_session
from prompt_toolkit.application.current import set_app
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.data_structures import Size
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import fragment_list_to_text, to_formatted_text
from prompt_toolkit.input import DummyInput
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.utils import get_cwidth

from stride_gpt.prompt import COMMANDS, StrideCompleter, build_session


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


class TestBottomToolbar:
    @staticmethod
    def _session(monkeypatch, tmp_path, config, columns):
        root = tmp_path / "uat-tree"
        root.mkdir()
        monkeypatch.chdir(root)
        output = DummyOutput()
        monkeypatch.setattr(output, "get_size", lambda: Size(rows=40, columns=columns[0]))
        with create_app_session(input=DummyInput(), output=output):
            return build_session(lambda: config)

    def test_hints_fit_as_complete_segments_after_resize(self, monkeypatch, tmp_path):
        columns = [160]
        config = {
            "architect_provider": "Google AI",
            "architect_model": "gemini-3.8-flash",
            "worker_provider": "DeepSeek",
            "worker_model": "deepseek-flash",
        }
        session = self._session(monkeypatch, tmp_path, config, columns)
        with set_app(session.app):
            for width, hints in [
                (160, ["Tab to complete", "Ctrl+L to clear", "/help"]),
                (137, ["Tab to complete", "Ctrl+L to clear", "/help"]),
                (120, ["Tab to complete"]),
                (90, []),
                (160, ["Tab to complete", "Ctrl+L to clear", "/help"]),
            ]:
                columns[0] = width
                text = fragment_list_to_text(to_formatted_text(session.bottom_toolbar()))
                assert get_cwidth(text) <= width
                assert "Google AI/gemini-3.8-flash" in text
                assert "DeepSeek/deepseek-flash" in text
                assert "cwd: uat-tree" in text
                for hint in ["Tab to complete", "Ctrl+L to clear", "/help"]:
                    assert (hint in text) == (hint in hints)

    def test_wide_directory_uses_display_columns(self, monkeypatch, tmp_path):
        columns = [70]
        session = self._session(
            monkeypatch, tmp_path, {"worker_provider": "Local", "worker_model": "model"}, columns
        )
        root = tmp_path / "项目资料目录"
        root.mkdir()
        monkeypatch.chdir(root)
        with set_app(session.app):
            text = fragment_list_to_text(to_formatted_text(session.bottom_toolbar()))
        assert get_cwidth(text) <= 70
        assert "cwd: 项目资料目录" in text
        assert "Tab to complete" in text
        assert "Ctrl+L to clear" not in text

    def test_core_information_takes_priority_over_hints(self, monkeypatch, tmp_path):
        session = self._session(
            monkeypatch, tmp_path, {"worker_provider": "Local", "worker_model": "model"}, [20]
        )
        with set_app(session.app):
            text = fragment_list_to_text(to_formatted_text(session.bottom_toolbar()))
        assert "Local / model" in text
        assert "cwd: uat-tree" in text
        assert "Tab to complete" not in text
        assert "Ctrl+L to clear" not in text
        assert "/help" not in text
