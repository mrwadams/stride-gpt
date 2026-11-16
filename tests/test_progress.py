"""Tests for stride_gpt.agent.progress — progress callback implementations."""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from stride_gpt.agent.progress import RichProgress


class TestRichProgress:
    def test_complete_keeps_bracketed_cache_split(self):
        # Rendered through a real Console: Rich parses "[cached: ...]" as a
        # markup tag and silently drops it unless the summary is escaped.
        out = io.StringIO()
        p = RichProgress(Console(file=out, width=120))
        p.complete("Token usage: 105 (prompt: 100 [cached: 60, uncached: 40] | completion: 5)")
        assert "(prompt: 100 [cached: 60, uncached: 40] | completion: 5)" in out.getvalue()

    def test_synthesis_failure_names_the_phase_not_a_subsystem(self):
        out = io.StringIO()
        p = RichProgress(Console(file=out, width=200))
        p.synthesis_failed("Unexpected error: bad key [x]")
        text = out.getvalue()
        assert "Synthesis failed" in text
        assert "Error analyzing" not in text
        assert "Unexpected error: bad key [x]" in text

    @pytest.mark.parametrize(
        "text",
        [
            r"pattern='\\.\\.[/\\\\]'",  # a path-traversal grep aborted the run
            "app/[id]/page.tsx",  # silently dropped as a markup tag
            "[/dim] closes nothing",
            "ends in a backslash\\",
        ],
    )
    @pytest.mark.parametrize(
        "call",
        [
            lambda p, text: p.tool_call("grep_content", text, cached=False),
            lambda p, text: p.tool_call(text, "path='a.py'", cached=True),
            lambda p, text: p.error(text, "boom"),
            lambda p, text: p.error("Auth", text),
            lambda p, text: p.status(text),
            lambda p, text: p.subsystem_start(1, 2, text, "desc"),
            lambda p, text: p.subsystem_start(1, 2, "Auth", text),
            lambda p, text: p.subsystem_done(text, 1, "completed"),
            lambda p, text: p.subsystem_done(text, 1, "budget_exhausted"),
            lambda p, text: p.subsystem_done(text, 1, "parse_failed"),
            lambda p, text: p.subsystem_done(text, 1, "unfinished"),
            lambda p, text: p.no_tool_use_warning(text),
        ],
    )
    def test_model_supplied_text_renders_literally(self, call, text):
        # Model output, repo paths and exception text are not Rich markup: a
        # stray tag raises MarkupError, which aborted the whole run because the
        # error handler printed the same text.
        out = io.StringIO()
        p = RichProgress(Console(file=out, width=300))
        call(p, text)
        assert text in out.getvalue()

    def test_unfinished_subsystem_says_it_stopped_early(self):
        out = io.StringIO()
        p = RichProgress(Console(file=out, width=200))
        p.subsystem_done("Auth", 2, "unfinished")
        text = out.getvalue()
        assert "2 threats" in text
        assert "could not be read" not in text
