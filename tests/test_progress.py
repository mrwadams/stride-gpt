"""Tests for stride_gpt.agent.progress — progress callback implementations."""

from __future__ import annotations

import io
import queue

import pytest
from rich.console import Console

from stride_gpt.agent.progress import QueueProgress, RichProgress


class TestQueueProgress:
    def test_phase_start(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.phase_start("Phase 1", "Planning")
        event = q.get_nowait()
        assert event["type"] == "phase_start"
        assert event["phase"] == "Phase 1"
        assert event["description"] == "Planning"

    def test_subsystem_start(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.subsystem_start(2, 5, "Auth", "Authentication module")
        event = q.get_nowait()
        assert event["type"] == "subsystem_start"
        assert event["index"] == 2
        assert event["total"] == 5
        assert event["name"] == "Auth"

    def test_subsystem_done(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.subsystem_done("Auth", 3, "completed")
        event = q.get_nowait()
        assert event["type"] == "subsystem_done"
        assert event["threat_count"] == 3
        assert event["outcome"] == "completed"

    def test_subsystems_skipped(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.subsystems_skipped(["API", "Storage"])
        event = q.get_nowait()
        assert event["type"] == "subsystems_skipped"
        assert event["names"] == ["API", "Storage"]

    @pytest.mark.parametrize("cached", [False, True])
    def test_tool_call(self, cached):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.tool_call("read_file", "path='auth.py'", cached=cached)
        event = q.get_nowait()
        assert event["type"] == "tool_call"
        assert event["name"] == "read_file"
        assert event["cached"] is cached

    def test_error(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.error("Auth", "Context window exceeded")
        event = q.get_nowait()
        assert event["type"] == "error"
        assert event["name"] == "Auth"

    def test_synthesis_failed(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.synthesis_failed("Rate limited by the provider.")
        event = q.get_nowait()
        assert event["type"] == "synthesis_failed"
        assert event["reason"] == "Rate limited by the provider."

    def test_complete(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.complete("Analysis complete!")
        event = q.get_nowait()
        assert event["type"] == "complete"
        assert event["summary"] == "Analysis complete!"




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
            lambda p, text: p.subsystems_skipped(["Auth", text]),
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
