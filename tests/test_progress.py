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
