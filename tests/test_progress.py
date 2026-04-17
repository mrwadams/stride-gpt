"""Tests for stride_gpt.agent.progress — progress callback implementations."""

from __future__ import annotations

import queue
from unittest.mock import MagicMock

from stride_gpt.agent.progress import (
    ProgressCallback,
    QueueProgress,
    RichProgress,
)


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
        p.subsystem_done("Auth", 3)
        event = q.get_nowait()
        assert event["type"] == "subsystem_done"
        assert event["threat_count"] == 3

    def test_tool_call(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.tool_call("read_file", "path='auth.py'", cached=False)
        event = q.get_nowait()
        assert event["type"] == "tool_call"
        assert event["name"] == "read_file"
        assert event["cached"] is False

    def test_tool_call_cached(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.tool_call("read_file", "path='auth.py'", cached=True)
        event = q.get_nowait()
        assert event["cached"] is True

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

    def test_full_sequence(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        p.phase_start("Phase 1", "Planning")
        p.status("Scanning...")
        p.subsystem_start(1, 2, "Auth", "Auth module")
        p.tool_call("read_file", "path='auth.py'", cached=False)
        p.subsystem_done("Auth", 3)
        p.synthesis_done(1)
        p.complete("Done")
        assert q.qsize() == 7


class TestRichProgress:
    def test_phase_start_calls_console(self):
        console = MagicMock()
        p = RichProgress(console)
        p.phase_start("Phase 1", "Planning")
        console.print.assert_called_once()

    def test_subsystem_done_calls_console(self):
        console = MagicMock()
        p = RichProgress(console)
        p.subsystem_done("Auth", 5)
        console.print.assert_called_once()


class TestProtocol:
    def test_queue_progress_satisfies_protocol(self):
        q: queue.Queue = queue.Queue()
        p = QueueProgress(q)
        assert isinstance(p, ProgressCallback)

    def test_rich_progress_satisfies_protocol(self):
        console = MagicMock()
        p = RichProgress(console)
        assert isinstance(p, ProgressCallback)
