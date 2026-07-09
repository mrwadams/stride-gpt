"""Tests for stride_gpt.agent.progress — progress callback implementations."""

from __future__ import annotations

import queue

import pytest

from stride_gpt.agent.progress import QueueProgress


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


