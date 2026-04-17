"""Progress callback protocol for the agent loop.

Decouples progress reporting from any specific UI framework (Rich, Streamlit, etc.).
"""

from __future__ import annotations

import queue
from typing import Any, Protocol, runtime_checkable

from rich.console import Console
from rich.panel import Panel


@runtime_checkable
class ProgressCallback(Protocol):
    """Interface for reporting agent loop progress."""

    def phase_start(self, phase: str, description: str) -> None:
        """A new analysis phase is starting (Planning, Analyzing, Synthesizing)."""
        ...

    def status(self, message: str) -> None:
        """Transient status update (e.g. 'Thinking about Auth...')."""
        ...

    def subsystem_start(self, index: int, total: int, name: str, description: str) -> None:
        """Starting analysis of a subsystem."""
        ...

    def subsystem_done(self, name: str, threat_count: int) -> None:
        """Finished analyzing a subsystem."""
        ...

    def tool_call(self, name: str, args_brief: str, cached: bool) -> None:
        """A tool was called during exploration."""
        ...

    def error(self, name: str, reason: str) -> None:
        """An error occurred analyzing a subsystem."""
        ...

    def limit_reached(self, kind: str, current: int, maximum: int) -> None:
        """A hard limit (LLM calls or tool calls) was reached."""
        ...

    def synthesis_done(self, count: int) -> None:
        """Cross-cutting threat synthesis completed."""
        ...

    def complete(self, summary: str) -> None:
        """Analysis finished. Summary is a human-readable status line."""
        ...


class RichProgress:
    """ProgressCallback implementation that writes to a Rich Console."""

    def __init__(self, console: Console) -> None:
        self.console = console
        self._status_ctx: Any = None

    def phase_start(self, phase: str, description: str) -> None:
        self.console.print(Panel(f"[bold]{phase}: {description}[/bold]", style="blue"))

    def status(self, message: str) -> None:
        self.console.print(f"  [dim]{message}[/dim]")

    def subsystem_start(self, index: int, total: int, name: str, description: str) -> None:
        self.console.print(f"\n[bold cyan]({index}/{total}) Analyzing: {name}[/bold cyan]")
        self.console.print(f"  {description}")

    def subsystem_done(self, name: str, threat_count: int) -> None:
        self.console.print(f"  [green]Found {threat_count} threats in {name}[/green]")

    def tool_call(self, name: str, args_brief: str, cached: bool) -> None:
        suffix = " (cached)" if cached else ""
        self.console.print(f"    [dim]{name}({args_brief}){suffix}[/dim]")

    def error(self, name: str, reason: str) -> None:
        self.console.print(f"  [red]Error analyzing {name}: {reason}[/red]")

    def limit_reached(self, kind: str, current: int, maximum: int) -> None:
        self.console.print(
            f"[yellow]Reached {kind} limit ({current}/{maximum}). Stopping early.[/yellow]"
        )

    def synthesis_done(self, count: int) -> None:
        self.console.print(f"  [green]Found {count} cross-cutting threats[/green]")

    def complete(self, summary: str) -> None:
        self.console.print(Panel(summary, title="Summary", style="green"))


class QueueProgress:
    """ProgressCallback implementation that pushes events onto a thread-safe queue.

    Designed for Streamlit: the UI thread polls the queue and renders updates.
    """

    def __init__(self, q: queue.Queue) -> None:
        self._q = q

    def _put(self, event: dict) -> None:
        self._q.put(event)

    def phase_start(self, phase: str, description: str) -> None:
        self._put({"type": "phase_start", "phase": phase, "description": description})

    def status(self, message: str) -> None:
        self._put({"type": "status", "message": message})

    def subsystem_start(self, index: int, total: int, name: str, description: str) -> None:
        self._put({"type": "subsystem_start", "index": index, "total": total,
                    "name": name, "description": description})

    def subsystem_done(self, name: str, threat_count: int) -> None:
        self._put({"type": "subsystem_done", "name": name, "threat_count": threat_count})

    def tool_call(self, name: str, args_brief: str, cached: bool) -> None:
        self._put({"type": "tool_call", "name": name, "args_brief": args_brief, "cached": cached})

    def error(self, name: str, reason: str) -> None:
        self._put({"type": "error", "name": name, "reason": reason})

    def limit_reached(self, kind: str, current: int, maximum: int) -> None:
        self._put({"type": "limit_reached", "kind": kind, "current": current, "maximum": maximum})

    def synthesis_done(self, count: int) -> None:
        self._put({"type": "synthesis_done", "count": count})

    def complete(self, summary: str) -> None:
        self._put({"type": "complete", "summary": summary})
