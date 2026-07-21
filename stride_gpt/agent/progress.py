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

    def verify_start(self, total: int) -> None:
        """The verification phase is starting over ``total`` threats."""
        ...

    def verify_threat_done(self, subsystem: str, outcome: str, confidence: int) -> None:
        """One threat was verified. ``outcome`` is 'kept' or a drop_reason."""
        ...

    def verify_summary(self, surviving: int, refuted: int, errored: int) -> None:
        """The verification phase finished."""
        ...

    def verify_aborted(self, reason: str) -> None:
        """The verification phase tripped its guardrail and was abandoned."""
        ...

    def token_budget(self, model: str, limit: int, source: str) -> None:
        """Report the context token budget for the model.

        Args:
            source: One of "queried", "inferred", "explicit".
        """
        ...

    def no_tool_use_warning(self, subsystem: str) -> None:
        """Warn that a subsystem was analyzed without any tool calls."""
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

    def token_budget(self, model: str, limit: int, source: str) -> None:
        if source == "queried" or source == "explicit":
            self.console.print(f"  [dim]Token budget: {limit:,} tokens[/dim]")
        else:
            self.console.print(
                f"[yellow]Warning: Could not query '{model}' for its context window size. "
                f"Context compression may not work correctly.[/yellow]"
            )

    def no_tool_use_warning(self, subsystem: str) -> None:
        self.console.print(
            f"  [yellow]Warning: No tool calls made for {subsystem} — "
            f"the model may not support function calling. "
            f"Threats are based on file names only, not actual code.[/yellow]"
        )

    def synthesis_done(self, count: int) -> None:
        self.console.print(f"  [green]Found {count} cross-cutting threats[/green]")

    def verify_start(self, total: int) -> None:
        self.console.print(
            f"  [dim]Verifying {total} threats (refutation pass)...[/dim]"
        )

    def verify_threat_done(self, subsystem: str, outcome: str, confidence: int) -> None:
        if outcome == "kept":
            self.console.print(
                f"    [green]kept[/green] [dim]({subsystem}, confidence {confidence}/10)[/dim]"
            )
        else:
            self.console.print(
                f"    [yellow]{outcome.lower()}[/yellow] [dim]({subsystem})[/dim]"
            )

    def verify_summary(self, surviving: int, refuted: int, errored: int) -> None:
        self.console.print(
            f"  [green]Verified: {surviving} kept, {refuted} refuted"
            + (f", {errored} errored" if errored else "")
            + "[/green]"
        )

    def verify_aborted(self, reason: str) -> None:
        self.console.print(
            f"  [red]Verification aborted: {reason}. "
            f"Keeping the unverified report.[/red]"
        )

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

    def token_budget(self, model: str, limit: int, source: str) -> None:
        self._put({"type": "token_budget", "model": model, "limit": limit,
                    "source": source})

    def no_tool_use_warning(self, subsystem: str) -> None:
        self._put({"type": "no_tool_use_warning", "subsystem": subsystem})

    def synthesis_done(self, count: int) -> None:
        self._put({"type": "synthesis_done", "count": count})

    def verify_start(self, total: int) -> None:
        self._put({"type": "verify_start", "total": total})

    def verify_threat_done(self, subsystem: str, outcome: str, confidence: int) -> None:
        self._put({"type": "verify_threat_done", "subsystem": subsystem,
                    "outcome": outcome, "confidence": confidence})

    def verify_summary(self, surviving: int, refuted: int, errored: int) -> None:
        self._put({"type": "verify_summary", "surviving": surviving,
                    "refuted": refuted, "errored": errored})

    def verify_aborted(self, reason: str) -> None:
        self._put({"type": "verify_aborted", "reason": reason})

    def complete(self, summary: str) -> None:
        self._put({"type": "complete", "summary": summary})
