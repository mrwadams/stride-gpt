"""LLM call budget: the per-subsystem default, the run's ceiling, and plan approval.

Kept free of heavy imports so the CLI can use the default at import time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console


# Default ``--max-llm-calls``: rounds each subsystem may spend exploring.
# Measured reference: a complete 6-subsystem run against crAPI's identity
# service took about 11.8 exploration rounds per subsystem (71 exploration
# calls of 76 total). 25 leaves roughly twice that headroom, so a typical
# subsystem finishes on its own and the cap only bites on a runaway one.
DEFAULT_MAX_LLM_CALLS = 25

# Calls a run can make outside the per-subsystem budget once the plan is
# approved: cross-cutting synthesis, which retries once when its first reply
# is not JSON, and the system-level DFD.
_POST_SUBSYSTEM_CALLS = 3


def llm_call_ceiling(subsystem_count: int, max_llm_calls: int) -> int | None:
    """Most LLM calls a run with this plan can make after approval.

    Each subsystem gets ``max_llm_calls`` rounds plus one final reporting
    round (``_grace_round``), then synthesis (at most two calls) and the DFD
    (one). It is an upper bound, never an estimate: a run can only come in under it.
    ``None`` when the cap is disabled (``0``), since nothing bounds the run.
    """
    if not max_llm_calls:
        return None
    return subsystem_count * (max_llm_calls + 1) + _POST_SUBSYSTEM_CALLS


def format_llm_call_ceiling(subsystem_count: int, max_llm_calls: int) -> str:
    """The ceiling line shown at the plan approval prompt."""
    ceiling = llm_call_ceiling(subsystem_count, max_llm_calls)
    if ceiling is None:
        return "LLM call ceiling: none (--max-llm-calls 0 leaves each subsystem unbounded)"
    return (
        f"LLM call ceiling: {ceiling} calls — a ceiling, not an estimate "
        f"({subsystem_count} subsystems x ({max_llm_calls} rounds + 1 final round)"
        f" + {_POST_SUBSYSTEM_CALLS} for synthesis, its retry and the diagram)"
    )


def prompt_plan_approval(console: Console) -> bool:
    """Ask whether to run the plan: ``y`` approves, ``n`` declines.

    The prompt used to offer ``y/n/q`` while treating ``n``, ``q`` and any
    typo alike as a decline. There are two answers, so it offers two; ``q``
    is still accepted as a decline, and anything unrecognised asks again
    rather than silently cancelling the run.
    """
    while True:
        response = console.input("[bold yellow]Approve this plan? (y/n): [/bold yellow]")
        answer = response.strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no", "q", "quit"):
            return False
        console.print("Please answer y (run the plan) or n (cancel).")
