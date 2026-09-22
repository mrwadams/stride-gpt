"""Estimate what an /analyze run will cost, before it starts (#198).

A run's cost is otherwise invisible until it's over: a five-subsystem plan
against a mid-sized repository runs to millions of tokens, and nothing says so
at the point where the user is asked to approve it. This module turns the
per-subsystem token usage recorded by #217 into a number the approval prompt
can show, so the choice to shrink the plan is made before the spend rather
than after it.

The estimate is deliberately coarse: mean cost per analysed subsystem for this
target, multiplied by the number of subsystems in the plan. It is an order of
magnitude, not a forecast — see ``DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE`` for how
wide the observed spread is.

Two things about the recorded data shape the matching rule:

* **Never match on subsystem names.** The planner names subsystems freshly
  every run; three instrumented runs against the same target at the same
  commit produced three disjoint name sets. A per-name lookup misses even
  against perfect history, which is why the unit of history here is the mean
  over a run's subsystems rather than a name-keyed table.
* **Match on the target.** ``target_id`` (a hash of the resolved target path)
  plus ``target_git_sha``, falling back to ``target_id`` alone. The redacted
  ``target_path`` is only consulted for manifests written before ``target_id``
  existed, and never when it reads ``"./"`` — every repository analysed from
  its own root records that same string, so matching on it would hand one
  repository's history to another.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from stride_gpt.agent.persistence import (
    AMBIGUOUS_TARGET_PATH,
    RunManifest,
    discover_git_sha,
    load_run_manifests,
    redact_path,
    target_identity,
)

# Per-subsystem token cost assumed when a target has no usable history.
#
# PROVENANCE — this is the mean of the three per-subsystem figures the #198
# instrumentation recorded against stride-gpt itself at commit 84c8a0f:
# 108,640, 264,652 and 458,135 tokens. All three are *lower bounds*: each run
# was cut short by a cap or a grace round, so none measured a subsystem
# running to its natural end, and the 4.2x spread across identical inputs is
# why the prompt presents this as an order of magnitude rather than a
# forecast. 280,000 also sits inside the 200,000-460,000 per-subsystem band
# implied by the 1M-2.3M extrapolation for a five-subsystem run.
#
# It deliberately replaces the old ``DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE`` of
# 50,000, which measurement ruled out: the cheapest completed subsystem ever
# observed cost 108,640 tokens, so the old constant was roughly 9x low and the
# budget check built on it never fired in time to matter.
#
# TODO(#198): replace with the figure from an uncapped five-subsystem run and
# cite that run here. The run this constant is meant to come from could not be
# made in the environment this was implemented in (no provider access), so
# what is here is the best-supported number the recorded measurements allow,
# not the measurement the issue asks for.
DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE = 280_000

# Where a ``PlanEstimate``'s per-subsystem figure came from. The prompt shows
# this, so a default is never mistaken for a measurement of this target and a
# stale measurement is never mistaken for a current one.
EstimateSource = Literal["history-same-commit", "history-other-commit", "default"]


@dataclass(frozen=True)
class PlanEstimate:
    """A plan's projected token cost, and the evidence behind it."""

    subsystem_count: int
    per_subsystem_tokens: int
    source: EstimateSource
    # How many recorded subsystems fed the mean. Zero for a default estimate.
    sample_size: int = 0
    # Provenance of the matched run, for display. Both ``None`` for a default.
    matched_git_sha: str | None = None
    matched_finished_at: datetime | None = None

    @property
    def total_tokens(self) -> int:
        return self.subsystem_count * self.per_subsystem_tokens

    @property
    def from_history(self) -> bool:
        return self.source != "default"


def subsystem_costs(manifest: RunManifest) -> list[int]:
    """Recorded per-subsystem token totals from ``manifest`` that can be used.

    Only subsystems whose usage is ``available`` count — a provider that never
    reports usage (some local Ollama models via LM Studio) records "unknown",
    which must not be averaged in as though it were cheap. A recorded zero is
    dropped for the same reason: a subsystem that was never started costs
    nothing and would drag the mean down without being a measurement of
    anything.

    A run that completed 1 of 5 subsystems still yields a usable figure from
    the one it finished.
    """
    return [
        usage.total_tokens
        for usage in manifest.run_summary.token_usage_by_subsystem.values()
        if usage.available and (usage.total_tokens or 0) > 0
    ]


def matches_target(
    manifest: RunManifest, *, target_id: str, target_path: str
) -> bool:
    """Whether ``manifest`` records a run against the same target.

    ``target_id`` is authoritative when the manifest carries one. Manifests
    written before it existed fall back to the redacted ``target_path``, which
    is usable only when it names something: ``"./"`` is what every target
    analysed from its own root records, so it identifies no repository in
    particular and never matches here.
    """
    if manifest.mode != "analyze":
        return False
    if manifest.target_id is not None:
        return manifest.target_id == target_id
    if manifest.target_path == AMBIGUOUS_TARGET_PATH:
        return False
    return manifest.target_path == target_path


def estimate_from_manifests(
    *,
    subsystem_count: int,
    manifests: list[RunManifest],
    target_id: str,
    target_path: str,
    target_git_sha: str | None,
) -> PlanEstimate:
    """Project the cost of a ``subsystem_count``-subsystem plan from history.

    Prefers the most recent run against this target at this commit; failing
    that, the most recent run against this target at any commit; failing that,
    :data:`DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE`. A run only counts as history if
    it recorded usage for at least one subsystem.
    """
    candidates = [
        m
        for m in manifests
        if matches_target(m, target_id=target_id, target_path=target_path)
        and subsystem_costs(m)
    ]
    candidates.sort(key=lambda m: m.finished_at, reverse=True)

    matched: RunManifest | None = None
    source: EstimateSource = "default"
    if target_git_sha is not None:
        same_commit = [m for m in candidates if m.target_git_sha == target_git_sha]
        if same_commit:
            matched, source = same_commit[0], "history-same-commit"
    if matched is None and candidates:
        matched, source = candidates[0], "history-other-commit"

    if matched is None:
        return PlanEstimate(
            subsystem_count=subsystem_count,
            per_subsystem_tokens=DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE,
            source="default",
        )

    costs = subsystem_costs(matched)
    return PlanEstimate(
        subsystem_count=subsystem_count,
        per_subsystem_tokens=round(sum(costs) / len(costs)),
        source=source,
        sample_size=len(costs),
        matched_git_sha=matched.target_git_sha,
        matched_finished_at=matched.finished_at,
    )


def estimate_plan_cost(*, subsystem_count: int, target: Path) -> PlanEstimate:
    """Estimate a plan's cost from the manifests saved alongside past reports.

    Reads ``~/.stride-gpt/reports/analyze/*.run.json``. Unreadable history is
    simply absent history — the estimate falls back to the default rather than
    failing, because nothing here is worth stopping a run over.
    """
    from stride_gpt.config import analyze_reports_dir

    return estimate_from_manifests(
        subsystem_count=subsystem_count,
        manifests=load_run_manifests(analyze_reports_dir()),
        target_id=target_identity(target),
        target_path=redact_path(target),
        target_git_sha=discover_git_sha(target),
    )


def format_tokens(count: int) -> str:
    """Render a token count at the precision the estimate actually supports."""
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 1_000:
        return f"{count / 1_000:.0f}k"
    return str(count)


def format_plan_estimate(estimate: PlanEstimate) -> str:
    """Render an estimate for the approval prompt, basis included.

    The basis line is not decoration: the spread between recorded runs is
    several-fold, so a number shown without saying where it came from would be
    read as a forecast of this run.
    """
    subsystems = "subsystem" if estimate.subsystem_count == 1 else "subsystems"
    headline = (
        f"Estimated cost: ~{format_tokens(estimate.total_tokens)} tokens "
        f"({estimate.subsystem_count} {subsystems} x ~{estimate.per_subsystem_tokens:,} each)"
    )

    if estimate.source == "default":
        basis = (
            f"Basis: the built-in default of {DEFAULT_SUBSYSTEM_TOKEN_ESTIMATE:,} tokens "
            "per subsystem — no recorded run of this target reported token usage. "
            "This is a default, not a measurement of this target."
        )
    else:
        measured = "subsystem" if estimate.sample_size == 1 else "subsystems"
        when = (
            estimate.matched_finished_at.strftime("%Y-%m-%d")
            if estimate.matched_finished_at is not None
            else "an earlier"
        )
        commit = (
            f"this commit ({estimate.matched_git_sha[:7]})"
            if estimate.source == "history-same-commit" and estimate.matched_git_sha
            else (
                f"a different commit ({estimate.matched_git_sha[:7]})"
                if estimate.matched_git_sha
                else "an unrecorded commit"
            )
        )
        basis = (
            f"Basis: recorded history — the {when} run of this target at {commit}, "
            f"averaged over its {estimate.sample_size} measured {measured}."
        )

    return (
        f"{headline}\n{basis}\n"
        "Order of magnitude, not a forecast — per-subsystem cost has varied "
        "several-fold between runs on identical inputs."
    )
