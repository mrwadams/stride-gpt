"""Persist structured intermediates alongside an exported report.

When the user passes ``-o <path>`` to /analyze or /quick, the report is the
human-readable conclusion — but the intermediate state (planner output,
per-subsystem findings, model/config metadata) is what an auditor or
downstream consumer needs. This module captures those intermediates as JSON
siblings next to the report:

* ``<stem>.plan.json`` — the ``AnalysisPlan`` (analyze only)
* ``<stem>.findings.json`` — the ``SubsystemFinding`` list + cross-cutting
  threats + data flow diagram (analyze only)
* ``<stem>.run.json`` — a ``RunManifest`` describing models, config, version,
  which reference cards the agent actually loaded, and a ``run_summary``
  recording whether every subsystem was analysed or some crashed, produced no
  readable answer, or never started (analyze and quick)

The format flag (`-f`) controls only the report artefact; siblings are
always JSON.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from stride_gpt.agent.evidence import normalise_path
from stride_gpt.core.schemas import (
    AnalysisPlan,
    LLMConfig,
    ModelPair,
    Subsystem,
    SubsystemFinding,
    TokenUsage,
    count_analysed,
    count_outcomes,
)


class ModelDescriptor(BaseModel):
    """Just the bits of an LLMConfig that identify which model was used.

    API keys and endpoints are deliberately excluded — a manifest will often
    end up checked into git or attached to tickets, so it must not leak
    credentials or per-deployment infrastructure detail.
    """

    provider: str
    model_name: str

    @classmethod
    def from_llm_config(cls, config: LLMConfig) -> ModelDescriptor:
        return cls(provider=config.provider, model_name=config.model_name)


class RunSummary(BaseModel):
    """Completeness of a run, so the intermediates are self-describing.

    Without this, an auditor reading ``findings.json`` in isolation can't
    tell a full analysis from one that lost subsystems along the way — a
    truncated run and a complete one look identical. ``status`` is:

    * ``"completed"`` — every planned subsystem was analysed (analyze), or the
      single-shot model returned (quick).
    * ``"partial"`` — at least one subsystem crashed, produced no readable
      answer, or was never started because the run budget ran out.

    A subsystem that took the #195 grace round still analysed the code, so it
    counts towards ``subsystems_analyzed`` and doesn't make a run partial;
    ``subsystem_outcomes`` is where that shows up.

    ``subsystems_planned`` / ``subsystems_analyzed`` are ``None`` for /quick,
    which has no per-subsystem phase.
    """

    status: Literal["completed", "partial"]
    subsystems_planned: int | None = None
    subsystems_analyzed: int | None = None
    # Subsystem count per ``SubsystemOutcome``, omitting outcomes that didn't
    # occur. Empty for /quick.
    subsystem_outcomes: dict[str, int] = {}
    llm_calls: int
    tool_calls: int
    # Names of subsystems reused from a checkpoint (``--resume``) versus
    # analysed fresh this run. A run that didn't resume leaves
    # ``resumed_subsystems`` empty and lists every subsystem it started in
    # ``rerun_subsystems``; both are empty for /quick, which has no
    # per-subsystem phase.
    resumed_subsystems: list[str] = []
    rerun_subsystems: list[str] = []
    # Token totals for the run. ``token_usage_total.available`` is ``False``
    # when no response anywhere in the run reported usage — distinct from a
    # genuine zero. Empty for /quick, which has no phase or subsystem
    # breakdown.
    #
    # The total is what *this* run spent. A ``--resume`` run reuses a
    # checkpointed subsystem without an LLM call, so that subsystem's entry
    # in ``token_usage_by_subsystem`` keeps the cost from the run that
    # produced it while contributing nothing to the total: on a resumed run
    # the per-subsystem figures deliberately don't sum to the total.
    token_usage_total: TokenUsage = TokenUsage()
    token_usage_by_phase: dict[str, TokenUsage] = {}
    token_usage_by_subsystem: dict[str, TokenUsage] = {}


class RunManifest(BaseModel):
    """Provenance for a single STRIDE-GPT run.

    Captures the inputs that determine outputs (models, prompt, references)
    plus enough environment metadata for an auditor to reason about the run
    later. Designed to be safe to share — no API keys, no absolute paths
    that leak filesystem layout.
    """

    stride_gpt_version: str
    python_version: str
    started_at: datetime
    finished_at: datetime
    architect: ModelDescriptor
    worker: ModelDescriptor
    detected_app_type: Literal["web", "genai", "agentic"]
    # Where ``detected_app_type`` came from:
    # ``"planner"`` — the architect classified the codebase
    # ``"override:<value>"`` — user passed ``--app-type``
    # ``"hint:<value>"`` — /quick was given an explicit hint
    # ``"default"`` — /quick fell back to the default classification
    app_type_source: str
    # Redacted per ``redact_path``. For /quick this is the input filename
    # or the literal ``"stdin"``.
    target_path: str
    target_git_sha: str | None
    # sha256 hex over the prompt + model identities + reference catalogue.
    # Lets two runs be compared at-a-glance: same hash ⇒ same inputs.
    config_hash: str
    # Names of reference cards the agent actually loaded during the run.
    references_loaded: list[str]
    # Outcome / coverage of the run — distinguishes a complete analysis from
    # one a call cap truncated.
    run_summary: RunSummary
    mode: Literal["analyze", "quick"]


# ---------------------------------------------------------------------------
# Path redaction
# ---------------------------------------------------------------------------


def redact_path(p: Path | str) -> str:
    """Return a serialisation-safe form of ``p``.

    Manifests end up in git and tickets, so absolute paths that leak
    ``/Users/<name>/...`` or ``/home/<name>/...`` are not acceptable. The
    rule, applied in order:

    1. If ``p`` resolves under the current working directory, return a
       ``"./..."``-prefixed relative path.
    2. Else if ``p`` resolves under ``$HOME``, return ``"~/..."``.
    3. Else return the absolute path verbatim — rare; the user explicitly
       pointed outside both anchors.
    """
    path = Path(p) if not isinstance(p, Path) else p
    try:
        resolved = path.resolve()
    except OSError:
        # An unresolvable path (e.g. ``"stdin"``) is returned untouched —
        # /quick uses this with non-filesystem identifiers.
        return str(p)

    cwd = Path.cwd().resolve()
    try:
        rel = resolved.relative_to(cwd)
        return "./" + str(rel) if str(rel) != "." else "./"
    except ValueError:
        pass

    home_str = os.environ.get("HOME") or str(Path.home())
    try:
        home = Path(home_str).resolve()
    except OSError:
        home = None
    if home is not None:
        try:
            rel = resolved.relative_to(home)
            return "~/" + str(rel) if str(rel) != "." else "~/"
        except ValueError:
            pass

    return str(resolved)


# ---------------------------------------------------------------------------
# Config hash
# ---------------------------------------------------------------------------


def _model_fingerprint(config: LLMConfig) -> dict[str, Any]:
    """Subset of an LLMConfig that influences model output.

    Excludes ``api_key``, ``api_base``, and ``timeout`` — those are
    deployment noise, not model behaviour. Two runs with different keys
    against the same model are functionally identical and should share a
    ``config_hash``.
    """
    return {
        "provider": config.provider,
        "model_name": config.model_name,
        "use_thinking": config.use_thinking,
        "max_tokens": config.max_tokens,
        "response_format": config.response_format,
    }


def compute_config_hash(
    *, system_prompt: str, models: ModelPair, references: list[str]
) -> str:
    """sha256 over a stable canonical view of the run's input contract."""
    payload = {
        "system_prompt": system_prompt,
        "worker": _model_fingerprint(models.worker),
        "architect": (
            _model_fingerprint(models.architect)
            if models.architect is not None
            else None
        ),
        "references": sorted(references),
    }
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Git SHA discovery
# ---------------------------------------------------------------------------


def discover_git_sha(target: Path) -> str | None:
    """Best-effort ``git rev-parse HEAD`` for ``target``.

    Returns ``None`` when ``target`` isn't a git checkout, git isn't on
    PATH, or the command fails for any other reason — provenance is a nice
    to have, not load-bearing.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    sha = result.stdout.strip()
    return sha or None


# ---------------------------------------------------------------------------
# Sibling writers
# ---------------------------------------------------------------------------


def _sibling_stem(output: Path) -> Path:
    """Strip the last suffix from ``output`` to get the sibling-file stem."""
    return output.with_suffix("") if output.suffix else output


def _redact_subsystem(sub: Subsystem) -> Subsystem:
    return sub.model_copy(update={"key_files": [redact_path(f) for f in sub.key_files]})


def _redact_finding(finding: SubsystemFinding) -> SubsystemFinding:
    return finding.model_copy(
        update={
            "files_analyzed": [redact_path(f) for f in finding.files_analyzed],
            "threats": [_redact_threat(t) for t in finding.threats],
        }
    )


def _redact_threat(threat: dict) -> dict:
    """Redact the paths inside a threat's evidence.

    Deep-copied rather than edited in place: ``model_copy`` is shallow, and
    ``write_intermediates`` promises the in-memory report is left alone so the
    auto-saved archive still gets verbatim values.
    """
    evidence = threat.get("evidence")
    if not isinstance(evidence, list):
        return threat
    redacted = copy.deepcopy(threat)
    for item in redacted["evidence"]:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            item["path"] = redact_path(item["path"])
    return redacted


def _write_json(path: Path, payload: str) -> None:
    """Write ``payload`` to ``path`` with the project's trailing-newline convention."""
    if not payload.endswith("\n"):
        payload = payload + "\n"
    path.write_text(payload)


def write_intermediates(
    output: Path,
    *,
    manifest: RunManifest,
    plan: AnalysisPlan | None = None,
    findings: list[SubsystemFinding] | None = None,
    cross_cutting: list[dict[str, Any]] | None = None,
    data_flow_diagram: str | None = None,
) -> list[Path]:
    """Persist JSON sibling artefacts next to ``output``.

    The manifest is always written. The plan and findings siblings are
    only written when their inputs are supplied (i.e. analyze runs);
    /quick passes them as ``None`` and gets a manifest-only emission.

    Path-bearing fields inside the findings file are passed through
    :func:`redact_path` so a downstream consumer never has to re-redact.
    The in-memory objects are not mutated — the auto-saved archive still
    receives verbatim values.

    Returns the list of paths written.
    """
    written: list[Path] = []
    stem = _sibling_stem(output)

    if plan is not None:
        redacted_plan = plan.model_copy(
            update={
                "target_path": redact_path(plan.target_path),
                "subsystems": [_redact_subsystem(s) for s in plan.subsystems],
            }
        )
        plan_path = stem.with_suffix(".plan.json")
        _write_json(plan_path, redacted_plan.model_dump_json(indent=2))
        written.append(plan_path)

    if findings is not None:
        redacted_findings = [_redact_finding(f) for f in findings]
        findings_payload = {
            "findings": [f.model_dump() for f in redacted_findings],
            "cross_cutting_threats": list(cross_cutting or []),
            "data_flow_diagram": data_flow_diagram,
        }
        findings_path = stem.with_suffix(".findings.json")
        _write_json(findings_path, json.dumps(findings_payload, indent=2))
        written.append(findings_path)

    run_path = stem.with_suffix(".run.json")
    _write_json(run_path, manifest.model_dump_json(indent=2))
    written.append(run_path)

    return written


def checkpoint_path_for(output: Path) -> Path:
    """Where a run's checkpoint lives, given its ``-o`` output path.

    Mirrors ``write_intermediates``'s sibling-file convention — the
    checkpoint sits alongside the ``.plan.json`` / ``.findings.json`` /
    ``.run.json`` siblings.
    """
    return _sibling_stem(output).with_suffix(".checkpoint.json")


# ---------------------------------------------------------------------------
# Manifest assembly helpers
# ---------------------------------------------------------------------------


def _stride_gpt_version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("stride-gpt")
    except PackageNotFoundError:
        return "unknown"


def _python_version() -> str:
    import platform

    return platform.python_version()


def build_analyze_manifest(
    *,
    models: ModelPair,
    plan: AnalysisPlan,
    target: Path,
    started_at: datetime,
    finished_at: datetime,
    app_type_source: str,
    system_prompt: str,
    references_loaded: list[str],
    llm_calls: int,
    tool_calls: int,
    findings: list[SubsystemFinding],
    resumed_subsystems: list[str] | None = None,
    rerun_subsystems: list[str] | None = None,
    token_usage_by_phase: dict[str, dict[str, int | None]] | None = None,
) -> RunManifest:
    """Assemble the manifest for a /analyze run.

    Completeness is derived from the findings' outcomes rather than from how
    many findings there are — every planned subsystem gets one now, including
    the ones that crashed or were never started.

    ``token_usage_by_phase`` is the JSON-safe dict from
    ``report.metadata["token_usage"]["by_phase"]`` — plain
    ``{"prompt_tokens": ..., "completion_tokens": ...}`` dicts, reconstructed
    into ``TokenUsage`` here. Per-subsystem totals come straight off
    ``findings`` rather than a separate parameter — each finding already
    carries its own.
    """
    subsystems_planned = len(plan.subsystems)
    subsystems_analyzed = count_analysed(findings)
    by_phase = {
        name: TokenUsage(**usage) for name, usage in (token_usage_by_phase or {}).items()
    }
    token_usage_total = TokenUsage()
    for usage in by_phase.values():
        token_usage_total.merge(usage)
    run_summary = RunSummary(
        status="partial" if subsystems_analyzed < subsystems_planned else "completed",
        subsystems_planned=subsystems_planned,
        subsystems_analyzed=subsystems_analyzed,
        subsystem_outcomes=count_outcomes(findings),
        llm_calls=llm_calls,
        tool_calls=tool_calls,
        resumed_subsystems=resumed_subsystems or [],
        rerun_subsystems=rerun_subsystems or [],
        token_usage_total=token_usage_total,
        token_usage_by_phase=by_phase,
        token_usage_by_subsystem={f.subsystem: f.token_usage for f in findings},
    )
    return RunManifest(
        stride_gpt_version=_stride_gpt_version(),
        python_version=_python_version(),
        started_at=started_at,
        finished_at=finished_at,
        architect=ModelDescriptor.from_llm_config(models.for_architect()),
        worker=ModelDescriptor.from_llm_config(models.worker),
        detected_app_type=plan.detected_app_type,
        app_type_source=app_type_source,
        target_path=redact_path(target),
        target_git_sha=discover_git_sha(target),
        config_hash=compute_config_hash(
            system_prompt=system_prompt,
            models=models,
            references=references_loaded,
        ),
        references_loaded=sorted(references_loaded),
        run_summary=run_summary,
        mode="analyze",
    )


def build_quick_manifest(
    *,
    models: ModelPair,
    target_label: str,
    detected_app_type: Literal["web", "genai", "agentic"],
    app_type_source: str,
    started_at: datetime,
    finished_at: datetime,
    system_prompt: str,
    references_loaded: list[str],
    llm_calls: int,
    tool_calls: int,
) -> RunManifest:
    """Assemble the manifest for a /quick run.

    ``target_label`` is the input filename (when ``-i`` is used) or the
    literal ``"stdin"`` — /quick has no codebase target, so the redaction
    rule doesn't apply to a filesystem path here.

    /quick is single-shot with no per-subsystem phase, so ``run_summary``
    always reports ``"completed"`` with ``None`` subsystem counts.
    """
    run_summary = RunSummary(
        status="completed",
        subsystems_planned=None,
        subsystems_analyzed=None,
        subsystem_outcomes={},
        llm_calls=llm_calls,
        tool_calls=tool_calls,
    )
    return RunManifest(
        stride_gpt_version=_stride_gpt_version(),
        python_version=_python_version(),
        started_at=started_at,
        finished_at=finished_at,
        architect=ModelDescriptor.from_llm_config(models.for_architect()),
        worker=ModelDescriptor.from_llm_config(models.worker),
        detected_app_type=detected_app_type,
        app_type_source=app_type_source,
        target_path=target_label,
        target_git_sha=None,
        config_hash=compute_config_hash(
            system_prompt=system_prompt,
            models=models,
            references=references_loaded,
        ),
        references_loaded=sorted(references_loaded),
        run_summary=run_summary,
        mode="quick",
    )


# ---------------------------------------------------------------------------
# Checkpoints — resuming an interrupted /analyze run (#197)
# ---------------------------------------------------------------------------


class Checkpoint(BaseModel):
    """In-progress /analyze state, written after each subsystem finishes.

    Lets ``--resume`` pick up a killed run (provider outage, Ctrl+C, crash)
    without re-paying for subsystems that already finished. Only the plan
    and per-subsystem findings are checkpointed — synthesis and the system
    DFD always rerun on resume, since they reason over the *full* set of
    findings and are cheap relative to a subsystem pass.
    """

    stride_gpt_version: str
    started_at: datetime
    updated_at: datetime
    # Redacted per ``redact_path``, like the run manifest's ``target_path``.
    target_path: str
    target_git_sha: str | None
    # Identifies the model/prompt pair this checkpoint was produced under.
    # See ``compute_checkpoint_config_hash`` for why this isn't the same
    # hash the run manifest records.
    config_hash: str
    app_type_source: str
    plan: AnalysisPlan
    findings: list[SubsystemFinding]


def compute_checkpoint_config_hash(models: ModelPair) -> str:
    """sha256 identifying the model/prompt pair a checkpoint was produced under.

    Deliberately narrower than the run manifest's ``config_hash``, which
    folds in every reference card loaded by the *end* of a run — discovered
    progressively as subsystems execute. Using that here would make a
    checkpoint's own hash drift as the run that wrote it progressed, so a
    checkpoint could never validate against a resumption of itself.
    ``references`` is always passed as ``[]``: this hash exists to catch
    "the model or prompt changed", not "a different reference card happened
    to load by this point".
    """
    from stride_gpt.core.prompts import base_system_prompt

    return compute_config_hash(
        system_prompt=base_system_prompt(), models=models, references=[]
    )


def build_checkpoint(
    *,
    plan: AnalysisPlan,
    findings: list[SubsystemFinding],
    target: Path,
    models: ModelPair,
    app_type_source: str,
    started_at: datetime,
) -> Checkpoint:
    """Assemble a redacted checkpoint snapshot of the run so far.

    Redaction mirrors ``write_intermediates`` — a checkpoint never contains
    anything the final intermediates wouldn't.
    """
    redacted_plan = plan.model_copy(
        update={
            "target_path": redact_path(plan.target_path),
            "subsystems": [_redact_subsystem(s) for s in plan.subsystems],
        }
    )
    return Checkpoint(
        stride_gpt_version=_stride_gpt_version(),
        started_at=started_at,
        updated_at=datetime.now(UTC),
        target_path=redact_path(target),
        target_git_sha=discover_git_sha(target),
        config_hash=compute_checkpoint_config_hash(models),
        app_type_source=app_type_source,
        plan=redacted_plan,
        findings=[_redact_finding(f) for f in findings],
    )


def write_checkpoint(path: Path, checkpoint: Checkpoint) -> None:
    """Atomically write ``checkpoint`` to ``path`` (temp file + rename).

    A crash mid-write must never leave a half-written, unparseable
    checkpoint behind — that defeats the whole point of checkpointing.
    Writing to a temp file alongside ``path`` and renaming it into place
    means the rename is the only step that has to be atomic; a reader never
    observes a partial file.
    """
    payload = checkpoint.model_dump_json(indent=2)
    if not payload.endswith("\n"):
        payload += "\n"
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(payload)
    tmp_path.replace(path)


class CheckpointValidationError(Exception):
    """A checkpoint is not safe to resume from. The message states why."""


def load_checkpoint(path: Path) -> Checkpoint:
    """Load and parse a checkpoint file.

    Raises :class:`CheckpointValidationError` when the file is not a
    checkpoint this version can read. A run is killed mid-write often enough
    that a truncated or older-schema file is an ordinary thing to meet on
    resume, and it has to come back as "cannot resume, here is why" — an
    unhandled ``JSONDecodeError`` takes the interactive session down with it.
    """
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise CheckpointValidationError(f"{path} could not be read as JSON: {e}") from e
    try:
        return Checkpoint(**data)
    except (TypeError, ValidationError) as e:
        raise CheckpointValidationError(
            f"{path} is not a checkpoint this version can read: {e}"
        ) from e


def restore_checkpoint_paths(checkpoint: Checkpoint, *, target: Path) -> Checkpoint:
    """Undo :func:`build_checkpoint`'s redaction, giving back live paths.

    A checkpoint holds the plan and findings redacted (``./...``, ``~/...``),
    which is right for a file on disk and wrong for the state a resumed run
    reports from: the report renders paths in ``normalise_path``'s form and
    titles itself from ``plan.target_path``. Handing the redacted copies
    straight back made a resumed report differ from an uninterrupted one —
    ``./src/a.py`` for reused subsystems beside ``src/a.py`` for re-run ones,
    and ``# STRIDE Threat Model:`` with no project name for ``analyze .``.

    ``redact_path`` only ever prefixes a project-relative path, so
    ``normalise_path`` inverts it exactly for the path lists; the plan's
    target is restored outright from the invocation, which knows it.
    """
    plan = checkpoint.plan.model_copy(
        update={
            "target_path": str(target),
            "subsystems": [
                s.model_copy(update={"key_files": [normalise_path(f) for f in s.key_files]})
                for s in checkpoint.plan.subsystems
            ],
        }
    )
    return checkpoint.model_copy(
        update={
            "plan": plan,
            "findings": [_restore_finding_paths(f) for f in checkpoint.findings],
        }
    )


def _restore_finding_paths(finding: SubsystemFinding) -> SubsystemFinding:
    """The inverse of ``_redact_finding`` for a finding's path fields."""
    return finding.model_copy(
        update={
            "files_analyzed": [normalise_path(f) for f in finding.files_analyzed],
            "threats": [_restore_threat_paths(t) for t in finding.threats],
        }
    )


def _restore_threat_paths(threat: dict) -> dict:
    evidence = threat.get("evidence")
    if not isinstance(evidence, list):
        return threat
    restored = copy.deepcopy(threat)
    for item in restored["evidence"]:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            item["path"] = normalise_path(item["path"])
    return restored


def is_git_dirty(target: Path, *, ignore: Path | None = None) -> bool:
    """Whether ``target``'s git working tree has uncommitted changes.

    Best-effort like :func:`discover_git_sha`, but errs the other way: a
    failure to run ``git status`` is treated as "dirty" so resume refuses by
    default rather than silently trusting code that might have moved on.

    ``ignore`` names one path that doesn't count as a change — the run's own
    checkpoint. ``analyze . -o report.md`` writes the checkpoint inside the
    repository being analysed, so without this the feature blocks itself: the
    file that makes resume possible is the untracked file that makes resume
    refuse, and the only way through is ``--force``, which also switches off
    the "the code moved on" protection this check exists to give.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(target), "status", "--porcelain"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return True
    if result.returncode != 0:
        return True
    changed = _porcelain_paths(result.stdout, target)
    if ignore is not None:
        try:
            ignored = ignore.resolve()
        except OSError:
            ignored = None
        if ignored is not None:
            changed = [p for p in changed if p != ignored]
    return bool(changed)


def _porcelain_paths(stdout: str, target: Path) -> list[Path]:
    """Resolve the paths in ``git status --porcelain`` output.

    Porcelain v1 prints paths relative to the repository root, not to
    ``target``, so the root is what they have to be joined to. A rename is
    printed as ``old -> new``; the new name is the one on disk.
    """
    root = _git_toplevel(target) or target
    paths: list[Path] = []
    for line in stdout.splitlines():
        if len(line) < 4:
            continue
        name = line[3:]
        if " -> " in name:
            name = name.split(" -> ", 1)[1]
        name = name.strip().strip('"')
        if not name:
            continue
        try:
            paths.append((root / name).resolve())
        except OSError:
            continue
    return paths


def _git_toplevel(target: Path) -> Path | None:
    """``git rev-parse --show-toplevel`` for ``target``, or None."""
    try:
        result = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    top = result.stdout.strip()
    return Path(top) if top else None


def validate_checkpoint_for_resume(
    checkpoint: Checkpoint,
    *,
    target: Path,
    models: ModelPair,
    force: bool,
    checkpoint_path: Path | None = None,
) -> None:
    """Raise :class:`CheckpointValidationError` if resuming would be unsound.

    A changed git SHA or config hash always refuses — those mean the
    checkpointed findings describe code or a model that no longer matches
    this invocation, and ``--force`` can't make stale findings sound. A
    dirty working tree, or a target with no discoverable git SHA at all, is
    weaker evidence (the code *might* still match what was analysed) so
    ``--force`` can override either of those.
    """
    current_sha = discover_git_sha(target)
    if checkpoint.target_git_sha != current_sha:
        raise CheckpointValidationError(
            "target_git_sha changed: checkpoint was "
            f"{checkpoint.target_git_sha!r}, current is {current_sha!r}."
        )

    current_hash = compute_checkpoint_config_hash(models)
    if checkpoint.config_hash != current_hash:
        raise CheckpointValidationError(
            "config_hash changed — the model or system prompt differs from "
            "the checkpointed run."
        )

    if force:
        return
    if current_sha is None:
        raise CheckpointValidationError(
            "target has no discoverable git SHA; pass --force to resume anyway."
        )
    if is_git_dirty(target, ignore=checkpoint_path):
        raise CheckpointValidationError(
            "target has uncommitted changes; pass --force to resume anyway."
        )
