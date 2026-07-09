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
  and which reference cards the agent actually loaded (analyze and quick)

The format flag (`-f`) controls only the report artefact; siblings are
always JSON.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from stride_gpt.core.schemas import (
    AnalysisPlan,
    LLMConfig,
    ModelPair,
    Subsystem,
    SubsystemFinding,
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
        update={"files_analyzed": [redact_path(f) for f in finding.files_analyzed]}
    )


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
) -> RunManifest:
    """Assemble the manifest for a /analyze run."""
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
) -> RunManifest:
    """Assemble the manifest for a /quick run.

    ``target_label`` is the input filename (when ``-i`` is used) or the
    literal ``"stdin"`` — /quick has no codebase target, so the redaction
    rule doesn't apply to a filesystem path here.
    """
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
        mode="quick",
    )
