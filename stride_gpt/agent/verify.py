"""Phase 3.5 — adversarial verification of generated threats.

After synthesis, each generated threat (per-subsystem and cross-cutting) is
handed to a fresh, refutation-biased verifier session that must confirm it
against the real source code using the same read-only tools the worker uses.
Survivors above the confidence gate stay inline in the report; the rest are
recorded in ``report.refuted_threats`` with a ``drop_reason`` — never silently
dropped.

Design (contrast with a deterministic-verdict approach): the LLM verifier is the
authority. It opens files and decides. Cheap deterministic signals are passed
into its prompt as advisory hints only; they never override its verdict. The
gate is asymmetric — an unparseable or errored verifier reply is refuted, never
promoted to a confirmation. A guardrail aborts the phase rather than emit an
empty survivor list that would read as "nothing was plausible".
"""

from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from stride_gpt.agent.progress import ProgressCallback
from stride_gpt.agent.tools import (
    AGENT_TOOLS,
    _resolve_safe_path,
    execute_tool,
    grep_content,
)
from stride_gpt.core.json_extract import extract_json_object
from stride_gpt.core.llm import call_llm, call_llm_with_tools
from stride_gpt.core.prompts import verify_system_prompt
from stride_gpt.core.schemas import (
    AnalysisReport,
    LLMConfig,
    ModelPair,
    VerifierResult,
    VerifyConfig,
)

# Max tool-calling rounds per verifier session — bounds cost per threat.
_MAX_VERIFY_ROUNDS = 8

# Neutralize a forged </finding-text> (or opening tag) embedded in untrusted
# threat text so it cannot break out of the prompt fence.
_FENCE_BREAK = re.compile(r"<\s*/?\s*finding-text", re.IGNORECASE)

# Redact userinfo (user:pass@) from any URL in an error string before it lands
# in a shareable report artifact.
_URL_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^/\s:@]+(?::[^/\s@]+)?@")

# Backticked bare identifiers and path-like tokens, for advisory signals.
_BACKTICK = re.compile(r"`([A-Za-z_][A-Za-z0-9_./-]*)`")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NON_PROD = re.compile(r"(^|/)(tests?|examples?|fixtures?)(/|$)|(^|/)test_|_test\.[^/]*$")


class VerifyAbortedError(Exception):
    """The verify phase tripped its guardrail and refused to emit survivors."""


def _defang(text: str) -> str:
    """Neutralize any <finding-text> fence tag embedded in untrusted text."""
    return _FENCE_BREAK.sub("[fenced-tag]", text or "")


def _redact_error(message: str) -> str:
    """Strip URL userinfo from an error string for safe inclusion in a report."""
    return _URL_USERINFO.sub(r"\1[redacted]@", message or "")


def _verifier_config(models: ModelPair, cfg: VerifyConfig) -> LLMConfig:
    """Pick the LLM tier the verifier runs on (worker by default)."""
    return models.for_architect() if cfg.verifier_model == "architect" else models.worker


def _coerce_confidence(value: Any) -> int:
    """Coerce a model-supplied confidence to an int in [0, 10]."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        n = round(value)
    elif isinstance(value, str):
        m = re.search(r"\d+", value)
        n = int(m.group()) if m else 0
    else:
        return 0
    return max(0, min(10, n))


def _advisory_signals(target_path: Path, threat: dict[str, Any]) -> str:
    """Cheap, advisory-only signals about the threat's named symbols/paths.

    Never authoritative: these are hints injected into the verifier prompt so it
    has a starting point, not a verdict. Best-effort; any failure yields no hint
    for that token rather than raising.
    """
    text = f"{threat.get('Scenario', '')}\n{threat.get('Potential Impact', '')}"
    tokens = set(_BACKTICK.findall(text))
    lines: list[str] = []
    for tok in sorted(tokens):
        if "/" in tok and "." in tok:  # path-ish
            try:
                exists = _resolve_safe_path(target_path, tok).is_file()
            except ValueError:
                exists = False
            note = "exists in repo" if exists else "not found at that path"
            if exists and _NON_PROD.search(tok):
                note = "exists (test/example path — may be non-production)"
            lines.append(f"- path `{tok}`: {note}")
        elif _IDENT.match(tok):
            try:
                hits = json.loads(grep_content(target_path, rf"\b{re.escape(tok)}\b"))
                found = isinstance(hits, list) and any(
                    isinstance(h, dict) and "file" in h for h in hits
                )
            except Exception:
                found = False
            lines.append(
                f"- symbol `{tok}`: {'referenced in repo' if found else 'no reference found (may be absent or dynamic)'}"
            )
    return "\n".join(lines) if lines else "- (no deterministic signals gathered)"


def verify_threat(
    models: ModelPair,
    target_path: Path,
    threat: dict[str, Any],
    subsystem: str,
    cfg: VerifyConfig,
) -> VerifierResult:
    """Run one refutation-biased verifier session against a single threat.

    Returns a VerifierResult. An unreadable reply yields verdict UNPARSEABLE
    (confidence 0) — it is not coerced to a confirmation or a refutation.
    """
    config = _verifier_config(models, cfg)
    model_id = f"{config.provider}/{config.model_name}"
    started = time.monotonic()

    system = verify_system_prompt().format(
        stride=_defang(str(threat.get("Threat Type", "Unknown"))),
        subsystem=_defang(subsystem),
        scenario=_defang(str(threat.get("Scenario", ""))),
        impact=_defang(str(threat.get("Potential Impact", ""))),
        signals=_advisory_signals(target_path, threat),
    )
    messages: list[dict] = [
        {"role": "system", "content": system},
        {
            "role": "user",
            "content": (
                "Investigate the threat above against the real code using the tools, "
                "then return ONLY the JSON verdict object."
            ),
        },
    ]

    content = ""
    for _ in range(_MAX_VERIFY_ROUNDS):
        response = call_llm_with_tools(config, messages, AGENT_TOOLS)
        if not response.tool_calls:
            content = response.content or ""
            break
        messages.append(
            {
                "role": "assistant",
                "content": response.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function_name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in response.tool_calls
                ],
            }
        )
        for tc in response.tool_calls:
            result = execute_tool(target_path, tc)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc.function_name,
                    "content": result,
                }
            )
    else:
        # Rounds exhausted without a final text answer — force a JSON verdict.
        messages.append(
            {
                "role": "user",
                "content": "Stop investigating and return ONLY the JSON verdict object now.",
            }
        )
        json_config = config.model_copy(update={"response_format": "json"})
        content = call_llm(json_config, messages).content or ""

    elapsed = time.monotonic() - started
    return _parse_verdict(content, model_id, elapsed)


def _parse_verdict(content: str, model_id: str, elapsed: float) -> VerifierResult:
    """Parse a verifier reply into a VerifierResult (UNPARSEABLE on failure)."""
    data = extract_json_object(content)
    if data is None:
        return VerifierResult(
            verdict="UNPARSEABLE",
            confidence=0,
            reason="verifier reply was not valid JSON",
            verifier_model=model_id,
            elapsed_seconds=elapsed,
        )
    raw_verdict = str(data.get("verdict", "")).strip().upper().replace(" ", "_")
    if raw_verdict not in ("PLAUSIBLE", "NOT_PLAUSIBLE"):
        return VerifierResult(
            verdict="UNPARSEABLE",
            confidence=0,
            reason=f"unrecognized verdict {data.get('verdict')!r}",
            reasoning=str(data.get("reasoning", "")),
            verifier_model=model_id,
            elapsed_seconds=elapsed,
        )
    evidence = data.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    return VerifierResult(
        verdict=raw_verdict,  # type: ignore[arg-type]
        confidence=_coerce_confidence(data.get("confidence", 0)),
        reason=str(data.get("reason", "")),
        evidence=[str(e) for e in evidence],
        reasoning=str(data.get("reasoning", "")),
        verifier_model=model_id,
        elapsed_seconds=elapsed,
    )


def _decide(result: VerifierResult, cfg: VerifyConfig) -> str | None:
    """Return the drop_reason for a refuted threat, or None if it survives."""
    if result.verdict == "PLAUSIBLE":
        if result.confidence >= cfg.min_confidence:
            return None
        return "LOW_CONFIDENCE"
    if result.verdict == "NOT_PLAUSIBLE":
        return "REFUTED"
    return "UNPARSEABLE"


def run_verification(
    models: ModelPair,
    target_path: Path,
    report: AnalysisReport,
    cfg: VerifyConfig,
    progress: ProgressCallback,
) -> tuple[AnalysisReport, dict[str, Any]]:
    """Verify every generated threat and partition survivors from refuted.

    Mutates ``report`` in place (survivors keep their slot with a ``verifier``
    key attached; refuted move to ``report.refuted_threats``) and returns
    ``(report, stats)``. Raises :class:`VerifyAborted` if the guardrail trips,
    leaving ``report`` untouched.
    """
    # (kind, subsystem_index, threat_index, threat, subsystem_name)
    tasks: list[tuple[str, int | None, int, dict[str, Any], str]] = []
    for si, finding in enumerate(report.findings):
        for ti, threat in enumerate(finding.threats):
            tasks.append(("sub", si, ti, threat, finding.subsystem))
    for ti, threat in enumerate(report.cross_cutting_threats):
        tasks.append(("cross", None, ti, threat, "cross-cutting"))

    if not tasks:
        return report, {
            "enabled": True,
            "min_confidence": cfg.min_confidence,
            "verifier_model": cfg.verifier_model,
            "surviving": 0,
            "refuted": 0,
            "errored": 0,
            "elapsed_seconds": 0.0,
        }

    progress.verify_start(len(tasks))
    started = time.monotonic()

    def _run(task: tuple[str, int | None, int, dict[str, Any], str]):
        _, _, _, threat, subsystem = task
        try:
            result = verify_threat(models, target_path, threat, subsystem, cfg)
            return result, None
        except Exception as e:  # recorded as VERIFY_ERROR, never fatal to the run
            return None, _redact_error(str(e))

    total = len(tasks)
    surviving = 0
    refuted_count = 0
    errored = 0
    successful = 0  # parseable verdicts (PLAUSIBLE or NOT_PLAUSIBLE)
    completed = 0
    # (result, drop_reason) per task index, resolved as futures land.
    processed: dict[int, tuple[VerifierResult, str | None]] = {}

    # Report each verdict the moment it lands (completion order) rather than
    # waiting on a barrier — otherwise the TUI stalls silently until the whole
    # pass finishes and then dumps every line at once.
    with ThreadPoolExecutor(max_workers=max(1, cfg.parallel)) as pool:
        future_to_idx = {pool.submit(_run, task): i for i, task in enumerate(tasks)}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            _, _, _, _threat, subsystem = tasks[idx]
            result, err = future.result()
            if err is not None:
                errored += 1
                result = VerifierResult(
                    verdict="UNPARSEABLE",
                    confidence=0,
                    reason=f"verification errored: {err}",
                    verifier_model=_verifier_config(models, cfg).model_name,
                )
                drop_reason = "VERIFY_ERROR"
            else:
                assert result is not None
                if result.verdict in ("PLAUSIBLE", "NOT_PLAUSIBLE"):
                    successful += 1
                drop_reason = _decide(result, cfg)

            processed[idx] = (result, drop_reason)
            completed += 1
            if drop_reason is None:
                surviving += 1
                progress.verify_threat_done(
                    completed, total, subsystem, "kept", result.confidence
                )
            else:
                refuted_count += 1
                progress.verify_threat_done(
                    completed, total, subsystem, drop_reason, result.confidence
                )

    # Guardrail: many failures and nothing successfully verified means the
    # verifier is broken (bad key, wrong endpoint). Refuse to emit an empty
    # survivor list that would masquerade as "nothing was plausible".
    threshold = max(3, cfg.parallel)
    if successful == 0 and refuted_count > threshold:
        progress.verify_aborted(
            f"{errored} errored / {refuted_count} unverifiable with 0 successful "
            f"verifications (threshold {threshold})"
        )
        raise VerifyAbortedError(
            f"verify guardrail: {successful} successful verifications, "
            f"{errored} errored, {refuted_count} refuted (threshold {threshold})"
        )

    # Partition in deterministic task order (futures completed out of order).
    survivor_keys: set[tuple[str, int | None, int]] = set()
    refuted_entries: list[dict[str, Any]] = []
    for idx, task in enumerate(tasks):
        kind, si, ti, threat, subsystem = task
        result, drop_reason = processed[idx]
        verifier_dump = result.model_dump()
        if drop_reason is None:
            survivor_keys.add((kind, si, ti))
            threat["verifier"] = verifier_dump
        else:
            refuted_entries.append(
                {
                    "subsystem": subsystem,
                    "threat": {**threat, "verifier": verifier_dump},
                    "verifier": verifier_dump,
                    "drop_reason": drop_reason,
                }
            )

    # Commit: rebuild threat lists to survivors only; attach refuted list.
    for si, finding in enumerate(report.findings):
        finding.threats = [
            t for ti, t in enumerate(finding.threats)
            if ("sub", si, ti) in survivor_keys
        ]
    report.cross_cutting_threats = [
        t for ti, t in enumerate(report.cross_cutting_threats)
        if ("cross", None, ti) in survivor_keys
    ]
    report.refuted_threats = refuted_entries

    elapsed = time.monotonic() - started
    stats = {
        "enabled": True,
        "min_confidence": cfg.min_confidence,
        "verifier_model": cfg.verifier_model,
        "surviving": surviving,
        "refuted": refuted_count,
        "errored": errored,
        "elapsed_seconds": round(elapsed, 2),
    }
    progress.verify_summary(surviving, refuted_count, errored)
    return report, stats
