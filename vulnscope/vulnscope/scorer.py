"""Core scoring logic.

Each finding is scored on four dimensions (0-10) against the threat model and
assigned a secondary classification. A composite score is the weighted average
of the four dimensions. Two scoring backends exist:

  * LLM-driven (default) — one prompt per finding, plus a synthesis prompt.
  * Heuristic (offline)  — deterministic, no network, still cites real threat
    model elements so the output remains useful (and the tool demonstrable)
    without an API key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from vulnscope.config import Weights
from vulnscope.json_extract import extract_json_object
from vulnscope.llm import LLMClient
from vulnscope.parsers.findings import Finding
from vulnscope.parsers.threat_model import ThreatModel, ThreatModelThreat
from vulnscope.prompts import (
    SCORING_SYSTEM_PROMPT,
    SYNTHESIS_SYSTEM_PROMPT,
    build_scoring_prompt,
    build_synthesis_prompt,
)

DIMENSIONS = (
    "asset_criticality",
    "threat_alignment",
    "trust_boundary_exposure",
    "stride_category_weight",
)

VALID_CLASSIFICATIONS = ("CORROBORATED", "NOVEL", "OUT_OF_SCOPE")


@dataclass
class ScoredFinding:
    """A finding with its dimension scores, composite, classification, reasoning."""

    finding: Finding
    scores: dict[str, float]
    composite_score: float
    classification: str
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding.id,
            "title": self.finding.title,
            "composite_score": self.composite_score,
            "classification": self.classification,
            "scores": self.scores,
            "reasoning": self.reasoning,
            "original_finding": self.finding.raw or self.finding.to_prompt_dict(),
        }


def composite_score(scores: dict[str, float], weights: Weights) -> float:
    """Weighted average of the four dimensions, on a 0-10 scale."""
    w = weights.normalised()
    total = (
        scores.get("asset_criticality", 0.0) * w.asset_criticality
        + scores.get("threat_alignment", 0.0) * w.threat_alignment
        + scores.get("trust_boundary_exposure", 0.0) * w.trust_boundary_exposure
        + scores.get("stride_category_weight", 0.0) * w.stride_category_weight
    )
    return round(total, 1)


def score_findings(
    findings: list[Finding],
    threat_model: ThreatModel,
    *,
    weights: Weights,
    client: LLMClient | None = None,
    on_progress: Callable[[int, int, Finding], None] | None = None,
) -> list[ScoredFinding]:
    """Score every finding and return them sorted by composite score, descending.

    When ``client`` is None, the deterministic offline heuristic is used.
    """
    scored: list[ScoredFinding] = []
    for i, finding in enumerate(findings, 1):
        if on_progress is not None:
            on_progress(i, len(findings), finding)
        if client is None:
            scored.append(score_finding_heuristic(finding, threat_model, weights))
        else:
            scored.append(score_finding_llm(finding, threat_model, weights, client))

    scored.sort(key=lambda s: s.composite_score, reverse=True)
    return scored


# ---------------------------------------------------------------------------
# LLM-driven scoring
# ---------------------------------------------------------------------------


def score_finding_llm(
    finding: Finding,
    threat_model: ThreatModel,
    weights: Weights,
    client: LLMClient,
) -> ScoredFinding:
    """Score one finding via the LLM, with a heuristic fallback on bad output."""
    prompt = build_scoring_prompt(
        threat_model_json=threat_model.to_prompt_json(),
        finding_json=json.dumps(finding.to_prompt_dict(), indent=2),
    )
    raw = client.complete(SCORING_SYSTEM_PROMPT, prompt)
    data = extract_json_object(raw)
    if data is None:
        # The model failed to produce parseable JSON — degrade gracefully to the
        # heuristic rather than dropping the finding from the report.
        return score_finding_heuristic(finding, threat_model, weights)

    scores = {dim: _clamp_score(data.get(dim)) for dim in DIMENSIONS}
    classification = _normalise_classification(
        data.get("classification"), finding, threat_model
    )
    reasoning = str(data.get("reasoning", "")).strip()
    if not reasoning:
        reasoning = _fallback_reasoning(finding, threat_model, classification)

    return ScoredFinding(
        finding=finding,
        scores=scores,
        composite_score=composite_score(scores, weights),
        classification=classification,
        reasoning=reasoning,
    )


def synthesize_summary(
    scored: list[ScoredFinding],
    threat_model: ThreatModel,
    *,
    client: LLMClient | None = None,
) -> str:
    """Produce the executive-summary prose for the markdown report."""
    if client is None:
        return _heuristic_summary(scored, threat_model)

    payload = [
        {
            "finding_id": s.finding.id,
            "title": s.finding.title,
            "composite_score": s.composite_score,
            "classification": s.classification,
            "scores": s.scores,
            "reasoning": s.reasoning,
        }
        for s in scored
    ]
    prompt = build_synthesis_prompt(
        n=len(scored),
        application_name=threat_model.application_name,
        scored_findings_json=json.dumps(payload, indent=2),
    )
    text = client.complete(SYNTHESIS_SYSTEM_PROMPT, prompt).strip()
    return text or _heuristic_summary(scored, threat_model)


# ---------------------------------------------------------------------------
# Heuristic (offline) scoring
# ---------------------------------------------------------------------------

# Coarse CWE -> STRIDE mapping, used only by the offline heuristic to decide
# whether a finding aligns with a model threat's STRIDE category. The LLM path
# reasons about this directly and does not use the table.
_CWE_STRIDE = {
    "CWE-79": "Tampering",
    "CWE-89": "Tampering",
    "CWE-78": "Tampering",
    "CWE-77": "Tampering",
    "CWE-94": "Tampering",
    "CWE-502": "Tampering",
    "CWE-287": "Spoofing",
    "CWE-306": "Spoofing",
    "CWE-384": "Spoofing",
    "CWE-200": "Information Disclosure",
    "CWE-209": "Information Disclosure",
    "CWE-312": "Information Disclosure",
    "CWE-532": "Information Disclosure",
    "CWE-269": "Elevation of Privilege",
    "CWE-285": "Elevation of Privilege",
    "CWE-862": "Elevation of Privilege",
    "CWE-863": "Elevation of Privilege",
    "CWE-732": "Elevation of Privilege",
    "CWE-400": "Denial of Service",
    "CWE-770": "Denial of Service",
    "CWE-117": "Repudiation",
    "CWE-778": "Repudiation",
}

_KEYWORD_STRIDE = [
    ("sql injection", "Tampering"),
    ("injection", "Tampering"),
    ("xss", "Tampering"),
    ("cross-site scripting", "Tampering"),
    ("deserial", "Tampering"),
    ("authentication", "Spoofing"),
    ("auth bypass", "Spoofing"),
    ("spoof", "Spoofing"),
    ("session", "Spoofing"),
    ("information disclosure", "Information Disclosure"),
    ("sensitive data", "Information Disclosure"),
    ("exposure", "Information Disclosure"),
    ("hardcoded", "Information Disclosure"),
    ("privilege", "Elevation of Privilege"),
    ("authorization", "Elevation of Privilege"),
    ("access control", "Elevation of Privilege"),
    ("denial of service", "Denial of Service"),
    ("dos", "Denial of Service"),
    ("logging", "Repudiation"),
    ("audit", "Repudiation"),
]


def infer_stride_category(finding: Finding) -> str:
    """Best-effort STRIDE category for a finding (heuristic path only)."""
    if finding.cwe in _CWE_STRIDE:
        return _CWE_STRIDE[finding.cwe]
    haystack = f"{finding.title} {finding.description}".lower()
    for keyword, category in _KEYWORD_STRIDE:
        if keyword in haystack:
            return category
    return ""


def score_finding_heuristic(
    finding: Finding, threat_model: ThreatModel, weights: Weights
) -> ScoredFinding:
    """Deterministic, network-free scoring that still cites real model elements."""
    component = threat_model.find_component(finding.component)
    category = infer_stride_category(finding)
    matched_threat = _matching_threat(finding, threat_model, component, category)
    crosses_boundary = _component_crosses_boundary(component, threat_model)

    # --- Dimension 1: asset criticality ---
    if component is None:
        asset = 2.0
    elif component.trust_zone in ("external", "dmz"):
        asset = 9.0
    elif component.trust_zone == "internal":
        asset = 5.0
    else:
        asset = 6.0  # known component, zone unspecified

    # --- Dimension 2: threat alignment ---
    if matched_threat is not None:
        align = 8.0
        classification = "CORROBORATED"
    elif component is not None:
        align = 4.0
        classification = "NOVEL"
    else:
        align = 1.0
        classification = "OUT_OF_SCOPE"

    # --- Dimension 3: trust boundary exposure ---
    if component is None:
        boundary = 2.0
    elif crosses_boundary or component.trust_zone in ("external", "dmz"):
        boundary = 8.0
    elif component.trust_zone == "internal":
        boundary = 3.0
    else:
        boundary = 5.0

    # --- Dimension 4: STRIDE category weight (from aggregate DREAD) ---
    aggregates = threat_model.stride_dread_aggregates()
    if category and category in aggregates:
        stride = _clamp_score(aggregates[category])
    elif matched_threat is not None and matched_threat.dread_score is not None:
        stride = _clamp_score(matched_threat.dread_score)
    else:
        stride = 5.0  # neutral when the model carries no DREAD data

    scores = {
        "asset_criticality": asset,
        "threat_alignment": align,
        "trust_boundary_exposure": boundary,
        "stride_category_weight": stride,
    }
    reasoning = _heuristic_reasoning(
        finding, component, matched_threat, category, crosses_boundary,
        classification, threat_model,
    )
    return ScoredFinding(
        finding=finding,
        scores=scores,
        composite_score=composite_score(scores, weights),
        classification=classification,
        reasoning=reasoning,
    )


def _matching_threat(
    finding: Finding,
    threat_model: ThreatModel,
    component: Any,
    category: str,
) -> ThreatModelThreat | None:
    """Find a model threat on the same component and STRIDE category."""
    if component is None:
        return None
    comp_name = component.name.strip().lower()
    for threat in threat_model.threats:
        if threat.component.strip().lower() != comp_name:
            continue
        if category and threat.stride_category.strip().lower() == category.strip().lower():
            return threat
    return None


def _component_crosses_boundary(component: Any, threat_model: ThreatModel) -> bool:
    if component is None:
        return False
    name = component.name.strip().lower()
    for flow in threat_model.data_flows:
        if not flow.get("crosses_trust_boundary"):
            continue
        endpoints = f"{flow.get('from', '')} {flow.get('to', '')}".lower()
        if name and name in endpoints:
            return True
    return False


def _heuristic_reasoning(
    finding: Finding,
    component: Any,
    matched_threat: ThreatModelThreat | None,
    category: str,
    crosses_boundary: bool,
    classification: str,
    threat_model: ThreatModel,
) -> str:
    """Compose reasoning that always cites a named threat model element."""
    if classification == "OUT_OF_SCOPE" or component is None:
        # Cite the modelled components it stands in contrast to, so even an
        # out-of-scope finding's reasoning names real threat model elements.
        modelled = ", ".join(sorted(threat_model.component_names()))
        return (
            f"This finding affects '{finding.component or 'an unknown component'}', "
            f"which is not among the components modelled in the "
            f"{threat_model.application_name} threat model ({modelled}). It cannot be "
            f"aligned to any existing threat; recommend adding it to the next threat "
            f"model revision before re-prioritising."
        )

    zone = component.trust_zone or "unspecified-zone"
    parts = [
        f"This finding affects '{component.name}', a {zone} component in the threat model"
    ]
    if crosses_boundary:
        parts.append(", which the model shows crossing a trust boundary")
    parts.append(". ")

    if matched_threat is not None:
        parts.append(
            f"It corroborates threat {matched_threat.threat_id} "
            f"({matched_threat.stride_category}) on the same component."
        )
    else:
        cat = category or "an uncovered STRIDE category"
        parts.append(
            f"No existing threat covers {cat} on this component, so it is flagged as a "
            f"threat model gap for review."
        )
    return "".join(parts)


def _heuristic_summary(scored: list[ScoredFinding], threat_model: ThreatModel) -> str:
    """Template-based executive summary used in offline mode."""
    total = len(scored)
    corroborated = [s for s in scored if s.classification == "CORROBORATED"]
    novel = [s for s in scored if s.classification == "NOVEL"]
    out_of_scope = [s for s in scored if s.classification == "OUT_OF_SCOPE"]
    top = scored[:3]

    para1 = (
        f"Across {total} finding(s) scored against the threat model for "
        f"{threat_model.application_name}, {len(corroborated)} corroborate existing "
        f"threats, {len(novel)} are novel to covered components, and "
        f"{len(out_of_scope)} fall outside the modelled scope. The corroborated "
        f"findings confirm that attack surfaces the threat model already flagged are "
        f"in fact vulnerable, which should raise their remediation priority."
    )

    if top:
        urgent = "; ".join(
            f"{s.finding.title} ({s.finding.id}, score {s.composite_score}, "
            f"{s.classification})"
            for s in top
        )
        para2 = (
            f"The most urgent findings are: {urgent}. Each is reasoned about in the "
            f"per-finding detail below, citing the specific threat model components "
            f"and threats they touch."
        )
    else:
        para2 = "No findings were available to prioritise."

    if novel or out_of_scope:
        para3 = (
            f"The {len(novel) + len(out_of_scope)} novel or out-of-scope finding(s) "
            f"suggest coverage gaps: components or STRIDE categories the threat model "
            f"does not yet address. These are surfaced in the threat model gaps section "
            f"as candidate additions for the next revision."
        )
    else:
        para3 = (
            "No coverage gaps were detected — every finding mapped onto a component the "
            "threat model already describes."
        )

    return f"{para1}\n\n{para2}\n\n{para3}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clamp_score(value: Any) -> float:
    """Coerce an LLM/aggregate value to a float in [0, 10]."""
    try:
        num = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, min(10.0, num)), 1)


def _normalise_classification(
    value: Any, finding: Finding, threat_model: ThreatModel
) -> str:
    """Validate the LLM classification, inferring a sensible value if invalid."""
    candidate = str(value or "").strip().upper()
    if candidate in VALID_CLASSIFICATIONS:
        return candidate
    # Infer from component membership when the model gave us nothing usable.
    if threat_model.find_component(finding.component) is None:
        return "OUT_OF_SCOPE"
    return "NOVEL"


def _fallback_reasoning(
    finding: Finding, threat_model: ThreatModel, classification: str
) -> str:
    component = threat_model.find_component(finding.component)
    category = infer_stride_category(finding)
    matched = _matching_threat(finding, threat_model, component, category)
    crosses = _component_crosses_boundary(component, threat_model)
    return _heuristic_reasoning(
        finding, component, matched, category, crosses, classification, threat_model
    )
