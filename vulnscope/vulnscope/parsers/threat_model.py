"""Threat model parsing.

Supports two input formats in v1:

  1. STRIDE-GPT JSON export — the structured report emitted by
     ``stride-gpt analyze ... -f json`` (a ``subsystems`` array of threats).
  2. A minimal hand-rolled schema — for users without STRIDE-GPT::

       {
         "application_name": "...",
         "components":  [{ "name", "description", "trust_zone" }],
         "data_flows":  [{ "from", "to", "data_types", "crosses_trust_boundary" }],
         "threats":     [{ "stride_category", "component", "description", "dread_score" }]
       }

STRIDE-GPT markdown export parsing is intentionally out of scope for v1 (the
JSON export is one click away); it raises a clear, actionable error.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Component:
    """A system component / subsystem from the threat model."""

    name: str
    description: str = ""
    # internal | external | dmz | "" (unknown). External/dmz components are
    # treated as higher-exposure during scoring.
    trust_zone: str = ""


@dataclass
class ThreatModelThreat:
    """A single threat the model already identified."""

    # Auto-assigned stable id (TM-001, TM-002, ...) so finding reasoning can
    # cite a specific threat even when the source format has no ids of its own.
    threat_id: str
    stride_category: str
    component: str
    description: str = ""
    dread_score: float | None = None


@dataclass
class ThreatModel:
    """Parsed, format-normalised threat model."""

    application_name: str
    components: list[Component] = field(default_factory=list)
    data_flows: list[dict[str, Any]] = field(default_factory=list)
    threats: list[ThreatModelThreat] = field(default_factory=list)
    source_format: str = ""
    # The original parsed document, kept verbatim for full-context prompt
    # injection (the LLM scores against the richest available view).
    raw: dict[str, Any] = field(default_factory=dict)

    def component_names(self) -> set[str]:
        return {c.name for c in self.components}

    def find_component(self, name: str) -> Component | None:
        """Case-insensitive, substring-tolerant component lookup.

        Scanner-reported component names (file paths, fully-qualified symbols)
        rarely match threat-model component names exactly, so we accept a match
        when either name contains the other.
        """
        if not name:
            return None
        needle = name.strip().lower()
        for comp in self.components:
            hay = comp.name.strip().lower()
            if not hay:
                continue
            if hay == needle or hay in needle or needle in hay:
                return comp
        return None

    def stride_dread_aggregates(self) -> dict[str, float]:
        """Mean DREAD score per STRIDE category, for categories that have scores."""
        sums: dict[str, float] = {}
        counts: dict[str, int] = {}
        for threat in self.threats:
            if threat.dread_score is None:
                continue
            cat = threat.stride_category
            sums[cat] = sums.get(cat, 0.0) + threat.dread_score
            counts[cat] = counts.get(cat, 0) + 1
        return {cat: round(sums[cat] / counts[cat], 2) for cat in sums}

    def to_prompt_dict(self) -> dict[str, Any]:
        """A compact, normalised view for prompt injection.

        Includes the auto-assigned threat ids and the per-category DREAD
        aggregates so the model can cite both in its reasoning.
        """
        return {
            "application_name": self.application_name,
            "components": [
                {"name": c.name, "description": c.description, "trust_zone": c.trust_zone}
                for c in self.components
            ],
            "data_flows": self.data_flows,
            "threats": [
                {
                    "threat_id": t.threat_id,
                    "stride_category": t.stride_category,
                    "component": t.component,
                    "description": t.description,
                    "dread_score": t.dread_score,
                }
                for t in self.threats
            ],
            "stride_dread_aggregates": self.stride_dread_aggregates(),
        }

    def to_prompt_json(self) -> str:
        return json.dumps(self.to_prompt_dict(), indent=2)


def parse_threat_model(path: str | Path) -> ThreatModel:
    """Parse a threat model file, auto-detecting the format."""
    path = Path(path)
    if path.suffix.lower() in (".md", ".markdown"):
        raise ValueError(
            "STRIDE-GPT markdown parsing is not supported in v1.0. Export your "
            "threat model as JSON (one click in STRIDE-GPT) and pass the .json "
            "file instead."
        )

    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Threat model file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Threat model is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError("Threat model JSON must be an object at the top level.")

    if "subsystems" in raw:
        return _parse_stride_gpt(raw)
    if "components" in raw or "threats" in raw:
        return _parse_minimal(raw)

    raise ValueError(
        "Unrecognised threat model format. Expected a STRIDE-GPT JSON export "
        "(with a 'subsystems' array) or the minimal schema (with 'components' "
        "and/or 'threats')."
    )


def _parse_stride_gpt(raw: dict[str, Any]) -> ThreatModel:
    """Parse a STRIDE-GPT ``-f json`` export."""
    target = raw.get("target", "") or "Application"
    app_name = Path(target).name if ("/" in target or "\\" in target) else target

    components: list[Component] = []
    threats: list[ThreatModelThreat] = []
    counter = _IdCounter()

    for sub in raw.get("subsystems", []):
        name = sub.get("name", "")
        if name:
            components.append(Component(name=name, description=_first_sentence(sub)))
        for threat in sub.get("threats", []):
            threats.append(_stride_gpt_threat(threat, name, counter))

    # Cross-cutting threats span subsystems; record them against a synthetic
    # component so finding alignment can still reference them.
    cross = raw.get("cross_cutting_threats", [])
    if cross:
        components.append(Component(name="cross-cutting", description="Cross-cutting concerns"))
    for threat in cross:
        threats.append(_stride_gpt_threat(threat, "cross-cutting", counter))

    return ThreatModel(
        application_name=app_name,
        components=components,
        data_flows=[],
        threats=threats,
        source_format="stride-gpt-json",
        raw=raw,
    )


def _stride_gpt_threat(
    threat: dict[str, Any], component: str, counter: _IdCounter
) -> ThreatModelThreat:
    return ThreatModelThreat(
        threat_id=counter.next(),
        stride_category=str(threat.get("Threat Type", "") or threat.get("stride_category", "")),
        component=component,
        description=str(threat.get("Scenario", "") or threat.get("description", "")),
        dread_score=_coerce_dread(threat),
    )


def _parse_minimal(raw: dict[str, Any]) -> ThreatModel:
    """Parse the documented minimal hand-rolled schema."""
    components = [
        Component(
            name=str(c.get("name", "")),
            description=str(c.get("description", "")),
            trust_zone=str(c.get("trust_zone", "")),
        )
        for c in raw.get("components", [])
        if isinstance(c, dict)
    ]

    counter = _IdCounter()
    threats: list[ThreatModelThreat] = []
    for t in raw.get("threats", []):
        if not isinstance(t, dict):
            continue
        threats.append(
            ThreatModelThreat(
                threat_id=str(t.get("id") or t.get("threat_id") or counter.next()),
                stride_category=str(t.get("stride_category", "")),
                component=str(t.get("component", "")),
                description=str(t.get("description", "")),
                dread_score=_coerce_float(t.get("dread_score")),
            )
        )

    return ThreatModel(
        application_name=str(raw.get("application_name", "") or "Application"),
        components=components,
        data_flows=[d for d in raw.get("data_flows", []) if isinstance(d, dict)],
        threats=threats,
        source_format="minimal-json",
        raw=raw,
    )


class _IdCounter:
    """Hands out sequential TM-001, TM-002, ... threat ids."""

    def __init__(self) -> None:
        self._n = 0

    def next(self) -> str:
        self._n += 1
        return f"TM-{self._n:03d}"


def _first_sentence(sub: dict[str, Any]) -> str:
    """STRIDE-GPT subsystem exports carry no description field; derive a short
    label from the first threat scenario so the component isn't anonymous."""
    threats = sub.get("threats", [])
    if threats and isinstance(threats[0], dict):
        scenario = str(threats[0].get("Scenario", ""))
        if scenario:
            return scenario.split(".")[0][:160]
    return ""


def _coerce_dread(threat: dict[str, Any]) -> float | None:
    """Pull a DREAD score from a STRIDE-GPT threat dict if one is present.

    STRIDE-GPT's threat export does not include DREAD by default (it lives in a
    separate Risk Assessment), but tools sometimes merge it in under a few
    common keys. Accept the obvious ones; otherwise leave it unscored.
    """
    for key in ("dread_score", "Risk Score", "dread", "DREAD"):
        val = _coerce_float(threat.get(key))
        if val is not None:
            return val
    return None


def _coerce_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
