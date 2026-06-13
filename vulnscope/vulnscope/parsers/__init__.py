"""Input parsers for threat models and vulnerability findings."""

from __future__ import annotations

from vulnscope.parsers.findings import Finding, parse_findings
from vulnscope.parsers.threat_model import (
    Component,
    ThreatModel,
    ThreatModelThreat,
    parse_threat_model,
)

__all__ = [
    "Finding",
    "parse_findings",
    "Component",
    "ThreatModel",
    "ThreatModelThreat",
    "parse_threat_model",
]
