"""Vulnerability finding parsing.

Supports two input formats in v1:

  1. SARIF v2.1.0 — the industry standard emitted by Semgrep, CodeQL, Snyk,
     XBOW, ZeroPath, and most scanners.
  2. A simple JSON array — an escape hatch for bespoke tools::

       [{ "id", "title", "severity", "component", "description", "cwe" }]

SARIF is parsed with the standard library rather than a third-party reader:
the subset we need (results, rules, locations, CWE taxa) is small and stable,
and a dependency-free parser is more robust across the many scanner dialects.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    """A single vulnerability finding, normalised across input formats."""

    id: str
    title: str
    severity: str = ""
    component: str = ""
    description: str = ""
    cwe: str = ""
    # The original finding object, kept verbatim for the report's
    # ``original_finding`` passthrough and for full-context prompt injection.
    raw: dict[str, Any] = field(default_factory=dict)

    def to_prompt_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "component": self.component,
            "description": self.description,
            "cwe": self.cwe,
        }


def parse_findings(path: str | Path) -> list[Finding]:
    """Parse a findings file, auto-detecting SARIF vs. the simple JSON array."""
    path = Path(path)
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Findings file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Findings file is not valid JSON: {exc}") from exc

    if isinstance(raw, list):
        return _parse_simple(raw)
    if isinstance(raw, dict) and "runs" in raw:
        return _parse_sarif(raw)

    raise ValueError(
        "Unrecognised findings format. Expected SARIF v2.1.0 (an object with a "
        "'runs' array) or a simple JSON array of findings."
    )


def _parse_simple(raw: list[Any]) -> list[Finding]:
    findings: list[Finding] = []
    for i, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            continue
        findings.append(
            Finding(
                id=str(item.get("id") or f"FINDING-{i:03d}"),
                title=str(item.get("title", "") or "Untitled finding"),
                severity=str(item.get("severity", "")).upper(),
                component=str(item.get("component", "")),
                description=str(item.get("description", "")),
                cwe=_normalise_cwe(item.get("cwe", "")),
                raw=item,
            )
        )
    return findings


def _parse_sarif(raw: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for run in raw.get("runs", []):
        if not isinstance(run, dict):
            continue
        rules = _index_rules(run)
        tool_name = (
            run.get("tool", {}).get("driver", {}).get("name", "scanner")
            if isinstance(run.get("tool"), dict)
            else "scanner"
        )
        for i, result in enumerate(run.get("results", []), 1):
            if isinstance(result, dict):
                findings.append(_sarif_result(result, rules, tool_name, i))
    return findings


def _index_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map ruleId -> rule object from a run's tool driver (and extensions)."""
    rules: dict[str, dict[str, Any]] = {}
    tool = run.get("tool", {})
    if not isinstance(tool, dict):
        return rules
    components = [tool.get("driver", {})] + list(tool.get("extensions", []) or [])
    for comp in components:
        if not isinstance(comp, dict):
            continue
        for rule in comp.get("rules", []) or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules[str(rule["id"])] = rule
    return rules


def _sarif_result(
    result: dict[str, Any], rules: dict[str, dict[str, Any]], tool: str, index: int
) -> Finding:
    rule_id = str(result.get("ruleId", "") or "")
    rule = rules.get(rule_id, {})

    title = (
        _text(rule.get("shortDescription"))
        or rule.get("name", "")
        or rule_id
        or "Untitled finding"
    )
    description = _text(result.get("message")) or _text(rule.get("fullDescription"))
    severity = _sarif_severity(result, rule)
    component = _sarif_component(result)
    cwe = _sarif_cwe(result, rule)
    finding_id = str(result.get("guid") or result.get("correlationGuid") or "")
    if not finding_id:
        finding_id = f"{tool}-{rule_id or 'RESULT'}-{index:03d}"

    return Finding(
        id=finding_id,
        title=str(title),
        severity=severity,
        component=component,
        description=description,
        cwe=cwe,
        raw=result,
    )


def _sarif_severity(result: dict[str, Any], rule: dict[str, Any]) -> str:
    """Derive a coarse HIGH/MEDIUM/LOW severity from SARIF metadata.

    Prefers the numeric ``security-severity`` (CVSS-style 0-10) when present —
    it's what GitHub code scanning uses — then falls back to the SARIF level.
    """
    sev = _security_severity(result.get("properties")) or _security_severity(
        rule.get("properties")
    )
    if sev is not None:
        if sev >= 9.0:
            return "CRITICAL"
        if sev >= 7.0:
            return "HIGH"
        if sev >= 4.0:
            return "MEDIUM"
        return "LOW"

    level = str(result.get("level", "") or _default_level(rule)).lower()
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}.get(
        level, "MEDIUM"
    )


def _default_level(rule: dict[str, Any]) -> str:
    config = rule.get("defaultConfiguration", {})
    if isinstance(config, dict):
        return str(config.get("level", "warning"))
    return "warning"


def _security_severity(props: Any) -> float | None:
    if not isinstance(props, dict):
        return None
    raw = props.get("security-severity")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _sarif_component(result: dict[str, Any]) -> str:
    """Resolve the affected component: prefer a logical location, else the file."""
    locations = result.get("locations", [])
    if not isinstance(locations, list) or not locations:
        return ""
    loc = locations[0]
    if not isinstance(loc, dict):
        return ""

    logical = loc.get("logicalLocations", [])
    if isinstance(logical, list) and logical and isinstance(logical[0], dict):
        name = logical[0].get("fullyQualifiedName") or logical[0].get("name")
        if name:
            return str(name)

    physical = loc.get("physicalLocation", {})
    if isinstance(physical, dict):
        artifact = physical.get("artifactLocation", {})
        if isinstance(artifact, dict) and artifact.get("uri"):
            return str(artifact["uri"])
    return ""


_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _sarif_cwe(result: dict[str, Any], rule: dict[str, Any]) -> str:
    """Extract a CWE id from rule taxa, tags, or result properties."""
    # 1. taxa relationships on the rule (the canonical SARIF location).
    for rel in rule.get("relationships", []) or []:
        if isinstance(rel, dict):
            target = rel.get("target", {})
            if isinstance(target, dict):
                cwe = _normalise_cwe(target.get("id", ""))
                if cwe:
                    return cwe

    # 2. tags (Semgrep/CodeQL stash "external/cwe/cwe-89" style tags here).
    for source in (rule.get("properties"), result.get("properties")):
        if isinstance(source, dict):
            for tag in source.get("tags", []) or []:
                cwe = _normalise_cwe(str(tag))
                if cwe:
                    return cwe
            cwe = _normalise_cwe(str(source.get("cwe", "")))
            if cwe:
                return cwe
    return ""


def _normalise_cwe(value: Any) -> str:
    """Return a canonical ``CWE-<n>`` string, or '' if none can be found."""
    match = _CWE_RE.search(str(value or ""))
    return f"CWE-{match.group(1)}" if match else ""


def _text(node: Any) -> str:
    """Extract ``.text`` from a SARIF multiformatMessageString-like node."""
    if isinstance(node, dict):
        return str(node.get("text", "") or "")
    if isinstance(node, str):
        return node
    return ""
