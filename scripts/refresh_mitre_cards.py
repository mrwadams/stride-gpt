#!/usr/bin/env python3
"""Regenerate the MITRE reference cards from authoritative upstream data.

Pulls MITRE ATT&CK Enterprise (STIX 2.x JSON) and MITRE ATLAS (YAML v6) from
their canonical distributions and rewrites
``stride_gpt/core/prompts/threat_model/mitre_{enterprise,atlas}.md``.

The narrative framing around each card is the source-of-truth template in
this file; the technique catalogue is the only piece regenerated from the
upstream data. Bump the pinned version constants below and re-run to refresh.

Usage::

    python scripts/refresh_mitre_cards.py
    python scripts/refresh_mitre_cards.py --attack PATH --atlas PATH  # offline
    python scripts/refresh_mitre_cards.py --print-only                # don't write

Requires PyYAML (transitively available via litellm). The script imports
``yaml`` lazily so the build-time-only dependency doesn't reach runtime.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Pinned source versions — bump these and re-run to refresh the cards.
# ---------------------------------------------------------------------------

ATTACK_VERSION = "v17.1"
ATTACK_URL = (
    f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-{ATTACK_VERSION}/"
    "enterprise-attack/enterprise-attack.json"
)

# ATLAS publishes dated YAML files in dist/v6/ (ATLAS-YYYY.MM.yaml).
# ATLAS-latest.yaml is a pointer file (one line: the current filename), not
# the data itself — always pin a dated file here so refreshes are reproducible.
ATLAS_VERSION = "ATLAS-2026.05"
ATLAS_URL = (
    f"https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/"
    f"dist/v6/{ATLAS_VERSION}.yaml"
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CARDS_DIR = REPO_ROOT / "stride_gpt" / "core" / "prompts" / "threat_model"

# ---------------------------------------------------------------------------
# Canonical tactic ordering. Hardcoded so upstream reorderings don't churn
# the cards and any new tactic surfaces as a build-time warning instead of
# silently appearing / disappearing from the rendered catalogue.
# ---------------------------------------------------------------------------

ATTACK_TACTIC_ORDER: list[str] = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]

ATLAS_TACTIC_ORDER: list[str] = [
    "AML.TA0002",  # Reconnaissance
    "AML.TA0003",  # Resource Development
    "AML.TA0004",  # Initial Access
    "AML.TA0000",  # AI Model Access
    "AML.TA0005",  # Execution
    "AML.TA0006",  # Persistence
    "AML.TA0012",  # Privilege Escalation
    "AML.TA0007",  # Defense Evasion
    "AML.TA0013",  # Credential Access
    "AML.TA0008",  # Discovery
    "AML.TA0015",  # Lateral Movement
    "AML.TA0009",  # Collection
    "AML.TA0001",  # AI Attack Staging
    "AML.TA0014",  # Command and Control
    "AML.TA0010",  # Exfiltration
    "AML.TA0011",  # Impact
]


# ---------------------------------------------------------------------------
# Domain model
# ---------------------------------------------------------------------------


@dataclass
class Tactic:
    key: str   # ATT&CK shortname, e.g. "initial-access"; or ATLAS ID, e.g. "AML.TA0004"
    name: str  # human label, e.g. "Initial Access"
    id: str    # external ID, e.g. "TA0001" / "AML.TA0004"


@dataclass
class Technique:
    id: str          # T#### or AML.T####
    name: str
    tactic_keys: list[str] = field(default_factory=list)


@dataclass
class Catalog:
    tactics: dict[str, Tactic]
    techniques: list[Technique]


# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------


def _fetch(url: str) -> bytes:
    """GET a URL and return the body. Raises a clear error on failure."""
    req = urllib.request.Request(url, headers={"User-Agent": "stride-gpt-refresh/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Network error fetching {url}: {exc.reason}") from exc


def _load_attack_json(source: str | Path) -> dict:
    """Load the ATT&CK STIX bundle from a URL or local path."""
    if isinstance(source, Path) or not str(source).startswith("http"):
        return json.loads(Path(source).read_text())
    return json.loads(_fetch(str(source)))


def _load_atlas_yaml(source: str | Path) -> dict:
    """Load the ATLAS YAML bundle from a URL or local path."""
    try:
        import yaml  # noqa: PLC0415 — optional, only needed at refresh time
    except ImportError as exc:
        raise SystemExit(
            "PyYAML is required to parse ATLAS. Install with `pip install pyyaml`."
        ) from exc
    if isinstance(source, Path) or not str(source).startswith("http"):
        text = Path(source).read_text()
    else:
        text = _fetch(str(source)).decode("utf-8")
    return yaml.safe_load(text)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_attack(bundle: dict) -> Catalog:
    """Extract tactics and (non-deprecated, non-revoked, top-level) techniques.

    Sub-techniques (``x_mitre_is_subtechnique``) are excluded for compactness —
    the cards are reference grouping, not a full taxonomy. Revoked and
    deprecated objects are filtered out so the LLM only ever sees current IDs.
    """
    tactics: dict[str, Tactic] = {}
    techniques: list[Technique] = []

    for obj in bundle.get("objects", []):
        otype = obj.get("type")

        if otype == "x-mitre-tactic":
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue
            shortname = obj.get("x_mitre_shortname")
            ext_id = _attack_external_id(obj)
            if shortname and ext_id and obj.get("name"):
                tactics[shortname] = Tactic(key=shortname, name=obj["name"], id=ext_id)
            continue

        if otype != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if obj.get("x_mitre_is_subtechnique"):
            continue

        ext_id = _attack_external_id(obj)
        if not ext_id or not obj.get("name"):
            continue

        tactic_keys = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
            and phase.get("phase_name")
        ]
        techniques.append(Technique(id=ext_id, name=obj["name"], tactic_keys=tactic_keys))

    return Catalog(tactics=tactics, techniques=techniques)


def _attack_external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def parse_atlas(bundle: dict) -> Catalog:
    """Extract tactics and top-level techniques from the ATLAS YAML bundle.

    ATLAS sub-techniques carry a dotted suffix (``AML.T0051.000``) — these
    are excluded for the same reason as ATT&CK sub-techniques. Tactic
    linkage lives in the ``relationships`` section, not on the technique
    object itself.
    """
    tactics: dict[str, Tactic] = {}
    for tid, tac in (bundle.get("tactics") or {}).items():
        if not isinstance(tac, dict):
            continue
        name = tac.get("name")
        if not name:
            continue
        tactics[tid] = Tactic(key=tid, name=name, id=tid)

    relationships = bundle.get("relationships") or {}

    techniques: list[Technique] = []
    for tid, tech in (bundle.get("techniques") or {}).items():
        if not isinstance(tech, dict):
            continue
        # ATLAS IDs always start with "AML." — the dot inside the prefix is
        # part of the ID, not a sub-technique marker. Sub-techniques carry a
        # *second* dot before the trailing ### suffix, e.g. AML.T0051.000.
        if tid.count(".") >= 2:
            continue
        name = tech.get("name")
        if not name:
            continue
        tactic_keys = _atlas_tactic_keys(relationships.get(tid, {}))
        techniques.append(Technique(id=tid, name=name, tactic_keys=tactic_keys))

    return Catalog(tactics=tactics, techniques=techniques)


def _atlas_tactic_keys(rel_block: dict) -> list[str]:
    """Pull tactic IDs from a technique's `achieves` relationships."""
    achieves = rel_block.get("achieves") or []
    out: list[str] = []
    for entry in achieves:
        if not isinstance(entry, dict):
            continue
        if entry.get("relationship-type") != "achieves":
            continue
        target = entry.get("target")
        if isinstance(target, str) and target.startswith("AML.TA"):
            out.append(target)
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_catalog(catalog: Catalog, tactic_order: Iterable[str]) -> str:
    """Render a tactic-grouped technique catalogue as markdown.

    Unknown tactics (present in the data but missing from ``tactic_order``)
    are appended at the end alphabetically — better to surface them than to
    silently drop techniques when the upstream framework grows.
    """
    by_tactic: dict[str, list[Technique]] = {}
    for tech in catalog.techniques:
        for key in tech.tactic_keys:
            by_tactic.setdefault(key, []).append(tech)

    ordered_keys = [k for k in tactic_order if k in by_tactic]
    extra = sorted(k for k in by_tactic if k not in tactic_order)
    if extra:
        print(
            f"warning: tactics in data but not in canonical order, appending: {extra}",
            file=sys.stderr,
        )
        ordered_keys.extend(extra)

    sections: list[str] = []
    for key in ordered_keys:
        tactic = catalog.tactics.get(key)
        if tactic is None:
            # Tactic referenced by techniques but missing from tactic table —
            # render with the raw key so the gap is visible rather than hidden.
            heading = f"### {key}"
        else:
            heading = f"### {tactic.name} ({tactic.id})"
        techs = sorted(by_tactic[key], key=_technique_sort_key)
        bullets = "\n".join(f"- **{t.id}** — {t.name}" for t in techs)
        sections.append(f"{heading}\n{bullets}")

    return "\n\n".join(sections)


def _technique_sort_key(t: Technique) -> tuple:
    """Sort by numeric ID: T1190 < T1078.004 < T9999, AML.T0051 lexicographic."""
    tid = t.id
    if tid.startswith("AML.T"):
        return (0, tid)
    # Enterprise: T#### or T####.###
    parent, _, sub = tid[1:].partition(".")
    try:
        return (1, int(parent), int(sub) if sub else 0)
    except ValueError:
        return (2, tid)


# ---------------------------------------------------------------------------
# Card templates — narrative framing + slot for the generated catalogue.
# ---------------------------------------------------------------------------


ENTERPRISE_TEMPLATE = """---
name: mitre_enterprise
title: MITRE ATT&CK Enterprise
when_to_load: |
  Load for almost any application threat model — Enterprise techniques cover
  web, server, cloud, container, and SaaS attack patterns. Always applicable
  unless the subsystem is purely ML/LLM behaviour with no traditional
  infrastructure surface (in which case load `mitre_atlas` instead).
adds_fields:
  - MITRE_ATTACK
stride_letters: [S, T, R, I, D, E]
source: https://attack.mitre.org/matrices/enterprise/
version: {version}
---

# MITRE ATT&CK Enterprise — Reference Card

You loaded this card because the subsystem you are analysing has a traditional
software / infrastructure surface. In addition to a STRIDE category, you MUST
attach the most-specific applicable MITRE ATT&CK techniques to each threat.

## How to use this card

For each threat you emit, choose **zero or more** techniques from the catalog
below that an adversary would plausibly invoke to realise the threat. A threat
maps to a technique when the technique is the *mechanism* the attacker uses,
not merely a related concept.

> **Anti-hallucination requirement.** Use **only** technique IDs and names
> exactly as written in this card. Do not invent IDs, do not paraphrase names,
> do not combine an ID with a different technique's name. If no technique
> fits, emit `"MITRE_ATTACK": []` — empty is preferable to a fabricated ID.
> If both this card and `mitre_atlas` are loaded, merge techniques from both
> into the same `MITRE_ATTACK` list on each threat.

Prefer 1–3 techniques per threat. Avoid stuffing techniques that share a
tactic — pick the most specific one.

## Schema additions

Each threat object must additionally include:

- `"MITRE_ATTACK"`: an array of objects, each shaped
  `{{"id": "T####", "name": "Technique Name"}}`. May be empty.

## Technique catalog

This catalog was generated from MITRE ATT&CK Enterprise {version}. Sub-techniques
are not listed individually — use the parent technique ID. Deprecated and
revoked techniques are excluded.

{catalog}
"""


ATLAS_TEMPLATE = """---
name: mitre_atlas
title: MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
when_to_load: |
  Load **in addition to `mitre_enterprise`** when the subsystem has
  machine-learning or LLM behaviour in scope — uses LLM SDKs (openai,
  anthropic, mistralai, google-generativeai, etc.), exposes ML inference
  endpoints, performs RAG/embedding operations, fine-tunes or serves a
  model, or otherwise has model-driven behaviour an adversary could
  target. Pairs naturally with the `genai` and `agentic` reference cards.
adds_fields:
  - MITRE_ATTACK
stride_letters: [S, T, R, I, D, E]
source: https://atlas.mitre.org/matrices/ATLAS
version: {version}
---

# MITRE ATLAS — Reference Card

You loaded this card because the subsystem you are analysing has
machine-learning or LLM behaviour in scope. ATLAS extends ATT&CK with
techniques specific to attacks on AI systems. Use it alongside
`mitre_enterprise` — most real-world AI threats combine traditional
infrastructure techniques with ML-specific ones.

## How to use this card

For each threat that involves the ML/LLM surface, attach **zero or more**
ATLAS technique IDs from the catalog below. Enterprise + ATLAS techniques
go into the **same** `MITRE_ATTACK` list on the threat.

> **Anti-hallucination requirement.** Use **only** technique IDs and names
> exactly as written in this card. Do not invent IDs, do not paraphrase
> names. ATLAS IDs always carry the `AML.` prefix (e.g. `AML.T0051`); do
> not strip it. If no ATLAS technique fits, emit nothing from this card —
> empty is preferable to a fabricated ID.

A given threat will often combine one Enterprise technique (the
infrastructure mechanism) with one ATLAS technique (the ML-specific
mechanism). Example — RAG context exfiltration:
`[{{"id": "T1041", "name": "Exfiltration Over C2 Channel"}},
  {{"id": "AML.T0024", "name": "Exfiltration via AI Inference API"}}]`.

## Schema additions

Each threat object must additionally include:

- `"MITRE_ATTACK"`: an array of objects, each shaped
  `{{"id": "AML.T####", "name": "Technique Name"}}` (or the equivalent
  Enterprise shape — both share the field). May be empty.

## Technique catalog

This catalog was generated from MITRE ATLAS {version}. Sub-techniques are not
listed individually — use the parent technique ID.

{catalog}
"""


def render_enterprise_card(catalog: Catalog, version: str) -> str:
    return ENTERPRISE_TEMPLATE.format(
        version=version,
        catalog=render_catalog(catalog, ATTACK_TACTIC_ORDER),
    )


def render_atlas_card(catalog: Catalog, version: str) -> str:
    return ATLAS_TEMPLATE.format(
        version=version,
        catalog=render_catalog(catalog, ATLAS_TACTIC_ORDER),
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--attack", default=ATTACK_URL,
        help="ATT&CK Enterprise STIX JSON (URL or path). Default: pinned upstream.",
    )
    parser.add_argument(
        "--atlas", default=ATLAS_URL,
        help="ATLAS YAML bundle (URL or path). Default: pinned upstream.",
    )
    parser.add_argument(
        "--print-only", action="store_true",
        help="Print the rendered cards to stdout instead of writing files.",
    )
    args = parser.parse_args(argv)

    print(f"Loading ATT&CK from {args.attack}...", file=sys.stderr)
    attack = parse_attack(_load_attack_json(args.attack))
    print(
        f"  {len(attack.tactics)} tactics, {len(attack.techniques)} top-level techniques",
        file=sys.stderr,
    )

    print(f"Loading ATLAS from {args.atlas}...", file=sys.stderr)
    atlas = parse_atlas(_load_atlas_yaml(args.atlas))
    print(
        f"  {len(atlas.tactics)} tactics, {len(atlas.techniques)} top-level techniques",
        file=sys.stderr,
    )

    enterprise_md = render_enterprise_card(attack, ATTACK_VERSION)
    atlas_md = render_atlas_card(atlas, ATLAS_VERSION)

    if args.print_only:
        sys.stdout.write(enterprise_md)
        sys.stdout.write("\n\n=== ATLAS ===\n\n")
        sys.stdout.write(atlas_md)
        return 0

    enterprise_path = CARDS_DIR / "mitre_enterprise.md"
    atlas_path = CARDS_DIR / "mitre_atlas.md"
    enterprise_path.write_text(enterprise_md)
    atlas_path.write_text(atlas_md)
    print(f"Wrote {enterprise_path.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(f"Wrote {atlas_path.relative_to(REPO_ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
