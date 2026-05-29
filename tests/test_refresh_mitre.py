"""Tests for scripts/refresh_mitre_cards.py — the MITRE catalogue refresher.

The script lives outside the importable package, so the test loads it via
importlib.util. It is exercised against synthetic STIX / YAML fixtures
rather than the real bundles — the parser shape is what we care about; the
upstream content is MITRE's problem.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "refresh_mitre_cards.py"


@pytest.fixture(scope="module")
def refresh_module():
    spec = importlib.util.spec_from_file_location("refresh_mitre_cards", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["refresh_mitre_cards"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# ATT&CK STIX parser
# ---------------------------------------------------------------------------


class TestParseAttack:
    def _stix(self, objects):
        return {"type": "bundle", "id": "bundle--x", "objects": objects}

    def test_extracts_tactic_metadata(self, refresh_module):
        bundle = self._stix([
            {
                "type": "x-mitre-tactic",
                "name": "Initial Access",
                "x_mitre_shortname": "initial-access",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "TA0001"},
                ],
            },
        ])
        catalog = refresh_module.parse_attack(bundle)
        assert "initial-access" in catalog.tactics
        tactic = catalog.tactics["initial-access"]
        assert tactic.name == "Initial Access"
        assert tactic.id == "TA0001"

    def test_extracts_techniques_and_links_to_tactics(self, refresh_module):
        bundle = self._stix([
            {
                "type": "attack-pattern",
                "name": "Exploit Public-Facing Application",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1190"},
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
                ],
            },
        ])
        catalog = refresh_module.parse_attack(bundle)
        assert len(catalog.techniques) == 1
        tech = catalog.techniques[0]
        assert tech.id == "T1190"
        assert tech.name == "Exploit Public-Facing Application"
        assert tech.tactic_keys == ["initial-access"]

    def test_skips_subtechniques(self, refresh_module):
        bundle = self._stix([
            {
                "type": "attack-pattern",
                "name": "Local Accounts",
                "x_mitre_is_subtechnique": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1078.003"},
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                ],
            },
        ])
        assert refresh_module.parse_attack(bundle).techniques == []

    def test_skips_revoked_and_deprecated(self, refresh_module):
        bundle = self._stix([
            {
                "type": "attack-pattern", "name": "Old", "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9001"}],
            },
            {
                "type": "attack-pattern", "name": "Older", "x_mitre_deprecated": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9002"}],
            },
        ])
        assert refresh_module.parse_attack(bundle).techniques == []

    def test_ignores_other_object_types(self, refresh_module):
        """Bundles carry malware, tools, intrusion-sets, etc. — the parser
        must filter to attack-pattern only."""
        bundle = self._stix([
            {"type": "malware", "name": "Some Malware"},
            {"type": "intrusion-set", "name": "APT99"},
            {"type": "relationship", "source_ref": "x", "target_ref": "y"},
        ])
        catalog = refresh_module.parse_attack(bundle)
        assert catalog.techniques == []
        assert catalog.tactics == {}

    def test_skips_techniques_without_mitre_attack_external_id(self, refresh_module):
        """Some objects carry only third-party references (CAPEC etc.). They
        must not produce phantom catalogue entries."""
        bundle = self._stix([
            {
                "type": "attack-pattern", "name": "Phantom",
                "external_references": [{"source_name": "capec", "external_id": "CAPEC-99"}],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                ],
            },
        ])
        assert refresh_module.parse_attack(bundle).techniques == []


# ---------------------------------------------------------------------------
# ATLAS YAML parser
# ---------------------------------------------------------------------------


class TestParseAtlas:
    def _atlas(self, *, tactics=None, techniques=None, relationships=None):
        return {
            "tactics": tactics or {},
            "techniques": techniques or {},
            "relationships": relationships or {},
        }

    def test_extracts_tactics(self, refresh_module):
        bundle = self._atlas(tactics={
            "AML.TA0004": {"name": "Initial Access", "object-type": "tactic"},
        })
        catalog = refresh_module.parse_atlas(bundle)
        tactic = catalog.tactics["AML.TA0004"]
        assert tactic.name == "Initial Access"
        assert tactic.id == "AML.TA0004"

    def test_extracts_techniques_with_tactic_links(self, refresh_module):
        """Tactic linkage in ATLAS lives in the `relationships` section, not
        on the technique itself. The parser has to join the two."""
        bundle = self._atlas(
            tactics={"AML.TA0005": {"name": "Execution"}},
            techniques={
                "AML.T0051": {"name": "LLM Prompt Injection"},
            },
            relationships={
                "AML.T0051": {
                    "achieves": [
                        {
                            "source": "AML.T0051",
                            "target": "AML.TA0005",
                            "relationship-type": "achieves",
                        },
                    ],
                },
            },
        )
        catalog = refresh_module.parse_atlas(bundle)
        assert len(catalog.techniques) == 1
        tech = catalog.techniques[0]
        assert tech.id == "AML.T0051"
        assert tech.name == "LLM Prompt Injection"
        assert tech.tactic_keys == ["AML.TA0005"]

    def test_excludes_subtechniques(self, refresh_module):
        """ATLAS sub-technique IDs have a *second* dot (AML.T0051.000). The
        `AML.` prefix dot must not be mistaken for a sub-technique marker."""
        bundle = self._atlas(techniques={
            "AML.T0051": {"name": "LLM Prompt Injection"},
            "AML.T0051.000": {"name": "Direct"},
            "AML.T0051.001": {"name": "Indirect"},
        })
        catalog = refresh_module.parse_atlas(bundle)
        ids = {t.id for t in catalog.techniques}
        assert ids == {"AML.T0051"}

    def test_techniques_without_tactic_relationship_still_listed(self, refresh_module):
        """A technique with no `achieves` block still belongs in the catalog
        — it just has no tactic_keys and will not appear under any heading."""
        bundle = self._atlas(techniques={"AML.T0099": {"name": "Orphan"}})
        catalog = refresh_module.parse_atlas(bundle)
        assert len(catalog.techniques) == 1
        assert catalog.techniques[0].tactic_keys == []


# ---------------------------------------------------------------------------
# Catalog rendering
# ---------------------------------------------------------------------------


class TestRenderCatalog:
    def test_groups_by_tactic_in_canonical_order(self, refresh_module):
        catalog = refresh_module.Catalog(
            tactics={
                "execution": refresh_module.Tactic("execution", "Execution", "TA0002"),
                "initial-access": refresh_module.Tactic(
                    "initial-access", "Initial Access", "TA0001"
                ),
            },
            techniques=[
                refresh_module.Technique("T1059", "Command and Scripting Interpreter",
                                         ["execution"]),
                refresh_module.Technique("T1190", "Exploit Public-Facing Application",
                                         ["initial-access"]),
            ],
        )
        md = refresh_module.render_catalog(catalog, ["initial-access", "execution"])
        # Initial Access heading must appear before Execution heading.
        ia_idx = md.index("Initial Access")
        ex_idx = md.index("Execution")
        assert ia_idx < ex_idx
        assert "- **T1190** — Exploit Public-Facing Application" in md
        assert "- **T1059** — Command and Scripting Interpreter" in md

    def test_sorts_techniques_by_numeric_id(self, refresh_module):
        """T1078 should appear before T1190 even if the input is reversed."""
        catalog = refresh_module.Catalog(
            tactics={"initial-access": refresh_module.Tactic(
                "initial-access", "Initial Access", "TA0001"
            )},
            techniques=[
                refresh_module.Technique("T1190", "Exploit", ["initial-access"]),
                refresh_module.Technique("T1078", "Valid Accounts", ["initial-access"]),
            ],
        )
        md = refresh_module.render_catalog(catalog, ["initial-access"])
        assert md.index("T1078") < md.index("T1190")

    def test_warns_on_unknown_tactic(self, refresh_module, capsys):
        """If the data carries a tactic that's not in the canonical order
        list, the renderer must surface it as a warning rather than dropping
        the techniques. New upstream tactics should be visible at refresh
        time, not buried."""
        catalog = refresh_module.Catalog(
            tactics={"new-tactic": refresh_module.Tactic(
                "new-tactic", "Brand New", "TA9999"
            )},
            techniques=[refresh_module.Technique("T9999", "X", ["new-tactic"])],
        )
        md = refresh_module.render_catalog(catalog, ["initial-access"])
        captured = capsys.readouterr()
        assert "new-tactic" in captured.err
        # Unknown tactics still render — appended at the end.
        assert "Brand New" in md


# ---------------------------------------------------------------------------
# Card rendering end-to-end
# ---------------------------------------------------------------------------


class TestRenderCards:
    def test_enterprise_card_carries_required_anchors(self, refresh_module):
        """Card must contain the frontmatter `name`, the anti-invention rule,
        and the schema field declaration — these are the bits other parts of
        the codebase (loader, tests, base.md prose) depend on."""
        catalog = refresh_module.Catalog(
            tactics={"initial-access": refresh_module.Tactic(
                "initial-access", "Initial Access", "TA0001"
            )},
            techniques=[refresh_module.Technique(
                "T1190", "Exploit Public-Facing Application", ["initial-access"]
            )],
        )
        md = refresh_module.render_enterprise_card(catalog, "v17.1")
        assert "name: mitre_enterprise" in md
        assert "MITRE_ATTACK" in md
        assert "do not invent" in md.lower()
        assert "v17.1" in md
        assert "T1190" in md

    def test_atlas_card_carries_required_anchors(self, refresh_module):
        catalog = refresh_module.Catalog(
            tactics={"AML.TA0005": refresh_module.Tactic(
                "AML.TA0005", "Execution", "AML.TA0005"
            )},
            techniques=[refresh_module.Technique(
                "AML.T0051", "LLM Prompt Injection", ["AML.TA0005"]
            )],
        )
        md = refresh_module.render_atlas_card(catalog, "ATLAS-2026.05")
        assert "name: mitre_atlas" in md
        assert "MITRE_ATTACK" in md
        assert "do not invent" in md.lower()
        assert "ATLAS-2026.05" in md
        assert "AML.T0051" in md
