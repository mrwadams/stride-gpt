"""Tests for stride_gpt.core.drawio_parser.

The parser turns untrusted, user-drawn draw.io XML into the authoritative
component/data-flow model injected into threat-modelling prompts
(apps/web/main.py). Two things must hold: it extracts the diagram structure
correctly, and it degrades safely (never expands entities, never raises) on
malformed or malicious input.
"""

from __future__ import annotations

from stride_gpt.core.drawio_parser import drawio_to_prompt_section, parse_drawio_xml

# A flat diagram: three vertices, two edges, no groups. Mirrors the module's
# own __main__ smoke sample (which pytest never runs).
FLAT_XML = """<mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="2" value="User" vertex="1" parent="1" style="ellipse;"><mxGeometry/></mxCell>
  <mxCell id="3" value="Web App" vertex="1" parent="1" style="rounded=1;"><mxGeometry/></mxCell>
  <mxCell id="4" value="Database" vertex="1" parent="1" style="shape=cylinder;"><mxGeometry/></mxCell>
  <mxCell id="5" value="HTTPS" edge="1" source="2" target="3" parent="1"><mxGeometry/></mxCell>
  <mxCell id="6" value="SQL" edge="1" source="3" target="4" parent="1"><mxGeometry/></mxCell>
</root></mxGraphModel>"""

# A grouped diagram: a swimlane "DMZ" containing two vertices with an edge
# between them.
GROUPED_XML = """<mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="z" value="DMZ" vertex="1" parent="1" style="swimlane;"><mxGeometry/></mxCell>
  <mxCell id="a" value="Web" vertex="1" parent="z" style="rounded=1;"><mxGeometry/></mxCell>
  <mxCell id="b" value="DB" vertex="1" parent="z" style="shape=cylinder;"><mxGeometry/></mxCell>
  <mxCell id="e" value="query" edge="1" source="a" target="b" parent="1"><mxGeometry/></mxCell>
</root></mxGraphModel>"""


class TestParseFlatDiagram:
    def test_extracts_all_labeled_vertices_as_components(self):
        result = parse_drawio_xml(FLAT_XML)
        labels = {c["label"] for c in result["components"]}
        assert labels == {"User", "Web App", "Database"}

    def test_root_and_layer_cells_are_not_components(self):
        # Cells "0" and "1" are the model root and default layer, never components.
        result = parse_drawio_xml(FLAT_XML)
        assert all(c["id"] not in ("0", "1") for c in result["components"])

    def test_flat_components_have_no_group(self):
        result = parse_drawio_xml(FLAT_XML)
        assert all(c["group"] is None for c in result["components"])

    def test_edges_resolve_endpoint_ids_to_labels(self):
        result = parse_drawio_xml(FLAT_XML)
        flows = {(c["from"], c["to"]): c["label"] for c in result["connections"]}
        assert flows == {("User", "Web App"): "HTTPS", ("Web App", "Database"): "SQL"}

    def test_flat_diagram_has_no_trust_boundaries(self):
        result = parse_drawio_xml(FLAT_XML)
        assert result["trust_boundaries"] == []


class TestParseGroupedDiagram:
    def test_grouped_vertices_carry_their_group_label(self):
        result = parse_drawio_xml(GROUPED_XML)
        by_label = {c["label"]: c for c in result["components"]}
        assert by_label["Web"]["group"] == "DMZ"
        assert by_label["DB"]["group"] == "DMZ"

    def test_swimlane_becomes_a_trust_boundary_with_its_members(self):
        result = parse_drawio_xml(GROUPED_XML)
        assert len(result["trust_boundaries"]) == 1
        boundary = result["trust_boundaries"][0]
        assert boundary["name"] == "DMZ"
        assert set(boundary["members"]) == {"Web", "DB"}

    def test_edge_inside_group_still_resolves(self):
        result = parse_drawio_xml(GROUPED_XML)
        assert {"label": "query", "from": "Web", "to": "DB"} in result["connections"]


class TestWrapperHandling:
    def test_mxfile_diagram_wrapper_is_unwrapped(self):
        wrapped = f"<mxfile><diagram>{FLAT_XML}</diagram></mxfile>"
        result = parse_drawio_xml(wrapped)
        assert len(result["components"]) == 3
        assert len(result["connections"]) == 2

    def test_well_formed_xml_without_graph_model_is_empty(self):
        result = parse_drawio_xml("<mxfile><diagram></diagram></mxfile>")
        assert result == {"components": [], "connections": [], "trust_boundaries": []}


class TestMalformedAndMaliciousInput:
    def test_empty_string_returns_empty_structures(self):
        assert parse_drawio_xml("") == {
            "components": [],
            "connections": [],
            "trust_boundaries": [],
        }

    def test_truncated_xml_returns_empty_structures(self):
        assert parse_drawio_xml("<bad xml") == {
            "components": [],
            "connections": [],
            "trust_boundaries": [],
        }

    def test_entity_expansion_is_blocked_not_expanded(self):
        # A billion-laughs / internal-entity payload: defusedxml must refuse the
        # DTD rather than expand it, and the parser must swallow the exception
        # and return empty structures — never an expanded/oversized document.
        billion_laughs = """<?xml version="1.0"?>
        <!DOCTYPE lolz [
          <!ENTITY lol "lol">
          <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;">
        ]>
        <mxGraphModel><root>
          <mxCell id="2" value="&lol1;" vertex="1" parent="1"/>
        </root></mxGraphModel>"""
        result = parse_drawio_xml(billion_laughs)
        assert result == {
            "components": [],
            "connections": [],
            "trust_boundaries": [],
        }


class TestDrawioToPromptSection:
    def test_empty_input_yields_empty_string(self):
        # Callers rely on truthiness to decide whether to inject the section.
        assert drawio_to_prompt_section("") == ""
        assert drawio_to_prompt_section("<bad xml") == ""

    def test_diagram_with_no_components_or_connections_yields_empty_string(self):
        assert drawio_to_prompt_section("<mxGraphModel><root/></mxGraphModel>") == ""

    def test_populated_section_lists_components_flows_and_boundaries(self):
        section = drawio_to_prompt_section(GROUPED_XML)
        assert "Components:" in section
        assert "Data Flows:" in section
        assert "Web -> DB" in section
        assert "Trust Boundaries / Security Zones:" in section
        assert "DMZ" in section
