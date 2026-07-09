"""Parse draw.io XML (mxGraphModel format) into structured text for LLM prompts.

Only handles uncompressed XML — which is what the diagrams.net embed API exports.
Compressed .drawio files (base64+deflate) are not supported; the embed component
always returns raw XML so this is fine in practice.
"""
from __future__ import annotations

from xml.etree.ElementTree import ParseError

from defusedxml.ElementTree import fromstring as _safe_fromstring
from defusedxml.common import DefusedXmlException


def parse_drawio_xml(xml: str) -> dict:
    """Extract components, connections, and trust boundaries from draw.io XML.

    Returns:
        {
          "components":       [{"id": str, "label": str, "group": str|None}],
          "connections":      [{"label": str, "from": str, "to": str}],
          "trust_boundaries": [{"name": str, "members": [str]}],
        }
    All lists are empty on parse error.
    """
    try:
        # defusedxml blocks entity-expansion / DTD / external-entity attacks on
        # this untrusted, user-supplied XML; malformed input raises ParseError.
        root = _safe_fromstring(xml.strip())
    except (ParseError, DefusedXmlException):
        return {"components": [], "connections": [], "trust_boundaries": []}

    # Support both bare <mxGraphModel> and <mxfile><diagram>...<mxGraphModel> wrappers.
    graph_model = root if root.tag == "mxGraphModel" else root.find(".//mxGraphModel")
    if graph_model is None:
        return {"components": [], "connections": [], "trust_boundaries": []}

    cells = graph_model.findall(".//mxCell")

    # Build id → (label, parent, style) lookup
    id_label: dict[str, str] = {}
    id_parent: dict[str, str] = {}
    id_style: dict[str, str] = {}
    for c in cells:
        cid = c.get("id", "")
        id_label[cid] = (c.get("value") or "").strip()
        id_parent[cid] = c.get("parent", "")
        id_style[cid] = (c.get("style") or "").lower()

    # Identify group cells (swimlane or any vertex that acts as parent).
    # pontytail: O(n) scan; fine for any diagram a human would draw.
    parent_count: dict[str, int] = {}
    for c in cells:
        p = c.get("parent", "")
        if p not in ("0", "1"):
            parent_count[p] = parent_count.get(p, 0) + 1

    group_ids: set[str] = {
        cid
        for cid, style in id_style.items()
        if "swimlane" in style or cid in parent_count
    }

    # Components: labeled vertices that are not root/default-layer cells.
    components = []
    for c in cells:
        cid = c.get("id", "")
        if cid in ("0", "1") or c.get("vertex") != "1":
            continue
        label = id_label.get(cid, "")
        if not label:
            continue
        parent = id_parent.get(cid, "")
        group_label = id_label.get(parent, "") if parent not in ("0", "1") else ""
        components.append({
            "id": cid,
            "label": label,
            "group": group_label or None,
        })

    # Connections: edge cells with source+target.
    connections = []
    for c in cells:
        if c.get("edge") != "1":
            continue
        src_id = c.get("source", "")
        tgt_id = c.get("target", "")
        src = id_label.get(src_id, src_id) or src_id
        tgt = id_label.get(tgt_id, tgt_id) or tgt_id
        if src and tgt:
            connections.append({
                "label": (c.get("value") or "").strip(),
                "from": src,
                "to": tgt,
            })

    # Trust boundaries: labeled group cells with their direct vertex children.
    trust_boundaries = []
    for gid in group_ids:
        name = id_label.get(gid, "").strip()
        if not name:
            continue
        members = [
            id_label[c.get("id", "")]
            for c in cells
            if c.get("parent") == gid
            and c.get("vertex") == "1"
            and id_label.get(c.get("id", ""), "").strip()
        ]
        trust_boundaries.append({"name": name, "members": members})

    return {
        "components": components,
        "connections": connections,
        "trust_boundaries": trust_boundaries,
    }


def drawio_to_prompt_section(xml: str) -> str:
    """Convert draw.io XML to a structured prompt section for threat modelling.

    Returns an empty string if the XML has no useful content (parse error,
    empty diagram, etc.) so callers can safely check truthiness.
    """
    parsed = parse_drawio_xml(xml)
    if not parsed["components"] and not parsed["connections"]:
        return ""

    lines = [
        "ARCHITECTURE DIAGRAM (from draw.io):",
        "The user created the following architecture diagram. Use it as the",
        "authoritative model of components and data flows when identifying threats.",
        "",
    ]

    if parsed["components"]:
        lines.append("Components:")
        for comp in parsed["components"]:
            entry = f"  - {comp['label']}"
            if comp["group"]:
                entry += f"  [zone: {comp['group']}]"
            lines.append(entry)
        lines.append("")

    if parsed["connections"]:
        lines.append("Data Flows:")
        for conn in parsed["connections"]:
            arrow = f"  {conn['from']} -> {conn['to']}"
            if conn["label"]:
                arrow += f"  ({conn['label']})"
            lines.append(arrow)
        lines.append("")

    if parsed["trust_boundaries"]:
        lines.append("Trust Boundaries / Security Zones:")
        for tb in parsed["trust_boundaries"]:
            members = ", ".join(tb["members"]) if tb["members"] else "—"
            lines.append(f"  - {tb['name']}: {members}")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    _SAMPLE = """<mxGraphModel><root>
      <mxCell id="0"/><mxCell id="1" parent="0"/>
      <mxCell id="2" value="User" vertex="1" parent="1" style="ellipse;"><mxGeometry/></mxCell>
      <mxCell id="3" value="Web App" vertex="1" parent="1" style="rounded=1;"><mxGeometry/></mxCell>
      <mxCell id="4" value="Database" vertex="1" parent="1" style="shape=cylinder;"><mxGeometry/></mxCell>
      <mxCell id="5" value="HTTPS" edge="1" source="2" target="3" parent="1"><mxGeometry/></mxCell>
      <mxCell id="6" value="SQL" edge="1" source="3" target="4" parent="1"><mxGeometry/></mxCell>
    </root></mxGraphModel>"""

    _r = parse_drawio_xml(_SAMPLE)
    assert len(_r["components"]) == 3, f"Expected 3 components, got {len(_r['components'])}"
    assert len(_r["connections"]) == 2, f"Expected 2 connections, got {len(_r['connections'])}"

    _section = drawio_to_prompt_section(_SAMPLE)
    assert "User" in _section
    assert "HTTPS" in _section
    assert "->" in _section

    # Empty/invalid XML returns empty string without crashing.
    assert drawio_to_prompt_section("") == ""
    assert drawio_to_prompt_section("<bad xml") == ""

    print("All assertions passed.\n")
    print(_section)
