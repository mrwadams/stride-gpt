"""Tests for stride_gpt.core.attack_tree — structured-tree -> Mermaid
conversion and the parse/fallback path. Pure functions, no LLM calls."""

from __future__ import annotations

from stride_gpt.core.attack_tree import (
    _parse_attack_tree_response,
    convert_tree_to_mermaid,
)

# ---------------------------------------------------------------------------
# convert_tree_to_mermaid
# ---------------------------------------------------------------------------


class TestConvertTreeToMermaid:
    def test_nested_tree_emits_nodes_and_edges(self):
        tree = {
            "nodes": [
                {
                    "id": "A1",
                    "label": "Root",
                    "children": [
                        {"id": "B1", "label": "Child", "children": []},
                    ],
                }
            ]
        }
        result = convert_tree_to_mermaid(tree)
        assert result.startswith("graph TD")
        assert "A1[Root]" in result
        assert "A1 --> B1" in result

    def test_label_with_spaces_is_quoted(self):
        tree = {"nodes": [{"id": "A1", "label": "Compromise Application", "children": []}]}
        result = convert_tree_to_mermaid(tree)
        assert 'A1["Compromise Application"]' in result

    def test_label_with_parens_is_quoted(self):
        tree = {"nodes": [{"id": "A1", "label": "Brute(force)", "children": []}]}
        result = convert_tree_to_mermaid(tree)
        assert 'A1["Brute(force)"]' in result

    def test_root_without_children_has_no_edge(self):
        tree = {"nodes": [{"id": "A1", "label": "Lonely", "children": []}]}
        result = convert_tree_to_mermaid(tree)
        assert "A1[Lonely]" in result
        assert "-->" not in result

    def test_multi_level_chain(self):
        tree = {
            "nodes": [
                {
                    "id": "A1",
                    "label": "L1",
                    "children": [
                        {
                            "id": "B1",
                            "label": "L2",
                            "children": [{"id": "C1", "label": "L3", "children": []}],
                        }
                    ],
                }
            ]
        }
        result = convert_tree_to_mermaid(tree)
        assert "A1 --> B1" in result
        assert "B1 --> C1" in result


# ---------------------------------------------------------------------------
# _parse_attack_tree_response — JSON path + fallback
# ---------------------------------------------------------------------------


class TestParseAttackTreeResponse:
    def test_valid_json_converts_to_mermaid(self):
        content = '{"nodes": [{"id": "A1", "label": "Root", "children": []}]}'
        result = _parse_attack_tree_response(content)
        assert result.startswith("graph TD")
        assert "A1[Root]" in result

    def test_malformed_json_falls_back_to_mermaid_extraction(self):
        """When the JSON can't be parsed, the parser falls back to pulling the
        Mermaid block out of the response text rather than raising. The node
        content from the fenced block survives into the result."""
        content = "Here is your tree:\n```mermaid\ngraph TD\n    A1[Root]\n```"
        result = _parse_attack_tree_response(content)
        assert "A1[Root]" in result
