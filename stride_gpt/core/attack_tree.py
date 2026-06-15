"""Core attack tree generation logic. Zero Streamlit imports."""

from __future__ import annotations

import json

from stride_gpt.core.llm import call_llm
from stride_gpt.core.mermaid_utils import (
    clean_json_response,
    clean_mermaid_syntax,
    extract_mermaid_code,
)
from stride_gpt.core.prompts import (
    create_json_structure_prompt,
    create_reasoning_system_prompt,
)
from stride_gpt.core.schemas import LLMConfig, LLMResponse

from stride_gpt.models import model_uses_completion_tokens

__all__ = [
    "clean_json_response",
    "clean_mermaid_syntax",
    "convert_tree_to_mermaid",
    "extract_mermaid_code",
    "generate_attack_tree",
]


def generate_attack_tree(config: LLMConfig, prompt: str) -> tuple[str, LLMResponse]:
    """Generate attack tree as Mermaid code. Returns (mermaid_string, response)."""
    system_prompt = _get_system_prompt(config)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]
    response = call_llm(config, messages)
    mermaid = _parse_attack_tree_response(response.content)
    return mermaid, response


def _get_system_prompt(config: LLMConfig) -> str:
    if model_uses_completion_tokens(config.model_name):
        return create_reasoning_system_prompt(
            task_description="Create a structured attack tree by analyzing potential attack paths.",
            approach_description="""Analyze the application and create an attack tree showing potential attack paths.

Rules:
- Use simple alphanumeric IDs (A1, A2, B1, etc.)
- Make labels clear and descriptive
- Include all attack paths and sub-paths
- Maintain proper parent-child relationships
- Ensure proper JSON structure

Example format:
{
    "nodes": [
        {
            "id": "A1",
            "label": "Compromise Application",
            "children": [
                {
                    "id": "B1",
                    "label": "Exploit Authentication Vulnerabilities",
                    "children": [
                        {
                            "id": "C1",
                            "label": "Brute Force Credentials",
                            "children": []
                        }
                    ]
                }
            ]
        }
    ]
}

ONLY RESPOND WITH THE JSON STRUCTURE, NO ADDITIONAL TEXT.""",
        )
    return create_json_structure_prompt()


def _parse_attack_tree_response(content: str) -> str:
    try:
        cleaned = clean_json_response(content)
        tree_data = json.loads(cleaned)
        return convert_tree_to_mermaid(tree_data)
    except (json.JSONDecodeError, KeyError, TypeError):
        return extract_mermaid_code(content)


def convert_tree_to_mermaid(tree_data):
    """
    Convert structured tree data to Mermaid syntax.

    Args:
        tree_data (dict): Dictionary containing the tree structure

    Returns:
        str: Mermaid diagram code
    """
    mermaid_lines = ["graph TD"]

    def process_node(node, parent_id=None):
        node_id = node["id"]
        node_label = node["label"]

        # Add quotes if label contains spaces or parentheses
        if " " in node_label or "(" in node_label or ")" in node_label:
            node_label = f'"{node_label}"'

        # Add the node definition
        mermaid_lines.append(f"    {node_id}[{node_label}]")

        # Add connection to parent if exists
        if parent_id:
            mermaid_lines.append(f"    {parent_id} --> {node_id}")

        # Process children
        if "children" in node:
            for child in node["children"]:
                process_node(child, node_id)

    # Process the root node(s)
    for root_node in tree_data["nodes"]:
        process_node(root_node)

    # Join lines with newlines
    return "\n".join(mermaid_lines)


# clean_json_response, extract_mermaid_code, and clean_mermaid_syntax now
# live in stride_gpt.core.mermaid_utils — re-exported above for callers that
# still import them from this module.
