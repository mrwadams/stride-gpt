"""Core attack tree generation logic. Zero Streamlit imports."""

from __future__ import annotations

import json
import re

from stride_gpt.core.llm import call_llm
from stride_gpt.core.prompts import (
    create_json_structure_prompt,
    create_reasoning_system_prompt,
)
from stride_gpt.core.schemas import LLMConfig, LLMResponse

GPT5_MODELS = {"gpt-5.2", "gpt-5-mini", "gpt-5-nano", "gpt-5.2-pro", "gpt-5"}


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
    if config.model_name in GPT5_MODELS:
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


def clean_json_response(response_text):
    """
    Clean JSON response by removing any markdown code block markers and finding the JSON content.

    Args:
        response_text (str): The raw response text that might contain JSON

    Returns:
        str: Cleaned JSON string
    """
    # Remove markdown JSON code block if present
    json_pattern = r"```json\s*(.*?)\s*```"
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()

    # If no JSON code block, try to find content between any code blocks
    code_pattern = r"```\s*(.*?)\s*```"
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()

    # If no code blocks, return the original text
    return response_text.strip()


def extract_mermaid_code(text):
    """
    Extract the Mermaid diagram code from text that may contain additional content.
    Looks for code between ```mermaid, ``` or just ``` tags, and extracts the graph content.
    Also cleans and validates the Mermaid syntax.

    Args:
        text (str): The text containing the Mermaid code

    Returns:
        str: The cleaned Mermaid code, or the original text if no code block is found
    """
    # Try to find code block with explicit mermaid tag
    mermaid_pattern = r"```mermaid\s*(graph[\s\S]*?)```"
    match = re.search(mermaid_pattern, text, re.MULTILINE)

    if not match:
        # Try to find any code block containing graph definition
        code_pattern = r"```\s*(graph[\s\S]*?)```"
        match = re.search(code_pattern, text, re.MULTILINE)

    code = match.group(1).strip() if match else text.strip()

    # Only proceed if we have a graph definition
    if not code.startswith("graph "):
        if "graph " in code:
            # Find the start of the graph definition
            code = code[code.find("graph "):]
        else:
            return text

    # Clean up common issues in Mermaid syntax
    return clean_mermaid_syntax(code)


def clean_mermaid_syntax(code):
    """
    Clean up common issues in Mermaid syntax.

    Args:
        code (str): The Mermaid code to clean

    Returns:
        str: The cleaned Mermaid code
    """
    # Ensure proper spacing around arrows
    code = re.sub(r"(\w+|\]|\)|\})(-->|==>|-.->)(\w+|\[|\(|\{)", r"\1 \2 \3", code)

    # Fix missing brackets around node labels
    def fix_node_brackets(match):
        node_id = match.group(1)
        if not any(c in node_id for c in "[](){}"):
            return f"{node_id}[{node_id}]"
        return node_id

    code = re.sub(r"(?:^|\s)(\w+)(?:\s|$)", fix_node_brackets, code)

    # Ensure node IDs with spaces are properly quoted
    def quote_node_labels(match):
        label = match.group(1)
        if " " in label and not label.startswith('"'):
            return f'["{label}"]'
        return f"[{label}]"

    code = re.sub(r"\[(.*?)\]", quote_node_labels, code)

    # Fix parentheses in node labels
    def fix_parentheses(match):
        label = match.group(1)
        if "(" in label or ")" in label:
            return f'["{label}"]'
        return f"[{label}]"

    code = re.sub(r"\[(.*?)\]", fix_parentheses, code)

    # Ensure proper line endings
    return code.replace("\r\n", "\n").strip()
