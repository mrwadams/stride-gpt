"""Shared helpers for LLM → JSON → Mermaid conversion.

Used by both `core/attack_tree.py` and `core/dfd.py`. Kept provider-agnostic
and free of Streamlit imports.
"""

from __future__ import annotations

import re


def clean_json_response(response_text: str) -> str:
    """Strip markdown code fences from an LLM response, returning the JSON body."""
    json_pattern = r"```json\s*(.*?)\s*```"
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()

    code_pattern = r"```\s*(.*?)\s*```"
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()

    return response_text.strip()


def extract_mermaid_code(text: str, start_keywords: tuple[str, ...] = ("graph", "flowchart")) -> str:
    """Pull a Mermaid diagram out of free-form text.

    Looks for fenced ```mermaid ... ``` or plain ``` ... ``` blocks containing
    one of the recognised diagram keywords. Falls through to the original
    text if nothing usable is found.
    """
    keyword_alternation = "|".join(re.escape(k) for k in start_keywords)
    mermaid_pattern = rf"```mermaid\s*((?:{keyword_alternation})[\s\S]*?)```"
    match = re.search(mermaid_pattern, text, re.MULTILINE)

    if not match:
        code_pattern = rf"```\s*((?:{keyword_alternation})[\s\S]*?)```"
        match = re.search(code_pattern, text, re.MULTILINE)

    code = match.group(1).strip() if match else text.strip()

    starts_with_keyword = any(code.startswith(f"{k} ") for k in start_keywords)
    if not starts_with_keyword:
        for keyword in start_keywords:
            marker = f"{keyword} "
            if marker in code:
                code = code[code.find(marker):]
                starts_with_keyword = True
                break
        if not starts_with_keyword:
            return text

    return clean_mermaid_syntax(code)


def clean_mermaid_syntax(code: str) -> str:
    """Best-effort cleanup of arrow spacing and bracketing in LLM-generated Mermaid."""
    code = re.sub(r"(\w+|\]|\)|\})(-->|==>|-.->)(\w+|\[|\(|\{)", r"\1 \2 \3", code)

    def fix_node_brackets(match: re.Match[str]) -> str:
        node_id = match.group(1)
        if not any(c in node_id for c in "[](){}"):
            return f"{node_id}[{node_id}]"
        return node_id

    code = re.sub(r"(?:^|\s)(\w+)(?:\s|$)", fix_node_brackets, code)

    def quote_node_labels(match: re.Match[str]) -> str:
        label = match.group(1)
        if " " in label and not label.startswith('"'):
            return f'["{label}"]'
        return f"[{label}]"

    code = re.sub(r"\[(.*?)\]", quote_node_labels, code)

    def fix_parentheses(match: re.Match[str]) -> str:
        label = match.group(1)
        if "(" in label or ")" in label:
            return f'["{label}"]'
        return f"[{label}]"

    code = re.sub(r"\[(.*?)\]", fix_parentheses, code)

    return code.replace("\r\n", "\n").strip()
