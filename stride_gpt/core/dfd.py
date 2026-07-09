"""Core Data Flow Diagram (DFD) generation logic. Zero Streamlit imports.

Mirrors the shape of `core/attack_tree.py`: build a prompt, call the LLM
asking for structured JSON, then convert the JSON into Mermaid `flowchart`
syntax. Trust boundaries render as Mermaid `subgraph` blocks with dashed
styling — the threat-modelling convention.

Two entry points:

- `generate_dfd(config, prompt)` — produce a DFD from a textual application
  description.
- `parse_dfd_from_image(config, base64_image, media_type)` — parse a
  user-uploaded DFD image (PNG/JPEG) into the same canonical JSON form,
  then render to Mermaid. Used by the iterative workflow so users can
  upload an existing DFD as input.
"""

from __future__ import annotations

import json
import re

from stride_gpt.core.llm import call_llm, call_llm_with_image
from stride_gpt.core.mermaid_utils import clean_json_response, extract_mermaid_code
from stride_gpt.core.prompts.builder import (
    create_dfd_image_analysis_prompt,
    create_reasoning_system_prompt,
)
from stride_gpt.core.schemas import LLMConfig, LLMResponse
from stride_gpt.models import model_uses_completion_tokens

VALID_NODE_TYPES = ("external_entity", "process", "data_store")


DFD_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "nodes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "label": {"type": "string"},
                    "type": {"enum": list(VALID_NODE_TYPES)},
                },
                "required": ["id", "label", "type"],
            },
        },
        "edges": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "label": {"type": "string"},
                },
                "required": ["from", "to", "label"],
            },
        },
        "trust_boundaries": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "node_ids": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["name", "node_ids"],
            },
        },
    },
    "required": ["nodes", "edges"],
}


def generate_dfd(config: LLMConfig, prompt: str) -> tuple[str, LLMResponse]:
    """Generate a DFD as Mermaid code. Returns (mermaid_string, response)."""
    system_prompt = _get_system_prompt(config)
    json_config = config.model_copy(update={"response_format": "json"})
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]
    response = call_llm(json_config, messages)
    mermaid = _parse_dfd_response(response.content)
    return mermaid, response


def parse_dfd_from_image(
    config: LLMConfig, base64_image: str, media_type: str = "image/png"
) -> tuple[str, LLMResponse]:
    """Vision-parse an uploaded DFD image into the canonical Mermaid form.

    Returns (mermaid_string, response). The vision provider is asked for
    JSON conforming to `DFD_SCHEMA`; the same fallback parser as
    `generate_dfd` covers cases where the model returns Mermaid directly.
    """
    prompt = create_dfd_image_analysis_prompt()
    # call_llm_with_image takes the prompt as a positional arg and routes
    # provider-specific multimodal kwargs internally. JSON response_format
    # is set on the config so json-mode is respected where supported.
    json_config = config.model_copy(update={"response_format": "json"})
    response = call_llm_with_image(json_config, prompt, base64_image, media_type)
    mermaid = _parse_dfd_response(response.content)
    return mermaid, response


def _get_system_prompt(config: LLMConfig) -> str:
    """Reasoning-model variant gets explicit step-by-step framing."""
    if model_uses_completion_tokens(config.model_name):
        return create_reasoning_system_prompt(
            task_description=(
                "Produce a Data Flow Diagram (DFD) for threat modelling as "
                "structured JSON."
            ),
            approach_description=_DFD_RULES_BLOCK,
        )
    return _DFD_BASE_PROMPT


_DFD_RULES_BLOCK = """Analyse the application and emit a JSON object describing the system as a Data Flow Diagram.

Rules:
- Use simple alphanumeric IDs (user, web, api, db, etc.) — no spaces or hyphens.
- Every node has a `type`: "external_entity" (actors / 3rd-party services), "process" (application components doing work), or "data_store" (databases, caches, queues, blob stores).
- Every edge has a descriptive `label` naming the data crossing it (e.g. "Login credentials", "Encrypted session token").
- Group nodes inside the same trust zone with `trust_boundaries` (e.g. "Internal VPC", "Browser/Untrusted").
- Cover the whole system — every external entity, process, data store, and the flows between them.
- Output JSON only — no commentary.

Example shape:
{
    "nodes": [
        {"id": "user",  "label": "End User",        "type": "external_entity"},
        {"id": "web",   "label": "Web Frontend",    "type": "process"},
        {"id": "api",   "label": "API Server",      "type": "process"},
        {"id": "db",    "label": "User Database",   "type": "data_store"}
    ],
    "edges": [
        {"from": "user", "to": "web", "label": "Login credentials"},
        {"from": "web",  "to": "api", "label": "Auth request"},
        {"from": "api",  "to": "db",  "label": "User lookup"},
        {"from": "db",   "to": "api", "label": "Hashed password"}
    ],
    "trust_boundaries": [
        {"name": "Internal Network", "node_ids": ["api", "db"]}
    ]
}

ONLY RESPOND WITH THE JSON STRUCTURE, NO ADDITIONAL TEXT."""


_DFD_BASE_PROMPT = "Your task is to model the application as a Data Flow Diagram for threat modelling.\n\n" + _DFD_RULES_BLOCK


def _parse_dfd_response(content: str) -> str:
    """JSON-first, Mermaid-fallback parser.

    The configured response_format=json should give us a JSON object, but
    a few providers (LM Studio, Groq with DeepSeek) sometimes emit raw
    Mermaid inside a code fence. Try the structured path first and fall
    back to extracting Mermaid directly.
    """
    try:
        cleaned = clean_json_response(content)
        dfd_data = json.loads(cleaned)
        return convert_dfd_to_mermaid(dfd_data)
    except (json.JSONDecodeError, KeyError, TypeError):
        return extract_mermaid_code(content, start_keywords=("flowchart", "graph"))


def convert_dfd_to_mermaid(dfd_data: dict) -> str:
    """Render the canonical DFD JSON form into Mermaid `flowchart TD` syntax.

    Node shapes follow DFD-on-Mermaid convention:
    - external_entity -> `[Label]`   (rectangle)
    - process         -> `((Label))` (circle)
    - data_store      -> `[(Label)]` (cylinder)

    Trust boundaries become Mermaid `subgraph` blocks with dashed styling
    applied via a `classDef` on each boundary.
    """
    nodes = dfd_data.get("nodes", [])
    edges = dfd_data.get("edges", [])
    boundaries = dfd_data.get("trust_boundaries", []) or []

    # Index nodes for shape lookup + which boundary they live in.
    node_lookup: dict[str, dict] = {n["id"]: n for n in nodes if "id" in n}
    boundary_for: dict[str, int] = {}
    for idx, b in enumerate(boundaries):
        for nid in b.get("node_ids", []) or []:
            boundary_for[nid] = idx

    lines: list[str] = ["flowchart TD"]

    # Emit nodes inside their boundary subgraph, then loose nodes outside.
    for idx, boundary in enumerate(boundaries):
        boundary_name = boundary.get("name", f"Trust Boundary {idx + 1}")
        safe_name = _sanitize_label(boundary_name)
        lines.append(f'    subgraph tb{idx}["{safe_name}"]')
        for nid in boundary.get("node_ids", []) or []:
            node = node_lookup.get(nid)
            if node is None:
                continue
            lines.append("        " + _render_node(node))
        lines.append("    end")

    for node in nodes:
        if node.get("id") in boundary_for:
            continue
        lines.append("    " + _render_node(node))

    for edge in edges:
        src = edge.get("from")
        dst = edge.get("to")
        if not src or not dst:
            continue
        label = edge.get("label", "")
        if label:
            lines.append(f'    {src} -->|{_sanitize_label(label)}| {dst}')
        else:
            lines.append(f"    {src} --> {dst}")

    # Dashed trust-boundary styling so they read as boundaries, not groups.
    if boundaries:
        lines.append("    classDef trustBoundary stroke-dasharray: 5 5,fill:transparent;")
        lines.extend(f"    class tb{idx} trustBoundary;" for idx in range(len(boundaries)))

    return "\n".join(lines)


def _render_node(node: dict) -> str:
    node_id = node["id"]
    label = _sanitize_label(node.get("label", node_id))
    node_type = node.get("type", "process")
    if node_type == "external_entity":
        return f'{node_id}["{label}"]'
    if node_type == "data_store":
        return f'{node_id}[("{label}")]'
    # process (default)
    return f'{node_id}(("{label}"))'


def _sanitize_label(label: str) -> str:
    """Strip characters that confuse Mermaid label parsing.

    Mermaid treats `"`, `|`, and unescaped brackets as syntax. We replace
    them with safe equivalents rather than failing the render.
    """
    cleaned = re.sub(r'["|`]', "'", str(label))
    return cleaned.replace("\n", " ").strip()
