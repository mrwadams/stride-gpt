"""Core threat model generation logic. Zero Streamlit imports."""

from __future__ import annotations

import json
import re

from stride_gpt.core.llm import call_llm, call_llm_with_image
from stride_gpt.core.prompts import create_image_analysis_prompt, create_reasoning_system_prompt
from stride_gpt.core.schemas import LLMConfig, LLMResponse, ThreatModelOutput

from stride_gpt.models import model_uses_completion_tokens


THREAT_MODEL_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "threat_model": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "Threat Type": {"type": "string"},
                    "Scenario": {"type": "string"},
                    "Potential Impact": {"type": "string"},
                    "OWASP_LLM": {"type": ["string", "null"]},
                    "OWASP_ASI": {"type": ["string", "null"]},
                    "INSIDER_CATEGORY": {"type": ["string", "null"]},
                },
                "required": ["Threat Type", "Scenario", "Potential Impact"],
            },
        },
        "improvement_suggestions": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["threat_model", "improvement_suggestions"],
}


def generate_threat_model(config: LLMConfig, prompt: str) -> tuple[ThreatModelOutput, LLMResponse]:
    """Generate a threat model using any supported LLM provider."""
    system_prompt = _get_system_prompt(config)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]
    # LM Studio doesn't support json_object mode — without an explicit schema it
    # gets no structured-output enforcement at all and frequently emits prose
    # that fails JSON parsing. Hand it the schema; other providers keep the
    # existing json_object path to avoid regressions in callers that depend on it.
    if config.provider == "LM Studio Server":
        json_config = config.model_copy(update={"response_format": THREAT_MODEL_SCHEMA})
    else:
        json_config = config.model_copy(update={"response_format": "json"})
    response = call_llm(json_config, messages)
    parsed = _parse_threat_model_response(response.content)
    return parsed, response


def analyze_image(
    config: LLMConfig,
    base64_image: str,
    media_type: str = "image/jpeg",
) -> LLMResponse:
    """Analyze an architecture diagram image."""
    prompt = create_image_analysis_prompt()
    return call_llm_with_image(config, prompt, base64_image, media_type)


def json_to_markdown(threat_model, improvement_suggestions):
    """Render a single-shot threat model as markdown.

    Optional columns (OWASP LLM, OWASP ASI, Insider Category) appear only when
    at least one threat carries a value for them — same conditional shape as
    the agent's per-subsystem renderer, via shared helpers.
    """
    from stride_gpt.core.report_utils import (
        detect_extra_columns,
        threat_table_header,
        threat_table_row,
    )

    show_llm, show_asi, show_insider = detect_extra_columns(threat_model)
    header, separator = threat_table_header(show_llm, show_asi, show_insider)

    lines = ["## Threat Model", "", header, separator]
    for threat in threat_model:
        lines.append(threat_table_row(threat, show_llm, show_asi, show_insider))

    lines.extend(["", "", "## Improvement Suggestions", ""])
    for suggestion in improvement_suggestions:
        lines.append(f"- {suggestion}")
    lines.append("")

    return "\n".join(lines)


def _get_system_prompt(config: LLMConfig) -> str:
    if model_uses_completion_tokens(config.model_name):
        return create_reasoning_system_prompt(
            task_description="Analyze the provided application description and generate a comprehensive threat model using the STRIDE methodology.",
            approach_description="""1. Carefully read and understand the application description
2. For each component and data flow:
   - Identify potential Spoofing threats
   - Identify potential Tampering threats
   - Identify potential Repudiation threats
   - Identify potential Information Disclosure threats
   - Identify potential Denial of Service threats
   - Identify potential Elevation of Privilege threats
3. For each identified threat:
   - Describe the specific scenario
   - Analyze the potential impact
4. Generate improvement suggestions based on identified threats
5. Format the output as a JSON object with 'threat_model' and 'improvement_suggestions' arrays""",
        )
    return "You are a helpful assistant designed to output JSON."


def _parse_threat_model_response(content: str) -> ThreatModelOutput:
    cleaned = _clean_json_content(content)
    try:
        data = json.loads(cleaned)
        return ThreatModelOutput(
            threat_model=data.get("threat_model", []),
            improvement_suggestions=data.get("improvement_suggestions", []),
        )
    except json.JSONDecodeError as e:
        raw = (content or "").strip()
        snippet = raw[:500].replace("\n", " ").replace("|", "\\|") or "(empty response)"
        truncated = " ..." if len(raw) > 500 else ""
        return ThreatModelOutput(
            threat_model=[
                {
                    "Threat Type": "Error",
                    "Scenario": "Failed to parse LLM response as JSON",
                    "Potential Impact": "Unable to generate threat model",
                }
            ],
            improvement_suggestions=[
                f"JSON parse error: {e.msg} (line {e.lineno}, col {e.colno})",
                f"Raw LLM response (first 500 chars): {snippet}{truncated}",
                "Try again — local models sometimes need a second attempt to produce valid JSON",
            ],
        )


def _clean_json_content(content: str) -> str:
    if "```json" in content:
        content = re.sub(r"```json\s*", "", content)
        content = re.sub(r"```\s*$", "", content)
    elif "```" in content:
        content = re.sub(r"```\s*", "", content)
    content = content.replace(",\n  ]", "\n  ]").replace(",\n]", "\n]")
    content = re.sub(r"//.*?\n", "\n", content)
    return content.strip()
