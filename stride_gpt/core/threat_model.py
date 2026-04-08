"""Core threat model generation logic. Zero Streamlit imports."""

from __future__ import annotations

import json
import re

from stride_gpt.core.llm import call_llm, call_llm_with_image
from stride_gpt.core.prompts import create_image_analysis_prompt, create_reasoning_system_prompt
from stride_gpt.core.schemas import LLMConfig, LLMResponse, ThreatModelOutput

# GPT-5 series models needing special system prompts
GPT5_MODELS = {"gpt-5.2", "gpt-5-mini", "gpt-5-nano", "gpt-5.2-pro", "gpt-5"}


def generate_threat_model(config: LLMConfig, prompt: str) -> tuple[ThreatModelOutput, LLMResponse]:
    """Generate a threat model using any supported LLM provider."""
    system_prompt = _get_system_prompt(config)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]
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
    markdown_output = "## Threat Model\n\n"

    # Check which OWASP fields are present
    has_owasp_llm = any(threat.get("OWASP_LLM") for threat in threat_model)
    has_owasp_asi = any(threat.get("OWASP_ASI") for threat in threat_model)

    if has_owasp_llm and has_owasp_asi:
        # Full table with both OWASP columns (agentic applications)
        markdown_output += "| Threat Type | Scenario | Potential Impact | OWASP LLM | OWASP ASI |\n"
        markdown_output += "|-------------|----------|------------------|-----------|------------|\n"
        for threat in threat_model:
            owasp_llm = threat.get("OWASP_LLM") or "-"
            owasp_asi = threat.get("OWASP_ASI") or "-"
            markdown_output += (
                f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} | {owasp_llm} | {owasp_asi} |\n"
            )
    elif has_owasp_llm:
        # Table with OWASP LLM column only (GenAI applications)
        markdown_output += "| Threat Type | Scenario | Potential Impact | OWASP LLM |\n"
        markdown_output += "|-------------|----------|------------------|------------|\n"
        for threat in threat_model:
            owasp_llm = threat.get("OWASP_LLM") or "-"
            markdown_output += (
                f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} | {owasp_llm} |\n"
            )
    elif has_owasp_asi:
        # Table with OWASP ASI column only (edge case)
        markdown_output += "| Threat Type | Scenario | Potential Impact | OWASP ASI |\n"
        markdown_output += "|-------------|----------|------------------|------------|\n"
        for threat in threat_model:
            owasp_asi = threat.get("OWASP_ASI") or "-"
            markdown_output += (
                f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} | {owasp_asi} |\n"
            )
    else:
        # Standard table without OWASP columns
        markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
        markdown_output += "|-------------|----------|------------------|\n"
        for threat in threat_model:
            markdown_output += (
                f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"
            )

    markdown_output += "\n\n## Improvement Suggestions\n\n"
    for suggestion in improvement_suggestions:
        markdown_output += f"- {suggestion}\n"

    return markdown_output


def _get_system_prompt(config: LLMConfig) -> str:
    if config.model_name in GPT5_MODELS:
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
    except json.JSONDecodeError:
        return ThreatModelOutput(
            threat_model=[
                {
                    "Threat Type": "Error",
                    "Scenario": "Failed to parse LLM response",
                    "Potential Impact": "Unable to generate threat model",
                }
            ],
            improvement_suggestions=[
                "Try again - sometimes the model returns a properly formatted response on subsequent attempts",
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
