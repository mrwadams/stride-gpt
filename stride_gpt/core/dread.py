"""Core DREAD risk assessment logic. Zero Streamlit imports."""

from __future__ import annotations

import json
import re

from stride_gpt.core.llm import call_llm
from stride_gpt.core.prompts import create_reasoning_system_prompt
from stride_gpt.core.schemas import LLMConfig, LLMResponse

from stride_gpt.models import model_uses_completion_tokens


def generate_dread_assessment(config: LLMConfig, prompt: str) -> tuple[dict, LLMResponse]:
    """Generate DREAD risk assessment. Returns (parsed_dict, response)."""
    system_prompt = _get_system_prompt(config)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]
    json_config = config.model_copy(update={"response_format": "json"})
    response = call_llm(json_config, messages)
    parsed = _parse_dread_response(response.content)
    return parsed, response


def dread_json_to_markdown(dread_assessment):
    # Create a clean Markdown table with proper spacing
    markdown_output = "| Threat Type | Scenario | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |\n"
    markdown_output += "|------------|----------|------------------|-----------------|----------------|----------------|-----------------|------------|\n"

    try:
        # Access the list of threats under the "Risk Assessment" key
        threats = dread_assessment.get("Risk Assessment", [])

        # If there are no threats, add a message row
        if not threats:
            markdown_output += "| No threats found | Please generate a threat model first | - | - | - | - | - | - |\n"
            return markdown_output

        for threat in threats:
            # Check if threat is a dictionary
            if isinstance(threat, dict):
                # Get values with defaults
                threat_type = threat.get("Threat Type", "N/A")
                scenario = threat.get("Scenario", "N/A")
                damage_potential = threat.get("Damage Potential", 0)
                reproducibility = threat.get("Reproducibility", 0)
                exploitability = threat.get("Exploitability", 0)
                affected_users = threat.get("Affected Users", 0)
                discoverability = threat.get("Discoverability", 0)

                # Calculate the Risk Score
                risk_score = (
                    damage_potential
                    + reproducibility
                    + exploitability
                    + affected_users
                    + discoverability
                ) / 5

                # Escape any pipe characters in text fields to prevent table formatting issues
                threat_type = str(threat_type).replace("|", "\\|")
                scenario = str(scenario).replace("|", "\\|")

                # Ensure scenario text doesn't break table formatting by removing newlines
                scenario = scenario.replace("\n", " ").replace("\r", "")

                # Add the row to the table with proper formatting
                markdown_output += f"| {threat_type} | {scenario} | {damage_potential} | {reproducibility} | {exploitability} | {affected_users} | {discoverability} | {risk_score:.2f} |\n"
            else:
                # Skip non-dictionary entries and log a warning
                markdown_output += "| Invalid threat | Threat data is not in the correct format | - | - | - | - | - | - |\n"
    except Exception:
        # Add a note about the error and a placeholder row
        markdown_output += "| Error | An error occurred while processing the DREAD assessment | - | - | - | - | - | - |\n"

    # Add a blank line after the table for better rendering
    markdown_output += "\n"
    return markdown_output


def _get_system_prompt(config: LLMConfig) -> str:
    if model_uses_completion_tokens(config.model_name):
        return create_reasoning_system_prompt(
            task_description="Perform a DREAD risk assessment for the identified security threats.",
            approach_description="""1. For each threat in the provided threat model:
   - Analyze the threat type and scenario in detail
   - Evaluate Damage Potential (1-10):
     * Consider direct and indirect damage
     * Assess financial, reputational, and operational impact
   - Evaluate Reproducibility (1-10):
     * Assess how reliably the attack can be reproduced
     * Consider required conditions and resources
   - Evaluate Exploitability (1-10):
     * Analyze technical complexity
     * Consider required skills and tools
   - Evaluate Affected Users (1-10):
     * Determine scope of impact
     * Consider both direct and indirect users
   - Evaluate Discoverability (1-10):
     * Assess how easily the vulnerability can be found
     * Consider visibility and detection methods
2. Format output as JSON with 'Risk Assessment' array containing:
   - Threat Type
   - Scenario
   - Numerical scores (1-10) for each DREAD category""",
        )
    return "You are a helpful assistant designed to output JSON."


def _parse_dread_response(content: str) -> dict:
    cleaned = _clean_json_content(content)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "Risk Assessment": [
                {
                    "Threat Type": "Error",
                    "Scenario": "Failed to parse DREAD assessment response",
                    "Damage Potential": 0,
                    "Reproducibility": 0,
                    "Exploitability": 0,
                    "Affected Users": 0,
                    "Discoverability": 0,
                }
            ]
        }


def _clean_json_content(content: str) -> str:
    if "```json" in content:
        content = re.sub(r"```json\s*", "", content)
        content = re.sub(r"```\s*$", "", content)
    elif "```" in content:
        content = re.sub(r"```\s*", "", content)
    content = content.replace(",\n  ]", "\n  ]").replace(",\n]", "\n]")
    content = re.sub(r"//.*?\n", "\n", content)
    return content.strip()
