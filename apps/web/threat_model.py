from stride_gpt.core.prompts import (
    create_agentic_stride_prompt_section,
    create_llm_stride_prompt_section,
    create_threat_model_prompt,
)

__all__ = [
    "create_agentic_stride_prompt_section",
    "create_llm_stride_prompt_section",
    "create_threat_model_prompt",
    "json_to_markdown",
]


def _md_cell(value) -> str:
    """Escape an LLM-supplied value for safe inclusion in a markdown table.

    Pipes break out of the column; newlines break out of the row entirely and
    let the model inject markdown beneath the table.
    """
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


# Function to convert JSON to Markdown for display.
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
                f"| {_md_cell(threat['Threat Type'])} | {_md_cell(threat['Scenario'])} | {_md_cell(threat['Potential Impact'])} | {_md_cell(owasp_llm)} | {_md_cell(owasp_asi)} |\n"
            )
    elif has_owasp_llm:
        # Table with OWASP LLM column only (GenAI applications)
        markdown_output += "| Threat Type | Scenario | Potential Impact | OWASP LLM |\n"
        markdown_output += "|-------------|----------|------------------|------------|\n"
        for threat in threat_model:
            owasp_llm = threat.get("OWASP_LLM") or "-"
            markdown_output += (
                f"| {_md_cell(threat['Threat Type'])} | {_md_cell(threat['Scenario'])} | {_md_cell(threat['Potential Impact'])} | {_md_cell(owasp_llm)} |\n"
            )
    elif has_owasp_asi:
        # Table with OWASP ASI column only (edge case)
        markdown_output += "| Threat Type | Scenario | Potential Impact | OWASP ASI |\n"
        markdown_output += "|-------------|----------|------------------|------------|\n"
        for threat in threat_model:
            owasp_asi = threat.get("OWASP_ASI") or "-"
            markdown_output += (
                f"| {_md_cell(threat['Threat Type'])} | {_md_cell(threat['Scenario'])} | {_md_cell(threat['Potential Impact'])} | {_md_cell(owasp_asi)} |\n"
            )
    else:
        # Standard table without OWASP columns
        markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
        markdown_output += "|-------------|----------|------------------|\n"
        for threat in threat_model:
            markdown_output += (
                f"| {_md_cell(threat['Threat Type'])} | {_md_cell(threat['Scenario'])} | {_md_cell(threat['Potential Impact'])} |\n"
            )

    markdown_output += "\n\n## Improvement Suggestions\n\n"
    for suggestion in improvement_suggestions:
        markdown_output += f"- {_md_cell(suggestion)}\n"

    return markdown_output
