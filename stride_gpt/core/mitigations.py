"""Core mitigations generation logic. Zero Streamlit imports."""

from __future__ import annotations

from stride_gpt.core.llm import call_llm
from stride_gpt.core.prompts import create_reasoning_system_prompt
from stride_gpt.core.schemas import LLMConfig, LLMResponse

from stride_gpt.models import model_uses_completion_tokens


def generate_mitigations(config: LLMConfig, prompt: str) -> tuple[str, LLMResponse]:
    """Generate threat mitigations. Returns (markdown_string, response)."""
    system_prompt = _get_system_prompt(config)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]
    response = call_llm(config, messages)
    return response.content, response


def _get_system_prompt(config: LLMConfig) -> str:
    if model_uses_completion_tokens(config.model_name):
        return create_reasoning_system_prompt(
            task_description="Generate effective security mitigations for the identified threats using the STRIDE methodology.",
            approach_description="""1. Analyze each threat in the provided threat model
2. For each threat:
   - Understand the threat type and scenario
   - Consider the potential impact
   - Identify appropriate security controls and mitigations
   - Ensure mitigations are specific and actionable
3. Format the output as a markdown table with columns for:
   - Threat Type
   - Scenario
   - Suggested Mitigation(s)
4. Ensure mitigations follow security best practices and industry standards""",
        )
    return "You are a helpful assistant that provides threat mitigation strategies in Markdown format."
