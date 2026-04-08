"""Core test cases generation logic. Zero Streamlit imports."""

from __future__ import annotations

from stride_gpt.core.llm import call_llm
from stride_gpt.core.prompts import create_reasoning_system_prompt
from stride_gpt.core.schemas import LLMConfig, LLMResponse

GPT5_MODELS = {"gpt-5.2", "gpt-5-mini", "gpt-5-nano", "gpt-5.2-pro", "gpt-5"}


def generate_test_cases(config: LLMConfig, prompt: str) -> tuple[str, LLMResponse]:
    """Generate security test cases. Returns (markdown_string, response)."""
    system_prompt = _get_system_prompt(config)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]
    response = call_llm(config, messages)
    return response.content, response


def _get_system_prompt(config: LLMConfig) -> str:
    if config.model_name in GPT5_MODELS:
        return create_reasoning_system_prompt(
            task_description="Generate comprehensive security test cases in Gherkin format for the identified threats.",
            approach_description="""1. Analyze each threat in the provided threat model:
   - Understand the threat type and scenario
   - Identify critical security aspects to test
   - Consider both positive and negative test cases
2. For each test case:
   - Write clear preconditions in 'Given' steps
   - Define specific actions in 'When' steps
   - Specify expected outcomes in 'Then' steps
   - Include relevant security validation checks
3. Structure the test cases:
   - Add descriptive titles for each scenario
   - Use proper Gherkin syntax and formatting
   - Group related test cases together
   - Include edge cases and boundary conditions
4. Format output as Markdown with Gherkin code blocks:
   - Use proper code block syntax
   - Ensure consistent indentation
   - Add clear scenario descriptions""",
        )
    return "You are a helpful assistant that provides security test cases in Gherkin format."
