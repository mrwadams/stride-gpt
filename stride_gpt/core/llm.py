"""Unified LLM interface. All providers routed through LiteLLM."""

from __future__ import annotations

import json as _json
import re

import litellm

from stride_gpt.core.schemas import LLMConfig, LLMResponse, ToolCallResult
from stride_gpt.models import (
    get_litellm_prefix,
    get_model,
    get_provider_by_key,
    model_supports_thinking,
    model_uses_completion_tokens,
)

# Local OpenAI-compatible servers (LM Studio) ignore the key, but the OpenAI SDK
# refuses to construct a client without one. Matches apps/web's convention.
LOCAL_PLACEHOLDER_API_KEY = "not-needed"


def _default_output_tokens(config: LLMConfig, fallback: int) -> int:
    """Resolve the output-token cap: caller override > registry default > fallback."""
    if config.max_tokens:
        return config.max_tokens
    registered = get_model(config.provider, config.model_name)
    if registered is not None:
        return registered.default_tokens
    return fallback

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True

# Gemini safety settings — allow security-related content generation
GEMINI_SAFETY_SETTINGS = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
]


def call_llm(config: LLMConfig, messages: list[dict]) -> LLMResponse:
    """Call an LLM with the given messages."""
    return _call_litellm(config, messages)


def call_llm_with_tools(
    config: LLMConfig, messages: list[dict], tools: list[dict]
) -> LLMResponse:
    """Call an LLM with tool definitions. Returns response with optional tool_calls."""
    return _call_litellm_with_tools(config, messages, tools)


def call_llm_with_image(
    config: LLMConfig,
    prompt: str,
    base64_image: str,
    media_type: str = "image/jpeg",
) -> LLMResponse:
    """Call an LLM with an image for analysis."""
    return _call_litellm_with_image(config, prompt, base64_image, media_type)


# ---------------------------------------------------------------------------
# LiteLLM path (all providers)
# ---------------------------------------------------------------------------


def _build_litellm_kwargs(config: LLMConfig) -> dict:
    """Build kwargs dict for litellm.completion() from config."""
    prefix = get_litellm_prefix(config.provider)
    model = prefix + config.model_name

    provider_info = get_provider_by_key(config.provider)
    api_key = config.api_key or None
    if api_key is None and provider_info is not None and not provider_info.needs_api_key:
        api_key = LOCAL_PLACEHOLDER_API_KEY

    kwargs: dict = {
        "model": model,
        "api_key": api_key,
        # Retry transient errors (429 rate limits, timeouts, 5xx). LiteLLM delegates
        # to the provider SDK, which uses exponential backoff and respects the
        # Retry-After header. Necessary because the agent loop bursts many calls
        # in close succession and easily trips TPM caps on tight org tiers.
        "num_retries": 3,
    }

    # Custom endpoint for LM Studio
    if config.api_base:
        if config.provider == "LM Studio Server":
            kwargs["api_base"] = f"{config.api_base}/v1"
        else:
            kwargs["api_base"] = config.api_base

    # JSON mode
    if isinstance(config.response_format, dict):
        # Caller provided an explicit JSON schema — use json_schema mode.
        kwargs["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "response", "schema": config.response_format},
        }
    elif config.response_format == "json" and config.provider != "LM Studio Server":
        # Generic JSON mode — use json_object where supported.
        # LM Studio only accepts json_schema or text.
        kwargs["response_format"] = {"type": "json_object"}

    # --- Google AI API specifics ---
    if config.provider == "Google AI API":
        kwargs["safety_settings"] = GEMINI_SAFETY_SETTINGS
        # Gemini thinking-capable models have thinking enabled by default and
        # surface it via `thinking_blocks` on the response — no explicit
        # opt-in kwarg is required. Don't send Anthropic's
        # `thinking={"type": "enabled", ...}` shape here; litellm's Gemini
        # provider rejects it for newer models (e.g. gemini-3.1-flash-lite).

    # --- Anthropic ---
    elif config.provider == "Anthropic API" and config.use_thinking:
        kwargs["thinking"] = {"type": "enabled", "budget_tokens": 16000}
        # max_tokens must exceed budget_tokens; never go below 48000 here.
        kwargs["max_tokens"] = max(_default_output_tokens(config, 48000), 48000)
        kwargs["timeout"] = config.timeout or 600
    elif config.provider == "Anthropic API":
        kwargs["max_tokens"] = _default_output_tokens(config, 32768)
        kwargs["timeout"] = config.timeout or 300

    # GPT-5 series: max_completion_tokens instead of max_tokens
    elif model_uses_completion_tokens(config.model_name):
        kwargs["max_completion_tokens"] = _default_output_tokens(config, 20000)

    # LM Studio: conservative default
    elif config.provider == "LM Studio Server":
        kwargs["max_tokens"] = config.max_tokens or 8000

    # Groq / Mistral: original code never set max_tokens — let the API decide
    elif config.provider in ("Groq API", "Mistral API"):
        if config.max_tokens:
            kwargs["max_tokens"] = config.max_tokens

    # Other providers: only set if explicitly provided
    elif config.max_tokens:
        kwargs["max_tokens"] = config.max_tokens

    return kwargs


def _extract_thinking(config: LLMConfig, response) -> tuple[str | None, str | None]:
    """Extract thinking/reasoning content from a response based on provider."""
    thinking = None
    reasoning = None

    if config.provider == "Anthropic API" and config.use_thinking:
        thinking = _extract_anthropic_thinking(response)
    elif config.provider == "Google AI API" and model_supports_thinking(config.provider, config.model_name):
        thinking = _extract_gemini_thinking(response)
    elif config.provider == "Groq API":
        # Groq/DeepSeek reasoning is extracted from content, handled separately
        pass

    return thinking, reasoning


def _extract_anthropic_thinking(response) -> str | None:
    """Extract thinking content from an Anthropic response via LiteLLM."""
    thinking_parts: list[str] = []
    choices = getattr(response, "choices", [])
    if choices:
        message = choices[0].message
        thinking_blocks = getattr(message, "thinking_blocks", None)
        if thinking_blocks:
            thinking_parts.extend(
                block.thinking for block in thinking_blocks if hasattr(block, "thinking")
            )
    return "\n\n".join(thinking_parts) if thinking_parts else None


def _extract_gemini_thinking(response) -> str | None:
    """Extract thinking content from a Gemini response via LiteLLM."""
    # LiteLLM exposes Gemini thinking as thought parts in the response
    thinking_parts: list[str] = []
    choices = getattr(response, "choices", [])
    if choices:
        message = choices[0].message
        # LiteLLM may include thinking in provider_specific_fields or similar
        thinking_blocks = getattr(message, "thinking_blocks", None)
        if thinking_blocks:
            thinking_parts.extend(
                block.thinking for block in thinking_blocks if hasattr(block, "thinking")
            )
        # Also check for thought in provider-specific response data
        provider_specific = getattr(message, "provider_specific_fields", None)
        if provider_specific and "thinking" in provider_specific:
            thinking_parts.append(str(provider_specific["thinking"]))
    return "\n\n".join(thinking_parts) if thinking_parts else None


def _call_litellm(config: LLMConfig, messages: list[dict]) -> LLMResponse:
    """Call LLM via LiteLLM (all providers)."""
    kwargs = _build_litellm_kwargs(config)
    response = litellm.completion(messages=messages, **kwargs)

    message = response.choices[0].message
    content = message.content or ""

    # Some reasoning models (e.g. qwen3 via LM Studio) emit the full structured
    # output into `reasoning_content` and leave `content` empty. When that
    # happens, treat the reasoning text as the answer — providers with genuine
    # thinking + answer separation (Anthropic, Google) populate content
    # normally, so this fallback only triggers when there's nothing else to use.
    if not content.strip():
        fallback = getattr(message, "reasoning_content", None)
        if fallback:
            content = fallback

    thinking, reasoning = _extract_thinking(config, response)

    if config.provider == "Groq API":
        reasoning, content = extract_deepseek_reasoning(content)

    return LLMResponse(
        content=content,
        thinking=thinking,
        reasoning=reasoning,
        model=config.model_name,
    )


def _call_litellm_with_tools(
    config: LLMConfig, messages: list[dict], tools: list[dict]
) -> LLMResponse:
    """Call LLM with tool definitions via LiteLLM."""
    kwargs = _build_litellm_kwargs(config)
    # Don't send JSON response_format when using tools — the model decides the format
    kwargs.pop("response_format", None)
    response = litellm.completion(messages=messages, tools=tools, **kwargs)

    message = response.choices[0].message
    content = message.content or ""

    tool_calls = None
    if message.tool_calls:
        tool_calls = [
            ToolCallResult(
                id=tc.id,
                function_name=tc.function.name,
                arguments=_json.loads(tc.function.arguments)
                if isinstance(tc.function.arguments, str)
                else tc.function.arguments,
            )
            for tc in message.tool_calls
        ]

    thinking, _ = _extract_thinking(config, response)

    return LLMResponse(
        content=content,
        thinking=thinking,
        model=config.model_name,
        tool_calls=tool_calls,
    )


def _call_litellm_with_image(
    config: LLMConfig,
    prompt: str,
    base64_image: str,
    media_type: str,
) -> LLMResponse:
    """Call LLM with an image via LiteLLM multimodal support."""
    kwargs = _build_litellm_kwargs(config)
    # Build multimodal message
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:{media_type};base64,{base64_image}"},
                },
            ],
        }
    ]

    # For reasoning models, add system message
    if model_uses_completion_tokens(config.model_name):
        from stride_gpt.core.prompts import create_reasoning_system_prompt

        system_prompt = create_reasoning_system_prompt(
            task_description="Analyze the provided architecture diagram and explain it to a Security Architect.",
            approach_description="""1. Carefully examine the diagram
2. Identify all components and their relationships
3. Note any technologies, protocols, or security measures shown
4. Create a clear, structured explanation with these sections:
   - Overall Architecture: Brief overview of the system
   - Key Components: List and explain each major component
   - Data Flow: How information moves through the system
   - Technologies Used: Identify technologies, frameworks, or platforms
   - Security Considerations: Note any visible security measures""",
        )
        messages.insert(0, {"role": "system", "content": system_prompt})

    response = litellm.completion(messages=messages, **kwargs)
    content = response.choices[0].message.content or ""
    thinking, _ = _extract_thinking(config, response)
    return LLMResponse(content=content, thinking=thinking, model=config.model_name)


# ---------------------------------------------------------------------------
# Utility functions (moved from utils.py)
# ---------------------------------------------------------------------------


def extract_deepseek_reasoning(response_text: str) -> tuple[str | None, str]:
    """Extract reasoning from <think></think> tags in DeepSeek R1 responses.

    Returns:
        Tuple of (reasoning, final_output). Reasoning is None if no tags found.
    """
    think_pattern = r"<think>(.*?)</think>"
    think_match = re.search(think_pattern, response_text, re.DOTALL)
    if think_match:
        reasoning = think_match.group(1).strip()
        final_output = re.sub(think_pattern, "", response_text, flags=re.DOTALL).strip()
        return reasoning, final_output
    return None, response_text


def process_groq_response(
    response_text: str, model_name: str, expect_json: bool = True
) -> tuple[str | None, str | dict]:
    """Process a Groq API response, handling DeepSeek R1 reasoning extraction.

    Returns:
        Tuple of (reasoning, processed_output).
    """
    reasoning = None
    final_output = response_text

    if model_name == "deepseek-r1-distill-llama-70b":
        reasoning, final_output = extract_deepseek_reasoning(response_text)

    if expect_json:
        try:
            processed_output = _json.loads(final_output)
        except _json.JSONDecodeError:
            processed_output = final_output
    elif "graph " in final_output:
        from stride_gpt.core.attack_tree import extract_mermaid_code

        processed_output = extract_mermaid_code(final_output)
    else:
        processed_output = final_output

    return reasoning, processed_output
