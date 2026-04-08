"""Unified LLM interface. LiteLLM for most providers, Google SDK direct for Gemini."""

from __future__ import annotations

import base64
import re

import litellm
from google import genai as google_genai
from google.genai import types as google_types

from stride_gpt.core.schemas import LLMConfig, LLMResponse

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True

# LiteLLM model prefix mapping. UI presents bare model names; we prepend the prefix.
PROVIDER_PREFIXES: dict[str, str] = {
    "OpenAI API": "",
    "Anthropic API": "anthropic/",
    "Mistral API": "mistral/",
    "Groq API": "groq/",
    "Ollama": "ollama/",
    "LM Studio Server": "openai/",
}

# GPT-5 series models that use max_completion_tokens instead of max_tokens
GPT5_MODELS = {"gpt-5.2", "gpt-5-mini", "gpt-5-nano", "gpt-5.2-pro", "gpt-5"}


def call_llm(config: LLMConfig, messages: list[dict]) -> LLMResponse:
    """Call an LLM with the given messages. Dispatches to Google SDK or LiteLLM."""
    if config.provider == "Google AI API":
        return _call_google(config, messages)
    return _call_litellm(config, messages)


def call_llm_with_image(
    config: LLMConfig,
    prompt: str,
    base64_image: str,
    media_type: str = "image/jpeg",
) -> LLMResponse:
    """Call an LLM with an image for analysis."""
    if config.provider == "Google AI API":
        return _call_google_with_image(config, prompt, base64_image, media_type)
    return _call_litellm_with_image(config, prompt, base64_image, media_type)


# ---------------------------------------------------------------------------
# Google SDK direct path (ThinkingConfig + safety settings not in LiteLLM)
# ---------------------------------------------------------------------------


def _google_safety_settings() -> list[google_genai.types.SafetySetting]:
    """Safety settings allowing security content generation."""
    return [
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE,
        ),
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE,
        ),
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_HARASSMENT,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE,
        ),
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE,
        ),
    ]


def _is_gemini_thinking(model_name: str) -> bool:
    """Gemini 2.5+ and 3+ support thinking capabilities."""
    lower = model_name.lower()
    return "gemini-2.5" in lower or "gemini-3" in lower


def _extract_google_response(response) -> tuple[str, str | None]:
    """Extract text and thinking content from a Google API response."""
    text_parts: list[str] = []
    thinking_parts: list[str] = []
    for candidate in getattr(response, "candidates", []):
        content = getattr(candidate, "content", None)
        if content and hasattr(content, "parts"):
            for part in content.parts:
                if hasattr(part, "thought") and part.thought:
                    thinking_parts.append(str(part.thought))
                elif hasattr(part, "text") and part.text:
                    text_parts.append(part.text)
    thinking = "\n\n".join(thinking_parts) if thinking_parts else None
    return "".join(text_parts), thinking


def _call_google(config: LLMConfig, messages: list[dict]) -> LLMResponse:
    """Call Google Gemini directly via the google-genai SDK."""
    client = google_genai.Client(api_key=config.api_key)
    safety = _google_safety_settings()

    # Extract system instruction and user content from messages
    system_instruction = None
    user_content = None
    for msg in messages:
        if msg["role"] == "system":
            system_instruction = msg["content"]
        elif msg["role"] == "user":
            user_content = msg["content"]
    if user_content is None:
        user_content = messages[-1]["content"] if messages else ""

    # Build config
    config_kwargs: dict = {"safety_settings": safety}
    if system_instruction:
        config_kwargs["system_instruction"] = system_instruction
    if config.response_format == "json":
        config_kwargs["response_mime_type"] = "application/json"
    if _is_gemini_thinking(config.model_name):
        config_kwargs["thinking_config"] = google_types.ThinkingConfig(thinking_budget=1024)

    gen_config = google_types.GenerateContentConfig(**config_kwargs)
    response = client.models.generate_content(
        model=config.model_name,
        contents=user_content,
        config=gen_config,
    )
    text, thinking = _extract_google_response(response)
    return LLMResponse(content=text, thinking=thinking, model=config.model_name)


def _call_google_with_image(
    config: LLMConfig,
    prompt: str,
    base64_image: str,
    media_type: str,
) -> LLMResponse:
    """Call Google Gemini with an image."""
    client = google_genai.Client(api_key=config.api_key)
    blob = google_types.Blob(data=base64.b64decode(base64_image), mime_type=media_type)
    content = [
        google_types.Content(
            role="user",
            parts=[
                google_types.Part(text=prompt),
                google_types.Part(inline_data=blob),
            ],
        )
    ]
    gen_config = google_types.GenerateContentConfig()
    response = client.models.generate_content(
        model=config.model_name,
        contents=content,
        config=gen_config,
    )
    text, thinking = _extract_google_response(response)
    return LLMResponse(content=text, thinking=thinking, model=config.model_name)


# ---------------------------------------------------------------------------
# LiteLLM path (OpenAI, Anthropic, Mistral, Groq, Ollama, LM Studio)
# ---------------------------------------------------------------------------


def _build_litellm_kwargs(config: LLMConfig) -> dict:  # noqa: C901
    """Build kwargs dict for litellm.completion() from config."""
    prefix = PROVIDER_PREFIXES.get(config.provider, "")
    model = prefix + config.model_name

    kwargs: dict = {
        "model": model,
        "api_key": config.api_key or None,
    }

    # Custom endpoints for Ollama / LM Studio
    if config.api_base:
        if config.provider == "LM Studio Server":
            kwargs["api_base"] = f"{config.api_base}/v1"
        else:
            kwargs["api_base"] = config.api_base

    # JSON mode
    if config.response_format == "json":
        kwargs["response_format"] = {"type": "json_object"}

    # Anthropic extended thinking
    if config.provider == "Anthropic API" and config.use_thinking:
        kwargs["thinking"] = {"type": "enabled", "budget_tokens": 16000}
        kwargs["max_tokens"] = 48000
        kwargs["timeout"] = config.timeout or 600
    elif config.provider == "Anthropic API":
        kwargs["max_tokens"] = config.max_tokens or 32768
        kwargs["timeout"] = config.timeout or 300
    # GPT-5 series: max_completion_tokens instead of max_tokens
    elif config.model_name in GPT5_MODELS:
        kwargs["max_completion_tokens"] = config.max_tokens or 20000
    # LM Studio: conservative default
    elif config.provider == "LM Studio Server":
        kwargs["max_tokens"] = config.max_tokens or 4000
    # Ollama: pass timeout and default max_tokens
    elif config.provider == "Ollama":
        if config.timeout:
            kwargs["timeout"] = config.timeout
        kwargs["max_tokens"] = config.max_tokens or 8192
    # Groq / Mistral: original code never set max_tokens — let the API decide
    elif config.provider in ("Groq API", "Mistral API"):
        if config.max_tokens:
            kwargs["max_tokens"] = config.max_tokens
    # Other providers: only set if explicitly provided
    elif config.max_tokens:
        kwargs["max_tokens"] = config.max_tokens

    return kwargs


def _extract_anthropic_thinking(response) -> str | None:
    """Extract thinking content from an Anthropic response via LiteLLM."""
    thinking_parts: list[str] = []
    # LiteLLM may expose Anthropic thinking blocks in the response
    choices = getattr(response, "choices", [])
    if choices:
        message = choices[0].message
        # Check for thinking blocks in the raw response
        thinking_blocks = getattr(message, "thinking_blocks", None)
        if thinking_blocks:
            thinking_parts.extend(
                block.thinking for block in thinking_blocks if hasattr(block, "thinking")
            )
    return "\n\n".join(thinking_parts) if thinking_parts else None


def _call_litellm(config: LLMConfig, messages: list[dict]) -> LLMResponse:
    """Call LLM via LiteLLM (supports OpenAI, Anthropic, Mistral, Groq, Ollama, LM Studio)."""
    kwargs = _build_litellm_kwargs(config)
    response = litellm.completion(messages=messages, **kwargs)

    content = response.choices[0].message.content or ""

    # Extract thinking/reasoning based on provider
    thinking = None
    reasoning = None

    if config.provider == "Anthropic API" and config.use_thinking:
        thinking = _extract_anthropic_thinking(response)

    if config.provider == "Groq API":
        reasoning, content = extract_deepseek_reasoning(content)

    return LLMResponse(
        content=content,
        thinking=thinking,
        reasoning=reasoning,
        model=config.model_name,
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

    # For GPT-5 series, add system message
    if config.model_name in GPT5_MODELS:
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
    return LLMResponse(content=content, model=config.model_name)


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
    import json

    reasoning = None
    final_output = response_text

    if model_name == "deepseek-r1-distill-llama-70b":
        reasoning, final_output = extract_deepseek_reasoning(response_text)

    if expect_json:
        try:
            processed_output = json.loads(final_output)
        except json.JSONDecodeError:
            processed_output = final_output
    elif "graph " in final_output:
        from stride_gpt.core.attack_tree import extract_mermaid_code

        processed_output = extract_mermaid_code(final_output)
    else:
        processed_output = final_output

    return reasoning, processed_output
