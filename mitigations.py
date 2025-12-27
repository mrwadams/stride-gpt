import requests
import streamlit as st
from anthropic import Anthropic
from google import genai as google_genai
from groq import Groq
from mistralai import Mistral
from openai import AzureOpenAI, OpenAI

from utils import create_reasoning_system_prompt, process_groq_response


# Function to create a prompt to generate mitigating controls
def create_mitigations_prompt(threats, is_genai=False, is_agentic=False):
    prompt = """Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology. Your task is to provide potential mitigations for the threats identified in the threat model. It is very important that your responses are tailored to reflect the details of the threats.

"""

    if is_genai or is_agentic:
        prompt += """For LLM/GENERATIVE AI threats, consider the following mitigation categories based on the OWASP Top 10 for LLM Applications 2025:

1. PROMPT INJECTION DEFENSE:
   - Implement input validation and sanitization for all user inputs
   - Use prompt/response filtering to detect injection attempts
   - Separate system instructions from user content with clear delimiters
   - Consider using instruction hierarchy or privileged prompts

2. SENSITIVE DATA PROTECTION:
   - Implement PII detection and redaction in LLM inputs and outputs
   - Use differential privacy techniques for fine-tuning
   - Sanitize training data to remove sensitive information
   - Apply output filtering to prevent data leakage

3. SUPPLY CHAIN SECURITY:
   - Verify model integrity with checksums and signatures
   - Use models only from trusted sources with security audits
   - Implement vulnerability scanning for ML dependencies
   - Maintain an ML bill of materials (ML-BOM)

4. DATA & MODEL INTEGRITY:
   - Validate and sanitize all data used for RAG and fine-tuning
   - Implement provenance tracking for training data
   - Use anomaly detection to identify poisoned data
   - Regularly evaluate model outputs for drift or degradation

5. OUTPUT VALIDATION:
   - Never trust LLM output - validate and sanitize before use
   - Implement output encoding appropriate to the context (HTML, SQL, etc.)
   - Use allowlists for permitted actions/commands
   - Apply content security policies for generated content

6. ACCESS CONTROL & RATE LIMITING:
   - Implement per-user and per-session rate limits
   - Set token/cost budgets to prevent unbounded consumption
   - Use tiered access based on user trust level
   - Monitor for anomalous usage patterns

7. SYSTEM PROMPT PROTECTION:
   - Avoid storing secrets or sensitive logic in system prompts
   - Implement prompt leakage detection
   - Use indirect references for sensitive configuration
   - Regularly audit prompts for information exposure risks

8. RAG & EMBEDDING SECURITY:
   - Implement access controls on vector databases
   - Validate retrieved content before injection into prompts
   - Use tenant isolation for multi-tenant RAG systems
   - Monitor for embedding manipulation attempts

"""

    if is_agentic:
        prompt += """For AGENTIC AI threats, consider the following mitigation categories based on the OWASP Top 10 for Agentic Applications:

1. INPUT VALIDATION & PROMPT SECURITY:
   - Sanitize all inputs before processing by the agent
   - Implement prompt injection detection and filtering
   - Validate and sanitize content from external sources (documents, emails, web pages)

2. LEAST PRIVILEGE & ACCESS CONTROL:
   - Minimize tool/function permissions to only what's necessary
   - Use scoped, short-lived credentials instead of long-lived tokens
   - Implement per-action authorization checks

3. SANDBOXING & ISOLATION:
   - Execute code in isolated containers with resource limits
   - Restrict file system and network access
   - Implement process isolation for multi-tenant environments

4. AUDIT LOGGING & OBSERVABILITY:
   - Log all agent actions, decisions, and tool invocations
   - Implement immutable audit trails for forensic analysis
   - Monitor for anomalous agent behavior patterns

5. HUMAN OVERSIGHT & APPROVAL WORKFLOWS:
   - Require human approval for high-risk actions
   - Implement confirmation prompts for irreversible operations
   - Provide clear visibility into agent decision-making

6. MEMORY & CONTEXT PROTECTION:
   - Encrypt persistent agent memory
   - Validate and sanitize retrieved context before use
   - Implement memory segmentation between users/sessions

7. AGENT AUTHENTICATION & INTEGRITY:
   - Use cryptographic signing for inter-agent communication
   - Verify tool provider authenticity (MCP server certificates)
   - Implement mutual TLS for agent-to-agent communication

8. CIRCUIT BREAKERS & RATE LIMITING:
   - Implement loop detection to prevent infinite reasoning cycles
   - Set resource consumption limits per request/session
   - Add circuit breakers to halt cascading failures

"""

    prompt += f"""Your output should be in the form of a markdown table with the following columns:
    - Column A: Threat Type
    - Column B: Scenario
    - Column C: Suggested Mitigation(s)

Below is the list of identified threats:
{threats}

YOUR RESPONSE (do not wrap in a code block):
"""
    return prompt


# Function to get mitigations from the GPT response.
def get_mitigations(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    # For reasoning models (o1, o3, o3-mini, o4-mini) and GPT-5 series models, use a structured system prompt
    if model_name in ["gpt-5", "gpt-5-mini", "gpt-5-nano", "o3", "o3-mini", "o4-mini"]:
        system_prompt = create_reasoning_system_prompt(
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
    else:
        system_prompt = "You are a helpful assistant that provides threat mitigation strategies in Markdown format."

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    )

    # Access the content directly as the response will be in text format
    return response.choices[0].message.content


# Function to get mitigations from the Azure OpenAI response.
def get_mitigations_azure(
    azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt
):
    client = AzureOpenAI(
        azure_endpoint=azure_api_endpoint,
        api_key=azure_api_key,
        api_version=azure_api_version,
    )

    response = client.chat.completions.create(
        model=azure_deployment_name,
        messages=[
            {
                "role": "system",
                "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format.",
            },
            {"role": "user", "content": prompt},
        ],
    )

    # Access the content directly as the response will be in text format
    return response.choices[0].message.content


# Function to get mitigations from the Google model's response.
def get_mitigations_google(google_api_key, google_model, prompt):
    client = google_genai.Client(api_key=google_api_key)

    safety_settings = [
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

    system_instruction = (
        "You are a helpful assistant that provides threat mitigation strategies in Markdown format."
    )
    is_gemini_2_5 = "gemini-2.5" in google_model.lower()

    try:
        from google.genai import types as google_types

        if is_gemini_2_5:
            config = google_types.GenerateContentConfig(
                system_instruction=system_instruction,
                safety_settings=safety_settings,
                thinking_config=google_types.ThinkingConfig(thinking_budget=1024),
            )
        else:
            config = google_types.GenerateContentConfig(
                system_instruction=system_instruction, safety_settings=safety_settings
            )
        response = client.models.generate_content(
            model=google_model, contents=prompt, config=config
        )
        # Extract Gemini 2.5 'thinking' content if present
        thinking_content = []
        for candidate in getattr(response, "candidates", []):
            content = getattr(candidate, "content", None)
            if content and hasattr(content, "parts"):
                for part in content.parts:
                    if hasattr(part, "thought") and part.thought:
                        thinking_content.append(str(part.thought))
        if thinking_content:
            joined_thinking = "\n\n".join(thinking_content)
            st.session_state["last_thinking_content"] = joined_thinking
    except Exception as e:
        st.error(f"Error generating mitigations with Google AI: {e!s}")
        return f"""
## Error Generating Mitigations

**API Error:** {e!s}

Please try again or select a different model provider.
"""

    return response.text


# Function to get mitigations from the Mistral model's response.
def get_mitigations_mistral(mistral_api_key, mistral_model, prompt):
    client = Mistral(api_key=mistral_api_key)

    response = client.chat.complete(
        model=mistral_model,
        messages=[
            {
                "role": "system",
                "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format.",
            },
            {"role": "user", "content": prompt},
        ],
    )

    # Access the content directly as the response will be in text format
    return response.choices[0].message.content


# Function to get mitigations from Ollama hosted LLM.
def get_mitigations_ollama(ollama_endpoint, ollama_model, prompt):
    """
    Get mitigations from Ollama hosted LLM.

    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://localhost:11434')
        ollama_model (str): The name of the model to use
        prompt (str): The prompt to send to the model

    Returns:
        str: The generated mitigations in markdown format

    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
        KeyError: If the response doesn't contain the expected fields
    """
    if not ollama_endpoint.endswith("/"):
        ollama_endpoint = ollama_endpoint + "/"

    url = ollama_endpoint + "api/chat"

    data = {
        "model": ollama_model,
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": """You are a cyber security expert with more than 20 years experience of implementing security controls for a wide range of applications. Your task is to analyze the provided application description and suggest appropriate security controls and mitigations.

Please provide your response in markdown format with appropriate headings and bullet points.""",
            },
            {"role": "user", "content": prompt},
        ],
    }

    try:
        response = requests.post(url, json=data, timeout=60)  # Add timeout
        response.raise_for_status()  # Raise exception for bad status codes
        outer_json = response.json()

        try:
            # Access the 'content' attribute of the 'message' dictionary
            return outer_json["message"]["content"]

        except KeyError:
            raise

    except requests.exceptions.RequestException:
        raise


# Function to get mitigations from the Anthropic model's response.
def get_mitigations_anthropic(anthropic_api_key, anthropic_model, prompt):
    client = Anthropic(api_key=anthropic_api_key)

    # Check if we're using extended thinking mode
    is_thinking_mode = "thinking" in anthropic_model.lower()

    # If using thinking mode, use the actual model name without the "thinking" suffix
    actual_model = "claude-3-7-sonnet-latest" if is_thinking_mode else anthropic_model

    try:
        # Configure the request based on whether thinking mode is enabled
        if is_thinking_mode:
            response = client.messages.create(
                model=actual_model,
                max_tokens=24000,
                thinking={"type": "enabled", "budget_tokens": 16000},
                system="You are a helpful assistant that provides threat mitigation strategies in Markdown format.",
                messages=[{"role": "user", "content": prompt}],
                timeout=600,  # 10-minute timeout
            )
        else:
            response = client.messages.create(
                model=actual_model,
                max_tokens=4096,
                system="You are a helpful assistant that provides threat mitigation strategies in Markdown format.",
                messages=[{"role": "user", "content": prompt}],
                timeout=300,  # 5-minute timeout
            )

        # Access the text content
        if is_thinking_mode:
            # For thinking mode, we need to extract only the text content blocks
            mitigations = "".join(block.text for block in response.content if block.type == "text")

            # Store thinking content in session state for debugging/transparency (optional)
            thinking_content = "".join(
                block.thinking for block in response.content if block.type == "thinking"
            )
            if thinking_content:
                st.session_state["last_thinking_content"] = thinking_content
        else:
            # Standard handling for regular responses
            mitigations = response.content[0].text

        return mitigations
    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")

        # Create a fallback response for timeout or other errors
        return f"""
## Error Generating Mitigations

**API Error:** {error_message}

### Suggestions:
- For complex applications, try simplifying the input or breaking it into smaller components
- If you're using extended thinking mode and encountering timeouts, try the standard model instead
- Consider reducing the complexity of the application description
"""


# Function to get mitigations from LM Studio Server response.
def get_mitigations_lm_studio(lm_studio_endpoint, model_name, prompt, api_key="not-needed"):
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key=api_key,  # Use provided API key or default to "not-needed"
    )

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {
                "role": "system",
                "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format.",
            },
            {"role": "user", "content": prompt},
        ],
    )

    # Access the content directly as the response will be in text format
    return response.choices[0].message.content


# Function to get mitigations from the Groq model's response.
def get_mitigations_groq(groq_api_key, groq_model, prompt):
    client = Groq(api_key=groq_api_key)
    response = client.chat.completions.create(
        model=groq_model,
        messages=[
            {
                "role": "system",
                "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format.",
            },
            {"role": "user", "content": prompt},
        ],
    )

    # Process the response using our utility function
    reasoning, mitigations = process_groq_response(
        response.choices[0].message.content, groq_model, expect_json=False
    )

    # If we got reasoning, display it in an expander in the UI
    if reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(reasoning)

    return mitigations
