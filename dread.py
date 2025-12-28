import json
import re
import time

import requests
import streamlit as st
from anthropic import Anthropic
from google import genai as google_genai
from groq import Groq
from mistralai import Mistral
from openai import OpenAI

from utils import create_reasoning_system_prompt, process_groq_response


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


# Function to create a prompt to generate DREAD risk assessment
def create_dread_assessment_prompt(threats, is_genai=False, is_agentic=False):
    prompt = """Act as a cyber security expert with more than 20 years of experience in threat modeling using STRIDE and DREAD methodologies.
Your task is to produce a DREAD risk assessment for the threats identified in a threat model.

"""

    if is_genai or is_agentic:
        prompt += """LLM/GENERATIVE AI DREAD SCORING CONSIDERATIONS:
When scoring threats for LLM/generative AI applications, consider these factors:

DAMAGE POTENTIAL:
- Prompt injection can lead to complete system compromise or data exfiltration
- Training data poisoning affects all users and persists across model updates
- Sensitive data disclosure may include PII, credentials, or proprietary information
- Malicious output generation can cause reputational damage and legal liability

REPRODUCIBILITY:
- Prompt injection success varies with model, temperature, and context
- Some attacks require specific phrasing or multi-turn conversations
- RAG poisoning may need time for embeddings to propagate
- Model behavior can be non-deterministic, making exact reproduction difficult

EXPLOITABILITY:
- Prompt injection requires minimal technical skill
- Supply chain attacks on models/plugins require access to trusted sources
- Training data poisoning may need access to fine-tuning pipelines
- Some attacks are as simple as crafting malicious user input

AFFECTED USERS:
- Model-level vulnerabilities affect all users of that model instance
- RAG/knowledge base poisoning impacts everyone querying that data
- Per-user context isolation failures can expose cross-user data
- Shared prompt templates multiply the blast radius

DISCOVERABILITY:
- Basic prompt injection is easily discoverable through experimentation
- System prompt extraction is often trivial with creative prompting
- Training data can sometimes be extracted through careful probing
- Model capabilities and limitations are often documented or enumerable

"""

    if is_agentic:
        prompt += """AGENTIC AI DREAD SCORING CONSIDERATIONS:
When scoring threats for agentic AI applications, consider these factors:

DAMAGE POTENTIAL:
- Consider cascading effects across agent chains and downstream systems
- Memory/context poisoning can affect all future sessions and users
- Credential exfiltration may grant persistent access to multiple systems
- Autonomous actions may cause irreversible damage before detection
- Multi-agent compromises can have exponential blast radius
- Infrastructure-level attacks (sandbox escape, container breakout) enable lateral movement

REPRODUCIBILITY:
- Agent behaviors may be probabilistic and context-dependent
- Prompt injection success depends on specific input formatting and model state
- Memory poisoning effects may manifest inconsistently across sessions
- Multi-step attacks through agent chains may be harder to reproduce exactly
- RAG-based attacks depend on embedding similarity and retrieval ranking
- Tool exploitation may require specific parameter combinations

EXPLOITABILITY:
- Prompt injection attacks require low technical skill but specific knowledge of agent behavior
- Tool misuse often exploits configuration gaps rather than code vulnerabilities
- Supply chain attacks (malicious MCP servers) require access to trusted repositories
- Context poisoning may require patience but little technical sophistication
- Code execution exploits vary: simple prompt tricks vs. advanced sandbox escapes
- Multi-agent attacks may require understanding of agent communication protocols

AFFECTED USERS:
- Multi-agent systems can amplify impact across all connected agents and their users
- Shared memory/RAG databases affect all users of that knowledge base
- Credential abuse may affect all systems accessible with those credentials
- Agent-to-agent communication attacks can cascade across entire agent ecosystems
- Foundation model compromises affect every application using that model
- Infrastructure attacks may impact all tenants in shared environments

DISCOVERABILITY:
- Prompt injection vulnerabilities are easily discoverable through normal interaction
- Agent decision logs may reveal exploitable patterns and tool permissions
- Tool permissions and capabilities are often documented or easily enumerated
- Memory contents may leak through carefully crafted queries
- Framework vulnerabilities are often published in CVE databases
- Agent behavior patterns can be profiled through systematic probing

ARCHITECTURAL PATTERN-SPECIFIC SCORING ADJUSTMENTS:
When analyzing threats, adjust DREAD scores based on detected patterns:

FOR RAG/RETRIEVAL SYSTEMS:
- Damage Potential: +1-2 if RAG serves multiple users (poisoning affects everyone)
- Reproducibility: -1 if retrieval is non-deterministic (harder to reproduce exactly)
- Affected Users: +2-3 if shared knowledge base across users/tenants
- Discoverability: +1 if document upload is user-accessible (easy to test poisoning)

FOR MULTI-AGENT SYSTEMS:
- Damage Potential: +2-3 for cascading/amplification effects across agent chains
- Reproducibility: -1-2 for complex multi-agent interactions (harder to reproduce)
- Affected Users: +2 for ecosystem-wide attacks affecting all connected agents
- Discoverability: +1 if agent communication patterns are observable

FOR CODE EXECUTION ENVIRONMENTS:
- Damage Potential: +3 if sandbox escape is possible (full system compromise)
- Exploitability: Variable based on sandbox strength (-2 for strong isolation, +2 for weak)
- Affected Users: +2-3 if shared infrastructure (affects co-tenants)
- Discoverability: -1 for sophisticated sandbox escapes (requires expertise to find)

FOR TOOL/MCP ECOSYSTEMS:
- Damage Potential: +1-2 based on tool permissions (higher for write/execute tools)
- Reproducibility: +1 if tool behavior is deterministic
- Exploitability: +2 if tools accept unvalidated parameters
- Discoverability: +2 if tool list and capabilities are enumerable

FOR PERSISTENT MEMORY SYSTEMS:
- Damage Potential: +2 if memory affects future sessions (persistent compromise)
- Reproducibility: -1 if memory retrieval is similarity-based (less predictable)
- Affected Users: +2-3 if memory is shared across users
- Discoverability: +1 if memory contents can be queried directly

FOR AUTONOMOUS OPERATIONS:
- Damage Potential: +2-3 if actions are irreversible before human review
- Exploitability: +1 if human oversight is minimal or can be bypassed
- Affected Users: Based on scope of autonomous actions
- Discoverability: -1 if attack occurs during low-monitoring periods

CROSS-LAYER THREAT SCORING:
For threats that span multiple architectural components, consider cumulative risk:
- If a threat enables follow-on attacks, score Damage Potential for the full attack chain
- If exploitation requires multiple steps across components, adjust Reproducibility accordingly
- If compromise propagates to shared infrastructure, increase Affected Users significantly

"""

    prompt += f"""Below is the list of identified threats:
{threats}

When providing the risk assessment, use a JSON formatted response with a top-level key "Risk Assessment" and a list of threats, each with the following sub-keys:
- "Threat Type": A string representing the type of threat (e.g., "Spoofing").
- "Scenario": A string describing the threat scenario.
- "Damage Potential": An integer between 1 and 10.
- "Reproducibility": An integer between 1 and 10.
- "Exploitability": An integer between 1 and 10.
- "Affected Users": An integer between 1 and 10.
- "Discoverability": An integer between 1 and 10.

Assign a value between 1 and 10 for each sub-key based on the DREAD methodology. Use the following scale:
- 1-3: Low
- 4-6: Medium
- 7-10: High

Ensure the JSON response is correctly formatted and does not contain any additional text. Here is an example of the expected JSON response format:
{{
  "Risk Assessment": [
    {{
      "Threat Type": "Spoofing",
      "Scenario": "An attacker could create a fake OAuth2 provider and trick users into logging in through it.",
      "Damage Potential": 8,
      "Reproducibility": 6,
      "Exploitability": 5,
      "Affected Users": 9,
      "Discoverability": 7
    }},
    {{
      "Threat Type": "Spoofing",
      "Scenario": "An attacker could intercept the OAuth2 token exchange process through a Man-in-the-Middle (MitM) attack.",
      "Damage Potential": 8,
      "Reproducibility": 7,
      "Exploitability": 6,
      "Affected Users": 8,
      "Discoverability": 6
    }}
  ]
}}
"""
    return prompt


def clean_json_response(response_text):
    import re

    # Remove markdown JSON code block if present
    json_pattern = r"```json\s*(.*?)\s*```"
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no JSON code block, try to find content between any code blocks
    code_pattern = r"```\s*(.*?)\s*```"
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no code blocks, return the original text
    return response_text.strip()


def get_dread_assessment(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    # For GPT-5 series models, use a structured system prompt
    if model_name in ["gpt-5.2", "gpt-5-mini", "gpt-5-nano", "gpt-5.2-pro", "gpt-5"]:
        system_prompt = create_reasoning_system_prompt(
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
    else:
        system_prompt = "You are a helpful assistant designed to output JSON."

    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    try:
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        # Handle error silently
        dread_assessment = {}

    return dread_assessment


# Function to get DREAD risk assessment from the Google model's response.
def get_dread_assessment_google(google_api_key, google_model, prompt):
    """
    Generate a DREAD risk assessment using the Gemini API (Google AI) as per official documentation:
    https://ai.google.dev/gemini-api/docs/text-generation
    """
    client = google_genai.Client(api_key=google_api_key)
    system_instruction = (
        "You are a helpful assistant designed to output JSON. "
        "Only provide the DREAD risk assessment in JSON format with no additional text. "
        "Do not wrap the output in a code block."
    )

    is_gemini_thinking = "gemini-2.5" in google_model.lower() or "gemini-3" in google_model.lower()

    try:
        from google.genai import types as google_types

        if is_gemini_thinking:
            config = google_types.GenerateContentConfig(
                system_instruction=system_instruction,
                thinking_config=google_types.ThinkingConfig(thinking_budget=1024),
            )
        else:
            config = google_types.GenerateContentConfig(system_instruction=system_instruction)
        response = client.models.generate_content(
            model=google_model, contents=[prompt], config=config
        )
        # Extract text and thinking content from response parts
        text_content = []
        thinking_content = []
        for candidate in getattr(response, "candidates", []):
            content = getattr(candidate, "content", None)
            if content and hasattr(content, "parts"):
                for part in content.parts:
                    if hasattr(part, "thought") and part.thought:
                        thinking_content.append(str(part.thought))
                    elif hasattr(part, "text") and part.text:
                        text_content.append(part.text)
        if thinking_content:
            joined_thinking = "\n\n".join(thinking_content)
            st.session_state["last_thinking_content"] = joined_thinking

        response_text = "".join(text_content)
    except Exception as e:
        st.error(f"Error generating DREAD assessment with Google AI: {e!s}")
        return {"Risk Assessment": []}

    cleaned = clean_json_response(response_text)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {}


# Function to get DREAD risk assessment from the Mistral model's response.
def get_dread_assessment_mistral(mistral_api_key, mistral_model, prompt):
    client = Mistral(api_key=mistral_api_key)

    response = client.chat.complete(
        model=mistral_model,
        response_format={"type": "json_object"},
        messages=[{"role": "user", "content": prompt}],
    )

    try:
        # Convert the JSON string in the 'content' field to a Python dictionary
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        dread_assessment = {}

    return dread_assessment


# Function to get DREAD risk assessment from Ollama hosted LLM.
def get_dread_assessment_ollama(ollama_endpoint, ollama_model, ollama_timeout, prompt):
    """
    Get DREAD risk assessment from Ollama hosted LLM.

    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://localhost:11434')
        ollama_model (str): The name of the model to use
        prompt (str): The prompt to send to the model

    Returns:
        dict: The parsed JSON response containing the DREAD assessment

    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
        json.JSONDecodeError: If the response cannot be parsed as JSON
        KeyError: If the response doesn't contain the expected fields
    """
    if not ollama_endpoint.endswith("/"):
        ollama_endpoint = ollama_endpoint + "/"

    url = ollama_endpoint + "api/chat"

    max_retries = 3
    retry_delay = 2  # seconds

    data = {
        "model": ollama_model,
        "stream": False,
        "format": "json",
        "messages": [
            {
                "role": "system",
                "content": """You are a cyber security expert with more than 20 years experience of using the DREAD risk assessment methodology to evaluate security threats. Your task is to analyze the provided application description and perform a DREAD assessment.

Please provide your response in JSON format with the following structure:
{
    "dread_assessment": [
        {
            "threat": "Description of the threat",
            "damage": "Score and explanation",
            "reproducibility": "Score and explanation",
            "exploitability": "Score and explanation",
            "affected_users": "Score and explanation",
            "discoverability": "Score and explanation",
            "risk_score": "Calculated total score"
        }
    ]
}""",
            },
            {"role": "user", "content": prompt},
        ],
    }

    for attempt in range(max_retries):
        try:
            response = requests.post(url, json=data, timeout=ollama_timeout)  # Add timeout
            response.raise_for_status()  # Raise exception for bad status codes
            outer_json = response.json()

            try:
                # Access the 'content' attribute of the 'message' dictionary and parse as JSON
                return json.loads(outer_json["message"]["content"])

            except (json.JSONDecodeError, KeyError):
                if attempt == max_retries - 1:  # Last attempt
                    raise
                time.sleep(retry_delay)
                continue

        except requests.exceptions.RequestException:
            if attempt == max_retries - 1:  # Last attempt
                raise
            time.sleep(retry_delay)
            continue
    return None


# Function to get DREAD risk assessment from the Anthropic model's response.
def get_dread_assessment_anthropic(anthropic_api_key, anthropic_model, prompt):
    client = Anthropic(api_key=anthropic_api_key)

    # Check if we're using extended thinking mode (from checkbox in UI)
    is_thinking_mode = st.session_state.get("use_thinking", False)

    # Use the selected model
    actual_model = anthropic_model

    try:
        # Configure the request based on whether thinking mode is enabled
        if is_thinking_mode:
            response = client.messages.create(
                model=actual_model,
                max_tokens=48000,
                thinking={"type": "enabled", "budget_tokens": 16000},
                system="You are a JSON-generating assistant. You must ONLY output valid, parseable JSON with no additional text or formatting.",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                        + "\n\nIMPORTANT: Your response MUST be a valid JSON object with the exact structure shown in the example above. Do not include any explanatory text, markdown formatting, or code blocks. Return only the raw JSON object.",
                    }
                ],
                timeout=600,  # 10-minute timeout
            )
        else:
            response = client.messages.create(
                model=actual_model,
                max_tokens=32768,
                system="You are a JSON-generating assistant. You must ONLY output valid, parseable JSON with no additional text or formatting.",
                messages=[{"role": "user", "content": prompt}],
                timeout=300,  # 5-minute timeout
            )

        try:
            # Extract the text content
            if is_thinking_mode:
                # For thinking mode, we need to extract only the text content blocks
                response_text = "".join(
                    block.text for block in response.content if block.type == "text"
                )

                # Store thinking content in session state for debugging/transparency (optional)
                thinking_content = "".join(
                    block.thinking for block in response.content if block.type == "thinking"
                )
                if thinking_content:
                    st.session_state["last_thinking_content"] = thinking_content
            else:
                # Standard handling for regular responses
                response_text = response.content[0].text

            # Check for and fix common JSON formatting issues
            if is_claude_3_7:
                # Sometimes Claude 3.7 adds trailing commas which are invalid in JSON
                response_text = response_text.replace(",\n  ]", "\n  ]").replace(",\n]", "\n]")

                # Sometimes it adds comments which are invalid in JSON
                response_text = re.sub(r"//.*?\n", "\n", response_text)

            # Check if the JSON is complete (should end with a closing brace)
            if not response_text.strip().endswith("}"):
                raise json.JSONDecodeError(
                    "Incomplete JSON response", response_text, len(response_text)
                )

            # Parse the JSON string
            return json.loads(response_text)
        except (json.JSONDecodeError, IndexError, AttributeError) as e:
            # Create a fallback response with a proper DREAD structure
            return {
                "Risk Assessment": [
                    {
                        "Threat Type": "Error",
                        "Scenario": f"Failed to parse Claude response: {e!s}",
                        "Damage Potential": 0,
                        "Reproducibility": 0,
                        "Exploitability": 0,
                        "Affected Users": 0,
                        "Discoverability": 0,
                    }
                ]
            }
    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")

        # Create a fallback response for timeout or other errors
        return {
            "Risk Assessment": [
                {
                    "Threat Type": "Error",
                    "Scenario": f"API Error: {error_message}",
                    "Damage Potential": 0,
                    "Reproducibility": 0,
                    "Exploitability": 0,
                    "Affected Users": 0,
                    "Discoverability": 0,
                }
            ]
        }


# Function to get DREAD risk assessment from LM Studio Server response.
def get_dread_assessment_lm_studio(lm_studio_endpoint, model_name, prompt, api_key="not-needed"):
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key=api_key,  # Use provided API key or default to "not-needed"
    )

    # Define the expected response structure
    dread_schema = {
        "type": "json_schema",
        "json_schema": {
            "name": "dread_assessment_response",
            "schema": {
                "type": "object",
                "properties": {
                    "Risk Assessment": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "Threat Type": {"type": "string"},
                                "Scenario": {"type": "string"},
                                "Damage Potential": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "maximum": 10,
                                },
                                "Reproducibility": {"type": "integer", "minimum": 1, "maximum": 10},
                                "Exploitability": {"type": "integer", "minimum": 1, "maximum": 10},
                                "Affected Users": {"type": "integer", "minimum": 1, "maximum": 10},
                                "Discoverability": {"type": "integer", "minimum": 1, "maximum": 10},
                            },
                            "required": [
                                "Threat Type",
                                "Scenario",
                                "Damage Potential",
                                "Reproducibility",
                                "Exploitability",
                                "Affected Users",
                                "Discoverability",
                            ],
                        },
                    }
                },
                "required": ["Risk Assessment"],
            },
        },
    }

    response = client.chat.completions.create(
        model=model_name,
        response_format=dread_schema,
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt},
        ],
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    try:
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        # Handle error silently
        dread_assessment = {}

    return dread_assessment


# Function to get DREAD risk assessment from the Groq model's response.
def get_dread_assessment_groq(groq_api_key, groq_model, prompt):
    client = Groq(api_key=groq_api_key)
    response = client.chat.completions.create(
        model=groq_model,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt},
        ],
    )

    # Process the response using our utility function
    reasoning, dread_assessment = process_groq_response(
        response.choices[0].message.content, groq_model, expect_json=True
    )

    # If we got reasoning, display it in an expander in the UI
    if reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(reasoning)

    return dread_assessment
