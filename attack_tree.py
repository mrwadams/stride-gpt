import json
import re

import requests
import streamlit as st
from anthropic import Anthropic
from google import genai as google_genai
from groq import Groq
from mistralai import Mistral
from openai import AzureOpenAI, OpenAI

from utils import create_reasoning_system_prompt, extract_mermaid_code, process_groq_response


# Function to create a prompt to generate an attack tree
def create_attack_tree_prompt(
    app_type, authentication, internet_facing, sensitive_data, app_input, genai_context=None, agentic_context=None
):
    prompt = f"""APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}
"""

    # Add GenAI attack vectors for both Generative AI and Agentic AI applications
    if app_type in ["Generative AI application", "Agentic AI application"] and genai_context:
        model_type = genai_context.get("model_type", "") or "Not specified"
        features = ", ".join(genai_context.get("features", [])) or "Not specified"
        data_sources = ", ".join(genai_context.get("data_sources", [])) or "Not specified"
        output_handling = ", ".join(genai_context.get("output_handling", [])) or "Not specified"

        prompt += f"""
GENERATIVE AI CONTEXT:
- LLM Model Type: {model_type}
- GenAI Features: {features}
- Data Sources: {data_sources}
- Output Handling: {output_handling}

LLM ATTACK VECTORS TO MODEL:
When generating the attack tree for this LLM/generative AI application, include attack paths for the following vectors:

1. PROMPT INJECTION ATTACKS:
   - Goal: Hijack model behavior or extract sensitive data
   - Path: Craft malicious user input -> Bypass input filters -> Override system instructions -> Exfiltrate data or perform unauthorized actions
   - Alternative: Embed hidden instructions in documents/URLs -> Model processes content -> Instructions executed -> Goal hijack

2. SENSITIVE DATA EXTRACTION:
   - Goal: Extract training data, PII, or system prompts
   - Path: Probe model with targeted queries -> Identify training data patterns -> Extract sensitive information
   - Alternative: Use prompt injection to reveal system prompt -> Extract API keys or credentials embedded in prompts

3. RAG/KNOWLEDGE BASE POISONING:
   - Goal: Corrupt model responses through poisoned data
   - Path: Identify data ingestion points -> Inject malicious content into knowledge base -> Content gets embedded -> Future queries return poisoned results
   - Alternative: Manipulate document metadata -> Bias retrieval results -> Influence model outputs

4. OUTPUT EXPLOITATION:
   - Goal: Abuse model outputs in downstream systems
   - Path: Trigger malicious code generation -> Output used without sanitization -> XSS/SQL injection/command injection in consuming application
   - Alternative: Generate convincing phishing content -> Social engineering attacks -> Credential theft

5. MODEL SUPPLY CHAIN:
   - Goal: Compromise the model or its dependencies
   - Path: Target model repository/weights -> Inject backdoors or trojans -> Deployed model contains malicious behavior
   - Alternative: Compromise plugins/extensions -> Malicious code executes in model context -> Data theft or system compromise

6. RESOURCE EXHAUSTION:
   - Goal: Denial of service or cost amplification
   - Path: Craft complex prompts -> Trigger expensive computations -> Exhaust API quotas or compute budgets
   - Alternative: Recursive prompt loops -> Model generates self-referencing content -> Infinite token consumption
"""

    if app_type == "Agentic AI application" and agentic_context:
        capabilities = ", ".join(agentic_context.get("capabilities", [])) or "Not specified"
        human_oversight = agentic_context.get("human_oversight", "") or "Not specified"
        autonomous_scope = ", ".join(agentic_context.get("autonomous_scope", [])) or "Not specified"

        prompt += f"""
AGENTIC AI CONTEXT:
- Agent Capabilities: {capabilities}
- Human Oversight Level: {human_oversight}
- Autonomous Action Scope: {autonomous_scope}

AGENTIC ATTACK VECTORS TO MODEL:
When generating the attack tree for this agentic AI application, include attack paths for the following vectors:

1. PROMPT INJECTION CHAINS:
   - Goal: Hijack agent objectives
   - Path: Malicious user input -> Bypasses input validation -> Alters agent instructions -> Unauthorized actions
   - Alternative: Poisoned document -> Agent processes content -> Hidden instructions executed -> Data exfiltration

2. TOOL EXPLOITATION PATHS:
   - Goal: Abuse agent tool access
   - Path: Discover available tools -> Enumerate permissions -> Craft malicious parameters -> Execute destructive commands
   - Alternative: Chain multiple tools -> Escalate through tool composition -> Bypass individual tool restrictions

3. MEMORY/CONTEXT POISONING:
   - Goal: Corrupt agent decision-making
   - Path: Inject adversarial content -> Persist in RAG/memory -> Affect future sessions -> Influence all users
   - Alternative: Cross-session leakage -> Extract sensitive context -> Use for targeted attacks

4. SUPPLY CHAIN ATTACKS:
   - Goal: Compromise agent infrastructure
   - Path: Target MCP server/plugin -> Inject malicious tool responses -> Agent trusts responses -> Data theft or manipulation
   - Alternative: Poison model/prompt templates -> Alter agent behavior at source

5. INTER-AGENT ATTACKS (if multi-agent):
   - Goal: Compromise agent ecosystem
   - Path: Spoof agent identity -> Send malicious messages -> Target agent trusts source -> Cascading compromise
   - Alternative: Replay captured messages -> Trigger unintended actions -> Exploit trust relationships

6. HUMAN TRUST EXPLOITATION:
   - Goal: Bypass human oversight
   - Path: Build user trust over time -> Gradually expand action scope -> User becomes complacent -> Execute unauthorized actions
   - Alternative: Present misleading summaries -> User approves without scrutiny -> Harmful actions proceed
"""

    return prompt


def convert_tree_to_mermaid(tree_data):
    """
    Convert structured tree data to Mermaid syntax.

    Args:
        tree_data (dict): Dictionary containing the tree structure

    Returns:
        str: Mermaid diagram code
    """
    mermaid_lines = ["graph TD"]

    def process_node(node, parent_id=None):
        node_id = node["id"]
        node_label = node["label"]

        # Add quotes if label contains spaces or parentheses
        if " " in node_label or "(" in node_label or ")" in node_label:
            node_label = f'"{node_label}"'

        # Add the node definition
        mermaid_lines.append(f"    {node_id}[{node_label}]")

        # Add connection to parent if exists
        if parent_id:
            mermaid_lines.append(f"    {parent_id} --> {node_id}")

        # Process children
        if "children" in node:
            for child in node["children"]:
                process_node(child, node_id)

    # Process the root node(s)
    for root_node in tree_data["nodes"]:
        process_node(root_node)

    # Join lines with newlines
    return "\n".join(mermaid_lines)


def create_json_structure_prompt():
    """
    Creates a prompt for generating attack tree data in JSON format.
    """
    return """Your task is to analyze the application and create an attack tree structure in JSON format.

The JSON structure should follow this format:
{
    "nodes": [
        {
            "id": "root",
            "label": "Compromise Application",
            "children": [
                {
                    "id": "auth",
                    "label": "Gain Unauthorized Access",
                    "children": [
                        {
                            "id": "auth1",
                            "label": "Exploit OAuth2 Vulnerabilities"
                        }
                    ]
                }
            ]
        }
    ]
}

Rules:
- Use simple IDs (root, auth, auth1, data, etc.)
- Make labels clear and descriptive
- Include all attack paths and sub-paths
- Maintain proper parent-child relationships
- Ensure the JSON is properly formatted

ONLY RESPOND WITH THE JSON STRUCTURE, NO ADDITIONAL TEXT."""


def clean_json_response(response_text):
    """
    Clean JSON response by removing any markdown code block markers and finding the JSON content.

    Args:
        response_text (str): The raw response text that might contain JSON

    Returns:
        str: Cleaned JSON string
    """
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


# Function to get attack tree from the GPT response.
def get_attack_tree(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    # For GPT-5 series models that support JSON output format
    if model_name in ["gpt-5.2", "gpt-5-mini", "gpt-5-nano", "gpt-5.2-pro", "gpt-5"]:
        system_prompt = create_reasoning_system_prompt(
            task_description="Create a structured attack tree by analyzing potential attack paths.",
            approach_description="""Analyze the application and create an attack tree showing potential attack paths.

Rules:
- Use simple alphanumeric IDs (A1, A2, B1, etc.)
- Make labels clear and descriptive
- Include all attack paths and sub-paths
- Maintain proper parent-child relationships
- Ensure proper JSON structure

Example format:
{
    "nodes": [
        {
            "id": "A1",
            "label": "Compromise Application",
            "children": [
                {
                    "id": "B1",
                    "label": "Exploit Authentication Vulnerabilities",
                    "children": [
                        {
                            "id": "C1",
                            "label": "Brute Force Credentials",
                            "children": []
                        }
                    ]
                }
            ]
        }
    ]
}

ONLY RESPOND WITH THE JSON STRUCTURE, NO ADDITIONAL TEXT.""",
        )

        response = client.chat.completions.create(
            model=model_name,
            response_format=create_attack_tree_schema(),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            max_completion_tokens=20000 if model_name.startswith("gpt-5") else 8192,
        )
    else:
        # For other models, try to get JSON output without format parameter
        system_prompt = create_json_structure_prompt()
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            max_tokens=8192,
        )

    # Try to parse JSON response
    try:
        # Clean the response text first
        cleaned_response = clean_json_response(response.choices[0].message.content)
        tree_data = json.loads(cleaned_response)
        return convert_tree_to_mermaid(tree_data)
    except json.JSONDecodeError:
        # Fallback: try to extract Mermaid code if JSON parsing fails
        return extract_mermaid_code(response.choices[0].message.content)


# Function to get attack tree from the Azure OpenAI response.
def get_attack_tree_azure(
    azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt
):
    client = AzureOpenAI(
        azure_endpoint=azure_api_endpoint,
        api_key=azure_api_key,
        api_version=azure_api_version,
    )

    # Try to get JSON output
    system_prompt = create_json_structure_prompt()
    response = client.chat.completions.create(
        model=azure_deployment_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    )

    # Try to parse JSON response
    try:
        cleaned_response = clean_json_response(response.choices[0].message.content)
        tree_data = json.loads(cleaned_response)
        return convert_tree_to_mermaid(tree_data)
    except json.JSONDecodeError:
        # Fallback: try to extract Mermaid code if JSON parsing fails
        return extract_mermaid_code(response.choices[0].message.content)


# Function to get attack tree from the Mistral model's response.
def get_attack_tree_mistral(mistral_api_key, mistral_model, prompt):
    client = Mistral(api_key=mistral_api_key)

    # Try to get JSON output
    system_prompt = create_json_structure_prompt()
    response = client.chat.complete(
        model=mistral_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    )

    # Try to parse JSON response
    try:
        cleaned_response = clean_json_response(response.choices[0].message.content)
        tree_data = json.loads(cleaned_response)
        return convert_tree_to_mermaid(tree_data)
    except json.JSONDecodeError:
        # Fallback: try to extract Mermaid code if JSON parsing fails
        return extract_mermaid_code(response.choices[0].message.content)


# Function to get attack tree from Ollama hosted LLM.
def get_attack_tree_ollama(ollama_endpoint, ollama_model, prompt):
    """
    Get attack tree from Ollama hosted LLM.

    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://localhost:11434')
        ollama_model (str): The name of the model to use
        prompt (str): The prompt to send to the model

    Returns:
        dict: The parsed JSON response from the model

    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
        json.JSONDecodeError: If the response cannot be parsed as JSON
    """
    if not ollama_endpoint.endswith("/"):
        ollama_endpoint = ollama_endpoint + "/"

    url = ollama_endpoint + "api/generate"

    system_prompt = "You are a helpful assistant designed to output JSON."
    full_prompt = f"{system_prompt}\n\n{prompt}"

    data = {"model": ollama_model, "prompt": full_prompt, "stream": False, "format": "json"}

    try:
        response = requests.post(url, json=data, timeout=60)  # Add timeout
        response.raise_for_status()  # Raise exception for bad status codes
        outer_json = response.json()

        try:
            # Parse the JSON response from the model's response field
            return json.loads(outer_json["response"])
        except (json.JSONDecodeError, KeyError):
            # Handle error without printing debug info
            raise

    except requests.exceptions.RequestException:
        # Handle error without printing debug info
        raise


# Function to get attack tree from Anthropic's Claude model.
def get_attack_tree_anthropic(anthropic_api_key, anthropic_model, prompt):
    client = Anthropic(api_key=anthropic_api_key)

    # Check if we're using extended thinking mode (from checkbox in UI)
    is_thinking_mode = st.session_state.get("use_thinking", False)

    # Use the selected model
    actual_model = anthropic_model

    # Try to get JSON output
    system_prompt = create_json_structure_prompt()

    try:
        # Configure the request based on whether thinking mode is enabled
        if is_thinking_mode:
            response = client.messages.create(
                model=actual_model,
                max_tokens=48000,
                thinking={"type": "enabled", "budget_tokens": 16000},
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
                timeout=600,  # 10-minute timeout
            )
        else:
            response = client.messages.create(
                model=actual_model,
                max_tokens=32768,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
                timeout=300,  # 5-minute timeout
            )

        # Try to parse JSON response
        try:
            if is_thinking_mode:
                # For thinking mode, we need to extract only the text content blocks
                text_content = "".join(
                    block.text for block in response.content if block.type == "text"
                )

                # Store thinking content in session state for debugging/transparency (optional)
                thinking_content = "".join(
                    block.thinking for block in response.content if block.type == "thinking"
                )
                if thinking_content:
                    st.session_state["last_thinking_content"] = thinking_content

                cleaned_response = clean_json_response(text_content)
            else:
                cleaned_response = clean_json_response(response.content[0].text)

            tree_data = json.loads(cleaned_response)
            return convert_tree_to_mermaid(tree_data)
        except (json.JSONDecodeError, IndexError, AttributeError):
            # Fallback: try to extract Mermaid code if JSON parsing fails
            if is_thinking_mode:
                text_content = "".join(
                    block.text for block in response.content if block.type == "text"
                )
                return extract_mermaid_code(text_content)
            return extract_mermaid_code(response.content[0].text)
    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")

        # Create a fallback response for timeout or other errors
        return """
graph TD
    A[Error Generating Attack Tree] --> B[API Error]
    B --> C["{error_message}"]
    A --> D[Suggestions]
    D --> E[Try simplifying the input]
    D --> F[Try standard model instead of thinking mode]
    D --> G[Break down complex applications]
        """.replace(
            "{error_message}", error_message.replace('"', "'")
        )


# Function to get attack tree from LM Studio Server response.
def get_attack_tree_lm_studio(lm_studio_endpoint, model_name, prompt, api_key="not-needed"):
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key=api_key,  # Use provided API key or default to "not-needed"
    )

    # Try to get JSON output
    system_prompt = create_json_structure_prompt()
    response = client.chat.completions.create(
        model=model_name,
        response_format=create_attack_tree_schema_lm_studio(),  # Use LM Studio specific schema
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    )

    # Try to parse JSON response
    try:
        cleaned_response = clean_json_response(response.choices[0].message.content)
        tree_data = json.loads(cleaned_response)
        return convert_tree_to_mermaid(tree_data)
    except json.JSONDecodeError:
        # Fallback: try to extract Mermaid code if JSON parsing fails
        return extract_mermaid_code(response.choices[0].message.content)


# Function to get attack tree from the Groq model's response.
def get_attack_tree_groq(groq_api_key, groq_model, prompt):
    client = Groq(api_key=groq_api_key)

    # Try to get JSON output
    system_prompt = create_json_structure_prompt()
    response = client.chat.completions.create(
        model=groq_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    )

    # Process the response using our utility function
    reasoning, content = process_groq_response(
        response.choices[0].message.content, groq_model, expect_json=True
    )

    # If we got reasoning, display it in an expander in the UI
    if reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(reasoning)

    # Try to parse JSON response
    try:
        if isinstance(content, dict):  # If already parsed by process_groq_response
            tree_data = content
        else:
            cleaned_response = clean_json_response(content)
            tree_data = json.loads(cleaned_response)
        return convert_tree_to_mermaid(tree_data)
    except (json.JSONDecodeError, TypeError):
        # Fallback: try to extract Mermaid code if JSON parsing fails
        return extract_mermaid_code(content)


def create_attack_tree_schema():
    """
    Creates a JSON schema for attack tree structure.
    """
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "attack_tree",
            "description": "A structured representation of an attack tree",
            "schema": {
                "type": "object",
                "properties": {"nodes": {"type": "array", "items": {"$ref": "#/$defs/node"}}},
                "$defs": {
                    "node": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Simple alphanumeric identifier for the node",
                            },
                            "label": {
                                "type": "string",
                                "description": "Description of the attack vector or goal",
                            },
                            "children": {"type": "array", "items": {"$ref": "#/$defs/node"}},
                        },
                        "required": ["id", "label", "children"],
                        "additionalProperties": False,
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    }


def create_attack_tree_schema_lm_studio():
    """
    Creates a non-recursive JSON schema for attack tree structure specifically for LM Studio.
    Limits the depth to 3 levels to avoid circular references.
    """
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "attack_tree",
            "description": "A structured representation of an attack tree",
            "schema": {
                "type": "object",
                "properties": {
                    "nodes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {
                                    "type": "string",
                                    "description": "Simple alphanumeric identifier for the root node",
                                },
                                "label": {
                                    "type": "string",
                                    "description": "Description of the attack vector or goal",
                                },
                                "children": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "id": {
                                                "type": "string",
                                                "description": "Simple alphanumeric identifier for the level 1 node",
                                            },
                                            "label": {
                                                "type": "string",
                                                "description": "Description of the attack vector or goal",
                                            },
                                            "children": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {
                                                            "type": "string",
                                                            "description": "Simple alphanumeric identifier for the leaf node",
                                                        },
                                                        "label": {
                                                            "type": "string",
                                                            "description": "Description of the attack vector or goal",
                                                        },
                                                        "children": {
                                                            "type": "array",
                                                            "items": {},
                                                            "default": [],
                                                        },
                                                    },
                                                    "required": ["id", "label", "children"],
                                                    "additionalProperties": False,
                                                },
                                            },
                                        },
                                        "required": ["id", "label", "children"],
                                        "additionalProperties": False,
                                    },
                                },
                            },
                            "required": ["id", "label", "children"],
                            "additionalProperties": False,
                        },
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    }


# Function to get attack tree from the Google model's response.
def get_attack_tree_google(google_api_key, google_model, prompt):
    """
    Generate an attack tree using the Gemini API (Google AI) as per official documentation:
    https://ai.google.dev/gemini-api/docs/text-generation
    """
    import json

    import streamlit as st

    client = google_genai.Client(api_key=google_api_key)
    system_instruction = create_json_structure_prompt()

    try:
        try:
            from google.genai import types as google_types

            response = client.models.generate_content(
                model=google_model,
                contents=[prompt],
                config=google_types.GenerateContentConfig(system_instruction=system_instruction),
            )
        except Exception:
            # Fallback: just prepend system instruction to prompt
            response = client.models.generate_content(
                model=google_model, contents=[f"{system_instruction}\n\n{prompt}"]
            )
    except Exception as e:
        st.error(f"Error generating attack tree with Google AI: {e!s}")
        return (
            'graph TD\n    A[Error Generating Attack Tree] --> B[API Error]\n    B --> C["Error: '
            + str(e).replace('"', "'")
            + "]"
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

    try:
        cleaned_response = clean_json_response(response.text)
        tree_data = json.loads(cleaned_response)
        return convert_tree_to_mermaid(tree_data)
    except (json.JSONDecodeError, AttributeError):
        return extract_mermaid_code(getattr(response, "text", str(response)))
