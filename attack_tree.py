import re
import requests
import streamlit as st
from anthropic import Anthropic
from mistralai import Mistral
from openai import OpenAI, AzureOpenAI
from groq import Groq
from utils import process_groq_response, create_reasoning_system_prompt, extract_mermaid_code
import json
from google import genai as google_genai

# Function to create a prompt to generate an attack tree
def create_attack_tree_prompt(app_type, authentication, internet_facing, sensitive_data, app_input):
    prompt = f"""
APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}
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
        mermaid_lines.append(f'    {node_id}[{node_label}]')
        
        # Add connection to parent if exists
        if parent_id:
            mermaid_lines.append(f'    {parent_id} --> {node_id}')
        
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
    json_pattern = r'```json\s*(.*?)\s*```'
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # If no JSON code block, try to find content between any code blocks
    code_pattern = r'```\s*(.*?)\s*```'
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # If no code blocks, return the original text
    return response_text.strip()

# Function to get attack tree from the GPT response.
def get_attack_tree(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    # For models that support JSON output format
    if model_name in ["o1", "o3", "o3-mini", "o4-mini"]:
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

ONLY RESPOND WITH THE JSON STRUCTURE, NO ADDITIONAL TEXT."""
        )
        
        response = client.chat.completions.create(
            model=model_name,
            response_format=create_attack_tree_schema(),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_completion_tokens=4000
        )
    else:
        # For other models, try to get JSON output without format parameter
        system_prompt = create_json_structure_prompt()
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4000
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
def get_attack_tree_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt):
    client = AzureOpenAI(
        azure_endpoint = azure_api_endpoint,
        api_key = azure_api_key,
        api_version = azure_api_version,
    )

    # Try to get JSON output
    system_prompt = create_json_structure_prompt()
    response = client.chat.completions.create(
        model = azure_deployment_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
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
            {"role": "user", "content": prompt}
        ]
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
    if not ollama_endpoint.endswith('/'):
        ollama_endpoint = ollama_endpoint + '/'
    
    url = ollama_endpoint + "api/generate"

    system_prompt = "You are a helpful assistant designed to output JSON."
    full_prompt = f"{system_prompt}\n\n{prompt}"

    data = {
        "model": ollama_model,
        "prompt": full_prompt,
        "stream": False,
        "format": "json"
    }

    try:
        response = requests.post(url, json=data, timeout=60)  # Add timeout
        response.raise_for_status()  # Raise exception for bad status codes
        outer_json = response.json()
        
        try:
            # Parse the JSON response from the model's response field
            inner_json = json.loads(outer_json['response'])
            return inner_json
        except (json.JSONDecodeError, KeyError):
            # Handle error without printing debug info
            raise
            
    except requests.exceptions.RequestException:
        # Handle error without printing debug info
        raise

# Function to get attack tree from Anthropic's Claude model.
def get_attack_tree_anthropic(anthropic_api_key, anthropic_model, prompt):
    client = Anthropic(api_key=anthropic_api_key)
    
    # Check if we're using extended thinking mode
    is_thinking_mode = "thinking" in anthropic_model.lower()
    
    # If using thinking mode, use the actual model name without the "thinking" suffix
    actual_model = "claude-3-7-sonnet-latest" if is_thinking_mode else anthropic_model

    # Try to get JSON output
    system_prompt = create_json_structure_prompt()
    
    try:
        # Configure the request based on whether thinking mode is enabled
        if is_thinking_mode:
            response = client.messages.create(
                model=actual_model,
                max_tokens=24000,
                thinking={
                    "type": "enabled",
                    "budget_tokens": 16000
                },
                system=system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                timeout=600  # 10-minute timeout
            )
        else:
            response = client.messages.create(
                model=actual_model,
                max_tokens=4096,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                timeout=300  # 5-minute timeout
            )

        # Try to parse JSON response
        try:
            if is_thinking_mode:
                # For thinking mode, we need to extract only the text content blocks
                text_content = ''.join(block.text for block in response.content if block.type == "text")
                
                # Store thinking content in session state for debugging/transparency (optional)
                thinking_content = ''.join(block.thinking for block in response.content if block.type == "thinking")
                if thinking_content:
                    st.session_state['last_thinking_content'] = thinking_content
                    
                cleaned_response = clean_json_response(text_content)
            else:
                cleaned_response = clean_json_response(response.content[0].text)
                
            tree_data = json.loads(cleaned_response)
            return convert_tree_to_mermaid(tree_data)
        except (json.JSONDecodeError, IndexError, AttributeError):
            # Fallback: try to extract Mermaid code if JSON parsing fails
            if is_thinking_mode:
                text_content = ''.join(block.text for block in response.content if block.type == "text")
                return extract_mermaid_code(text_content)
            else:
                return extract_mermaid_code(response.content[0].text)
    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")
        
        # Create a fallback response for timeout or other errors
        fallback_mermaid = """
graph TD
    A[Error Generating Attack Tree] --> B[API Error]
    B --> C["{error_message}"]
    A --> D[Suggestions]
    D --> E[Try simplifying the input]
    D --> F[Try standard model instead of thinking mode]
    D --> G[Break down complex applications]
        """.replace("{error_message}", error_message.replace('"', "'"))
        
        return fallback_mermaid

# Function to get attack tree from LM Studio Server response.
def get_attack_tree_lm_studio(lm_studio_endpoint, model_name, prompt):
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key="not-needed"  # LM Studio Server doesn't require an API key
    )

    # Try to get JSON output
    system_prompt = create_json_structure_prompt()
    response = client.chat.completions.create(
        model=model_name,
        response_format=create_attack_tree_schema_lm_studio(),  # Use LM Studio specific schema
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
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
            {"role": "user", "content": prompt}
        ]
    )

    # Process the response using our utility function
    reasoning, content = process_groq_response(
        response.choices[0].message.content,
        groq_model,
        expect_json=True
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
                "properties": {
                    "nodes": {
                        "type": "array",
                        "items": {
                            "$ref": "#/$defs/node"
                        }
                    }
                },
                "$defs": {
                    "node": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Simple alphanumeric identifier for the node"
                            },
                            "label": {
                                "type": "string",
                                "description": "Description of the attack vector or goal"
                            },
                            "children": {
                                "type": "array",
                                "items": {
                                    "$ref": "#/$defs/node"
                                }
                            }
                        },
                        "required": ["id", "label", "children"],
                        "additionalProperties": False
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False
            },
            "strict": True
        }
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
                                    "description": "Simple alphanumeric identifier for the root node"
                                },
                                "label": {
                                    "type": "string",
                                    "description": "Description of the attack vector or goal"
                                },
                                "children": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "id": {
                                                "type": "string",
                                                "description": "Simple alphanumeric identifier for the level 1 node"
                                            },
                                            "label": {
                                                "type": "string",
                                                "description": "Description of the attack vector or goal"
                                            },
                                            "children": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {
                                                            "type": "string",
                                                            "description": "Simple alphanumeric identifier for the leaf node"
                                                        },
                                                        "label": {
                                                            "type": "string",
                                                            "description": "Description of the attack vector or goal"
                                                        },
                                                        "children": {
                                                            "type": "array",
                                                            "items": {},
                                                            "default": []
                                                        }
                                                    },
                                                    "required": ["id", "label", "children"],
                                                    "additionalProperties": False
                                                }
                                            }
                                        },
                                        "required": ["id", "label", "children"],
                                        "additionalProperties": False
                                    }
                                }
                            },
                            "required": ["id", "label", "children"],
                            "additionalProperties": False
                        }
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False
            },
            "strict": True
        }
    }

# Function to get attack tree from the Google model's response.
def get_attack_tree_google(google_api_key, google_model, prompt):
    """
    Generate an attack tree using the Gemini API (Google AI) as per official documentation:
    https://ai.google.dev/gemini-api/docs/text-generation
    """
    from google import genai as google_genai
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
                config=google_types.GenerateContentConfig(system_instruction=system_instruction)
            )
        except Exception:
            # Fallback: just prepend system instruction to prompt
            response = client.models.generate_content(
                model=google_model,
                contents=[f"{system_instruction}\n\n{prompt}"]
            )
    except Exception as e:
        st.error(f"Error generating attack tree with Google AI: {str(e)}")
        return "graph TD\n    A[Error Generating Attack Tree] --> B[API Error]\n    B --> C[\"Error: " + str(e).replace('"', "'") + "]"

    try:
        cleaned_response = clean_json_response(response.text)
        tree_data = json.loads(cleaned_response)
        return convert_tree_to_mermaid(tree_data)
    except (json.JSONDecodeError, AttributeError):
        return extract_mermaid_code(getattr(response, 'text', str(response)))