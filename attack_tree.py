import json
import re

import streamlit as st

from stride_gpt.core.attack_tree import generate_attack_tree
from stride_gpt.core.schemas import LLMConfig


# Function to create a prompt to generate an attack tree
def create_attack_tree_prompt(
    app_type, authentication, internet_facing, sensitive_data, app_input
):
    prompt = f"""APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}
"""

    # Add GenAI attack vectors for both Generative AI and Agentic AI applications
    if app_type in ["Generative AI application", "Agentic AI application"]:
        prompt += """
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

    if app_type == "Agentic AI application":
        prompt += """
ARCHITECTURAL PATTERN DETECTION FOR ATTACK TREES:
Analyze the application description to detect architectural patterns. For each pattern detected, include specific attack paths:

1. IF RAG/RETRIEVAL DETECTED (mentions of RAG, vector database, embeddings, knowledge base, document ingestion):
   Include attack tree branch:
   - Root: Compromise via RAG Pipeline
     - Poison Knowledge Base
       - Inject malicious documents during ingestion
       - Manipulate document metadata to bias retrieval
       - Cross-tenant data injection (if multi-tenant)
     - Exploit Embedding Weaknesses
       - Craft adversarial content that clusters with target queries
       - Extract embeddings to reverse-engineer sensitive documents
     - Stale Index Exploitation
       - Exploit outdated cached content
       - Race condition during index updates

2. IF MULTI-AGENT DETECTED (mentions of multiple agents, orchestration, CrewAI, AutoGen, LangGraph, swarms):
   Include attack tree branch:
   - Root: Compromise Agent Ecosystem
     - Agent Impersonation
       - Spoof agent identity credentials
       - Replay captured agent messages
       - Register malicious agent with trusted identity
     - Inter-Agent Message Attacks
       - Tamper with message content in transit
       - Inject malicious messages into communication channel
       - Exploit message ordering/timing vulnerabilities
     - Cascading Compromise
       - Compromise one agent -> use trust to attack others
       - Exploit shared memory/state between agents
       - Trigger emergent malicious behavior through agent interactions

3. IF CODE EXECUTION DETECTED (mentions of code generation, execution, REPL, interpreter, sandbox):
   Include attack tree branch:
   - Root: Escape Execution Sandbox
     - Container/Sandbox Breakout
       - Exploit kernel vulnerabilities from within container
       - Abuse mounted volumes or network access
       - Resource exhaustion to destabilize host
     - Malicious Code Generation
       - Prompt injection to generate backdoored code
       - Dependency confusion via generated package installs
       - Obfuscated payload in generated code
     - Execution Environment Manipulation
       - Modify environment variables
       - Hijack imported modules
       - Persist malicious code across sessions

4. IF TOOL/MCP ECOSYSTEM DETECTED (mentions of MCP servers, plugins, tools, function calling):
   Include attack tree branch:
   - Root: Compromise Tool Ecosystem
     - Malicious Tool Provider
       - Compromise MCP server to return poisoned responses
       - Impersonate legitimate tool provider
       - Supply chain attack on tool package
     - Tool Abuse Chains
       - Chain multiple tools to bypass individual restrictions
       - Use read tool to discover secrets -> use write tool to exfiltrate
       - Exploit tool parameter injection
     - Confused Deputy via Tools
       - Trick agent into misusing legitimate tools
       - Exploit implicit trust in tool responses
       - Manipulate tool selection logic

5. IF PERSISTENT MEMORY DETECTED (mentions of memory, context persistence, long-term memory, session history):
   Include attack tree branch:
   - Root: Exploit Agent Memory
     - Memory Poisoning
       - Inject malicious content into long-term memory
       - Corrupt memory to alter agent personality/goals
       - Cross-session attack via persistent context
     - Memory Extraction
       - Query agent to reveal stored memories
       - Extract other users' context from shared memory
       - Side-channel memory inference
     - Memory Manipulation
       - Delete safety-related memories
       - Insert false memories to establish trust
       - Manipulate memory timestamps/ordering

6. IF AUTONOMOUS OPERATIONS DETECTED (mentions of autonomous, automated, scheduled, background tasks):
   Include attack tree branch:
   - Root: Exploit Autonomous Operations
     - Human Oversight Bypass
       - Gradually normalize risky actions to reduce scrutiny
       - Present misleading action summaries
       - Time attacks during low-monitoring periods
     - Rogue Agent Persistence
       - Establish persistence beyond intended lifecycle
       - Create hidden scheduled tasks
       - Resist shutdown commands
     - Autonomous Loop Attacks
       - Trigger infinite reasoning cycles
       - Exhaust resources through recursive operations
       - Create self-reinforcing malicious behaviors

AGENTIC ATTACK VECTORS (always include):

1. PROMPT INJECTION CHAINS:
   - Goal: Hijack agent objectives
   - Path: Malicious user input -> Bypasses input validation -> Alters agent instructions -> Unauthorized actions
   - Alternative: Poisoned document -> Agent processes content -> Hidden instructions executed -> Data exfiltration
   - Cross-layer: Poisoned RAG content -> Affects foundation model output -> Triggers tool misuse

2. TOOL EXPLOITATION PATHS:
   - Goal: Abuse agent tool access
   - Path: Discover available tools -> Enumerate permissions -> Craft malicious parameters -> Execute destructive commands
   - Alternative: Chain multiple tools -> Escalate through tool composition -> Bypass individual tool restrictions
   - Cross-layer: Compromise tool provider -> Return malicious data -> Corrupt agent memory

3. CREDENTIAL & IDENTITY ATTACKS:
   - Goal: Abuse delegated permissions
   - Path: Identify cached credentials -> Exploit confused deputy -> Access resources beyond agent scope
   - Alternative: Impersonate user to agent -> Agent acts on behalf of attacker -> Legitimate-appearing malicious actions
   - Cross-layer: Extract credentials from memory -> Use to access infrastructure directly

4. SUPPLY CHAIN ATTACKS:
   - Goal: Compromise agent infrastructure
   - Path: Target MCP server/plugin -> Inject malicious tool responses -> Agent trusts responses -> Data theft or manipulation
   - Alternative: Poison model/prompt templates -> Alter agent behavior at source
   - Cross-layer: Compromise framework dependency -> Affects all agents using framework

5. CASCADING FAILURE EXPLOITATION:
   - Goal: Cause system-wide outage or exploit error handling
   - Path: Trigger error in one agent -> Error propagates to dependent agents -> System-wide failure
   - Alternative: Exploit error messages to leak information -> Use leaked info for targeted attacks
   - Cross-layer: Infrastructure failure -> Affects observability -> Masks ongoing attack

6. HUMAN TRUST EXPLOITATION:
   - Goal: Bypass human oversight
   - Path: Build user trust over time -> Gradually expand action scope -> User becomes complacent -> Execute unauthorized actions
   - Alternative: Present misleading summaries -> User approves without scrutiny -> Harmful actions proceed
   - Cross-layer: Manipulate logs/observability -> Hide true actions from human reviewers

CROSS-COMPONENT ATTACK CHAINS:
Include at least 2 attack paths that span multiple architectural components, showing how compromise in one area enables attacks on others. Examples:
- RAG poisoning -> Agent goal hijack -> Tool misuse -> Data exfiltration
- Tool provider compromise -> Memory poisoning -> Future session hijacking
- Multi-agent manipulation -> Cascading failures -> Observability blind spot -> Persistent access
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


# Function to get attack tree from the GPT response.
def get_attack_tree(api_key, model_name, prompt):
    config = LLMConfig(provider="OpenAI API", model_name=model_name, api_key=api_key)
    mermaid, _response = generate_attack_tree(config, prompt)
    return mermaid


# Function to get attack tree from the Mistral model's response.
def get_attack_tree_mistral(mistral_api_key, mistral_model, prompt):
    config = LLMConfig(provider="Mistral API", model_name=mistral_model, api_key=mistral_api_key)
    mermaid, _response = generate_attack_tree(config, prompt)
    return mermaid


# Function to get attack tree from Ollama hosted LLM.
def get_attack_tree_ollama(ollama_endpoint, ollama_model, ollama_timeout, prompt):
    config = LLMConfig(
        provider="Ollama",
        model_name=ollama_model,
        api_key="",
        api_base=ollama_endpoint,
        timeout=ollama_timeout,
        response_format="json",
    )
    mermaid, response = generate_attack_tree(config, prompt)
    # Ollama originally returned parsed JSON dict; try to parse mermaid back to dict
    # but if the core already converted to mermaid, try to get raw JSON from response
    try:
        cleaned = clean_json_response(response.content)
        return json.loads(cleaned)
    except (json.JSONDecodeError, TypeError):
        return mermaid


# Function to get attack tree from Anthropic's Claude model.
def get_attack_tree_anthropic(anthropic_api_key, anthropic_model, prompt):
    config = LLMConfig(
        provider="Anthropic API",
        model_name=anthropic_model,
        api_key=anthropic_api_key,
        use_thinking=st.session_state.get("use_thinking", False),
    )
    mermaid, response = generate_attack_tree(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return mermaid


# Function to get attack tree from LM Studio Server response.
def get_attack_tree_lm_studio(lm_studio_endpoint, model_name, prompt, api_key="not-needed"):
    config = LLMConfig(
        provider="LM Studio Server",
        model_name=model_name,
        api_key=api_key,
        api_base=lm_studio_endpoint,
    )
    mermaid, _response = generate_attack_tree(config, prompt)
    return mermaid


# Function to get attack tree from the Groq model's response.
def get_attack_tree_groq(groq_api_key, groq_model, prompt):
    config = LLMConfig(provider="Groq API", model_name=groq_model, api_key=groq_api_key)
    mermaid, response = generate_attack_tree(config, prompt)
    if response.reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(response.reasoning)
    return mermaid


# Function to get attack tree from the Google model's response.
def get_attack_tree_google(google_api_key, google_model, prompt):
    config = LLMConfig(provider="Google AI API", model_name=google_model, api_key=google_api_key)
    mermaid, response = generate_attack_tree(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return mermaid
