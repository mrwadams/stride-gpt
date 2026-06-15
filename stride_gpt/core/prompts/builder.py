"""Prompt templates for LLM calls. Zero Streamlit imports."""

from __future__ import annotations


def create_reasoning_system_prompt(task_description: str, approach_description: str) -> str:
    """Creates a system prompt formatted for OpenAI's GPT-5 series models.

    Args:
        task_description: Description of what the model needs to do
        approach_description: Step-by-step approach the model should follow

    Returns:
        Formatted system prompt
    """
    return f"""Task: {task_description}

Approach:
{approach_description}"""


def create_image_analysis_prompt() -> str:
    """Creates a prompt for analyzing architecture diagrams."""
    return """
    You are a Senior Solution Architect tasked with explaining the following architecture diagram to
    a Security Architect to support the threat modelling of the system.

    In order to complete this task you must:

      1. Analyse the diagram
      2. Explain the system architecture to the Security Architect. Your explanation should cover the key
         components, their interactions, and any technologies used.

    Provide a direct explanation of the diagram in a clear, structured format, suitable for a professional
    discussion.

    IMPORTANT INSTRUCTIONS:
     - Do not include any words before or after the explanation itself. For example, do not start your
    explanation with "The image shows..." or "The diagram shows..." just start explaining the key components
    and other relevant details.
     - Do not infer or speculate about information that is not visible in the diagram. Only provide information that can be
    directly determined from the diagram itself.
    """


def create_json_structure_prompt() -> str:
    """Creates a prompt for generating attack tree data in JSON format."""
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


def create_attack_tree_schema() -> dict:
    """Creates a JSON schema for attack tree structure."""
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


def create_llm_stride_prompt_section() -> str:
    """LLM-specific section of the threat model prompt.

    Maps OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10) to STRIDE
    categories. Content is the packaged `genai.md` reference card so the
    single-shot path and the agent's progressive-disclosure loader stay in
    sync.
    """
    from stride_gpt.core.prompts.variants import load_reference

    return "\n" + load_reference("genai")


def create_agentic_stride_prompt_section() -> str:
    """Agentic-specific section of the threat model prompt.

    Maps OWASP ASI01-ASI10 to STRIDE categories and incorporates architectural
    layer analysis. Content is the packaged `agentic.md` reference card so the
    single-shot path and the agent's progressive-disclosure loader stay in
    sync.
    """
    from stride_gpt.core.prompts.variants import load_reference

    return "\n" + load_reference("agentic")


def create_insider_threat_prompt_section() -> str:
    """AI insider-threat section of the threat model prompt.

    Treats the agent as a potentially-untrusted insider with credentials,
    access, and autonomy — complementary to the OWASP "asset under attack"
    framing. Content is the packaged `insider_threat.md` reference card so
    the single-shot path and the agent's progressive-disclosure loader stay
    in sync.
    """
    from stride_gpt.core.prompts.variants import load_reference

    return "\n" + load_reference("insider_threat")


def dfd_to_prompt_section(dfd_mermaid: str) -> str:
    """Render a confirmed DFD into a prompt section.

    When the user has reviewed (and possibly edited) a DFD in the web UI
    and confirmed it for use, the Mermaid source is spliced into the
    threat-model and attack-tree prompts. The DFD is the user's canonical
    statement of the system under analysis, so we surface it explicitly
    rather than just appending to the free-form description.
    """
    return f"""
CONFIRMED DATA FLOW DIAGRAM (Mermaid):
The user has reviewed the following Data Flow Diagram and confirmed it as
an accurate representation of the system under analysis. Use it as the
authoritative model of components, data flows, and trust boundaries when
identifying threats — pay particular attention to flows that cross trust
boundaries.

```mermaid
{dfd_mermaid.strip()}
```
"""


def create_dfd_prompt(
    app_type: str,
    authentication: str,
    internet_facing: str,
    sensitive_data: str,
    app_input: str,
) -> str:
    """Build the DFD-generation prompt for a given application profile.

    The output of this prompt is fed to `core.dfd.generate_dfd`, which
    expects JSON conforming to `DFD_SCHEMA`. The detailed JSON shape and
    rules live in the system prompt set by `core.dfd._get_system_prompt`;
    this user prompt provides the application context.
    """
    return f"""APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}

Produce a Data Flow Diagram (DFD) for this application as JSON conforming
to the schema described in your system instructions. Cover every external
entity, process, and data store you can identify from the description, and
group internal components inside trust boundaries (e.g. "Internal Network",
"Cloud VPC") so the diagram is useful for STRIDE threat modelling. Edge
labels should name the data crossing the flow."""


def create_dfd_image_analysis_prompt() -> str:
    """Instruction for vision models parsing a user-supplied DFD image.

    Asks the model to extract structured DFD JSON (nodes/edges/trust
    boundaries) so we can re-render the user's existing diagram in our
    canonical Mermaid form. Falls back gracefully if the model emits raw
    Mermaid in a code fence — `_parse_dfd_response` handles that path.
    """
    return """You are reviewing a Data Flow Diagram (DFD) that a security architect has provided.

Extract the diagram's structure as a JSON object with this exact shape:

{
    "nodes": [
        {"id": "<short-id>", "label": "<displayed name>", "type": "external_entity" | "process" | "data_store"}
    ],
    "edges": [
        {"from": "<node id>", "to": "<node id>", "label": "<data flow name>"}
    ],
    "trust_boundaries": [
        {"name": "<boundary name>", "node_ids": ["<node id>", "..."]}
    ]
}

Classification rules:
- external_entity: actors outside the system (users, third-party APIs, browsers)
- process: components that transform data (services, functions, workers)
- data_store: persistent stores (databases, queues, caches, file systems)

If the diagram shows trust boundaries (dashed lines, labelled zones, network
perimeters), capture them in `trust_boundaries`. If no boundaries are shown,
return an empty list.

ONLY RESPOND WITH THE JSON OBJECT, NO ADDITIONAL TEXT. Do not infer
components that aren't visible in the diagram."""


def create_threat_model_prompt(
    app_type: str,
    authentication: str,
    internet_facing: str,
    sensitive_data: str,
    app_input: str,
    confirmed_dfd: str | None = None,
) -> str:
    """Build the threat-model prompt for a given application profile.

    If `confirmed_dfd` is supplied (Mermaid source the user has confirmed
    in the DFD tab), it's spliced in as an authoritative system model so
    the LLM threats reference the same components and trust boundaries.
    """
    is_genai = app_type == "Generative AI application"
    is_agentic = app_type == "Agentic AI application"
    include_llm_risks = is_genai or is_agentic

    prompt = """Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to analyze the provided code summary, README content, and application description to produce a list of specific threats for the application.

Pay special attention to the README content as it often provides valuable context about the project's purpose, architecture, and potential security considerations.

"""

    if is_agentic:
        prompt += """For this AGENTIC AI APPLICATION, you must consider traditional STRIDE threats, LLM-specific threats from the OWASP Top 10 for LLM Applications (LLM01-LLM10), agentic-specific threats from the OWASP Top 10 for Agentic Applications (ASI01-ASI10), AND insider-threat risks from the AI Insider Threat framework (treating the agent itself as a potentially-untrusted insider with access). For each STRIDE category, identify threats covering AI agent risks including prompt injection, tool misuse, memory poisoning, autonomous action risks, LLM vulnerabilities, and what the agent could do *against* its operator if its trust were misplaced.

"""
    elif is_genai:
        prompt += """For this GENERATIVE AI APPLICATION, you must consider both traditional STRIDE threats AND LLM-specific threats from the OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10). For each STRIDE category, identify threats specific to LLM-powered applications including prompt injection, sensitive data disclosure, and improper output handling.

"""
    else:
        prompt += """For each of the STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege), list multiple (3 or 4) credible threats if applicable. """

    prompt += """Each threat scenario should provide a credible scenario in which the threat could occur in the context of the application. It is very important that your responses are tailored to reflect the details you are given.

"""

    if is_agentic:
        prompt += """When providing the threat model, use a JSON formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", "Potential Impact", "OWASP_LLM" (the applicable LLM risk code, e.g., "LLM01", "LLM02", etc., or null), "OWASP_ASI" (the applicable Agentic Security Issue code, e.g., "ASI01", "ASI02", etc., or null), and "INSIDER_CATEGORY" (one of "Credential Compromise", "Supply Chain Sabotage", "Data Exfiltration", "Infrastructure Sabotage", "Deception & Evasion", or null if no insider-threat category applies). A threat may carry any combination of these codes if it applies to multiple categories.

"""
    elif is_genai:
        prompt += """When providing the threat model, use a JSON formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", "Potential Impact", and "OWASP_LLM" (the applicable OWASP LLM risk code, e.g., "LLM01", "LLM02", etc., or null if not applicable).

"""
    else:
        prompt += """When providing the threat model, use a JSON formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", and "Potential Impact".

"""

    if is_agentic:
        prompt += """Under "improvement_suggestions", include an array of strings that suggest what additional information or details the user could provide to make the threat model more comprehensive and accurate in the next iteration. Focus on identifying gaps in the provided application description that, if filled, would enable a more detailed and precise threat analysis.

For AGENTIC AI applications, specifically look for and suggest clarification on:
- Agent framework/orchestration details (e.g., LangChain, CrewAI, AutoGen, custom) if not specified
- RAG pipeline architecture if retrieval is mentioned but vector store details are missing
- Sandbox/isolation mechanisms if code execution is mentioned
- Inter-agent communication protocols if multi-agent is mentioned but coordination method is unclear
- Memory persistence mechanisms if long-running agents are implied
- Tool validation and output sanitization approaches
- Circuit breaker and rate limiting implementations for agent loops
- Audit logging coverage for agent decisions and tool invocations
- Human escalation paths and approval workflows

Do not provide general security recommendations - focus only on what additional information would help create a better threat model.

"""
    else:
        prompt += """Under "improvement_suggestions", include an array of strings that suggest what additional information or details the user could provide to make the threat model more comprehensive and accurate in the next iteration. Focus on identifying gaps in the provided application description that, if filled, would enable a more detailed and precise threat analysis. For example:
- Missing architectural details that would help identify more specific threats
- Unclear authentication flows that need more detail
- Incomplete data flow descriptions
- Missing technical stack information
- Unclear system boundaries or trust zones
- Incomplete description of sensitive data handling

Do not provide general security recommendations - focus only on what additional information would help create a better threat model.

"""

    prompt += f"""APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
"""

    if include_llm_risks:
        prompt += create_llm_stride_prompt_section()

    if is_agentic:
        prompt += create_agentic_stride_prompt_section()
        prompt += create_insider_threat_prompt_section()

    if confirmed_dfd:
        prompt += dfd_to_prompt_section(confirmed_dfd)

    prompt += f"""
CODE SUMMARY, README CONTENT, AND APPLICATION DESCRIPTION:
{app_input}

"""

    if is_agentic:
        prompt += """Example of expected JSON response format for Agentic AI applications:

    {
      "threat_model": [
        {
          "Threat Type": "Spoofing",
          "Scenario": "An attacker injects malicious instructions into a document processed by the agent, causing it to impersonate a legitimate service when responding to users.",
          "Potential Impact": "Users may trust fraudulent communications, leading to credential theft or financial loss.",
          "OWASP_LLM": "LLM01",
          "OWASP_ASI": "ASI01"
        },
        {
          "Threat Type": "Information Disclosure",
          "Scenario": "The LLM reveals fragments of its system prompt containing API keys when users craft specific queries about its configuration.",
          "Potential Impact": "Exposure of credentials enables unauthorized access to backend services.",
          "OWASP_LLM": "LLM07",
          "OWASP_ASI": null
        },
        {
          "Threat Type": "Elevation of Privilege",
          "Scenario": "The agent's code execution capability lacks proper sandboxing, allowing generated code to access the host filesystem and escalate privileges.",
          "Potential Impact": "Complete system compromise and lateral movement.",
          "OWASP_LLM": "LLM05",
          "OWASP_ASI": "ASI05"
        }
      ],
      "improvement_suggestions": [
        "Provide details about how agent memory/state is persisted and protected.",
        "Describe the validation mechanisms for external tool responses.",
        "Clarify the boundaries between agent actions and human-required approvals.",
        "Detail the sandboxing mechanisms for any code execution capabilities."
      ]
    }
"""
    elif is_genai:
        prompt += """Example of expected JSON response format for Generative AI applications:

    {
      "threat_model": [
        {
          "Threat Type": "Tampering",
          "Scenario": "An attacker injects malicious instructions through user-uploaded documents that are processed by the RAG system, causing the LLM to provide misleading financial advice.",
          "Potential Impact": "Users make poor decisions based on manipulated LLM outputs, leading to financial losses.",
          "OWASP_LLM": "LLM01"
        },
        {
          "Threat Type": "Information Disclosure",
          "Scenario": "The LLM inadvertently reveals PII from its training data when users ask questions similar to training examples.",
          "Potential Impact": "Privacy breach exposing customer personal information.",
          "OWASP_LLM": "LLM02"
        },
        {
          "Threat Type": "Elevation of Privilege",
          "Scenario": "LLM output containing user-controlled content is passed to a SQL query without sanitization, enabling SQL injection.",
          "Potential Impact": "Database compromise and unauthorized data access.",
          "OWASP_LLM": "LLM05"
        }
      ],
      "improvement_suggestions": [
        "Describe how user inputs are validated before being sent to the LLM.",
        "Clarify what sensitive data the LLM has access to via RAG or fine-tuning.",
        "Detail how LLM outputs are sanitized before use in downstream systems.",
        "Specify rate limiting and cost controls for LLM API usage."
      ]
    }
"""
    else:
        prompt += """Example of expected JSON response format:

    {
      "threat_model": [
        {
          "Threat Type": "Spoofing",
          "Scenario": "Example Scenario 1",
          "Potential Impact": "Example Potential Impact 1"
        },
        {
          "Threat Type": "Spoofing",
          "Scenario": "Example Scenario 2",
          "Potential Impact": "Example Potential Impact 2"
        }
      ],
      "improvement_suggestions": [
        "Please provide more details about the authentication flow between components to better analyze potential authentication bypass scenarios.",
        "Consider adding information about how sensitive data is stored and transmitted to enable more precise data exposure threat analysis."
      ]
    }
"""

    return prompt


def create_attack_tree_schema_lm_studio() -> dict:
    """Creates a non-recursive JSON schema for attack tree structure specifically for LM Studio.

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
