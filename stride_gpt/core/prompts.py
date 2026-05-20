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

    Maps OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10) to STRIDE categories.
    """
    return """
LLM-SPECIFIC THREAT CATEGORIES (OWASP Top 10 for LLM Applications 2025):
You MUST analyze threats from both traditional STRIDE categories AND the following LLM-specific threat categories. Map each LLM threat to its corresponding STRIDE category and include the OWASP_LLM code:

SPOOFING (Traditional + LLM):
- Traditional: Identity spoofing, credential theft
- LLM01 (Prompt Injection): Attacker crafts inputs that override system prompts or instructions, making the LLM impersonate other entities or bypass intended behavior
- LLM07 (System Prompt Leakage): Extraction of system prompts reveals intended identity/behavior, enabling more targeted spoofing

TAMPERING (Traditional + LLM):
- Traditional: Data modification, code injection
- LLM01 (Prompt Injection): Direct or indirect injection that manipulates LLM behavior or outputs
- LLM04 (Data and Model Poisoning): Malicious modification of training data, fine-tuning data, or embeddings
- LLM08 (Vector and Embedding Weaknesses): Manipulation of RAG data or embeddings to alter retrieval results

REPUDIATION (Traditional + LLM):
- Traditional: Denial of actions, log manipulation
- LLM09 (Misinformation): LLM generates false information that users act upon; difficult to attribute accountability
- Lack of audit trails for LLM decision-making and content generation

INFORMATION DISCLOSURE (Traditional + LLM):
- Traditional: Data leaks, unauthorized access
- LLM02 (Sensitive Information Disclosure): LLM reveals training data, PII, credentials, or proprietary information
- LLM07 (System Prompt Leakage): Exposure of confidential system instructions, business logic, or secrets embedded in prompts
- LLM08 (Vector and Embedding Weaknesses): Information leakage through embeddings or cross-tenant RAG data

DENIAL OF SERVICE (Traditional + LLM):
- Traditional: Resource exhaustion, service disruption
- LLM10 (Unbounded Consumption): Resource exhaustion through expensive queries, long contexts, or repeated requests
- LLM04 (Data and Model Poisoning): Model performance degradation through poisoned training data

ELEVATION OF PRIVILEGE (Traditional + LLM):
- Traditional: Privilege escalation, unauthorized access
- LLM05 (Improper Output Handling): LLM output passed to downstream systems without validation enables command injection, XSS, SSRF
- LLM06 (Excessive Agency): LLM granted excessive permissions or autonomy to perform actions
- LLM03 (Supply Chain): Compromised models, plugins, or dependencies introduce backdoors or malicious capabilities

CRITICAL LLM RISKS TO EVALUATE:
1. LLM01 - Prompt Injection: Can users or external content manipulate the LLM's behavior through crafted inputs?
2. LLM02 - Sensitive Information Disclosure: Could the LLM leak training data, PII, or secrets in its responses?
3. LLM03 - Supply Chain: Are models, plugins, and dependencies from trusted sources with integrity verification?
4. LLM04 - Data and Model Poisoning: Could training data, fine-tuning data, or RAG content be poisoned?
5. LLM05 - Improper Output Handling: Is LLM output validated and sanitized before use in downstream systems?
6. LLM06 - Excessive Agency: Does the LLM have appropriate limits on its actions and permissions?
7. LLM07 - System Prompt Leakage: Could system prompts containing secrets or logic be extracted?
8. LLM08 - Vector and Embedding Weaknesses: Are embeddings and RAG systems protected from manipulation and leakage?
9. LLM09 - Misinformation: Could LLM hallucinations or false outputs cause harm if trusted?
10. LLM10 - Unbounded Consumption: Are there limits on resource consumption to prevent DoS and cost overruns?
"""


def create_agentic_stride_prompt_section() -> str:
    """Agentic-specific section of the threat model prompt.

    Maps OWASP ASI01-ASI10 to STRIDE categories and incorporates architectural
    layer analysis for comprehensive threat coverage.
    """
    return """
ARCHITECTURAL PATTERN DETECTION:
Before generating threats, analyze the application description to detect which architectural patterns are present. For each pattern detected, you MUST include threats specific to that pattern:

1. RAG / RETRIEVAL SYSTEMS: Look for mentions of RAG, retrieval, vector databases, embeddings, knowledge bases, document ingestion, Pinecone, Weaviate, ChromaDB, FAISS, or similar. If detected:
   - Include vector store poisoning threats (malicious documents injected into knowledge base)
   - Include embedding manipulation threats (adversarial content designed to surface in retrieval)
   - Include cross-tenant data leakage if multi-tenant RAG is implied
   - Include stale/poisoned index threats if incremental updates are mentioned

2. MULTI-AGENT SYSTEMS: Look for mentions of multiple agents, agent orchestration, agent-to-agent communication, CrewAI, AutoGen, LangGraph, swarms, hierarchical agents, or similar. If detected:
   - Include agent impersonation threats (malicious agent posing as trusted agent)
   - Include inter-agent message tampering threats
   - Include malicious agent injection into the ecosystem
   - Include goal conflicts and unintended emergent behaviors
   - Include cascading failure propagation across agent chains

3. CODE EXECUTION / SANDBOXING: Look for mentions of code generation, code execution, REPL, interpreter, sandbox, Docker, containers, or executing generated code. If detected:
   - Include sandbox escape threats
   - Include container breakout if containerized
   - Include resource exhaustion via generated code (fork bombs, infinite loops)
   - Include filesystem/network access beyond intended scope
   - Include malicious dependency installation if package installation is possible

4. TOOL/PLUGIN ECOSYSTEMS: Look for mentions of MCP servers, plugins, tools, function calling, external APIs, or third-party integrations. If detected:
   - Include malicious tool provider threats (tool returning poisoned data)
   - Include tool impersonation (fake tool masquerading as legitimate)
   - Include supply chain attacks via compromised tool packages
   - Include confused deputy attacks (agent tricked into misusing legitimate tools)

5. PERSISTENT MEMORY / STATE: Look for mentions of memory, conversation history, session persistence, long-term memory, memory stores, or context carried across sessions. If detected:
   - Include memory poisoning threats (past interactions corrupting future behavior)
   - Include cross-session data leakage
   - Include memory extraction attacks (retrieving other users' context)
   - Include state manipulation to alter agent personality/goals over time

6. FINE-TUNED / CUSTOM MODELS: Look for mentions of fine-tuning, custom training, LoRA, adapters, or proprietary models. If detected:
   - Include training data poisoning threats
   - Include backdoor trigger injection during fine-tuning
   - Include model supply chain threats (compromised base model or training pipeline)
   - Include intellectual property extraction from fine-tuned model

AGENTIC-SPECIFIC THREAT CATEGORIES (OWASP Top 10 for Agentic Applications):
You MUST analyze threats from both traditional STRIDE categories AND the following agentic-specific threat categories. Map each agentic threat to its corresponding STRIDE category and include the OWASP_ASI code:

SPOOFING (Traditional + Agentic):
- Traditional: Identity spoofing, credential theft
- ASI07 (Insecure Inter-Agent Communication): Spoofed agent identities, fake agents joining multi-agent systems
- ASI04 (Agentic Supply Chain Vulnerabilities): Malicious MCP servers or tool providers impersonating legitimate ones
- Fake tool responses injected into agent context

TAMPERING (Traditional + Agentic):
- Traditional: Data modification, code injection
- ASI06 (Memory and Context Poisoning): RAG poisoning, manipulated agent memory/state, cross-session contamination
- ASI01 (Agent Goal Hijack): Prompt injection via poisoned documents, emails, or user inputs that alter agent objectives
- ASI07: Message tampering in inter-agent communication channels

REPUDIATION (Traditional + Agentic):
- Traditional: Denial of actions, log manipulation
- ASI09 (Human-Agent Trust Exploitation): Agent actions that circumvent audit trails by exploiting user over-trust
- Untraceable autonomous agent decisions due to insufficient logging
- Gaps in agent decision audit logs making forensics impossible

INFORMATION DISCLOSURE (Traditional + Agentic):
- Traditional: Data leaks, unauthorized access
- ASI06: Context window leakage exposing sensitive data from previous sessions, cross-tenant data exposure
- ASI01: Prompt injection attacks leading to data exfiltration via crafted outputs
- Sensitive credentials or data exposed through agent tool call logs or persistent memory

DENIAL OF SERVICE (Traditional + Agentic):
- Traditional: Resource exhaustion, service disruption
- ASI08 (Cascading Failures): Error propagation across agent chains causing system-wide outages
- Agent loop attacks where malicious input causes infinite reasoning cycles
- Resource exhaustion through repeated expensive tool invocations or runaway code execution

ELEVATION OF PRIVILEGE (Traditional + Agentic):
- Traditional: Privilege escalation, unauthorized access
- ASI02 (Tool Misuse and Exploitation): Over-privileged tools executing destructive commands, unvalidated tool inputs
- ASI03 (Identity and Privilege Abuse): Cached credential misuse, confused deputy attacks, cross-agent delegation abuse
- ASI05 (Unexpected Code Execution): Unsafe eval/exec of generated code, shell injection, sandbox escape
- ASI10 (Rogue Agents): Agents persisting beyond intended lifecycle, impersonating other agents or users

CROSS-LAYER THREAT ANALYSIS:
For each threat identified, consider how it could cascade across system boundaries:
- How could a data poisoning attack (in retrieval/RAG) affect agent decision-making and tool usage?
- How could a compromised tool provider affect the foundation model's outputs or agent memory?
- How could an agent ecosystem attack (multi-agent manipulation) lead to infrastructure compromise?
- How could observability gaps hide attack progression across components?

Include at least 2-3 threats that explicitly describe cross-component attack chains where applicable.

CRITICAL AGENTIC RISKS TO EVALUATE:
1. ASI01 - Agent Goal Hijack: How could adversarial inputs (documents, emails, web content) redirect the agent's objectives?
2. ASI02 - Tool Misuse: Are tools properly scoped with least privilege? Can the agent execute dangerous commands?
3. ASI03 - Identity/Privilege Abuse: Can the agent abuse delegated permissions or cached credentials?
4. ASI04 - Supply Chain: Are external tool providers (MCP servers, plugins) trusted, verified, and integrity-checked?
5. ASI05 - Code Execution: Does the agent have code execution capabilities? Are they properly sandboxed?
6. ASI06 - Memory Poisoning: Can persistent memory be poisoned to affect future sessions or other users?
7. ASI07 - Inter-Agent Communication: In multi-agent systems, can agents be spoofed or messages tampered with?
8. ASI08 - Cascading Failures: How do errors propagate through agent chains? Are there circuit breakers?
9. ASI09 - Human-Agent Trust: Can the agent exploit user over-trust to perform harmful actions without scrutiny?
10. ASI10 - Rogue Agents: Can the agent persist beyond its intended lifecycle, impersonate users, or resist shutdown?
"""


def create_threat_model_prompt(
    app_type: str,
    authentication: str,
    internet_facing: str,
    sensitive_data: str,
    app_input: str,
) -> str:
    """Build the threat-model prompt for a given application profile."""
    is_genai = app_type == "Generative AI application"
    is_agentic = app_type == "Agentic AI application"
    include_llm_risks = is_genai or is_agentic

    prompt = """Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to analyze the provided code summary, README content, and application description to produce a list of specific threats for the application.

Pay special attention to the README content as it often provides valuable context about the project's purpose, architecture, and potential security considerations.

"""

    if is_agentic:
        prompt += """For this AGENTIC AI APPLICATION, you must consider traditional STRIDE threats, LLM-specific threats from the OWASP Top 10 for LLM Applications (LLM01-LLM10), AND agentic-specific threats from the OWASP Top 10 for Agentic Applications (ASI01-ASI10). For each STRIDE category, identify threats covering AI agent risks including prompt injection, tool misuse, memory poisoning, autonomous action risks, and LLM vulnerabilities.

"""
    elif is_genai:
        prompt += """For this GENERATIVE AI APPLICATION, you must consider both traditional STRIDE threats AND LLM-specific threats from the OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10). For each STRIDE category, identify threats specific to LLM-powered applications including prompt injection, sensitive data disclosure, and improper output handling.

"""
    else:
        prompt += """For each of the STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege), list multiple (3 or 4) credible threats if applicable. """

    prompt += """Each threat scenario should provide a credible scenario in which the threat could occur in the context of the application. It is very important that your responses are tailored to reflect the details you are given.

"""

    if is_agentic:
        prompt += """When providing the threat model, use a JSON formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", "Potential Impact", "OWASP_LLM" (the applicable LLM risk code, e.g., "LLM01", "LLM02", etc., or null), and "OWASP_ASI" (the applicable Agentic Security Issue code, e.g., "ASI01", "ASI02", etc., or null). A threat may have both codes if it applies to both categories.

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
