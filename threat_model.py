import base64
import json
import re

import requests
import streamlit as st
from anthropic import Anthropic
from google import genai as google_genai
from groq import Groq
from mistralai import Mistral
from openai import AzureOpenAI, OpenAI

from utils import create_reasoning_system_prompt, process_groq_response


# Function to convert JSON to Markdown for display.
def json_to_markdown(threat_model, improvement_suggestions):
    markdown_output = "## Threat Model\n\n"

    # Check which OWASP fields are present
    has_owasp_llm = any(threat.get("OWASP_LLM") for threat in threat_model)
    has_owasp_asi = any(threat.get("OWASP_ASI") for threat in threat_model)

    if has_owasp_llm and has_owasp_asi:
        # Full table with both OWASP columns (agentic applications)
        markdown_output += "| Threat Type | Scenario | Potential Impact | OWASP LLM | OWASP ASI |\n"
        markdown_output += "|-------------|----------|------------------|-----------|------------|\n"
        for threat in threat_model:
            owasp_llm = threat.get("OWASP_LLM") or "-"
            owasp_asi = threat.get("OWASP_ASI") or "-"
            markdown_output += (
                f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} | {owasp_llm} | {owasp_asi} |\n"
            )
    elif has_owasp_llm:
        # Table with OWASP LLM column only (GenAI applications)
        markdown_output += "| Threat Type | Scenario | Potential Impact | OWASP LLM |\n"
        markdown_output += "|-------------|----------|------------------|------------|\n"
        for threat in threat_model:
            owasp_llm = threat.get("OWASP_LLM") or "-"
            markdown_output += (
                f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} | {owasp_llm} |\n"
            )
    elif has_owasp_asi:
        # Table with OWASP ASI column only (edge case)
        markdown_output += "| Threat Type | Scenario | Potential Impact | OWASP ASI |\n"
        markdown_output += "|-------------|----------|------------------|------------|\n"
        for threat in threat_model:
            owasp_asi = threat.get("OWASP_ASI") or "-"
            markdown_output += (
                f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} | {owasp_asi} |\n"
            )
    else:
        # Standard table without OWASP columns
        markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
        markdown_output += "|-------------|----------|------------------|\n"
        for threat in threat_model:
            markdown_output += (
                f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"
            )

    markdown_output += "\n\n## Improvement Suggestions\n\n"
    for suggestion in improvement_suggestions:
        markdown_output += f"- {suggestion}\n"

    return markdown_output


def create_llm_stride_prompt_section(genai_context):
    """
    Creates the LLM-specific section of the threat model prompt.
    Maps OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10) to STRIDE categories.
    """
    if not genai_context:
        return ""

    model_type = genai_context.get("model_type", "") or "Not specified"
    features = ", ".join(genai_context.get("features", [])) or "Not specified"
    data_sources = ", ".join(genai_context.get("data_sources", [])) or "Not specified"
    output_handling = ", ".join(genai_context.get("output_handling", [])) or "Not specified"

    return f"""
GENERATIVE AI / LLM CONTEXT:
- LLM Model Type: {model_type}
- LLM Features Used: {features}
- Data Sources for Context: {data_sources}
- Output Handling: {output_handling}

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

IMPORTANT - CONFLICT RESOLUTION:
If the GENERATIVE AI / LLM CONTEXT above conflicts with details in the APPLICATION DESCRIPTION below, treat the APPLICATION DESCRIPTION as the authoritative source of truth. Note any significant discrepancies in your improvement_suggestions.
"""


def create_agentic_stride_prompt_section(agentic_context):
    """
    Creates the agentic-specific section of the threat model prompt.
    Maps OWASP ASI01-ASI10 to STRIDE categories.
    """
    if not agentic_context:
        return ""

    capabilities = ", ".join(agentic_context.get("capabilities", [])) or "Not specified"
    human_oversight = agentic_context.get("human_oversight", "") or "Not specified"
    autonomous_scope = ", ".join(agentic_context.get("autonomous_scope", [])) or "Not specified"
    credential_access = ", ".join(agentic_context.get("credential_access", [])) or "Not specified"
    tool_providers = agentic_context.get("tool_providers", "") or "Not specified"

    return f"""
AGENTIC AI CONTEXT:
- Agent Capabilities: {capabilities}
- Human Oversight Level: {human_oversight}
- Autonomous Action Scope: {autonomous_scope}
- Credential Access: {credential_access}
- External Tool Providers: {tool_providers}

AGENTIC-SPECIFIC THREAT CATEGORIES (OWASP Top 10 for Agentic Applications):
You MUST analyze threats from both traditional STRIDE categories AND the following agentic-specific threat categories. Map each agentic threat to its corresponding STRIDE category and include the OWASP_ASI code:

SPOOFING (Traditional + Agentic):
- Traditional: Identity spoofing, credential theft
- ASI07 (Insecure Inter-Agent Communication): Spoofed agent identities, fake agents joining multi-agent systems
- ASI04 (Agentic Supply Chain Vulnerabilities): Malicious MCP servers impersonating legitimate tool providers
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
- Resource exhaustion through repeated expensive tool invocations

ELEVATION OF PRIVILEGE (Traditional + Agentic):
- Traditional: Privilege escalation, unauthorized access
- ASI02 (Tool Misuse and Exploitation): Over-privileged tools executing destructive commands, unvalidated tool inputs
- ASI03 (Identity and Privilege Abuse): Cached credential misuse, confused deputy attacks, cross-agent delegation abuse
- ASI05 (Unexpected Code Execution): Unsafe eval/exec of generated code, shell injection, sandbox escape
- ASI10 (Rogue Agents): Agents persisting beyond intended lifecycle, impersonating other agents or users

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

IMPORTANT - CONFLICT RESOLUTION:
If the AGENTIC AI CONTEXT above conflicts with details in the APPLICATION DESCRIPTION below, treat the APPLICATION DESCRIPTION as the authoritative source of truth. Note any significant discrepancies in your improvement_suggestions to help the user align their inputs.
"""


# Function to create a prompt for generating a threat model
def create_threat_model_prompt(
    app_type,
    authentication,
    internet_facing,
    sensitive_data,
    app_input,
    genai_context=None,
    agentic_context=None,
):
    is_genai = app_type == "Generative AI application" and genai_context
    is_agentic = app_type == "Agentic AI application" and agentic_context
    # Agentic apps also get LLM risks
    include_llm_risks = is_genai or (is_agentic and genai_context)

    # Base prompt
    prompt = """Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to analyze the provided code summary, README content, and application description to produce a list of specific threats for the application.

Pay special attention to the README content as it often provides valuable context about the project's purpose, architecture, and potential security considerations.

"""

    # STRIDE guidance - different for each app type
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

    # JSON format instructions
    if is_agentic:
        prompt += """When providing the threat model, use a JSON formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", "Potential Impact", "OWASP_LLM" (the applicable LLM risk code, e.g., "LLM01", "LLM02", etc., or null), and "OWASP_ASI" (the applicable Agentic Security Issue code, e.g., "ASI01", "ASI02", etc., or null). A threat may have both codes if it applies to both categories.

"""
    elif is_genai:
        prompt += """When providing the threat model, use a JSON formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", "Potential Impact", and "OWASP_LLM" (the applicable OWASP LLM risk code, e.g., "LLM01", "LLM02", etc., or null if not applicable).

"""
    else:
        prompt += """When providing the threat model, use a JSON formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", and "Potential Impact".

"""

    prompt += """Under "improvement_suggestions", include an array of strings that suggest what additional information or details the user could provide to make the threat model more comprehensive and accurate in the next iteration. Focus on identifying gaps in the provided application description that, if filled, would enable a more detailed and precise threat analysis. For example:
- Missing architectural details that would help identify more specific threats
- Unclear authentication flows that need more detail
- Incomplete data flow descriptions
- Missing technical stack information
- Unclear system boundaries or trust zones
- Incomplete description of sensitive data handling

Do not provide general security recommendations - focus only on what additional information would help create a better threat model.

"""

    # Application details
    prompt += f"""APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
"""

    # Add LLM context if applicable (for GenAI and Agentic apps)
    if include_llm_risks:
        prompt += create_llm_stride_prompt_section(genai_context)

    # Add agentic context if applicable
    if is_agentic:
        prompt += create_agentic_stride_prompt_section(agentic_context)

    prompt += f"""
CODE SUMMARY, README CONTENT, AND APPLICATION DESCRIPTION:
{app_input}

"""

    # Example JSON format
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


def create_image_analysis_prompt():
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


# Function to get analyse uploaded architecture diagrams.
def get_image_analysis(api_key, model_name, prompt, base64_image):
    client = OpenAI(api_key=api_key)

    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"},
                },
            ],
        }
    ]

    # If using GPT-5 series models, use the structured system prompt approach
    if model_name in ["gpt-5.2", "gpt-5-mini", "gpt-5-nano", "gpt-5.2-pro", "gpt-5"]:
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
        # Insert system message at the beginning
        messages.insert(0, {"role": "system", "content": system_prompt})

        # Create completion with max_completion_tokens for reasoning models
        try:
            max_tokens = 20000 if model_name.startswith("gpt-5") else 8192
            response = client.chat.completions.create(
                model=model_name, messages=messages, max_completion_tokens=max_tokens
            )
            return {"choices": [{"message": {"content": response.choices[0].message.content}}]}
        except Exception:
            return None
    else:
        # For standard models (gpt-4.1, etc.)
        try:
            response = client.chat.completions.create(
                model=model_name, messages=messages, max_tokens=8192
            )
            return {"choices": [{"message": {"content": response.choices[0].message.content}}]}
        except Exception:
            return None


# Function to get image analysis using Azure OpenAI
def get_image_analysis_azure(
    api_endpoint, api_key, api_version, deployment_name, prompt, base64_image
):
    client = AzureOpenAI(
        azure_endpoint=api_endpoint,
        api_key=api_key,
        api_version=api_version,
    )

    response = client.chat.completions.create(
        model=deployment_name,
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"},
                    },
                ],
            }
        ],
        max_tokens=4000,
    )

    return {"choices": [{"message": {"content": response.choices[0].message.content}}]}


# Function to get image analysis using Google Gemini models
def get_image_analysis_google(api_key, model_name, prompt, base64_image):
    client = google_genai.Client(api_key=api_key)
    from google.genai import types as google_types

    blob = google_types.Blob(data=base64.b64decode(base64_image), mime_type="image/jpeg")
    content = [
        google_types.Content(
            role="user",
            parts=[
                google_types.Part(text=prompt),
                google_types.Part(inlineData=blob),
            ],
        )
    ]

    config = google_types.GenerateContentConfig()
    response = client.models.generate_content(model=model_name, contents=content, config=config)

    return {"choices": [{"message": {"content": response.text}}]}


# Function to get image analysis using Anthropic Claude models
def get_image_analysis_anthropic(
    api_key, model_name, prompt, base64_image, media_type="image/jpeg"
):
    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model_name,
        max_tokens=4000,
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": base64_image,
                        },
                    },
                    {"type": "text", "text": prompt},
                ],
            }
        ],
    )

    text = "".join(block.text for block in response.content if getattr(block, "text", None))
    return {"choices": [{"message": {"content": text}}]}


# Function to get threat model from the GPT response.
def get_threat_model(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    # For GPT-5 series models, use a structured system prompt
    if model_name in ["gpt-5.2", "gpt-5-mini", "gpt-5-nano", "gpt-5.2-pro", "gpt-5"]:
        system_prompt = create_reasoning_system_prompt(
            task_description="Analyze the provided application description and generate a comprehensive threat model using the STRIDE methodology.",
            approach_description="""1. Carefully read and understand the application description
2. For each component and data flow:
   - Identify potential Spoofing threats
   - Identify potential Tampering threats
   - Identify potential Repudiation threats
   - Identify potential Information Disclosure threats
   - Identify potential Denial of Service threats
   - Identify potential Elevation of Privilege threats
3. For each identified threat:
   - Describe the specific scenario
   - Analyze the potential impact
4. Generate improvement suggestions based on identified threats
5. Format the output as a JSON object with 'threat_model' and 'improvement_suggestions' arrays""",
        )
        # Create completion with max_completion_tokens for reasoning models
        # GPT-5 models need more tokens for reasoning + output
        max_tokens = 20000 if model_name.startswith("gpt-5") else 8192
        response = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            max_completion_tokens=max_tokens,
        )
    else:
        system_prompt = "You are a helpful assistant designed to output JSON."
        # Create completion with max_tokens for other models
        response = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            max_tokens=8192,
        )

    # Convert the JSON string in the 'content' field to a Python dictionary
    content = response.choices[0].message.content

    if not content:
        raise ValueError(
            f"Empty response from model {model_name}. This may indicate the model is not available or has rate limits."
        )

    return json.loads(content)


# Function to get threat model from the Azure OpenAI response.
def get_threat_model_azure(
    azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt
):
    client = AzureOpenAI(
        azure_endpoint=azure_api_endpoint,
        api_key=azure_api_key,
        api_version=azure_api_version,
    )

    response = client.chat.completions.create(
        model=azure_deployment_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt},
        ],
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    return json.loads(response.choices[0].message.content)


# Function to get threat model from the Google response.
def get_threat_model_google(google_api_key, google_model, prompt):
    # Create a client with the Google API key
    client = google_genai.Client(api_key=google_api_key)

    # Set up safety settings to allow security content
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

    # Check if we're using a Gemini 2.5+ model (which supports thinking capabilities)
    is_gemini_thinking = "gemini-2.5" in google_model.lower() or "gemini-3" in google_model.lower()

    try:
        from google.genai import types as google_types

        if is_gemini_thinking:
            config = google_types.GenerateContentConfig(
                response_mime_type="application/json",
                safety_settings=safety_settings,
                thinking_config=google_types.ThinkingConfig(thinking_budget=1024),
            )
        else:
            config = google_types.GenerateContentConfig(
                response_mime_type="application/json", safety_settings=safety_settings
            )

        # Generate content using the configured settings
        response = client.models.generate_content(
            model=google_model, contents=prompt, config=config
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
        st.error(f"Error generating content with Google AI: {e!s}")
        return None

    try:
        # Parse the response text as JSON
        response_content = json.loads(response_text)
    except json.JSONDecodeError:
        st.error("Failed to parse JSON response from Google AI")
        return None

    return response_content


# Function to get threat model from the Mistral response.
def get_threat_model_mistral(mistral_api_key, mistral_model, prompt):
    client = Mistral(api_key=mistral_api_key)

    response = client.chat.complete(
        model=mistral_model,
        response_format={"type": "json_object"},
        messages=[{"role": "user", "content": prompt}],
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    return json.loads(response.choices[0].message.content)


# Function to get threat model from Ollama hosted LLM.
def get_threat_model_ollama(ollama_endpoint, ollama_model, prompt):
    """
    Get threat model from Ollama hosted LLM.

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
            raise

    except requests.exceptions.RequestException:
        raise


# Function to get threat model from the Claude response.
def get_threat_model_anthropic(anthropic_api_key, anthropic_model, prompt):
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
                messages=[{"role": "user", "content": prompt}],
                timeout=600,  # 10-minute timeout
            )
        else:
            # Standard handling for Claude models
            response = client.messages.create(
                model=actual_model,
                max_tokens=32768,
                system="You are a helpful assistant designed to output JSON. Your response must be a valid, parseable JSON object with no additional text, markdown formatting, or explanation. Do not include ```json code blocks or any other formatting - just return the raw JSON object.",
                messages=[{"role": "user", "content": prompt}],
                timeout=300,  # 5-minute timeout
            )

        # Combine all text blocks into a single string
        if is_thinking_mode:
            # For thinking mode, we need to extract only the text content blocks
            full_content = "".join(block.text for block in response.content if block.type == "text")

            # Store thinking content in session state for debugging/transparency (optional)
            thinking_content = "".join(
                block.thinking for block in response.content if block.type == "thinking"
            )
            if thinking_content:
                st.session_state["last_thinking_content"] = thinking_content
        else:
            # Standard handling for regular responses
            full_content = "".join(block.text for block in response.content)

        # Parse the JSON response
        try:
            # Strip markdown code blocks if present
            if "```json" in full_content:
                full_content = re.sub(r"```json\s*", "", full_content)
                full_content = re.sub(r"```\s*$", "", full_content)
            elif "```" in full_content:
                full_content = re.sub(r"```\s*", "", full_content)

            # Fix common JSON formatting issues (trailing commas, comments)
            full_content = full_content.replace(",\n  ]", "\n  ]").replace(",\n]", "\n]")
            full_content = re.sub(r"//.*?\n", "\n", full_content)

            # Strip any leading/trailing whitespace
            full_content = full_content.strip()

            return json.loads(full_content)
        except json.JSONDecodeError:
            # Create a fallback response
            return {
                "threat_model": [
                    {
                        "Threat Type": "Error",
                        "Scenario": "Failed to parse Claude response",
                        "Potential Impact": "Unable to generate threat model",
                    }
                ],
                "improvement_suggestions": [
                    "Try again - sometimes the model returns a properly formatted response on subsequent attempts",
                    "Check the logs for detailed error information",
                ],
            }

    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")

        # Create a fallback response for timeout or other errors
        return {
            "threat_model": [
                {
                    "Threat Type": "Error",
                    "Scenario": f"API Error: {error_message}",
                    "Potential Impact": "Unable to generate threat model",
                }
            ],
            "improvement_suggestions": [
                "For complex applications, try simplifying the input or breaking it into smaller components",
                "If you're using extended thinking mode and encountering timeouts, try the standard model instead",
                "Consider reducing the complexity of the application description",
            ],
        }


# Function to get threat model from LM Studio Server response.
def get_threat_model_lm_studio(lm_studio_endpoint, model_name, prompt, api_key="not-needed"):
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key=api_key,  # Use provided API key or default to "not-needed"
    )

    # Define the expected response structure
    threat_model_schema = {
        "type": "json_schema",
        "json_schema": {
            "name": "threat_model_response",
            "schema": {
                "type": "object",
                "properties": {
                    "threat_model": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "Threat Type": {"type": "string"},
                                "Scenario": {"type": "string"},
                                "Potential Impact": {"type": "string"},
                            },
                            "required": ["Threat Type", "Scenario", "Potential Impact"],
                        },
                    },
                    "improvement_suggestions": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["threat_model", "improvement_suggestions"],
            },
        },
    }

    response = client.chat.completions.create(
        model=model_name,
        response_format=threat_model_schema,
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=4000,
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    return json.loads(response.choices[0].message.content)


# Function to get threat model from the Groq response.
def get_threat_model_groq(groq_api_key, groq_model, prompt):
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
    reasoning, response_content = process_groq_response(
        response.choices[0].message.content, groq_model, expect_json=True
    )

    # If we got reasoning, display it in an expander in the UI
    if reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(reasoning)

    return response_content
