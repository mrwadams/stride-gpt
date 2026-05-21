import streamlit as st

from stride_gpt.core.mitigations import generate_mitigations
from stride_gpt.core.schemas import LLMConfig


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
   - Implement prompt injection detection and filtering (both direct and indirect)
   - Validate and sanitize content from external sources (documents, emails, web pages)
   - Use content security scanning for ingested documents
   - Implement input source verification and provenance tracking

2. LEAST PRIVILEGE & ACCESS CONTROL:
   - Minimize tool/function permissions to only what's necessary for each task
   - Use scoped, short-lived credentials instead of long-lived tokens
   - Implement per-action authorization checks
   - Apply different permission levels based on input source trust
   - Use capability-based security for tool access

3. SANDBOXING & ISOLATION:
   - Execute generated code in isolated containers with resource limits (CPU, memory, time)
   - Restrict file system access to specific directories with read/write controls
   - Limit network access to allowlisted destinations only
   - Implement process isolation for multi-tenant environments
   - Use seccomp/AppArmor profiles to restrict system calls

4. AUDIT LOGGING & OBSERVABILITY:
   - Log all agent actions, decisions, and tool invocations with timestamps
   - Implement immutable audit trails for forensic analysis
   - Monitor for anomalous agent behavior patterns (unusual tool usage, data access patterns)
   - Track agent decision chains for explainability
   - Implement real-time alerting for high-risk actions

5. HUMAN OVERSIGHT & APPROVAL WORKFLOWS:
   - Require human approval for high-risk actions (financial, destructive, external communication)
   - Implement confirmation prompts for irreversible operations
   - Provide clear visibility into agent decision-making rationale
   - Support human-in-the-loop review for sensitive data access
   - Enable action rollback where possible

6. MEMORY & CONTEXT PROTECTION:
   - Encrypt persistent agent memory at rest and in transit
   - Validate and sanitize retrieved context before use
   - Implement memory segmentation between users/sessions/tenants
   - Set memory retention limits and automatic expiration
   - Scan memory contents for sensitive data leakage

7. AGENT AUTHENTICATION & INTEGRITY:
   - Use cryptographic signing for inter-agent communication
   - Verify tool provider authenticity (MCP server certificates, package signatures)
   - Implement mutual TLS for agent-to-agent communication
   - Use agent identity attestation in multi-agent systems
   - Validate agent configuration integrity at startup

8. CIRCUIT BREAKERS & RATE LIMITING:
   - Implement loop detection to prevent infinite reasoning cycles
   - Set resource consumption limits per request/session (tokens, API calls, compute time)
   - Add circuit breakers to halt cascading failures between agents
   - Implement backoff strategies for failing operations
   - Set hard limits on autonomous operation duration

ARCHITECTURAL PATTERN-SPECIFIC MITIGATIONS:
When analyzing threats, also consider these pattern-specific controls:

FOR RAG/RETRIEVAL SYSTEMS:
- Implement document provenance tracking and integrity verification
- Use content classification to tag and control access to sensitive retrieved content
- Apply tenant isolation in vector databases (separate collections/namespaces)
- Validate retrieval results before injection into prompts
- Monitor for embedding drift and anomalous retrieval patterns
- Implement freshness controls to prevent stale content attacks

FOR MULTI-AGENT SYSTEMS:
- Implement agent registration and identity management
- Use message authentication codes (MACs) for inter-agent messages
- Apply trust boundaries between agent groups
- Implement consensus mechanisms for critical decisions
- Monitor for coalition attacks and emergent malicious behaviors
- Use agent behavioral profiling to detect compromised agents

FOR CODE EXECUTION ENVIRONMENTS:
- Use ephemeral containers that are destroyed after each execution
- Implement static analysis on generated code before execution
- Block dangerous imports and system calls
- Use resource quotas (CPU time, memory, disk, network)
- Implement output sanitization for code execution results
- Monitor for persistence attempts and sandbox escape indicators

FOR TOOL/MCP ECOSYSTEMS:
- Maintain an allowlist of approved tool providers with version pinning
- Implement tool response validation and sanitization
- Use tool-specific rate limits and quotas
- Monitor for unusual tool invocation patterns
- Validate tool parameter bounds before invocation
- Implement tool capability attestation

FOR PERSISTENT MEMORY SYSTEMS:
- Implement memory content classification and access controls
- Use differential privacy for shared memory contexts
- Apply memory poisoning detection (anomaly detection on stored content)
- Implement memory versioning with rollback capability
- Set per-user memory quotas and isolation
- Scan memory for credential and PII exposure

CROSS-LAYER MITIGATIONS:
Consider controls that address attack chains spanning multiple components:
- Implement defense-in-depth with controls at each architectural layer
- Use correlation of events across layers for advanced threat detection
- Apply blast radius limiting to contain breaches to single components
- Implement graceful degradation when components fail
- Use zero-trust principles between all architectural components

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
    config = LLMConfig(provider="OpenAI API", model_name=model_name, api_key=api_key)
    content, _response = generate_mitigations(config, prompt)
    return content


# Function to get mitigations from the Google model's response.
def get_mitigations_google(google_api_key, google_model, prompt):
    config = LLMConfig(provider="Google AI API", model_name=google_model, api_key=google_api_key)
    content, response = generate_mitigations(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return content


# Function to get mitigations from the Mistral model's response.
def get_mitigations_mistral(mistral_api_key, mistral_model, prompt):
    config = LLMConfig(provider="Mistral API", model_name=mistral_model, api_key=mistral_api_key)
    content, _response = generate_mitigations(config, prompt)
    return content


# Function to get mitigations from the Anthropic model's response.
def get_mitigations_anthropic(anthropic_api_key, anthropic_model, prompt):
    config = LLMConfig(
        provider="Anthropic API",
        model_name=anthropic_model,
        api_key=anthropic_api_key,
        use_thinking=st.session_state.get("use_thinking", False),
    )
    content, response = generate_mitigations(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return content


# Function to get mitigations from LM Studio Server response.
def get_mitigations_lm_studio(lm_studio_endpoint, model_name, prompt, api_key="not-needed"):
    config = LLMConfig(
        provider="LM Studio Server",
        model_name=model_name,
        api_key=api_key,
        api_base=lm_studio_endpoint,
    )
    content, _response = generate_mitigations(config, prompt)
    return content


# Function to get mitigations from the Groq model's response.
def get_mitigations_groq(groq_api_key, groq_model, prompt):
    config = LLMConfig(provider="Groq API", model_name=groq_model, api_key=groq_api_key)
    content, response = generate_mitigations(config, prompt)
    if response.reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(response.reasoning)
    return content
