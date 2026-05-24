---
name: agentic
title: OWASP Top 10 for Agentic Applications
when_to_load: |
  Load in addition to the genai card when the subsystem uses an agent
  framework (langchain, langgraph, crewai, autogen, pydantic-ai, smolagents,
  llama-index agents), implements a tool-use or function-calling loop,
  coordinates multiple agents, or persists agent memory across sessions.
adds_fields:
  - OWASP_ASI
stride_letters: [S, T, R, I, D, E]
source: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
version: 2025
---

# OWASP Top 10 for Agentic Applications — Reference Card

You loaded this card because the subsystem you are analysing uses agent patterns. In addition to traditional STRIDE and the LLM-specific threats from the genai card, you MUST consider the agentic-specific threats below and map each to a STRIDE category. A single threat may carry both an OWASP_LLM and an OWASP_ASI code if it applies to both categories.

## Architectural pattern detection

Before generating threats, analyse the subsystem to detect which architectural patterns are present. For each pattern detected, you MUST include threats specific to that pattern:

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

## Agentic-specific threat categories (OWASP Top 10 for Agentic Applications)

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

## Cross-layer threat analysis

For each threat identified, consider how it could cascade across system boundaries:
- How could a data poisoning attack (in retrieval/RAG) affect agent decision-making and tool usage?
- How could a compromised tool provider affect the foundation model's outputs or agent memory?
- How could an agent ecosystem attack (multi-agent manipulation) lead to infrastructure compromise?
- How could observability gaps hide attack progression across components?

Include at least 2-3 threats that explicitly describe cross-component attack chains where applicable.

## Critical agentic risks to evaluate

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

## Schema additions

Each threat object in `"threats"` must additionally include:
- `"OWASP_ASI"`: the applicable Agentic Security Issue code as a string (e.g. `"ASI01"`), or `null` if not applicable.

A threat may carry both `"OWASP_LLM"` (from the genai card) and `"OWASP_ASI"` codes when it applies to both categories.
