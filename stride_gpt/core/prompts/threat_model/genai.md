---
name: genai
title: OWASP Top 10 for LLM Applications
when_to_load: |
  Load when the subsystem uses LLM SDKs (openai, anthropic, mistralai,
  google.generativeai, etc.), exposes LLM-driven endpoints, performs RAG or
  embedding operations, or otherwise has language-model behaviour in scope.
adds_fields:
  - OWASP_LLM
stride_letters: [S, T, R, I, D, E]
source: https://owasp.org/www-project-top-10-for-large-language-model-applications/
version: 2025
---

# OWASP Top 10 for LLM Applications — Reference Card

You loaded this card because the subsystem you are analysing has language-model behaviour in scope. In addition to traditional STRIDE categories, you MUST consider the LLM-specific threats below and map each to a STRIDE category.

## LLM-specific threat categories (OWASP Top 10 for LLM Applications 2025)

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

## Critical LLM risks to evaluate

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

## Schema additions

Each threat object in `"threats"` must additionally include:
- `"OWASP_LLM"`: the applicable LLM risk code as a string (e.g. `"LLM01"`), or `null` if not applicable.
