---
name: mitre_atlas
title: MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
when_to_load: |
  Load **in addition to `mitre_enterprise`** when the subsystem has
  machine-learning or LLM behaviour in scope — uses LLM SDKs (openai,
  anthropic, mistralai, google-generativeai, etc.), exposes ML inference
  endpoints, performs RAG/embedding operations, fine-tunes or serves a
  model, or otherwise has model-driven behaviour an adversary could
  target. Pairs naturally with the `genai` and `agentic` reference cards.
adds_fields:
  - MITRE_ATTACK
stride_letters: [S, T, R, I, D, E]
source: https://atlas.mitre.org/matrices/ATLAS
version: ATLAS-2026.05
---

# MITRE ATLAS — Reference Card

You loaded this card because the subsystem you are analysing has
machine-learning or LLM behaviour in scope. ATLAS extends ATT&CK with
techniques specific to attacks on AI systems. Use it alongside
`mitre_enterprise` — most real-world AI threats combine traditional
infrastructure techniques with ML-specific ones.

## How to use this card

For each threat that involves the ML/LLM surface, attach **zero or more**
ATLAS technique IDs from the catalog below. Enterprise + ATLAS techniques
go into the **same** `MITRE_ATTACK` list on the threat.

> **Anti-hallucination requirement.** Use **only** technique IDs and names
> exactly as written in this card. Do not invent IDs, do not paraphrase
> names. ATLAS IDs always carry the `AML.` prefix (e.g. `AML.T0051`); do
> not strip it. If no ATLAS technique fits, emit nothing from this card —
> empty is preferable to a fabricated ID.

A given threat will often combine one Enterprise technique (the
infrastructure mechanism) with one ATLAS technique (the ML-specific
mechanism). Example — RAG context exfiltration:
`[{"id": "T1041", "name": "Exfiltration Over C2 Channel"},
  {"id": "AML.T0024", "name": "Exfiltration via AI Inference API"}]`.

## Schema additions

Each threat object must additionally include:

- `"MITRE_ATTACK"`: an array of objects, each shaped
  `{"id": "AML.T####", "name": "Technique Name"}` (or the equivalent
  Enterprise shape — both share the field). May be empty.

## Technique catalog

This catalog was generated from MITRE ATLAS ATLAS-2026.05. Sub-techniques are not
listed individually — use the parent technique ID.

### Reconnaissance (AML.TA0002)
- **AML.T0000** — Search Open Technical Databases
- **AML.T0001** — Search Open AI Vulnerability Analysis
- **AML.T0003** — Search Victim-Owned Websites
- **AML.T0004** — Search Application Repositories
- **AML.T0006** — Active Scanning
- **AML.T0064** — Gather RAG-Indexed Targets
- **AML.T0087** — Gather Victim Identity Information
- **AML.T0095** — Search Open Websites/Domains

### Resource Development (AML.TA0003)
- **AML.T0002** — Acquire Public AI Artifacts
- **AML.T0008** — Acquire Infrastructure
- **AML.T0016** — Obtain Capabilities
- **AML.T0017** — Develop Capabilities
- **AML.T0019** — Publish Poisoned Datasets
- **AML.T0020** — Poison Training Data
- **AML.T0021** — Establish Accounts
- **AML.T0058** — Publish Poisoned Models
- **AML.T0060** — Publish Hallucinated Entities
- **AML.T0065** — LLM Prompt Crafting
- **AML.T0066** — Retrieval Content Crafting
- **AML.T0079** — Stage Capabilities
- **AML.T0104** — Publish Poisoned AI Agent Tool

### Initial Access (AML.TA0004)
- **AML.T0010** — AI Supply Chain Compromise
- **AML.T0012** — Valid Accounts
- **AML.T0015** — Evade AI Model
- **AML.T0049** — Exploit Public-Facing Application
- **AML.T0052** — Phishing
- **AML.T0078** — Drive-by Compromise
- **AML.T0093** — Prompt Infiltration via Public-Facing Application

### AI Model Access (AML.TA0000)
- **AML.T0040** — AI Model Inference API Access
- **AML.T0041** — Physical Environment Access
- **AML.T0044** — Full AI Model Access
- **AML.T0047** — AI-Enabled Product or Service

### Execution (AML.TA0005)
- **AML.T0011** — User Execution
- **AML.T0050** — Command and Scripting Interpreter
- **AML.T0051** — LLM Prompt Injection
- **AML.T0053** — AI Agent Tool Invocation
- **AML.T0100** — AI Agent Clickbait
- **AML.T0103** — Deploy AI Agent

### Persistence (AML.TA0006)
- **AML.T0018** — Manipulate AI Model
- **AML.T0020** — Poison Training Data
- **AML.T0061** — LLM Prompt Self-Replication
- **AML.T0070** — RAG Poisoning
- **AML.T0080** — AI Agent Context Poisoning
- **AML.T0081** — Modify AI Agent Configuration
- **AML.T0093** — Prompt Infiltration via Public-Facing Application
- **AML.T0099** — AI Agent Tool Data Poisoning
- **AML.T0110** — AI Agent Tool Poisoning

### Privilege Escalation (AML.TA0012)
- **AML.T0012** — Valid Accounts
- **AML.T0053** — AI Agent Tool Invocation
- **AML.T0054** — LLM Jailbreak
- **AML.T0105** — Escape to Host

### Defense Evasion (AML.TA0007)
- **AML.T0015** — Evade AI Model
- **AML.T0054** — LLM Jailbreak
- **AML.T0067** — LLM Trusted Output Components Manipulation
- **AML.T0068** — LLM Prompt Obfuscation
- **AML.T0071** — False RAG Entry Injection
- **AML.T0073** — Impersonation
- **AML.T0074** — Masquerading
- **AML.T0076** — Corrupt AI Model
- **AML.T0081** — Modify AI Agent Configuration
- **AML.T0092** — Manipulate User LLM Chat History
- **AML.T0094** — Delay Execution of LLM Instructions
- **AML.T0097** — Virtualization/Sandbox Evasion
- **AML.T0107** — Exploitation for Defense Evasion
- **AML.T0109** — AI Supply Chain Rug Pull
- **AML.T0111** — AI Supply Chain Reputation Inflation

### Credential Access (AML.TA0013)
- **AML.T0055** — Unsecured Credentials
- **AML.T0082** — RAG Credential Harvesting
- **AML.T0083** — Credentials from AI Agent Configuration
- **AML.T0090** — OS Credential Dumping
- **AML.T0098** — AI Agent Tool Credential Harvesting
- **AML.T0106** — Exploitation for Credential Access

### Discovery (AML.TA0008)
- **AML.T0007** — Discover AI Artifacts
- **AML.T0013** — Discover AI Model Ontology
- **AML.T0014** — Discover AI Model Family
- **AML.T0062** — Discover LLM Hallucinations
- **AML.T0063** — Discover AI Model Outputs
- **AML.T0069** — Discover LLM System Information
- **AML.T0075** — Cloud Service Discovery
- **AML.T0084** — Discover AI Agent Configuration
- **AML.T0089** — Process Discovery

### Lateral Movement (AML.TA0015)
- **AML.T0052** — Phishing
- **AML.T0091** — Use Alternate Authentication Material

### Collection (AML.TA0009)
- **AML.T0035** — AI Artifact Collection
- **AML.T0036** — Data from Information Repositories
- **AML.T0037** — Data from Local System
- **AML.T0085** — Data from AI Services

### AI Attack Staging (AML.TA0001)
- **AML.T0005** — Create Proxy AI Model
- **AML.T0018** — Manipulate AI Model
- **AML.T0042** — Verify Attack
- **AML.T0043** — Craft Adversarial Data
- **AML.T0088** — Generate Deepfakes
- **AML.T0102** — Generate Malicious Commands

### Command and Control (AML.TA0014)
- **AML.T0072** — Reverse Shell
- **AML.T0096** — AI Service API
- **AML.T0108** — AI Agent

### Exfiltration (AML.TA0010)
- **AML.T0024** — Exfiltration via AI Inference API
- **AML.T0025** — Exfiltration via Cyber Means
- **AML.T0056** — Extract LLM System Prompt
- **AML.T0057** — LLM Data Leakage
- **AML.T0077** — LLM Response Rendering
- **AML.T0086** — Exfiltration via AI Agent Tool Invocation

### Impact (AML.TA0011)
- **AML.T0015** — Evade AI Model
- **AML.T0029** — Denial of AI Service
- **AML.T0031** — Erode AI Model Integrity
- **AML.T0034** — Cost Harvesting
- **AML.T0046** — Spamming AI System with Chaff Data
- **AML.T0048** — External Harms
- **AML.T0059** — Erode Dataset Integrity
- **AML.T0101** — Data Destruction via AI Agent Tool Invocation
- **AML.T0112** — Machine Compromise
