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
version: 4.7.0
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
  {"id": "AML.T0024", "name": "Exfiltration via ML Inference API"}]`.

## Schema additions

Each threat object must additionally include:

- `"MITRE_ATTACK"`: an array of objects, each shaped
  `{"id": "AML.T####", "name": "Technique Name"}` (or the equivalent
  Enterprise shape — both share the field). May be empty.

## Technique catalog (curated for LLM / ML threat models)

### Reconnaissance (AML.TA0002)
- **AML.T0000** — Search for Victim's Publicly Available Research Materials
- **AML.T0001** — Search for Publicly Available Adversarial Vulnerability Analysis
- **AML.T0003** — Search Victim-Owned Websites
- **AML.T0004** — Search Application Repositories
- **AML.T0006** — Active Scanning

### Resource Development (AML.TA0003)
- **AML.T0002** — Acquire Public ML Artifacts
- **AML.T0005** — Acquire Infrastructure
- **AML.T0008** — Acquire Infrastructure: ML Development Workspaces
- **AML.T0016** — Obtain Capabilities
- **AML.T0017** — Develop Capabilities
- **AML.T0019** — Publish Poisoned Datasets
- **AML.T0021** — Establish Accounts

### Initial Access (AML.TA0004)
- **AML.T0010** — ML Supply Chain Compromise
- **AML.T0011** — User Execution
- **AML.T0012** — Valid Accounts
- **AML.T0049** — Exploit Public-Facing Application
- **AML.T0052** — Phishing

### ML Model Access (AML.TA0000)
- **AML.T0040** — ML Model Inference API Access
- **AML.T0041** — Physical Environment Access
- **AML.T0044** — Full ML Model Access
- **AML.T0047** — ML-Enabled Product or Service

### Execution (AML.TA0005)
- **AML.T0050** — Command and Scripting Interpreter
- **AML.T0051** — LLM Prompt Injection
- **AML.T0053** — LLM Plugin Compromise

### Persistence (AML.TA0006)
- **AML.T0018** — Backdoor ML Model
- **AML.T0020** — Poison Training Data
- **AML.T0061** — LLM Prompt Self-Replication

### Defense Evasion (AML.TA0007)
- **AML.T0015** — Evade ML Model
- **AML.T0043** — Craft Adversarial Data
- **AML.T0054** — LLM Jailbreak

### Discovery (AML.TA0008)
- **AML.T0013** — Discover ML Model Ontology
- **AML.T0014** — Discover ML Model Family
- **AML.T0062** — Discover LLM Hallucinations

### Collection (AML.TA0009)
- **AML.T0035** — ML Artifact Collection
- **AML.T0036** — Data from Information Repositories
- **AML.T0037** — Data from Local System

### ML Attack Staging (AML.TA0001)
- **AML.T0042** — Verify Attack
- **AML.T0043** — Craft Adversarial Data

### Exfiltration (AML.TA0010)
- **AML.T0024** — Exfiltration via ML Inference API
- **AML.T0025** — Exfiltration via Cyber Means
- **AML.T0056** — Extract LLM System Prompt
- **AML.T0057** — LLM Data Leakage

### Impact (AML.TA0011)
- **AML.T0029** — Denial of ML Service
- **AML.T0031** — Erode ML Model Integrity
- **AML.T0034** — Cost Harvesting
- **AML.T0045** — ML Intellectual Property Theft
- **AML.T0046** — Spamming ML System with Chaff Data
- **AML.T0048** — External Harms
