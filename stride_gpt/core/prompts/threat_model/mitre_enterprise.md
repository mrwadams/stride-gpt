---
name: mitre_enterprise
title: MITRE ATT&CK Enterprise
when_to_load: |
  Load for almost any application threat model — Enterprise techniques cover
  web, server, cloud, container, and SaaS attack patterns. Always applicable
  unless the subsystem is purely ML/LLM behaviour with no traditional
  infrastructure surface (in which case load `mitre_atlas` instead).
adds_fields:
  - MITRE_ATTACK
stride_letters: [S, T, R, I, D, E]
source: https://attack.mitre.org/matrices/enterprise/
version: v17
---

# MITRE ATT&CK Enterprise — Reference Card

You loaded this card because the subsystem you are analysing has a traditional
software / infrastructure surface. In addition to a STRIDE category, you MUST
attach the most-specific applicable MITRE ATT&CK techniques to each threat.

## How to use this card

For each threat you emit, choose **zero or more** techniques from the catalog
below that an adversary would plausibly invoke to realise the threat. A threat
maps to a technique when the technique is the *mechanism* the attacker uses,
not merely a related concept.

> **Anti-hallucination requirement.** Use **only** technique IDs and names
> exactly as written in this card. Do not invent IDs, do not paraphrase names,
> do not combine an ID with a different technique's name. If no technique
> fits, emit `"MITRE_ATTACK": []` — empty is preferable to a fabricated ID.
> If both this card and `mitre_atlas` are loaded, merge techniques from both
> into the same `MITRE_ATTACK` list on each threat.

Prefer 1–3 techniques per threat. Avoid stuffing techniques that share a
tactic — pick the most specific one.

## Schema additions

Each threat object must additionally include:

- `"MITRE_ATTACK"`: an array of objects, each shaped
  `{"id": "T####", "name": "Technique Name"}`. May be empty.

## Technique catalog (curated for application threat models)

### Reconnaissance (TA0043)
- **T1595** — Active Scanning
- **T1592** — Gather Victim Host Information
- **T1589** — Gather Victim Identity Information
- **T1591** — Gather Victim Org Information
- **T1593** — Search Open Websites/Domains
- **T1596** — Search Open Technical Databases
- **T1594** — Search Victim-Owned Websites

### Resource Development (TA0042)
- **T1583** — Acquire Infrastructure
- **T1586** — Compromise Accounts
- **T1584** — Compromise Infrastructure
- **T1587** — Develop Capabilities
- **T1585** — Establish Accounts
- **T1588** — Obtain Capabilities
- **T1608** — Stage Capabilities

### Initial Access (TA0001)
- **T1189** — Drive-by Compromise
- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services
- **T1566** — Phishing
- **T1195** — Supply Chain Compromise
- **T1199** — Trusted Relationship
- **T1078** — Valid Accounts

### Execution (TA0002)
- **T1059** — Command and Scripting Interpreter
- **T1609** — Container Administration Command
- **T1610** — Deploy Container
- **T1203** — Exploitation for Client Execution
- **T1559** — Inter-Process Communication
- **T1106** — Native API
- **T1053** — Scheduled Task/Job
- **T1648** — Serverless Execution
- **T1072** — Software Deployment Tools
- **T1569** — System Services
- **T1204** — User Execution

### Persistence (TA0003)
- **T1098** — Account Manipulation
- **T1554** — Compromise Host Software Binary
- **T1136** — Create Account
- **T1543** — Create or Modify System Process
- **T1546** — Event Triggered Execution
- **T1525** — Implant Internal Image
- **T1556** — Modify Authentication Process
- **T1505** — Server Software Component
- **T1078** — Valid Accounts

### Privilege Escalation (TA0004)
- **T1548** — Abuse Elevation Control Mechanism
- **T1134** — Access Token Manipulation
- **T1484** — Domain or Tenant Policy Modification
- **T1611** — Escape to Host
- **T1068** — Exploitation for Privilege Escalation
- **T1055** — Process Injection

### Defense Evasion (TA0005)
- **T1480** — Execution Guardrails
- **T1222** — File and Directory Permissions Modification
- **T1562** — Impair Defenses
- **T1656** — Impersonation
- **T1070** — Indicator Removal
- **T1036** — Masquerading
- **T1578** — Modify Cloud Compute Infrastructure
- **T1027** — Obfuscated Files or Information
- **T1553** — Subvert Trust Controls
- **T1550** — Use Alternate Authentication Material
- **T1497** — Virtualization/Sandbox Evasion

### Credential Access (TA0006)
- **T1557** — Adversary-in-the-Middle
- **T1110** — Brute Force
- **T1555** — Credentials from Password Stores
- **T1212** — Exploitation for Credential Access
- **T1606** — Forge Web Credentials
- **T1056** — Input Capture
- **T1556** — Modify Authentication Process
- **T1111** — Multi-Factor Authentication Interception
- **T1621** — Multi-Factor Authentication Request Generation
- **T1040** — Network Sniffing
- **T1528** — Steal Application Access Token
- **T1649** — Steal or Forge Authentication Certificates
- **T1539** — Steal Web Session Cookie
- **T1552** — Unsecured Credentials

### Discovery (TA0007)
- **T1087** — Account Discovery
- **T1580** — Cloud Infrastructure Discovery
- **T1526** — Cloud Service Discovery
- **T1619** — Cloud Storage Object Discovery
- **T1613** — Container and Resource Discovery
- **T1083** — File and Directory Discovery
- **T1046** — Network Service Discovery
- **T1069** — Permission Groups Discovery
- **T1518** — Software Discovery
- **T1082** — System Information Discovery

### Lateral Movement (TA0008)
- **T1210** — Exploitation of Remote Services
- **T1570** — Lateral Tool Transfer
- **T1021** — Remote Services
- **T1550** — Use Alternate Authentication Material

### Collection (TA0009)
- **T1119** — Automated Collection
- **T1530** — Data from Cloud Storage
- **T1602** — Data from Configuration Repository
- **T1213** — Data from Information Repositories
- **T1005** — Data from Local System
- **T1074** — Data Staged
- **T1114** — Email Collection
- **T1056** — Input Capture

### Command and Control (TA0011)
- **T1071** — Application Layer Protocol
- **T1659** — Content Injection
- **T1573** — Encrypted Channel
- **T1105** — Ingress Tool Transfer
- **T1090** — Proxy
- **T1102** — Web Service

### Exfiltration (TA0010)
- **T1020** — Automated Exfiltration
- **T1030** — Data Transfer Size Limits
- **T1048** — Exfiltration Over Alternative Protocol
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service
- **T1537** — Transfer Data to Cloud Account

### Impact (TA0040)
- **T1531** — Account Access Removal
- **T1485** — Data Destruction
- **T1486** — Data Encrypted for Impact
- **T1565** — Data Manipulation
- **T1491** — Defacement
- **T1499** — Endpoint Denial of Service
- **T1498** — Network Denial of Service
- **T1496** — Resource Hijacking
- **T1489** — Service Stop
