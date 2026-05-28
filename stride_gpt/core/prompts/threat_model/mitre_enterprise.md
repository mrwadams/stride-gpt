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
version: v17.1
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

## Technique catalog

This catalog was generated from MITRE ATT&CK Enterprise v17.1. Sub-techniques
are not listed individually — use the parent technique ID. Deprecated and
revoked techniques are excluded.

### Reconnaissance (TA0043)
- **T1589** — Gather Victim Identity Information
- **T1590** — Gather Victim Network Information
- **T1591** — Gather Victim Org Information
- **T1592** — Gather Victim Host Information
- **T1593** — Search Open Websites/Domains
- **T1594** — Search Victim-Owned Websites
- **T1595** — Active Scanning
- **T1596** — Search Open Technical Databases
- **T1597** — Search Closed Sources
- **T1598** — Phishing for Information

### Resource Development (TA0042)
- **T1583** — Acquire Infrastructure
- **T1584** — Compromise Infrastructure
- **T1585** — Establish Accounts
- **T1586** — Compromise Accounts
- **T1587** — Develop Capabilities
- **T1588** — Obtain Capabilities
- **T1608** — Stage Capabilities
- **T1650** — Acquire Access

### Initial Access (TA0001)
- **T1078** — Valid Accounts
- **T1091** — Replication Through Removable Media
- **T1133** — External Remote Services
- **T1189** — Drive-by Compromise
- **T1190** — Exploit Public-Facing Application
- **T1195** — Supply Chain Compromise
- **T1199** — Trusted Relationship
- **T1200** — Hardware Additions
- **T1566** — Phishing
- **T1659** — Content Injection
- **T1669** — Wi-Fi Networks

### Execution (TA0002)
- **T1047** — Windows Management Instrumentation
- **T1053** — Scheduled Task/Job
- **T1059** — Command and Scripting Interpreter
- **T1072** — Software Deployment Tools
- **T1106** — Native API
- **T1129** — Shared Modules
- **T1203** — Exploitation for Client Execution
- **T1204** — User Execution
- **T1559** — Inter-Process Communication
- **T1569** — System Services
- **T1609** — Container Administration Command
- **T1610** — Deploy Container
- **T1648** — Serverless Execution
- **T1651** — Cloud Administration Command
- **T1674** — Input Injection
- **T1675** — ESXi Administration Command

### Persistence (TA0003)
- **T1037** — Boot or Logon Initialization Scripts
- **T1053** — Scheduled Task/Job
- **T1078** — Valid Accounts
- **T1098** — Account Manipulation
- **T1112** — Modify Registry
- **T1133** — External Remote Services
- **T1136** — Create Account
- **T1137** — Office Application Startup
- **T1176** — Software Extensions
- **T1197** — BITS Jobs
- **T1205** — Traffic Signaling
- **T1505** — Server Software Component
- **T1525** — Implant Internal Image
- **T1542** — Pre-OS Boot
- **T1543** — Create or Modify System Process
- **T1546** — Event Triggered Execution
- **T1547** — Boot or Logon Autostart Execution
- **T1554** — Compromise Host Software Binary
- **T1556** — Modify Authentication Process
- **T1574** — Hijack Execution Flow
- **T1653** — Power Settings
- **T1668** — Exclusive Control
- **T1671** — Cloud Application Integration

### Privilege Escalation (TA0004)
- **T1037** — Boot or Logon Initialization Scripts
- **T1053** — Scheduled Task/Job
- **T1055** — Process Injection
- **T1068** — Exploitation for Privilege Escalation
- **T1078** — Valid Accounts
- **T1098** — Account Manipulation
- **T1134** — Access Token Manipulation
- **T1484** — Domain or Tenant Policy Modification
- **T1543** — Create or Modify System Process
- **T1546** — Event Triggered Execution
- **T1547** — Boot or Logon Autostart Execution
- **T1548** — Abuse Elevation Control Mechanism
- **T1574** — Hijack Execution Flow
- **T1611** — Escape to Host

### Defense Evasion (TA0005)
- **T1006** — Direct Volume Access
- **T1014** — Rootkit
- **T1027** — Obfuscated Files or Information
- **T1036** — Masquerading
- **T1055** — Process Injection
- **T1070** — Indicator Removal
- **T1078** — Valid Accounts
- **T1112** — Modify Registry
- **T1127** — Trusted Developer Utilities Proxy Execution
- **T1134** — Access Token Manipulation
- **T1140** — Deobfuscate/Decode Files or Information
- **T1197** — BITS Jobs
- **T1202** — Indirect Command Execution
- **T1205** — Traffic Signaling
- **T1207** — Rogue Domain Controller
- **T1211** — Exploitation for Defense Evasion
- **T1216** — System Script Proxy Execution
- **T1218** — System Binary Proxy Execution
- **T1220** — XSL Script Processing
- **T1221** — Template Injection
- **T1222** — File and Directory Permissions Modification
- **T1480** — Execution Guardrails
- **T1484** — Domain or Tenant Policy Modification
- **T1497** — Virtualization/Sandbox Evasion
- **T1535** — Unused/Unsupported Cloud Regions
- **T1542** — Pre-OS Boot
- **T1548** — Abuse Elevation Control Mechanism
- **T1550** — Use Alternate Authentication Material
- **T1553** — Subvert Trust Controls
- **T1556** — Modify Authentication Process
- **T1562** — Impair Defenses
- **T1564** — Hide Artifacts
- **T1574** — Hijack Execution Flow
- **T1578** — Modify Cloud Compute Infrastructure
- **T1599** — Network Boundary Bridging
- **T1600** — Weaken Encryption
- **T1601** — Modify System Image
- **T1610** — Deploy Container
- **T1612** — Build Image on Host
- **T1620** — Reflective Code Loading
- **T1622** — Debugger Evasion
- **T1647** — Plist File Modification
- **T1656** — Impersonation
- **T1666** — Modify Cloud Resource Hierarchy
- **T1672** — Email Spoofing

### Credential Access (TA0006)
- **T1003** — OS Credential Dumping
- **T1040** — Network Sniffing
- **T1056** — Input Capture
- **T1110** — Brute Force
- **T1111** — Multi-Factor Authentication Interception
- **T1187** — Forced Authentication
- **T1212** — Exploitation for Credential Access
- **T1528** — Steal Application Access Token
- **T1539** — Steal Web Session Cookie
- **T1552** — Unsecured Credentials
- **T1555** — Credentials from Password Stores
- **T1556** — Modify Authentication Process
- **T1557** — Adversary-in-the-Middle
- **T1558** — Steal or Forge Kerberos Tickets
- **T1606** — Forge Web Credentials
- **T1621** — Multi-Factor Authentication Request Generation
- **T1649** — Steal or Forge Authentication Certificates

### Discovery (TA0007)
- **T1007** — System Service Discovery
- **T1010** — Application Window Discovery
- **T1012** — Query Registry
- **T1016** — System Network Configuration Discovery
- **T1018** — Remote System Discovery
- **T1033** — System Owner/User Discovery
- **T1040** — Network Sniffing
- **T1046** — Network Service Discovery
- **T1049** — System Network Connections Discovery
- **T1057** — Process Discovery
- **T1069** — Permission Groups Discovery
- **T1082** — System Information Discovery
- **T1083** — File and Directory Discovery
- **T1087** — Account Discovery
- **T1120** — Peripheral Device Discovery
- **T1124** — System Time Discovery
- **T1135** — Network Share Discovery
- **T1201** — Password Policy Discovery
- **T1217** — Browser Information Discovery
- **T1482** — Domain Trust Discovery
- **T1497** — Virtualization/Sandbox Evasion
- **T1518** — Software Discovery
- **T1526** — Cloud Service Discovery
- **T1538** — Cloud Service Dashboard
- **T1580** — Cloud Infrastructure Discovery
- **T1613** — Container and Resource Discovery
- **T1614** — System Location Discovery
- **T1615** — Group Policy Discovery
- **T1619** — Cloud Storage Object Discovery
- **T1622** — Debugger Evasion
- **T1652** — Device Driver Discovery
- **T1654** — Log Enumeration
- **T1673** — Virtual Machine Discovery

### Lateral Movement (TA0008)
- **T1021** — Remote Services
- **T1072** — Software Deployment Tools
- **T1080** — Taint Shared Content
- **T1091** — Replication Through Removable Media
- **T1210** — Exploitation of Remote Services
- **T1534** — Internal Spearphishing
- **T1550** — Use Alternate Authentication Material
- **T1563** — Remote Service Session Hijacking
- **T1570** — Lateral Tool Transfer

### Collection (TA0009)
- **T1005** — Data from Local System
- **T1025** — Data from Removable Media
- **T1039** — Data from Network Shared Drive
- **T1056** — Input Capture
- **T1074** — Data Staged
- **T1113** — Screen Capture
- **T1114** — Email Collection
- **T1115** — Clipboard Data
- **T1119** — Automated Collection
- **T1123** — Audio Capture
- **T1125** — Video Capture
- **T1185** — Browser Session Hijacking
- **T1213** — Data from Information Repositories
- **T1530** — Data from Cloud Storage
- **T1557** — Adversary-in-the-Middle
- **T1560** — Archive Collected Data
- **T1602** — Data from Configuration Repository

### Command and Control (TA0011)
- **T1001** — Data Obfuscation
- **T1008** — Fallback Channels
- **T1071** — Application Layer Protocol
- **T1090** — Proxy
- **T1092** — Communication Through Removable Media
- **T1095** — Non-Application Layer Protocol
- **T1102** — Web Service
- **T1104** — Multi-Stage Channels
- **T1105** — Ingress Tool Transfer
- **T1132** — Data Encoding
- **T1205** — Traffic Signaling
- **T1219** — Remote Access Tools
- **T1568** — Dynamic Resolution
- **T1571** — Non-Standard Port
- **T1572** — Protocol Tunneling
- **T1573** — Encrypted Channel
- **T1659** — Content Injection
- **T1665** — Hide Infrastructure

### Exfiltration (TA0010)
- **T1011** — Exfiltration Over Other Network Medium
- **T1020** — Automated Exfiltration
- **T1029** — Scheduled Transfer
- **T1030** — Data Transfer Size Limits
- **T1041** — Exfiltration Over C2 Channel
- **T1048** — Exfiltration Over Alternative Protocol
- **T1052** — Exfiltration Over Physical Medium
- **T1537** — Transfer Data to Cloud Account
- **T1567** — Exfiltration Over Web Service

### Impact (TA0040)
- **T1485** — Data Destruction
- **T1486** — Data Encrypted for Impact
- **T1489** — Service Stop
- **T1490** — Inhibit System Recovery
- **T1491** — Defacement
- **T1495** — Firmware Corruption
- **T1496** — Resource Hijacking
- **T1498** — Network Denial of Service
- **T1499** — Endpoint Denial of Service
- **T1529** — System Shutdown/Reboot
- **T1531** — Account Access Removal
- **T1561** — Disk Wipe
- **T1565** — Data Manipulation
- **T1657** — Financial Theft
- **T1667** — Email Bombing
