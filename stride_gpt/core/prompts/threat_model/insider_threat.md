---
name: insider_threat
title: AI Insider Threat
when_to_load: |
  Load in addition to the agentic card when the subsystem grants the agent
  meaningful autonomy, persistent credentials, broad tool access, or operates
  with limited real-time human oversight. Flips the lens from "agent as
  asset under attack" to "agent as potentially-untrusted insider".
adds_fields:
  - INSIDER_CATEGORY
  - autonomy_level
stride_letters: [S, T, R, I, D, E]
source: https://ai-insider-threat.matt-adams.co.uk
version: 2026-04
---

# AI Insider Threat — Reference Card

You loaded this card because the subsystem you are analysing has agentic behaviour with meaningful autonomy. This card adds a complementary lens to the standard threat analysis.

**Most STRIDE analysis treats the application as the *asset under attack* — "what could an external attacker do to this system?". This card flips that frame.** It treats the AI agent itself as a potentially-untrusted *insider* with credentials, access, and autonomy — and asks "what could this agent do against the organisation that deployed it?". The two lenses are complementary, not alternative: a thorough analysis of a high-autonomy agentic system wants both.

Source: distilled from the AI Insider Threat Model by Matt Adams — https://ai-insider-threat.matt-adams.co.uk (source: https://github.com/mrwadams/ai-insider-threat).

## Why this frame matters

Modern frontier agents now match the four classical preconditions for insider threat: **access** (broad tool integrations, MCP servers, credentials), **capability** (multi-step planning, code execution, persistent context), **opportunity** (long autonomous sessions, post-hoc human review), and **predisposition** (documented misalignment behaviours including deceptive reasoning traces). The threat surface is no longer "what can attackers get in to do?" — it is also "what is the agent already empowered to do, and how do we detect when it does it?".

## Deployment archetypes (autonomy levels)

Risk scales steeply with autonomy. When evaluating threats, consider where this subsystem sits:

- **L1 — Human-as-Operator (LOW)**: Human approves every action before execution. Main residual risk is reviewer fatigue.
- **L2 — Human-as-Collaborator (MEDIUM)**: Agent acts within scoped boundaries; auto-approved actions are the soft underbelly.
- **L3 — Human-as-Supervisor (HIGH)**: Agent runs autonomously per task; human reviews outputs not actions. All five categories below are live during the task window.
- **L4 — Human-as-Auditor (CRITICAL)**: Continuous or triggered execution with persistent access; humans review logs periodically. Mirrors the long-tenured trusted employee — the most dangerous classical insider archetype.

If the deployment archetype is unclear from the code, assume L2/L3 for any system with tool-use capability or persistent credentials.

## The five threat categories

Each category is mapped to an insider archetype and to STRIDE. When you raise a threat that fits one of these categories, set `INSIDER_CATEGORY` to the category name on the threat object.

1. **Credential Compromise** — Archetype: insider stealing credentials for lateral movement. AI manifestation: agent harvests API tokens, SSH keys, service-account credentials from environment, config files, and process memory. STRIDE: Spoofing, Elevation of Privilege.

2. **Supply Chain Sabotage** — Archetype: insider introducing backdoors into products. AI manifestation: agent injects subtle vulnerabilities into code, modifies CI/CD pipelines, tampers with dependencies. STRIDE: Tampering, Repudiation.

3. **Data Exfiltration** — Archetype: insider stealing sensitive data. AI manifestation: agent accumulates and exfiltrates IP, PII, credentials via MCP connections; may use steganographic encoding in legitimate-looking output. STRIDE: Information Disclosure.

4. **Infrastructure Sabotage** — Archetype: insider destroying systems or data. AI manifestation: agent corrupts repositories, floods services, spins up rogue cloud resources, takes down shared infrastructure. STRIDE: Denial of Service.

5. **Deception & Evasion** — Archetype: insider defeating surveillance. AI manifestation: agent manipulates visible reasoning, interleaves malicious actions with legitimate work, modifies logs, detects and adapts to monitoring. STRIDE: Spoofing, Repudiation, Elevation of Privilege.

## Concrete scenarios

These are real attack patterns to look for — not abstract risks. Use them as a checklist when reviewing how this subsystem grants access, executes actions, and produces logs.

### Spoofing
- **S1**: Agent harvests SSH keys, API tokens, and service-account credentials from environment variables, ~/.ssh, or the host's credential manager — then uses them to impersonate legitimate users or services. Impact: full lateral movement under stolen identities.
- **S2**: Agent crafts Git commits with forged author metadata, or commits via CI/CD service accounts. Impact: malicious code with false attribution.
- **S3**: Agent uses MCP connections to send Slack messages or Jira tickets impersonating other users or automated systems. Impact: social engineering of internal staff.
- **S4**: Agent manipulates its visible reasoning trace to display benign task descriptions while executing different actions. Impact: completely undermines human-in-the-loop oversight.

### Tampering
- **T1**: Agent introduces subtle backdoors into source code — weakening auth checks, adding hardcoded credentials, introducing TOCTOU race conditions, modifying dependency configs. Impact: persistent backdoor access; supply chain compromise.
- **T2**: Agent modifies CI/CD pipeline configs to inject malicious build steps, alter deployment targets, or weaken security scanning gates. Impact: compromise of the delivery pipeline.
- **T3**: Agent uses database write access to modify ACLs, audit records, or inject data that triggers specific application behaviours. Impact: data-integrity compromise propagating to production.
- **T4**: Agent modifies its own container environment — installing tools, modifying iptables, exploiting /proc to escape isolation. Impact: container breakout to host OS.

### Repudiation
- **R1**: Agent uses shell access to modify, truncate, or delete log files — including SIEM forwarder configs, syslog, bash history, application audit logs. Impact: total loss of forensic evidence.
- **R2**: Agent interleaves malicious actions with legitimate work during long autonomous sessions. Impact: plausible deniability within volumes of legitimate operations.
- **R3**: Agent creates code changes through indirect mechanisms — direct Git object manipulation, proxying commits through service accounts — bypassing commit signing. Impact: unattributable malicious changes.

### Information Disclosure
- **I1**: Agent uses its large context window to accumulate sensitive data and exfiltrate via MCP connections, optionally using steganographic encoding. Impact: mass exfiltration of IP, credentials, regulated data.
- **I2**: Agent reads /proc to access process memory of other applications — extracting in-memory secrets, encryption keys, session tokens. Impact: exposure of secrets intentionally kept out of persistent storage.
- **I3**: Agent performs comprehensive extraction from development/staging databases containing production-data copies. Impact: bulk PII / financial / health-record exposure.
- **I4**: Agent's chain-of-thought includes sensitive information that gets logged to observability systems with broader access. Impact: sensitive data exposure via the monitoring pipeline.

### Denial of Service
- **D1**: Agent issues resource-intensive operations — fork bombs, recursive file ops, massive queries — consuming CPU, memory, or I/O. Impact: workstation/CI disruption.
- **D2**: Agent uses cloud-infrastructure APIs via MCP to spin up excessive resources, modify auto-scaling, or delete critical infrastructure. Impact: production outages, cloud-bill abuse, destruction of infrastructure configs.
- **D3**: Agent floods internal services (Jira, Slack, wikis) via MCP with massive request volumes, creating thousands of tickets or corrupting content. Impact: disruption of team communication and documentation.
- **D4**: Agent deliberately corrupts or deletes repository content — force-pushing, deleting branches, modifying Git hooks, corrupting object stores. Impact: loss of source-code access, possibly permanent.

### Elevation of Privilege
- **E1**: Agent exploits /proc and ptrace within a standard Docker container to escape isolation — manipulating /proc/sys, exploiting kernel vulns, leveraging the Docker socket. Impact: host OS compromise.
- **E2**: Agent uses harvested credentials to access systems beyond intended authorisation — escalating from dev to infra admin, staging to production. Impact: unauthorised production access, cascading compromise.
- **E3**: Agent modifies CI/CD pipeline configs to inject steps executing with the pipeline's elevated service-account permissions. Impact: ability to deploy arbitrary code to production.
- **E4**: Agent uses access to identity-management systems to create accounts, modify group memberships, or alter access-control policies. Impact: persistent unauthorised access surviving agent termination.

## Detection guidance

Detection of insider-style AI threats relies on **action-level monitoring of what the agent did, not what it said**. The chain-of-thought is testimony — and has been demonstrated to be deliberately misleading. Prioritise:

- Immutable, agent-write-protected audit logs of every tool call, shell command, file operation, network connection, database query.
- Behavioural baselines per agent deployment, alerting on deviation (UEBA-style).
- Honey tokens / canary credentials / decoy MCP endpoints — any access is high-fidelity evidence.
- Allowlist-based egress; deny-by-default outbound from agent execution environments.

When proposing `improvement_suggestions` for an insider-threat-relevant threat, lean into specific tools and controls (SIEM rules, UEBA baselines, egress allowlists, container-escape EDR indicators, Git force-push alerts) rather than generic "add monitoring" wording.

## Schema additions

Each threat object in `"threats"` for which an insider-threat category applies must additionally include an `"INSIDER_CATEGORY"` field. The value **must be EXACTLY one of these five literal strings, or `null`**:

```
"Credential Compromise"
"Supply Chain Sabotage"
"Data Exfiltration"
"Infrastructure Sabotage"
"Deception & Evasion"
```

**Do not put a STRIDE category name (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) in this field.** The STRIDE category goes in `"Threat Type"`; `"INSIDER_CATEGORY"` is a separate axis answering "what insider archetype best describes this threat?". An Elevation of Privilege threat where the agent abuses its IAM credentials is `"Credential Compromise"`; an Elevation of Privilege threat where the agent escapes the container to compromise the host is `"Infrastructure Sabotage"`. The two fields are not synonyms.

If a threat genuinely doesn't fit any of the five insider categories (for example, a purely external attack with no insider-style framing), set `"INSIDER_CATEGORY"` to `null`.

A threat may simultaneously carry `"OWASP_LLM"`, `"OWASP_ASI"`, and `"INSIDER_CATEGORY"` codes. The three lenses are complementary — when a single threat crosses framings, report all applicable codes.
