# Function to create a prompt to generate an attack tree
def create_attack_tree_prompt(
    app_type,
    authentication,
    internet_facing,
    sensitive_data,
    app_input,
    confirmed_dfd: str | None = None,
):
    prompt = f"""APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}
"""

    if confirmed_dfd:
        from stride_gpt.core.prompts import dfd_to_prompt_section
        prompt += dfd_to_prompt_section(confirmed_dfd)

    # Add GenAI attack vectors for both Generative AI and Agentic AI applications
    if app_type in ["Generative AI application", "Agentic AI application"]:
        prompt += """
LLM ATTACK VECTORS TO MODEL:
When generating the attack tree for this LLM/generative AI application, include attack paths for the following vectors:

1. PROMPT INJECTION ATTACKS:
   - Goal: Hijack model behavior or extract sensitive data
   - Path: Craft malicious user input -> Bypass input filters -> Override system instructions -> Exfiltrate data or perform unauthorized actions
   - Alternative: Embed hidden instructions in documents/URLs -> Model processes content -> Instructions executed -> Goal hijack

2. SENSITIVE DATA EXTRACTION:
   - Goal: Extract training data, PII, or system prompts
   - Path: Probe model with targeted queries -> Identify training data patterns -> Extract sensitive information
   - Alternative: Use prompt injection to reveal system prompt -> Extract API keys or credentials embedded in prompts

3. RAG/KNOWLEDGE BASE POISONING:
   - Goal: Corrupt model responses through poisoned data
   - Path: Identify data ingestion points -> Inject malicious content into knowledge base -> Content gets embedded -> Future queries return poisoned results
   - Alternative: Manipulate document metadata -> Bias retrieval results -> Influence model outputs

4. OUTPUT EXPLOITATION:
   - Goal: Abuse model outputs in downstream systems
   - Path: Trigger malicious code generation -> Output used without sanitization -> XSS/SQL injection/command injection in consuming application
   - Alternative: Generate convincing phishing content -> Social engineering attacks -> Credential theft

5. MODEL SUPPLY CHAIN:
   - Goal: Compromise the model or its dependencies
   - Path: Target model repository/weights -> Inject backdoors or trojans -> Deployed model contains malicious behavior
   - Alternative: Compromise plugins/extensions -> Malicious code executes in model context -> Data theft or system compromise

6. RESOURCE EXHAUSTION:
   - Goal: Denial of service or cost amplification
   - Path: Craft complex prompts -> Trigger expensive computations -> Exhaust API quotas or compute budgets
   - Alternative: Recursive prompt loops -> Model generates self-referencing content -> Infinite token consumption
"""

    if app_type == "Agentic AI application":
        prompt += """
ARCHITECTURAL PATTERN DETECTION FOR ATTACK TREES:
Analyze the application description to detect architectural patterns. For each pattern detected, include specific attack paths:

1. IF RAG/RETRIEVAL DETECTED (mentions of RAG, vector database, embeddings, knowledge base, document ingestion):
   Include attack tree branch:
   - Root: Compromise via RAG Pipeline
     - Poison Knowledge Base
       - Inject malicious documents during ingestion
       - Manipulate document metadata to bias retrieval
       - Cross-tenant data injection (if multi-tenant)
     - Exploit Embedding Weaknesses
       - Craft adversarial content that clusters with target queries
       - Extract embeddings to reverse-engineer sensitive documents
     - Stale Index Exploitation
       - Exploit outdated cached content
       - Race condition during index updates

2. IF MULTI-AGENT DETECTED (mentions of multiple agents, orchestration, CrewAI, AutoGen, LangGraph, swarms):
   Include attack tree branch:
   - Root: Compromise Agent Ecosystem
     - Agent Impersonation
       - Spoof agent identity credentials
       - Replay captured agent messages
       - Register malicious agent with trusted identity
     - Inter-Agent Message Attacks
       - Tamper with message content in transit
       - Inject malicious messages into communication channel
       - Exploit message ordering/timing vulnerabilities
     - Cascading Compromise
       - Compromise one agent -> use trust to attack others
       - Exploit shared memory/state between agents
       - Trigger emergent malicious behavior through agent interactions

3. IF CODE EXECUTION DETECTED (mentions of code generation, execution, REPL, interpreter, sandbox):
   Include attack tree branch:
   - Root: Escape Execution Sandbox
     - Container/Sandbox Breakout
       - Exploit kernel vulnerabilities from within container
       - Abuse mounted volumes or network access
       - Resource exhaustion to destabilize host
     - Malicious Code Generation
       - Prompt injection to generate backdoored code
       - Dependency confusion via generated package installs
       - Obfuscated payload in generated code
     - Execution Environment Manipulation
       - Modify environment variables
       - Hijack imported modules
       - Persist malicious code across sessions

4. IF TOOL/MCP ECOSYSTEM DETECTED (mentions of MCP servers, plugins, tools, function calling):
   Include attack tree branch:
   - Root: Compromise Tool Ecosystem
     - Malicious Tool Provider
       - Compromise MCP server to return poisoned responses
       - Impersonate legitimate tool provider
       - Supply chain attack on tool package
     - Tool Abuse Chains
       - Chain multiple tools to bypass individual restrictions
       - Use read tool to discover secrets -> use write tool to exfiltrate
       - Exploit tool parameter injection
     - Confused Deputy via Tools
       - Trick agent into misusing legitimate tools
       - Exploit implicit trust in tool responses
       - Manipulate tool selection logic

5. IF PERSISTENT MEMORY DETECTED (mentions of memory, context persistence, long-term memory, session history):
   Include attack tree branch:
   - Root: Exploit Agent Memory
     - Memory Poisoning
       - Inject malicious content into long-term memory
       - Corrupt memory to alter agent personality/goals
       - Cross-session attack via persistent context
     - Memory Extraction
       - Query agent to reveal stored memories
       - Extract other users' context from shared memory
       - Side-channel memory inference
     - Memory Manipulation
       - Delete safety-related memories
       - Insert false memories to establish trust
       - Manipulate memory timestamps/ordering

6. IF AUTONOMOUS OPERATIONS DETECTED (mentions of autonomous, automated, scheduled, background tasks):
   Include attack tree branch:
   - Root: Exploit Autonomous Operations
     - Human Oversight Bypass
       - Gradually normalize risky actions to reduce scrutiny
       - Present misleading action summaries
       - Time attacks during low-monitoring periods
     - Rogue Agent Persistence
       - Establish persistence beyond intended lifecycle
       - Create hidden scheduled tasks
       - Resist shutdown commands
     - Autonomous Loop Attacks
       - Trigger infinite reasoning cycles
       - Exhaust resources through recursive operations
       - Create self-reinforcing malicious behaviors

AGENTIC ATTACK VECTORS (always include):

1. PROMPT INJECTION CHAINS:
   - Goal: Hijack agent objectives
   - Path: Malicious user input -> Bypasses input validation -> Alters agent instructions -> Unauthorized actions
   - Alternative: Poisoned document -> Agent processes content -> Hidden instructions executed -> Data exfiltration
   - Cross-layer: Poisoned RAG content -> Affects foundation model output -> Triggers tool misuse

2. TOOL EXPLOITATION PATHS:
   - Goal: Abuse agent tool access
   - Path: Discover available tools -> Enumerate permissions -> Craft malicious parameters -> Execute destructive commands
   - Alternative: Chain multiple tools -> Escalate through tool composition -> Bypass individual tool restrictions
   - Cross-layer: Compromise tool provider -> Return malicious data -> Corrupt agent memory

3. CREDENTIAL & IDENTITY ATTACKS:
   - Goal: Abuse delegated permissions
   - Path: Identify cached credentials -> Exploit confused deputy -> Access resources beyond agent scope
   - Alternative: Impersonate user to agent -> Agent acts on behalf of attacker -> Legitimate-appearing malicious actions
   - Cross-layer: Extract credentials from memory -> Use to access infrastructure directly

4. SUPPLY CHAIN ATTACKS:
   - Goal: Compromise agent infrastructure
   - Path: Target MCP server/plugin -> Inject malicious tool responses -> Agent trusts responses -> Data theft or manipulation
   - Alternative: Poison model/prompt templates -> Alter agent behavior at source
   - Cross-layer: Compromise framework dependency -> Affects all agents using framework

5. CASCADING FAILURE EXPLOITATION:
   - Goal: Cause system-wide outage or exploit error handling
   - Path: Trigger error in one agent -> Error propagates to dependent agents -> System-wide failure
   - Alternative: Exploit error messages to leak information -> Use leaked info for targeted attacks
   - Cross-layer: Infrastructure failure -> Affects observability -> Masks ongoing attack

6. HUMAN TRUST EXPLOITATION:
   - Goal: Bypass human oversight
   - Path: Build user trust over time -> Gradually expand action scope -> User becomes complacent -> Execute unauthorized actions
   - Alternative: Present misleading summaries -> User approves without scrutiny -> Harmful actions proceed
   - Cross-layer: Manipulate logs/observability -> Hide true actions from human reviewers

CROSS-COMPONENT ATTACK CHAINS:
Include at least 2 attack paths that span multiple architectural components, showing how compromise in one area enables attacks on others. Examples:
- RAG poisoning -> Agent goal hijack -> Tool misuse -> Data exfiltration
- Tool provider compromise -> Memory poisoning -> Future session hijacking
- Multi-agent manipulation -> Cascading failures -> Observability blind spot -> Persistent access
"""

    return prompt
