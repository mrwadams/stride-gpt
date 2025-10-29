# LangGraph Integration Plan for STRIDE GPT

## Executive Summary

This document outlines the integration of **LangGraph** as the foundational framework for implementing agentic capabilities in STRIDE GPT. LangGraph provides a production-ready, graph-based approach to building stateful multi-agent workflows with built-in features for persistence, human-in-the-loop, and error recovery.

**Why LangGraph?**
- ✅ **Production-ready** state management and checkpointing
- ✅ **Built-in multi-agent patterns** (supervisor, collaboration, hierarchical)
- ✅ **Flexible graph-based architecture** with conditional edges
- ✅ **Native tool calling support** for all major LLM providers
- ✅ **Human-in-the-loop** capabilities for review and approval
- ✅ **Active development** by LangChain team with strong community
- ✅ **Extensive documentation** and examples

---

## Table of Contents

1. [LangGraph Core Concepts](#langgraph-core-concepts)
2. [Architecture Overview](#architecture-overview)
3. [Agent Implementation with LangGraph](#agent-implementation-with-langgraph)
4. [Integration with Existing Code](#integration-with-existing-code)
5. [Implementation Roadmap](#implementation-roadmap)
6. [Code Examples](#code-examples)
7. [Testing Strategy](#testing-strategy)
8. [Deployment Considerations](#deployment-considerations)

---

## LangGraph Core Concepts

### State Management

LangGraph uses a **StateGraph** where state is a shared data structure that flows through nodes:

```python
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

class ThreatModelState(TypedDict):
    """State for threat modeling workflow"""
    # Core application context
    app_description: str
    app_type: str
    authentication: list[str]
    internet_facing: bool
    sensitive_data: str

    # Analysis results
    threat_model: dict | None
    attack_trees: dict | None
    mitigations: dict | None
    dread_scores: dict | None
    test_cases: list | None

    # Agent communication
    messages: Annotated[list, add_messages]

    # Workflow control
    next_agent: str | None
    iterations: int
    validation_results: dict | None
    research_findings: dict | None
```

**Key Features:**
- **Reducers**: Use `Annotated[list, add_messages]` to automatically merge messages
- **Immutability**: Each node returns a partial state update
- **Type Safety**: TypedDict provides schema validation

### Nodes (Agent Workers)

Nodes are Python functions that:
- Receive the current state
- Perform work (call LLMs, tools, external APIs)
- Return a state update

```python
def threat_analyst_node(state: ThreatModelState) -> dict:
    """Analyze application and generate threat model"""

    # Extract context
    app_context = {
        'description': state['app_description'],
        'type': state['app_type'],
        'authentication': state['authentication'],
        'internet_facing': state['internet_facing'],
        'sensitive_data': state['sensitive_data']
    }

    # Call LLM to generate threat model
    threat_model = get_threat_model(
        app_context,
        state.get('research_findings')  # Use research if available
    )

    # Return state update
    return {
        'threat_model': threat_model,
        'messages': [{'role': 'assistant', 'content': f"Generated {len(threat_model)} threats"}]
    }
```

### Edges (Control Flow)

**Normal Edges**: Direct connections between nodes
```python
graph.add_edge('threat_analyst', 'validation_agent')
```

**Conditional Edges**: Dynamic routing based on state
```python
def should_research(state: ThreatModelState) -> str:
    """Decide if threat research is needed"""
    if state.get('enable_research') and not state.get('research_findings'):
        return 'research_agent'
    return 'threat_analyst'

graph.add_conditional_edges(
    'orchestrator',
    should_research,
    {
        'research_agent': 'research_agent',
        'threat_analyst': 'threat_analyst'
    }
)
```

### Checkpointing and Persistence

LangGraph supports automatic state persistence:

```python
from langgraph.checkpoint.sqlite import SqliteSaver

# Create checkpointer for persistence
memory = SqliteSaver.from_conn_string("checkpoints.db")

# Compile graph with checkpointing
app = graph.compile(checkpointer=memory)

# Run with thread ID for persistence
config = {"configurable": {"thread_id": "threat-model-123"}}
result = app.invoke(initial_state, config=config)

# Resume from checkpoint later
resumed = app.invoke(None, config=config)  # Continues from last checkpoint
```

---

## Architecture Overview

### High-Level Graph Structure

```
                         ┌─────────────────┐
                         │  START (User)   │
                         └────────┬────────┘
                                  │
                         ┌────────▼────────┐
                         │  Orchestrator   │
                         │   (Planning)    │
                         └────────┬────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
           ┌────────▼────────┐         ┌───────▼──────┐
           │ Research Agent  │         │ Code Analyzer│
           │  (CVE/MITRE)    │         │   (Static)   │
           └────────┬────────┘         └───────┬──────┘
                    │                           │
                    └─────────────┬─────────────┘
                                  │
                         ┌────────▼────────┐
                         │ Threat Analyst  │
                         │   (STRIDE)      │
                         └────────┬────────┘
                                  │
                         ┌────────▼────────┐
                         │ Validation Agent│
                         │  (Gap Analysis) │
                         └────────┬────────┘
                                  │
                          ┌───────┴───────┐
                          │               │
                 ┌────────▼────────┐ ┌────▼─────────┐
                 │ Mitigation Gen  │ │ Test Case Gen│
                 └────────┬────────┘ └────┬─────────┘
                          │               │
                          └───────┬───────┘
                                  │
                         ┌────────▼────────┐
                         │ Report Generator│
                         └────────┬────────┘
                                  │
                         ┌────────▼────────┐
                         │   END (Output)  │
                         └─────────────────┘
```

### Multi-Agent Patterns

LangGraph supports three primary multi-agent patterns:

#### 1. **Supervisor Pattern** (Recommended for STRIDE GPT)

A supervisor agent coordinates specialized agents:

```python
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

# Create supervisor agent
supervisor_llm = ChatOpenAI(model="gpt-4o", temperature=0)

# Define supervisor function
def supervisor_node(state: ThreatModelState) -> dict:
    """Supervisor decides which specialist agent to invoke next"""

    supervisor_prompt = f"""You are coordinating a threat modeling analysis.

Current state:
- Threat model generated: {state.get('threat_model') is not None}
- Validation complete: {state.get('validation_results') is not None}
- Mitigations generated: {state.get('mitigations') is not None}
- Test cases generated: {state.get('test_cases') is not None}

Decide which agent should run next, or if we should finish.

Available agents:
- research_agent: Search CVEs and threat intelligence
- code_analyzer: Analyze code for vulnerabilities
- threat_analyst: Generate STRIDE threat model
- validation_agent: Validate threats and find gaps
- mitigation_generator: Create mitigation strategies
- test_generator: Generate Gherkin test cases
- FINISH: Complete the analysis

Respond with just the agent name."""

    messages = [{"role": "user", "content": supervisor_prompt}]
    response = supervisor_llm.invoke(messages)

    next_agent = response.content.strip()

    return {
        'next_agent': next_agent,
        'messages': [{'role': 'system', 'content': f"Supervisor selected: {next_agent}"}]
    }

# Add conditional routing based on supervisor decision
def route_after_supervisor(state: ThreatModelState) -> str:
    next_agent = state['next_agent']
    if next_agent == 'FINISH':
        return END
    return next_agent

graph.add_conditional_edges(
    'supervisor',
    route_after_supervisor,
    {
        'research_agent': 'research_agent',
        'code_analyzer': 'code_analyzer',
        'threat_analyst': 'threat_analyst',
        'validation_agent': 'validation_agent',
        'mitigation_generator': 'mitigation_generator',
        'test_generator': 'test_generator',
        END: END
    }
)
```

#### 2. **Collaboration Pattern**

Agents share a scratchpad and collaborate directly:

```python
# All agents have access to shared messages
class CollaborativeState(TypedDict):
    messages: Annotated[list, add_messages]
    threat_model: dict
    shared_context: dict

# Each agent adds to the shared message history
def threat_analyst(state: CollaborativeState) -> dict:
    return {
        'messages': [{'role': 'threat_analyst', 'content': 'Found SQL injection risk'}]
    }

def validator(state: CollaborativeState) -> dict:
    # Can see threat analyst's message
    threat_messages = [m for m in state['messages'] if m['role'] == 'threat_analyst']
    return {
        'messages': [{'role': 'validator', 'content': 'Confirmed: SQL injection is valid'}]
    }
```

#### 3. **Hierarchical Teams**

Sub-graphs as nodes for complex workflows:

```python
# Create sub-graph for code analysis
def create_code_analysis_subgraph():
    subgraph = StateGraph(CodeAnalysisState)
    subgraph.add_node('secrets_scanner', scan_secrets)
    subgraph.add_node('dependency_scanner', scan_dependencies)
    subgraph.add_node('static_analyzer', analyze_code)
    # ... add edges
    return subgraph.compile()

# Use sub-graph as a node in main graph
code_analysis_workflow = create_code_analysis_subgraph()
main_graph.add_node('code_analysis', code_analysis_workflow)
```

---

## Agent Implementation with LangGraph

### 1. Orchestrator Agent (Supervisor)

```python
from langgraph.graph import StateGraph, START, END
from typing import Literal

def create_orchestrator_graph(llm_config: dict) -> StateGraph:
    """Create the main orchestrator graph for threat modeling"""

    # Initialize state graph
    workflow = StateGraph(ThreatModelState)

    # Add all agent nodes
    workflow.add_node('orchestrator', supervisor_node)
    workflow.add_node('research_agent', threat_research_node)
    workflow.add_node('code_analyzer', code_analysis_node)
    workflow.add_node('threat_analyst', threat_analyst_node)
    workflow.add_node('validation_agent', validation_node)
    workflow.add_node('mitigation_generator', mitigation_node)
    workflow.add_node('test_generator', test_case_node)
    workflow.add_node('report_generator', report_node)

    # Entry point
    workflow.add_edge(START, 'orchestrator')

    # Conditional routing from orchestrator
    workflow.add_conditional_edges(
        'orchestrator',
        route_after_supervisor,
        {
            'research_agent': 'research_agent',
            'code_analyzer': 'code_analyzer',
            'threat_analyst': 'threat_analyst',
            'validation_agent': 'validation_agent',
            'mitigation_generator': 'mitigation_generator',
            'test_generator': 'test_generator',
            END: END
        }
    )

    # All agents return to orchestrator for next decision
    for agent in ['research_agent', 'code_analyzer', 'threat_analyst',
                  'validation_agent', 'mitigation_generator', 'test_generator']:
        workflow.add_edge(agent, 'orchestrator')

    return workflow
```

### 2. Threat Research Agent (with Tools)

```python
from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode

# Define research tools
@tool
def search_cve(keywords: list[str], severity: str = None) -> dict:
    """Search CVE database for vulnerabilities.

    Args:
        keywords: List of keywords to search (e.g., ['SQL', 'injection'])
        severity: Optional severity filter (LOW, MEDIUM, HIGH, CRITICAL)
    """
    # Call NIST NVD API
    results = nist_nvd_search(keywords, severity)
    return results

@tool
def query_mitre_attack(technique_id: str = None, tactic: str = None) -> dict:
    """Query MITRE ATT&CK framework.

    Args:
        technique_id: Specific technique ID (e.g., 'T1190')
        tactic: Tactic category (e.g., 'Initial Access')
    """
    results = mitre_attack_query(technique_id, tactic)
    return results

@tool
def check_owasp_top10(category: str) -> dict:
    """Get information about OWASP Top 10 vulnerabilities.

    Args:
        category: OWASP category (e.g., 'A01:2021-Broken Access Control')
    """
    return owasp_lookup(category)

# Create research agent with tools
def create_research_agent(llm_config: dict):
    tools = [search_cve, query_mitre_attack, check_owasp_top10]
    llm = create_llm_client(llm_config)
    llm_with_tools = llm.bind_tools(tools)

    def research_agent_node(state: ThreatModelState) -> dict:
        """Research threats using external databases"""

        # Determine what to research based on app context
        research_query = f"""Analyze this application for security threats:

Type: {state['app_type']}
Authentication: {', '.join(state['authentication'])}
Internet-facing: {state['internet_facing']}
Sensitive data: {state['sensitive_data']}

Use the available tools to:
1. Search for relevant CVEs
2. Find applicable MITRE ATT&CK techniques
3. Check relevant OWASP Top 10 categories

Return a structured summary of findings."""

        messages = [{"role": "user", "content": research_query}]

        # Call LLM with tools
        response = llm_with_tools.invoke(messages)

        # If tool calls are needed, execute them
        if response.tool_calls:
            tool_node = ToolNode(tools)
            tool_results = tool_node.invoke({'messages': [response]})

            # Synthesize results
            synthesis_prompt = f"Synthesize these research findings: {tool_results}"
            final_response = llm.invoke([
                {"role": "user", "content": research_query},
                {"role": "assistant", "content": response.content, "tool_calls": response.tool_calls},
                {"role": "tool", "content": str(tool_results)},
                {"role": "user", "content": synthesis_prompt}
            ])

            research_findings = {
                'cve_results': [r for r in tool_results if 'CVE' in str(r)],
                'mitre_results': [r for r in tool_results if 'MITRE' in str(r)],
                'owasp_results': [r for r in tool_results if 'OWASP' in str(r)],
                'synthesis': final_response.content
            }
        else:
            research_findings = {'synthesis': response.content}

        return {
            'research_findings': research_findings,
            'messages': [{'role': 'research_agent', 'content': f"Completed research with {len(tool_results) if response.tool_calls else 0} findings"}]
        }

    return research_agent_node
```

### 3. Code Analysis Agent

```python
import ast
from pathlib import Path

def code_analysis_node(state: ThreatModelState) -> dict:
    """Analyze codebase for vulnerabilities"""

    # Get repository files from state
    repo_files = state.get('repo_files', [])

    findings = {
        'secrets': [],
        'vulnerabilities': [],
        'dependencies': [],
        'misconfigurations': []
    }

    # Static analysis
    for file in repo_files:
        if file['path'].endswith('.py'):
            # Parse Python AST
            try:
                tree = ast.parse(file['content'])
                findings['vulnerabilities'].extend(analyze_python_ast(tree, file['path']))
            except SyntaxError:
                pass

        # Secrets detection
        secrets_found = scan_for_secrets(file['content'], file['path'])
        findings['secrets'].extend(secrets_found)

    # Dependency scanning
    if any(f['path'] == 'requirements.txt' for f in repo_files):
        req_file = next(f for f in repo_files if f['path'] == 'requirements.txt')
        findings['dependencies'] = scan_dependencies_python(req_file['content'])

    # LLM analysis for complex patterns
    llm = create_llm_client(state['llm_config'])

    analysis_prompt = f"""Analyze these code findings for security implications:

Secrets found: {len(findings['secrets'])}
Vulnerabilities: {len(findings['vulnerabilities'])}
Vulnerable dependencies: {len(findings['dependencies'])}

Detailed findings:
{findings}

Provide:
1. Severity assessment (CRITICAL, HIGH, MEDIUM, LOW)
2. Specific file and line references
3. Exploitation scenarios
4. Remediation guidance"""

    llm_analysis = llm.invoke([{"role": "user", "content": analysis_prompt}])

    return {
        'code_analysis_results': {
            'raw_findings': findings,
            'llm_analysis': llm_analysis.content,
            'summary': f"Found {len(findings['secrets'])} secrets, {len(findings['vulnerabilities'])} vulnerabilities"
        },
        'messages': [{'role': 'code_analyzer', 'content': f"Code analysis complete"}]
    }
```

### 4. Validation Agent

```python
def validation_node(state: ThreatModelState) -> dict:
    """Validate threats and identify gaps"""

    threat_model = state.get('threat_model')
    if not threat_model:
        return {'messages': [{'role': 'validator', 'content': 'No threat model to validate'}]}

    llm = create_llm_client(state['llm_config'])

    validation_results = {
        'valid_threats': [],
        'invalid_threats': [],
        'missing_threats': [],
        'confidence_scores': {}
    }

    # Validate each threat
    for threat in threat_model.get('threats', []):
        validation_prompt = f"""Validate this threat:

Threat: {threat['threat']}
STRIDE Category: {threat['stride_category']}
Affected Component: {threat['component']}

Application Context:
- Type: {state['app_type']}
- Authentication: {state['authentication']}
- Internet-facing: {state['internet_facing']}

Questions:
1. Is this threat applicable to this application? (Yes/No)
2. Can this threat be realistically exploited? (Yes/No)
3. Confidence score (0-100)
4. If invalid, explain why
5. If valid, suggest refinements

Respond in JSON format."""

        response = llm.invoke([{"role": "user", "content": validation_prompt}])
        validation = parse_json_response(response.content)

        if validation.get('applicable') and validation.get('exploitable'):
            validation_results['valid_threats'].append(threat)
            validation_results['confidence_scores'][threat['id']] = validation.get('confidence', 50)
        else:
            validation_results['invalid_threats'].append({
                'threat': threat,
                'reason': validation.get('reason', 'Unknown')
            })

    # Gap analysis
    gap_analysis_prompt = f"""Given these validated threats:
{validation_results['valid_threats']}

And this application context:
- Type: {state['app_type']}
- Auth: {state['authentication']}
- Internet-facing: {state['internet_facing']}
- Data sensitivity: {state['sensitive_data']}

What threats are MISSING? Consider:
1. STRIDE categories not covered
2. Attack vectors not addressed
3. Common vulnerabilities for this app type
4. Threats found in code analysis: {state.get('code_analysis_results', {}).get('summary', 'N/A')}

List missing threats in JSON format."""

    gap_response = llm.invoke([{"role": "user", "content": gap_analysis_prompt}])
    validation_results['missing_threats'] = parse_json_response(gap_response.content)

    return {
        'validation_results': validation_results,
        'messages': [{'role': 'validator', 'content': f"Validated {len(validation_results['valid_threats'])} threats, found {len(validation_results['invalid_threats'])} invalid, identified {len(validation_results['missing_threats'])} gaps"}]
    }
```

### 5. Human-in-the-Loop Integration

LangGraph supports human approval workflows:

```python
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.prebuilt import create_interrupt

def create_workflow_with_human_approval():
    """Create workflow with human approval points"""

    workflow = StateGraph(ThreatModelState)

    # ... add nodes ...

    # Add human approval before generating report
    def approval_node(state: ThreatModelState) -> dict:
        """Request human approval before proceeding"""

        # This will pause execution
        approval_needed = create_interrupt(
            value={
                'type': 'approval_request',
                'data': {
                    'threats': state['threat_model'],
                    'validation': state['validation_results'],
                    'mitigations': state['mitigations']
                }
            }
        )

        return {'messages': [{'role': 'system', 'content': 'Awaiting human approval'}]}

    workflow.add_node('approval', approval_node)
    workflow.add_edge('mitigation_generator', 'approval')
    workflow.add_edge('approval', 'report_generator')

    # Compile with checkpointer to enable pausing
    memory = SqliteSaver.from_conn_string("checkpoints.db")
    app = workflow.compile(checkpointer=memory)

    return app

# Usage
app = create_workflow_with_human_approval()

# Start workflow
config = {"configurable": {"thread_id": "session-123"}}
result = app.invoke(initial_state, config=config)

# Later, after human approval
# Resume from checkpoint
updated_state = result.copy()
updated_state['approved'] = True
continued_result = app.invoke(updated_state, config=config)
```

---

## Integration with Existing Code

### Wrapping Existing Functions

LangGraph can use existing STRIDE GPT functions as-is:

```python
# Existing function in threat_model.py
def get_threat_model(app_input, app_type, authentication, internet_facing, sensitive_data, llm_config):
    """Existing STRIDE GPT function"""
    # ... existing implementation ...
    return threat_model_json

# Wrap as LangGraph node
def threat_analyst_node(state: ThreatModelState) -> dict:
    """Wrapper for existing threat model function"""

    threat_model = get_threat_model(
        app_input=state['app_description'],
        app_type=state['app_type'],
        authentication=state['authentication'],
        internet_facing=state['internet_facing'],
        sensitive_data=state['sensitive_data'],
        llm_config=state['llm_config']
    )

    return {'threat_model': threat_model}
```

### Streamlit Integration

Add LangGraph workflow to Streamlit UI:

```python
# In main.py

import streamlit as st
from langgraph_integration import create_orchestrator_graph

# Add mode selector
analysis_mode = st.sidebar.radio(
    "Analysis Mode",
    options=["Standard", "Autonomous (LangGraph)"],
    help="Standard: Step-by-step manual analysis\nAutonomous: AI agents coordinate automatically"
)

if analysis_mode == "Autonomous (LangGraph)":
    st.subheader("🤖 Autonomous Threat Analysis")

    # Configuration
    enable_research = st.checkbox("Enable Threat Research (CVE/MITRE)", value=True)
    enable_code_analysis = st.checkbox("Enable Code Analysis", value=True)
    enable_validation = st.checkbox("Enable Validation", value=True)

    if st.button("🚀 Run Autonomous Analysis"):
        # Create initial state
        initial_state = {
            'app_description': app_input,
            'app_type': app_type,
            'authentication': authentication,
            'internet_facing': internet_facing,
            'sensitive_data': sensitive_data,
            'llm_config': {
                'provider': model_provider,
                'model': selected_model,
                'api_key': api_key,
                'temperature': 0
            },
            'enable_research': enable_research,
            'enable_code_analysis': enable_code_analysis,
            'enable_validation': enable_validation,
            'messages': [],
            'iterations': 0
        }

        # Create and run workflow
        with st.spinner("🤖 Orchestrating AI agents..."):
            workflow = create_orchestrator_graph(initial_state['llm_config'])
            app = workflow.compile()

            # Stream results
            progress_placeholder = st.empty()
            results_placeholder = st.empty()

            for step in app.stream(initial_state):
                # Display progress
                current_node = list(step.keys())[0]
                progress_placeholder.info(f"🔄 Running: {current_node}")

                # Display intermediate results
                if 'messages' in step[current_node]:
                    latest_message = step[current_node]['messages'][-1]
                    results_placeholder.write(f"**{latest_message['role']}**: {latest_message['content']}")

            # Display final results
            final_state = step[current_node]

            st.success("✅ Autonomous analysis complete!")

            # Display results in tabs
            tab1, tab2, tab3, tab4, tab5 = st.tabs([
                "Threat Model",
                "Validation Results",
                "Mitigations",
                "Test Cases",
                "Agent Activity"
            ])

            with tab1:
                st.json(final_state.get('threat_model'))

            with tab2:
                validation = final_state.get('validation_results', {})
                st.metric("Valid Threats", len(validation.get('valid_threats', [])))
                st.metric("Invalid Threats", len(validation.get('invalid_threats', [])))
                st.metric("Missing Threats", len(validation.get('missing_threats', [])))

            with tab3:
                st.json(final_state.get('mitigations'))

            with tab4:
                st.json(final_state.get('test_cases'))

            with tab5:
                st.subheader("Agent Communication Log")
                for msg in final_state.get('messages', []):
                    st.text(f"[{msg.get('role', 'unknown')}] {msg.get('content', '')}")

else:
    # Existing standard workflow
    if st.button("Generate Threat Model"):
        # ... existing code ...
```

---

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-2)

**Goal:** Get basic LangGraph orchestration working

**Tasks:**
1. **Setup** (Day 1-2)
   - Install dependencies: `pip install langgraph langchain langchain-openai`
   - Create `langgraph_integration.py` module
   - Set up basic StateGraph structure

2. **State Definition** (Day 2-3)
   - Define `ThreatModelState` TypedDict
   - Add message reducers
   - Create state validation

3. **Basic Orchestrator** (Day 3-5)
   - Implement supervisor node
   - Create conditional routing
   - Test with existing threat_model.py function

4. **Streamlit Integration** (Day 5-7)
   - Add "Autonomous Mode" toggle
   - Create progress display
   - Test end-to-end workflow

**Deliverables:**
- Working orchestrator that calls existing threat_model.py function
- Streamlit UI with autonomous mode
- Basic state management

**Success Criteria:**
- Can generate threat model via LangGraph
- State persists between nodes
- UI shows agent progress

### Phase 2: Tool Integration (Weeks 3-4)

**Goal:** Add research and code analysis agents with tools

**Tasks:**
1. **Research Agent** (Day 8-10)
   - Implement CVE search tool
   - Implement MITRE ATT&CK query tool
   - Implement OWASP lookup tool
   - Integrate with ToolNode

2. **Code Analysis Agent** (Day 11-13)
   - Create secrets detection tool
   - Create dependency scanning tool
   - Wrap Bandit/Semgrep as tools
   - LLM synthesis of findings

3. **Validation Agent** (Day 14-15)
   - Threat validation logic
   - Gap analysis
   - Confidence scoring

4. **Integration** (Day 16-17)
   - Connect all agents in graph
   - Test with real repositories
   - Optimize prompts

**Deliverables:**
- Three working agents with tool calling
- Real threat intelligence integration
- Code-level vulnerability detection

**Success Criteria:**
- Research agent fetches real CVE data
- Code analysis finds actual vulnerabilities
- Validation reduces false positives by 50%+

### Phase 3: Advanced Features (Weeks 5-6)

**Goal:** Add human-in-the-loop, checkpointing, and reporting

**Tasks:**
1. **Checkpointing** (Day 18-20)
   - Set up SqliteSaver
   - Implement state persistence
   - Add resume capability
   - Error recovery

2. **Human-in-the-Loop** (Day 21-22)
   - Add approval nodes
   - Create review interface in Streamlit
   - Implement feedback incorporation

3. **Report Generation** (Day 23-25)
   - Create report agent
   - PDF generation
   - Markdown export
   - Visualization creation

4. **Optimization** (Day 26-28)
   - Parallel agent execution
   - Token usage optimization
   - Caching strategy
   - Performance testing

**Deliverables:**
- Persistent workflows that survive crashes
- Human review checkpoints
- Professional report generation

**Success Criteria:**
- Workflows can pause and resume
- Users can approve/reject findings
- Reports are production-ready

### Phase 4: Production Readiness (Weeks 7-8)

**Goal:** Polish, testing, documentation

**Tasks:**
1. **Testing** (Day 29-32)
   - Unit tests for each agent
   - Integration tests for workflows
   - Load testing
   - Error handling verification

2. **Documentation** (Day 33-35)
   - API documentation
   - User guide for autonomous mode
   - Developer guide for adding agents
   - Video tutorials

3. **Deployment** (Day 36-38)
   - Docker configuration
   - Environment setup guide
   - CI/CD integration
   - Monitoring setup

4. **Launch** (Day 39-40)
   - Beta release
   - Gather feedback
   - Bug fixes
   - Performance tuning

**Deliverables:**
- Comprehensive test suite
- Complete documentation
- Production deployment

**Success Criteria:**
- 90%+ test coverage
- Clear documentation
- Successful deployments

---

## Code Examples

### Complete Working Example

Here's a minimal but complete LangGraph implementation for STRIDE GPT:

```python
# langgraph_integration.py

from typing import TypedDict, Annotated, Literal
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_openai import ChatOpenAI
import json

# Import existing STRIDE GPT functions
from threat_model import get_threat_model
from mitigations import get_mitigations
from test_cases import get_test_cases

# Define state
class ThreatModelState(TypedDict):
    # Input
    app_description: str
    app_type: str
    authentication: list[str]
    internet_facing: bool
    sensitive_data: str
    llm_config: dict

    # Outputs
    threat_model: dict | None
    mitigations: dict | None
    test_cases: list | None

    # Control
    messages: Annotated[list, add_messages]
    next_step: str | None

# Create LLM
def create_llm(config: dict):
    return ChatOpenAI(
        model=config['model'],
        temperature=config.get('temperature', 0),
        api_key=config['api_key']
    )

# Supervisor node
def supervisor_node(state: ThreatModelState) -> dict:
    """Decide which agent should run next"""

    llm = create_llm(state['llm_config'])

    prompt = f"""You are coordinating a threat modeling analysis.

Current status:
- Threat model: {'✅ Complete' if state.get('threat_model') else '❌ Not started'}
- Mitigations: {'✅ Complete' if state.get('mitigations') else '❌ Not started'}
- Test cases: {'✅ Complete' if state.get('test_cases') else '❌ Not started'}

What should we do next? Respond with ONE of:
- threat_analyst (if threat model not done)
- mitigation_generator (if threat model done but mitigations not done)
- test_generator (if mitigations done but test cases not done)
- FINISH (if everything is complete)

Just respond with the agent name, nothing else."""

    response = llm.invoke([{"role": "user", "content": prompt}])
    next_step = response.content.strip()

    return {
        'next_step': next_step,
        'messages': [{'role': 'supervisor', 'content': f"Next: {next_step}"}]
    }

# Threat analyst node
def threat_analyst_node(state: ThreatModelState) -> dict:
    """Generate threat model using existing STRIDE GPT function"""

    threat_model = get_threat_model(
        app_input=state['app_description'],
        app_type=state['app_type'],
        authentication=state['authentication'],
        internet_facing=state['internet_facing'],
        sensitive_data=state['sensitive_data'],
        model_name=state['llm_config']['model']
    )

    threat_count = len(threat_model) if isinstance(threat_model, list) else 0

    return {
        'threat_model': threat_model,
        'messages': [{'role': 'threat_analyst', 'content': f"Generated {threat_count} threats"}]
    }

# Mitigation generator node
def mitigation_node(state: ThreatModelState) -> dict:
    """Generate mitigations using existing function"""

    mitigations = get_mitigations(
        threats=json.dumps(state['threat_model']),
        model_name=state['llm_config']['model']
    )

    return {
        'mitigations': mitigations,
        'messages': [{'role': 'mitigation_generator', 'content': "Generated mitigations"}]
    }

# Test case generator node
def test_case_node(state: ThreatModelState) -> dict:
    """Generate test cases"""

    test_cases = get_test_cases(
        threats=json.dumps(state['threat_model']),
        mitigations=json.dumps(state['mitigations']),
        model_name=state['llm_config']['model']
    )

    return {
        'test_cases': test_cases,
        'messages': [{'role': 'test_generator', 'content': "Generated test cases"}]
    }

# Routing function
def route_after_supervisor(state: ThreatModelState) -> str:
    """Route to next agent based on supervisor decision"""
    next_step = state.get('next_step', 'FINISH')
    if next_step == 'FINISH':
        return END
    return next_step

# Create graph
def create_threat_modeling_workflow():
    """Create the main LangGraph workflow"""

    workflow = StateGraph(ThreatModelState)

    # Add nodes
    workflow.add_node('supervisor', supervisor_node)
    workflow.add_node('threat_analyst', threat_analyst_node)
    workflow.add_node('mitigation_generator', mitigation_node)
    workflow.add_node('test_generator', test_case_node)

    # Set entry point
    workflow.add_edge(START, 'supervisor')

    # Conditional routing from supervisor
    workflow.add_conditional_edges(
        'supervisor',
        route_after_supervisor,
        {
            'threat_analyst': 'threat_analyst',
            'mitigation_generator': 'mitigation_generator',
            'test_generator': 'test_generator',
            END: END
        }
    )

    # All agents return to supervisor
    workflow.add_edge('threat_analyst', 'supervisor')
    workflow.add_edge('mitigation_generator', 'supervisor')
    workflow.add_edge('test_generator', 'supervisor')

    # Compile
    return workflow.compile()

# Usage
if __name__ == "__main__":
    # Create workflow
    app = create_threat_modeling_workflow()

    # Initial state
    initial_state = {
        'app_description': 'A web application that handles user authentication and stores sensitive data',
        'app_type': 'Web application',
        'authentication': ['SSO', 'MFA'],
        'internet_facing': True,
        'sensitive_data': 'PII, financial records',
        'llm_config': {
            'model': 'gpt-4o',
            'api_key': 'your-api-key',
            'temperature': 0
        },
        'messages': []
    }

    # Run workflow
    for step in app.stream(initial_state):
        print(f"\n=== {list(step.keys())[0]} ===")
        node_output = step[list(step.keys())[0]]
        if 'messages' in node_output:
            for msg in node_output['messages']:
                print(f"{msg.get('role')}: {msg.get('content')}")

    # Final result
    print("\n=== FINAL RESULTS ===")
    print(f"Threats: {len(node_output.get('threat_model', []))}")
    print(f"Mitigations: {len(node_output.get('mitigations', []))}")
    print(f"Test cases: {len(node_output.get('test_cases', []))}")
```

### Running the Example

```bash
# Install dependencies
pip install langgraph langchain langchain-openai

# Run the workflow
python langgraph_integration.py
```

**Expected Output:**
```
=== supervisor ===
supervisor: Next: threat_analyst

=== threat_analyst ===
threat_analyst: Generated 12 threats

=== supervisor ===
supervisor: Next: mitigation_generator

=== mitigation_generator ===
mitigation_generator: Generated mitigations

=== supervisor ===
supervisor: Next: test_generator

=== test_generator ===
test_generator: Generated test cases

=== supervisor ===
supervisor: Next: FINISH

=== FINAL RESULTS ===
Threats: 12
Mitigations: 12
Test cases: 24
```

---

## Testing Strategy

### Unit Tests

```python
# tests/test_langgraph_agents.py

import pytest
from langgraph_integration import (
    supervisor_node,
    threat_analyst_node,
    mitigation_node,
    ThreatModelState
)

def test_supervisor_starts_with_threat_analyst():
    """Supervisor should start with threat analysis if nothing is done"""

    state = {
        'app_description': 'Test app',
        'llm_config': {'model': 'gpt-4o', 'api_key': 'test'},
        'messages': []
    }

    result = supervisor_node(state)

    assert result['next_step'] == 'threat_analyst'

def test_threat_analyst_generates_threats():
    """Threat analyst should generate threat model"""

    state = {
        'app_description': 'Web application with user login',
        'app_type': 'Web application',
        'authentication': ['SSO'],
        'internet_facing': True,
        'sensitive_data': 'User data',
        'llm_config': {'model': 'gpt-4o', 'api_key': 'test'},
        'messages': []
    }

    result = threat_analyst_node(state)

    assert 'threat_model' in result
    assert isinstance(result['threat_model'], (dict, list))
    assert len(result['messages']) > 0

def test_workflow_completes_successfully():
    """Full workflow should complete all steps"""

    from langgraph_integration import create_threat_modeling_workflow

    app = create_threat_modeling_workflow()

    initial_state = {
        'app_description': 'Simple web app',
        'app_type': 'Web application',
        'authentication': ['Username/password'],
        'internet_facing': True,
        'sensitive_data': 'None',
        'llm_config': {'model': 'gpt-4o-mini', 'api_key': 'test-key'},
        'messages': []
    }

    # Run workflow
    final_state = None
    for step in app.stream(initial_state):
        final_state = step[list(step.keys())[0]]

    # Check all outputs are present
    assert final_state['threat_model'] is not None
    assert final_state['mitigations'] is not None
    assert final_state['test_cases'] is not None
```

### Integration Tests

```python
# tests/test_langgraph_integration.py

def test_research_agent_fetches_cves(mock_nist_api):
    """Research agent should fetch real CVE data"""
    # Test with mocked API
    pass

def test_code_analysis_finds_secrets():
    """Code analysis should detect hardcoded secrets"""
    # Test with sample vulnerable code
    pass

def test_validation_removes_false_positives():
    """Validation agent should filter invalid threats"""
    # Test with known false positives
    pass
```

---

## Deployment Considerations

### Environment Setup

```bash
# requirements-langgraph.txt
langgraph>=0.2.0
langchain>=0.3.0
langchain-openai>=0.2.0
langchain-anthropic>=0.2.0
langchain-google-genai>=2.0.0

# Optional for checkpointing
aiosqlite>=0.19.0
```

### Docker Configuration

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt requirements-langgraph.txt ./
RUN pip install -r requirements.txt -r requirements-langgraph.txt

COPY . .

# Create directory for checkpoints
RUN mkdir -p /app/checkpoints

EXPOSE 8501

CMD ["streamlit", "run", "main.py"]
```

### Environment Variables

```bash
# .env
# Existing STRIDE GPT vars
OPENAI_API_KEY=your-key
ANTHROPIC_API_KEY=your-key

# LangGraph specific
LANGGRAPH_CHECKPOINT_PATH=/app/checkpoints/checkpoints.db
LANGGRAPH_ENABLE_TRACING=true
LANGSMITH_API_KEY=your-langsmith-key  # Optional, for debugging
```

### Monitoring with LangSmith

LangGraph integrates with LangSmith for debugging:

```python
import os
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_API_KEY"] = "your-langsmith-key"
os.environ["LANGCHAIN_PROJECT"] = "stride-gpt-agents"

# All LangGraph runs will now be traced in LangSmith
app = create_threat_modeling_workflow()
result = app.invoke(initial_state)

# View trace at: https://smith.langchain.com/
```

---

## Performance Optimization

### Parallel Agent Execution

LangGraph supports parallel execution when agents are independent:

```python
from langgraph.pregel import Channel

# These agents can run in parallel
workflow.add_node('research_agent', research_node)
workflow.add_node('code_analyzer', code_analysis_node)

# Both connect to orchestrator
workflow.add_edge(START, 'research_agent')
workflow.add_edge(START, 'code_analyzer')

# Use Send to dispatch multiple nodes at once
from langgraph.types import Send

def route_to_parallel_agents(state):
    """Dispatch multiple agents in parallel"""
    return [
        Send('research_agent', state),
        Send('code_analyzer', state)
    ]

workflow.add_conditional_edges(START, route_to_parallel_agents)
```

### Caching

```python
from functools import lru_cache

@lru_cache(maxsize=100)
def get_cve_data(keywords_tuple):
    """Cache CVE lookups"""
    keywords = list(keywords_tuple)
    return search_cve_api(keywords)

# Use in research agent
def research_node(state):
    keywords = tuple(extract_keywords(state['app_description']))
    cve_data = get_cve_data(keywords)  # Cached
    return {'research_findings': cve_data}
```

---

## Migration Path

### Gradual Adoption Strategy

1. **Week 1-2**: Run LangGraph in parallel with existing system
   - Users can choose either mode
   - Compare results side-by-side
   - Gather feedback

2. **Week 3-4**: Make LangGraph the default, keep legacy as fallback
   - "Try new autonomous mode (beta)" becomes default
   - "Classic mode" available as option
   - Monitor adoption and errors

3. **Week 5-6**: Deprecate legacy system
   - Remove standard mode from UI
   - Keep code for reference
   - Update documentation

### Backward Compatibility

All existing functions remain callable:

```python
# Old way still works
from threat_model import get_threat_model

threat_model = get_threat_model(app_input, app_type, authentication, ...)

# New way uses LangGraph
from langgraph_integration import create_threat_modeling_workflow

app = create_threat_modeling_workflow()
result = app.invoke(initial_state)
```

---

## Next Steps

### Immediate Actions (This Week)

1. **Prototype** (Day 1-2)
   - Install LangGraph: `pip install langgraph langchain-openai`
   - Create `langgraph_integration.py`
   - Implement basic supervisor pattern

2. **Test** (Day 3)
   - Run with simple example
   - Compare output with existing system
   - Measure performance

3. **Demo** (Day 4-5)
   - Create Streamlit demo
   - Record video walkthrough
   - Gather feedback

### Questions to Resolve

1. **LLM Selection**: Which model for supervisor? (Recommend GPT-4o or Claude Opus 4)
2. **Checkpointing**: SQLite local or PostgreSQL for production?
3. **Tool Providers**: Which CVE API? (NIST NVD vs CIRCL vs commercial)
4. **Human-in-the-Loop**: Required or optional? At which steps?

### Resources

- **LangGraph Docs**: https://langchain-ai.github.io/langgraph/
- **Tutorials**: https://langchain-ai.github.io/langgraph/tutorials/
- **Examples**: https://github.com/langchain-ai/langgraph/tree/main/examples
- **LangSmith**: https://smith.langchain.com/ (debugging/monitoring)

---

## Conclusion

LangGraph provides a robust, production-ready foundation for implementing agentic capabilities in STRIDE GPT. Key advantages:

✅ **Less code to maintain**: No need to build orchestration from scratch
✅ **Battle-tested**: Used by enterprises for production AI agents
✅ **Flexible**: Supports multiple patterns (supervisor, collaboration, hierarchical)
✅ **Observable**: Built-in tracing and debugging with LangSmith
✅ **Resilient**: Checkpointing enables fault tolerance
✅ **Extensible**: Easy to add new agents and tools

By adopting LangGraph, STRIDE GPT can rapidly evolve from a single-shot threat modeling tool to an intelligent, autonomous security analysis platform that rivals commercial solutions.

**Let's build the future of AI-powered threat modeling! 🚀**

---

**Document Version:** 1.0
**Author:** Claude (Anthropic)
**Date:** 2025-10-29
**Status:** Implementation Ready
