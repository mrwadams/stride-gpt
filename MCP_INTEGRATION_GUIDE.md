# MCP Integration Guide for STRIDE GPT with LangGraph

## Executive Summary

This guide demonstrates how to integrate **Model Context Protocol (MCP)** servers with **LangGraph** to provide security intelligence tools (CVE databases, OWASP references, Shodan, etc.) for STRIDE GPT's agentic capabilities. Using MCP provides a standardized, modular approach to connecting threat intelligence sources.

**Key Benefits:**
- ✅ **Standardized protocol** for tool integration
- ✅ **Reusable servers** - leverage existing MCP ecosystem
- ✅ **Modular architecture** - easily add/remove intelligence sources
- ✅ **Community-driven** - hundreds of MCP servers available
- ✅ **Native LangGraph support** via `langchain-mcp-adapters`

**Important Security Note:** MCP servers themselves have security risks (CVE-2025-6514, CVE-2025-49596). We implement security best practices throughout this guide.

---

## Table of Contents

1. [MCP Overview](#mcp-overview)
2. [Available Security MCP Servers](#available-security-mcp-servers)
3. [LangGraph + MCP Integration](#langgraph-mcp-integration)
4. [Security Best Practices](#security-best-practices)
5. [Implementation Examples](#implementation-examples)
6. [Creating Custom MCP Servers](#creating-custom-mcp-servers)
7. [Deployment Configuration](#deployment-configuration)

---

## MCP Overview

### What is MCP?

**Model Context Protocol (MCP)** is an open protocol by Anthropic that standardizes how applications provide tools and context to LLMs. Think of it as a universal adapter for AI tools.

**Architecture:**
```
┌─────────────────┐
│   LangGraph     │
│     Agent       │
└────────┬────────┘
         │
         │ langchain-mcp-adapters
         │
    ┌────┴────────────────────────────┐
    │                                 │
┌───▼──────────┐            ┌────────▼───────┐
│ CVE-Search   │            │    Shodan      │
│ MCP Server   │            │   MCP Server   │
└──────────────┘            └────────────────┘
```

### LangChain MCP Adapters

The official `langchain-mcp-adapters` package makes MCP servers compatible with LangGraph:

```bash
pip install langchain-mcp-adapters langgraph
```

**Key Features:**
- Converts MCP tools into LangChain/LangGraph tools
- Supports multiple simultaneous MCP servers
- Handles stdio, SSE, and HTTP transports
- Integrates with hundreds of existing MCP servers

---

## Available Security MCP Servers

### 1. CVE-Search MCP Server ⭐

**Repository:** `roadwy/cve-search_mcp`
**Description:** Queries the CVE-Search API for comprehensive vulnerability data

**Tools Provided:**
- Search CVEs by keyword
- Get CVE by ID
- Browse vendors and products
- Get recently updated CVEs
- CAPEC (attack patterns) lookup

**Installation:**
```bash
# Install via npm
npm install -g cve-search-mcp-server

# Or run directly with npx
npx cve-search-mcp-server
```

**Configuration:**
```json
{
  "mcpServers": {
    "cve-search": {
      "command": "npx",
      "args": ["-y", "cve-search-mcp-server"]
    }
  }
}
```

### 2. Shodan MCP Server

**Repository:** `BurtTheCoder/mcp-shodan`
**Description:** Queries Shodan for device information and CVE database

**Tools Provided:**
- IP lookups
- Device searches
- DNS lookups
- CVE queries via Shodan's CVEDB
- CPE lookups
- Exploit searches

**Configuration:**
```json
{
  "mcpServers": {
    "shodan": {
      "command": "node",
      "args": ["path/to/shodan-mcp/dist/index.js"],
      "env": {
        "SHODAN_API_KEY": "your-shodan-api-key"
      }
    }
  }
}
```

### 3. Semgrep MCP Server

**Repository:** `semgrep/mcp`
**Description:** Code security scanning via Semgrep

**Tools Provided:**
- Scan code for vulnerabilities
- Custom rule execution
- Multi-language support

**Installation:**
```bash
pip install semgrep-mcp
```

### 4. CVE Intelligence Server

**Description:** Multi-source CVE aggregation with EPSS scoring

**Tools Provided:**
- Multi-database CVE search
- Exploit discovery
- EPSS risk scoring
- Trend analysis

### 5. Custom OWASP MCP Server (To Build)

We'll create a custom MCP server for OWASP references:

**Proposed Tools:**
- Query OWASP Top 10
- Get CWE details
- ASVS requirements lookup
- Testing guide references

---

## LangGraph + MCP Integration

### Installation

```bash
# Core dependencies
pip install langgraph langchain-openai langchain-anthropic

# MCP adapter
pip install langchain-mcp-adapters

# For running Node.js MCP servers (if needed)
npm install -g cve-search-mcp-server
```

### Basic Example: Single MCP Server

```python
from langchain_mcp_adapters import MCPClient
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

async def create_agent_with_cve_tools():
    """Create LangGraph agent with CVE-Search MCP server"""

    # Initialize MCP client
    async with MCPClient.stdio_client(
        command="npx",
        args=["-y", "cve-search-mcp-server"]
    ) as client:
        # Initialize session
        await client.initialize()

        # Load MCP tools
        mcp_tools = client.get_tools()

        print(f"Loaded {len(mcp_tools)} tools from CVE-Search MCP:")
        for tool in mcp_tools:
            print(f"  - {tool.name}: {tool.description}")

        # Create LangGraph agent with MCP tools
        llm = ChatOpenAI(model="gpt-4o")
        agent = create_react_agent(llm, mcp_tools)

        # Use the agent
        result = await agent.ainvoke({
            "messages": [{
                "role": "user",
                "content": "Search for recent SQL injection CVEs"
            }]
        })

        return result

# Run
import asyncio
result = asyncio.run(create_agent_with_cve_tools())
```

### Multi-Server Example: CVE + Shodan

```python
from langchain_mcp_adapters import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_anthropic import ChatAnthropic

async def create_multi_source_threat_agent():
    """Create agent with multiple security intelligence sources"""

    # Configure multiple MCP servers
    servers = {
        "cve-search": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "cve-search-mcp-server"]
        },
        "shodan": {
            "transport": "stdio",
            "command": "node",
            "args": ["path/to/shodan-mcp/dist/index.js"],
            "env": {
                "SHODAN_API_KEY": "your-api-key"
            }
        }
    }

    # Initialize multi-server client
    async with MultiServerMCPClient(servers) as client:
        # Get tools from all servers
        all_tools = client.get_tools()

        print(f"Loaded {len(all_tools)} tools from {len(servers)} MCP servers")

        # Group tools by server
        tools_by_server = {}
        for tool in all_tools:
            server = tool.metadata.get("server", "unknown")
            tools_by_server.setdefault(server, []).append(tool.name)

        for server, tool_names in tools_by_server.items():
            print(f"\n{server}: {', '.join(tool_names)}")

        # Create agent
        llm = ChatAnthropic(model="claude-opus-4")
        agent = create_react_agent(llm, all_tools)

        # Query with multi-source intelligence
        result = await agent.ainvoke({
            "messages": [{
                "role": "user",
                "content": """
                Research security threats for a web application using:
                1. CVE database for known vulnerabilities
                2. Shodan to check for exposed instances
                Focus on authentication and SQL injection risks.
                """
            }]
        })

        return result

# Run
result = asyncio.run(create_multi_source_threat_agent())
```

---

## Integration with STRIDE GPT LangGraph Workflow

### Updated State Definition

```python
from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages

class ThreatModelState(TypedDict):
    # Application context
    app_description: str
    app_type: str
    authentication: list[str]
    internet_facing: bool
    sensitive_data: str

    # Analysis results
    threat_model: dict | None
    mitigations: dict | None
    test_cases: list | None

    # MCP-based research results
    cve_findings: list | None
    shodan_findings: dict | None
    owasp_references: list | None

    # Agent communication
    messages: Annotated[list, add_messages]

    # MCP tools (passed between agents)
    mcp_tools: list | None
```

### Research Agent with MCP Tools

```python
from langchain_mcp_adapters import MultiServerMCPClient
from langgraph.graph import StateGraph

async def create_research_agent_node(mcp_servers: dict):
    """Create research agent node that uses MCP tools"""

    async def research_node(state: ThreatModelState) -> dict:
        """Research threats using MCP security intelligence sources"""

        async with MultiServerMCPClient(mcp_servers) as mcp_client:
            # Get all MCP tools
            mcp_tools = mcp_client.get_tools()

            # Create research agent
            llm = ChatOpenAI(model="gpt-4o", temperature=0)
            research_agent = create_react_agent(llm, mcp_tools)

            # Build research query
            research_query = f"""
            Research security threats for this application:

            Type: {state['app_type']}
            Authentication: {', '.join(state['authentication'])}
            Internet-facing: {state['internet_facing']}
            Data sensitivity: {state['sensitive_data']}
            Description: {state['app_description']}

            Use the available tools to:
            1. Search CVE database for relevant vulnerabilities
            2. Check OWASP Top 10 categories that apply
            3. Query Shodan for similar exposed systems (if applicable)
            4. Identify common attack patterns (CAPEC)

            Return a structured summary of findings with:
            - Specific CVE IDs and descriptions
            - OWASP categories
            - Real-world exploit examples
            - Risk severity assessments
            """

            # Execute research
            research_result = await research_agent.ainvoke({
                "messages": [{"role": "user", "content": research_query}]
            })

            # Parse findings
            findings = {
                'cve_findings': extract_cves(research_result),
                'shodan_findings': extract_shodan_data(research_result),
                'owasp_references': extract_owasp_refs(research_result),
                'summary': research_result['messages'][-1]['content']
            }

            return {
                'cve_findings': findings['cve_findings'],
                'shodan_findings': findings['shodan_findings'],
                'owasp_references': findings['owasp_references'],
                'messages': [{
                    'role': 'research_agent',
                    'content': f"Research complete: {len(findings['cve_findings'])} CVEs found"
                }]
            }

    return research_node

# Helper functions
def extract_cves(result):
    """Extract CVE IDs and details from research results"""
    import re
    content = result['messages'][-1]['content']
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cves = re.findall(cve_pattern, content)
    return [{'id': cve, 'context': extract_context(content, cve)} for cve in cves]

def extract_shodan_data(result):
    """Extract Shodan findings"""
    # Parse Shodan data from result
    return {}

def extract_owasp_refs(result):
    """Extract OWASP references"""
    import re
    content = result['messages'][-1]['content']
    owasp_pattern = r'(A\d{2}:\d{4}[-\s][\w\s]+)'
    return re.findall(owasp_pattern, content)

def extract_context(text, cve_id):
    """Extract context around CVE mention"""
    sentences = text.split('.')
    for sentence in sentences:
        if cve_id in sentence:
            return sentence.strip()
    return ""
```

### Complete Workflow with MCP Integration

```python
from langgraph.graph import StateGraph, START, END

async def create_stride_gpt_workflow_with_mcp():
    """Create complete STRIDE GPT workflow with MCP tools"""

    # Configure MCP servers
    mcp_servers = {
        "cve-search": {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "cve-search-mcp-server"]
        },
        # Add more servers as needed
    }

    # Create workflow
    workflow = StateGraph(ThreatModelState)

    # Create nodes
    research_node = await create_research_agent_node(mcp_servers)

    workflow.add_node("orchestrator", supervisor_node)
    workflow.add_node("research_agent", research_node)
    workflow.add_node("threat_analyst", threat_analyst_node)
    workflow.add_node("validation_agent", validation_node)
    workflow.add_node("mitigation_generator", mitigation_node)

    # Set up edges
    workflow.add_edge(START, "orchestrator")
    workflow.add_conditional_edges(
        "orchestrator",
        route_after_supervisor,
        {
            "research_agent": "research_agent",
            "threat_analyst": "threat_analyst",
            "validation_agent": "validation_agent",
            "mitigation_generator": "mitigation_generator",
            END: END
        }
    )

    # All agents return to orchestrator
    for agent in ["research_agent", "threat_analyst", "validation_agent", "mitigation_generator"]:
        workflow.add_edge(agent, "orchestrator")

    return workflow.compile()

# Usage
async def analyze_application(app_context):
    """Run threat analysis with MCP-powered research"""

    workflow = await create_stride_gpt_workflow_with_mcp()

    initial_state = {
        'app_description': app_context['description'],
        'app_type': app_context['type'],
        'authentication': app_context['auth_methods'],
        'internet_facing': app_context['internet_facing'],
        'sensitive_data': app_context['data_sensitivity'],
        'messages': []
    }

    # Stream results
    async for step in workflow.astream(initial_state):
        current_node = list(step.keys())[0]
        print(f"Running: {current_node}")

        if 'messages' in step[current_node]:
            for msg in step[current_node]['messages']:
                print(f"  {msg.get('role')}: {msg.get('content')}")

    # Return final state
    return step[current_node]
```

---

## Security Best Practices

### MCP Security Risks (2025)

Recent CVEs discovered in MCP implementations:
- **CVE-2025-6514** (CVSS 9.6): RCE in mcp-remote
- **CVE-2025-49596** (CVSS 9.4): RCE in MCP Inspector
- **CVE-2025-53967** (CVSS 7.5): Command injection in Figma MCP

**Risk Statistics:**
- 43% of MCP servers have command injection flaws
- 33% allow unrestricted URL fetches
- 22% leak files outside intended directories
- 92% exploit probability with 10 MCP plugins

### Security Hardening

#### 1. Isolate MCP Servers

```yaml
# docker-compose.yml
version: '3.8'

services:
  stride-gpt:
    image: stride-gpt:latest
    networks:
      - frontend

  mcp-cve-search:
    image: cve-search-mcp:latest
    networks:
      - mcp-isolated
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

  mcp-proxy:
    image: mcp-security-proxy:latest
    networks:
      - frontend
      - mcp-isolated
    # Proxy filters and validates all MCP requests

networks:
  frontend:
  mcp-isolated:
    internal: true
```

#### 2. Input Validation

```python
import re
from typing import Any

def validate_mcp_tool_call(tool_name: str, arguments: dict) -> bool:
    """Validate MCP tool calls before execution"""

    # Whitelist allowed tools
    ALLOWED_TOOLS = [
        'search_cve',
        'get_cve_by_id',
        'query_owasp_top10',
        'lookup_cwe'
    ]

    if tool_name not in ALLOWED_TOOLS:
        raise ValueError(f"Tool '{tool_name}' not in whitelist")

    # Validate arguments
    for key, value in arguments.items():
        # Prevent command injection
        if isinstance(value, str):
            if re.search(r'[;&|`$()]', value):
                raise ValueError(f"Suspicious characters in argument: {key}")

            # Limit length
            if len(value) > 500:
                raise ValueError(f"Argument too long: {key}")

    return True

# Wrap MCP tools with validation
def create_secure_mcp_tool(mcp_tool):
    """Wrap MCP tool with security checks"""

    async def secure_wrapper(*args, **kwargs):
        # Validate before execution
        validate_mcp_tool_call(mcp_tool.name, kwargs)

        # Execute with timeout
        try:
            result = await asyncio.wait_for(
                mcp_tool.ainvoke(*args, **kwargs),
                timeout=30.0  # 30 second timeout
            )
            return result
        except asyncio.TimeoutError:
            return {"error": "Tool execution timeout"}

    return secure_wrapper
```

#### 3. Rate Limiting

```python
from collections import defaultdict
from datetime import datetime, timedelta
import asyncio

class MCPRateLimiter:
    """Rate limit MCP tool calls to prevent abuse"""

    def __init__(self, max_calls_per_minute=10):
        self.max_calls = max_calls_per_minute
        self.calls = defaultdict(list)

    async def check_rate_limit(self, tool_name: str) -> bool:
        """Check if tool call is within rate limit"""

        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)

        # Remove old calls
        self.calls[tool_name] = [
            call_time for call_time in self.calls[tool_name]
            if call_time > minute_ago
        ]

        # Check limit
        if len(self.calls[tool_name]) >= self.max_calls:
            wait_time = (self.calls[tool_name][0] - minute_ago).total_seconds()
            raise Exception(f"Rate limit exceeded. Wait {wait_time:.1f}s")

        # Record call
        self.calls[tool_name].append(now)
        return True

# Use in agent
rate_limiter = MCPRateLimiter(max_calls_per_minute=10)

async def safe_call_mcp_tool(tool, **kwargs):
    """Call MCP tool with rate limiting"""
    await rate_limiter.check_rate_limit(tool.name)
    return await tool.ainvoke(**kwargs)
```

#### 4. Authentication & Authorization

```python
import os
import hashlib
import hmac

class MCPAuthManager:
    """Manage authentication for MCP servers"""

    def __init__(self):
        self.api_keys = {
            'cve-search': os.getenv('CVE_SEARCH_API_KEY'),
            'shodan': os.getenv('SHODAN_API_KEY'),
            'owasp': os.getenv('OWASP_API_KEY')
        }

    def configure_server_with_auth(self, server_name: str, config: dict) -> dict:
        """Add authentication to MCP server config"""

        api_key = self.api_keys.get(server_name)

        if api_key:
            config['env'] = config.get('env', {})
            config['env']['API_KEY'] = api_key

            # Add HMAC signature if required
            if config.get('requires_signature'):
                config['env']['API_SIGNATURE'] = self.generate_signature(
                    server_name,
                    api_key
                )

        return config

    def generate_signature(self, server_name: str, api_key: str) -> str:
        """Generate HMAC signature for authenticated requests"""
        message = f"{server_name}:{datetime.now().isoformat()}"
        signature = hmac.new(
            api_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
```

#### 5. Audit Logging

```python
import logging
import json

class MCPAuditLogger:
    """Audit log all MCP tool calls"""

    def __init__(self, log_file='mcp_audit.log'):
        self.logger = logging.getLogger('mcp_audit')
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log_tool_call(self, tool_name: str, arguments: dict, result: Any, user_id: str = None):
        """Log MCP tool call details"""

        log_entry = {
            'event': 'mcp_tool_call',
            'tool': tool_name,
            'arguments': self.sanitize_args(arguments),
            'result_size': len(str(result)),
            'user': user_id,
            'timestamp': datetime.now().isoformat()
        }

        self.logger.info(json.dumps(log_entry))

    def sanitize_args(self, args: dict) -> dict:
        """Remove sensitive data from logs"""
        sanitized = args.copy()
        for key in ['api_key', 'token', 'password', 'secret']:
            if key in sanitized:
                sanitized[key] = '***REDACTED***'
        return sanitized

# Use in agent
audit_logger = MCPAuditLogger()

async def audited_mcp_call(tool, user_id, **kwargs):
    """Call MCP tool with audit logging"""
    result = await tool.ainvoke(**kwargs)
    audit_logger.log_tool_call(tool.name, kwargs, result, user_id)
    return result
```

---

## Creating Custom MCP Servers

### Example: OWASP MCP Server

Create a custom MCP server for OWASP references:

```python
# owasp_mcp_server.py

from mcp.server import Server
from mcp.types import Tool, TextContent
import httpx

app = Server("owasp-mcp-server")

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available OWASP tools"""
    return [
        Tool(
            name="get_owasp_top10",
            description="Get OWASP Top 10 vulnerability category details",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "OWASP category (e.g., 'A01:2021-Broken Access Control')"
                    },
                    "year": {
                        "type": "integer",
                        "description": "Year (2017, 2021, etc.)",
                        "default": 2021
                    }
                },
                "required": ["category"]
            }
        ),
        Tool(
            name="get_cwe_details",
            description="Get Common Weakness Enumeration (CWE) details",
            inputSchema={
                "type": "object",
                "properties": {
                    "cwe_id": {
                        "type": "string",
                        "description": "CWE ID (e.g., 'CWE-79')"
                    }
                },
                "required": ["cwe_id"]
            }
        ),
        Tool(
            name="search_asvs_requirements",
            description="Search OWASP Application Security Verification Standard (ASVS) requirements",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "ASVS category (e.g., 'Authentication', 'Session Management')"
                    },
                    "level": {
                        "type": "integer",
                        "description": "ASVS level (1, 2, or 3)",
                        "default": 2
                    }
                },
                "required": ["category"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls"""

    if name == "get_owasp_top10":
        return await get_owasp_top10_impl(
            arguments['category'],
            arguments.get('year', 2021)
        )

    elif name == "get_cwe_details":
        return await get_cwe_details_impl(arguments['cwe_id'])

    elif name == "search_asvs_requirements":
        return await search_asvs_impl(
            arguments['category'],
            arguments.get('level', 2)
        )

    raise ValueError(f"Unknown tool: {name}")

# Implementation functions
async def get_owasp_top10_impl(category: str, year: int) -> list[TextContent]:
    """Fetch OWASP Top 10 data"""

    # Static data (could be fetched from OWASP API if available)
    owasp_data = {
        "A01:2021-Broken Access Control": {
            "description": "Restrictions on what authenticated users are allowed to do are often not properly enforced.",
            "impact": "Attackers can access unauthorized functionality and/or data.",
            "examples": [
                "Accessing API with missing access controls",
                "Viewing or editing someone else's account",
                "Acting as a user without being logged in",
                "Elevation of privilege"
            ],
            "prevention": [
                "Deny by default",
                "Implement access control mechanisms once and reuse",
                "Enforce record ownership",
                "Disable web server directory listing",
                "Log access control failures, alert admins"
            ],
            "cwe_mappings": ["CWE-22", "CWE-284", "CWE-285", "CWE-639"]
        }
        # Add more categories...
    }

    data = owasp_data.get(category, {
        "error": f"Category '{category}' not found in OWASP Top 10 {year}"
    })

    return [TextContent(
        type="text",
        text=json.dumps(data, indent=2)
    )]

async def get_cwe_details_impl(cwe_id: str) -> list[TextContent]:
    """Fetch CWE details from MITRE"""

    async with httpx.AsyncClient() as client:
        # MITRE CWE API (if available, or use scraped data)
        response = await client.get(
            f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html"
        )

        # Parse and return structured data
        # (Implementation would parse HTML or use API)

        return [TextContent(
            type="text",
            text=f"CWE details for {cwe_id}"
        )]

async def search_asvs_impl(category: str, level: int) -> list[TextContent]:
    """Search ASVS requirements"""

    # Static ASVS data
    asvs_data = {
        "Authentication": {
            "V2.1": "Password Security",
            "V2.2": "General Authenticator Security",
            "V2.3": "Authenticator Lifecycle",
            # ... more requirements
        }
        # Add more categories
    }

    results = asvs_data.get(category, {})

    return [TextContent(
        type="text",
        text=json.dumps(results, indent=2)
    )]

# Run server
if __name__ == "__main__":
    import mcp.server.stdio
    mcp.server.stdio.stdio_server(app)
```

**Package as MCP Server:**

```json
// package.json
{
  "name": "owasp-mcp-server",
  "version": "1.0.0",
  "type": "module",
  "bin": {
    "owasp-mcp-server": "./dist/index.js"
  },
  "scripts": {
    "build": "python -m mcp.server.build owasp_mcp_server.py"
  },
  "dependencies": {
    "mcp": "^0.9.0"
  }
}
```

**Use in LangGraph:**

```python
async with MCPClient.stdio_client(
    command="python",
    args=["owasp_mcp_server.py"]
) as client:
    await client.initialize()
    owasp_tools = client.get_tools()
    # Use tools in agent...
```

---

## Deployment Configuration

### Environment Variables

```bash
# .env

# MCP Server Configuration
MCP_CVE_SEARCH_ENABLED=true
MCP_SHODAN_ENABLED=true
MCP_SHODAN_API_KEY=your-shodan-key
MCP_OWASP_ENABLED=true

# Security Settings
MCP_MAX_CALLS_PER_MINUTE=10
MCP_TOOL_TIMEOUT_SECONDS=30
MCP_ENABLE_AUDIT_LOG=true
MCP_AUDIT_LOG_PATH=/var/log/stride-gpt/mcp_audit.log

# Server Isolation
MCP_USE_DOCKER_ISOLATION=true
MCP_NETWORK_MODE=isolated
```

### Streamlit Configuration

```python
# config.py

import os
from typing import Dict

def get_mcp_server_config() -> Dict:
    """Get MCP server configuration from environment"""

    config = {}

    # CVE-Search
    if os.getenv('MCP_CVE_SEARCH_ENABLED', 'false').lower() == 'true':
        config['cve-search'] = {
            'transport': 'stdio',
            'command': 'npx',
            'args': ['-y', 'cve-search-mcp-server']
        }

    # Shodan
    if os.getenv('MCP_SHODAN_ENABLED', 'false').lower() == 'true':
        shodan_key = os.getenv('MCP_SHODAN_API_KEY')
        if shodan_key:
            config['shodan'] = {
                'transport': 'stdio',
                'command': 'node',
                'args': ['path/to/shodan-mcp/dist/index.js'],
                'env': {'SHODAN_API_KEY': shodan_key}
            }

    # OWASP (custom)
    if os.getenv('MCP_OWASP_ENABLED', 'false').lower() == 'true':
        config['owasp'] = {
            'transport': 'stdio',
            'command': 'python',
            'args': ['owasp_mcp_server.py']
        }

    return config
```

### Streamlit UI Integration

```python
# main.py

import streamlit as st
import asyncio
from config import get_mcp_server_config
from langgraph_mcp_integration import create_stride_gpt_workflow_with_mcp

st.title("STRIDE GPT - Autonomous Threat Modeling")

# Sidebar configuration
with st.sidebar:
    st.header("Analysis Configuration")

    analysis_mode = st.radio(
        "Mode",
        options=["Standard", "Autonomous (MCP-Enhanced)"],
        help="Autonomous mode uses MCP servers for real-time threat intelligence"
    )

    if analysis_mode == "Autonomous (MCP-Enhanced)":
        st.subheader("🔌 MCP Intelligence Sources")

        # Get available MCP servers
        mcp_config = get_mcp_server_config()

        for server_name in mcp_config.keys():
            st.checkbox(
                server_name.replace('-', ' ').title(),
                value=True,
                key=f"mcp_{server_name}",
                help=f"Enable {server_name} MCP server"
            )

# Main interface
if analysis_mode == "Autonomous (MCP-Enhanced)":
    st.info("🔍 Autonomous mode uses real-time threat intelligence from CVE databases, Shodan, and OWASP")

    app_description = st.text_area("Application Description", height=150)
    app_type = st.selectbox("Application Type", ["Web application", "Mobile app", "API", "Desktop application"])

    if st.button("🚀 Run Autonomous Analysis with MCP"):
        with st.spinner("Initializing MCP servers..."):
            # Filter enabled servers
            enabled_servers = {
                name: config for name, config in mcp_config.items()
                if st.session_state.get(f"mcp_{name}", True)
            }

            st.info(f"Connected to {len(enabled_servers)} MCP servers")

        with st.spinner("Orchestrating AI agents..."):
            # Run async workflow
            async def run_analysis():
                workflow = await create_stride_gpt_workflow_with_mcp()
                result = await workflow.ainvoke({
                    'app_description': app_description,
                    'app_type': app_type,
                    # ... other fields
                })
                return result

            result = asyncio.run(run_analysis())

        # Display results
        st.success("✅ Analysis complete!")

        tab1, tab2, tab3, tab4 = st.tabs([
            "Threat Model",
            "CVE Intelligence",
            "OWASP References",
            "Mitigations"
        ])

        with tab1:
            st.json(result.get('threat_model'))

        with tab2:
            st.subheader("Real CVE Data")
            cve_findings = result.get('cve_findings', [])
            for cve in cve_findings:
                with st.expander(f"🔴 {cve['id']}"):
                    st.write(cve.get('description', 'No description available'))
                    st.write(f"**Severity:** {cve.get('severity', 'Unknown')}")
                    if 'link' in cve:
                        st.link_button("View CVE Details", cve['link'])

        with tab3:
            st.subheader("OWASP Top 10 References")
            owasp_refs = result.get('owasp_references', [])
            for ref in owasp_refs:
                st.info(ref)

        with tab4:
            st.json(result.get('mitigations'))
```

---

## Performance Optimization

### 1. Parallel MCP Server Initialization

```python
import asyncio

async def initialize_mcp_servers_parallel(server_configs: dict):
    """Initialize multiple MCP servers in parallel"""

    async def init_server(name, config):
        client = MCPClient.from_config(config)
        await client.initialize()
        return name, client

    # Create initialization tasks
    tasks = [
        init_server(name, config)
        for name, config in server_configs.items()
    ]

    # Run in parallel
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter successful initializations
    clients = {}
    for result in results:
        if isinstance(result, Exception):
            print(f"Failed to initialize server: {result}")
        else:
            name, client = result
            clients[name] = client

    return clients
```

### 2. Caching MCP Results

```python
from functools import lru_cache
import hashlib
import pickle

class MCPResultCache:
    """Cache MCP tool results to reduce API calls"""

    def __init__(self, cache_file='mcp_cache.pkl'):
        self.cache_file = cache_file
        self.cache = self.load_cache()

    def load_cache(self):
        try:
            with open(self.cache_file, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            return {}

    def save_cache(self):
        with open(self.cache_file, 'wb') as f:
            pickle.dump(self.cache, f)

    def get_cache_key(self, tool_name: str, arguments: dict) -> str:
        """Generate cache key from tool call"""
        key_data = f"{tool_name}:{sorted(arguments.items())}"
        return hashlib.md5(key_data.encode()).hexdigest()

    async def get_or_call(self, tool, **kwargs):
        """Get cached result or call MCP tool"""
        cache_key = self.get_cache_key(tool.name, kwargs)

        if cache_key in self.cache:
            print(f"Cache hit for {tool.name}")
            return self.cache[cache_key]

        # Call tool
        result = await tool.ainvoke(**kwargs)

        # Cache result
        self.cache[cache_key] = result
        self.save_cache()

        return result

# Use in agent
cache = MCPResultCache()

async def cached_mcp_call(tool, **kwargs):
    """Call MCP tool with caching"""
    return await cache.get_or_call(tool, **kwargs)
```

---

## Testing

### Unit Tests

```python
# tests/test_mcp_integration.py

import pytest
from unittest.mock import Mock, AsyncMock
from langgraph_mcp_integration import create_research_agent_node

@pytest.mark.asyncio
async def test_mcp_tool_loading():
    """Test that MCP tools are loaded correctly"""

    mock_client = Mock()
    mock_client.get_tools.return_value = [
        Mock(name='search_cve', description='Search CVE database'),
        Mock(name='get_owasp_top10', description='Get OWASP Top 10')
    ]

    async with mock_client:
        tools = mock_client.get_tools()

    assert len(tools) == 2
    assert any(t.name == 'search_cve' for t in tools)

@pytest.mark.asyncio
async def test_research_agent_with_mcp():
    """Test research agent using MCP tools"""

    # Mock MCP server
    mock_servers = {
        'cve-search': {
            'transport': 'stdio',
            'command': 'echo',
            'args': ['mock']
        }
    }

    research_node = await create_research_agent_node(mock_servers)

    state = {
        'app_description': 'Test web app',
        'app_type': 'Web application',
        'authentication': ['OAuth'],
        'internet_facing': True,
        'sensitive_data': 'User data'
    }

    result = await research_node(state)

    assert 'cve_findings' in result
    assert 'messages' in result

@pytest.mark.asyncio
async def test_mcp_security_validation():
    """Test MCP tool call validation"""

    from langgraph_mcp_integration import validate_mcp_tool_call

    # Valid call
    assert validate_mcp_tool_call('search_cve', {'keyword': 'SQL injection'})

    # Invalid tool
    with pytest.raises(ValueError):
        validate_mcp_tool_call('rm_rf', {})

    # Command injection attempt
    with pytest.raises(ValueError):
        validate_mcp_tool_call('search_cve', {'keyword': 'test; rm -rf /'})
```

---

## Conclusion

Integrating MCP servers with LangGraph provides STRIDE GPT with:

✅ **Modular intelligence sources** - Easily add/remove threat intelligence providers
✅ **Real-time data** - Live CVE lookups, not static databases
✅ **Community ecosystem** - Leverage hundreds of existing MCP servers
✅ **Standardized protocol** - Future-proof architecture
✅ **Security isolation** - Proper hardening mitigates MCP vulnerabilities

**Next Steps:**
1. Install `langchain-mcp-adapters` and test with CVE-Search MCP server
2. Create OWASP custom MCP server
3. Implement security hardening (validation, rate limiting, isolation)
4. Add MCP configuration to Streamlit UI
5. Test with real threat modeling scenarios

**Resources:**
- LangGraph MCP Docs: https://langchain-ai.github.io/langgraph/agents/mcp/
- MCP Official Servers: https://github.com/modelcontextprotocol/servers
- CVE-Search MCP: https://github.com/roadwy/cve-search_mcp
- Awesome MCP Servers: https://github.com/wong2/awesome-mcp-servers
- MCP Security Guide: https://github.com/Puliczek/awesome-mcp-security

---

**Document Version:** 1.0
**Author:** Claude (Anthropic)
**Date:** 2025-10-29
**Status:** Implementation Ready
