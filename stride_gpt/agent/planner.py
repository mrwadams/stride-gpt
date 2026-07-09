"""Analysis planning — scan a codebase and propose subsystems for STRIDE analysis."""

from __future__ import annotations

import json
from pathlib import Path

from stride_gpt.agent.tools import list_directory, search_files
from stride_gpt.core.json_extract import extract_json_object
from stride_gpt.core.llm import call_llm
from stride_gpt.core.schemas import AnalysisPlan, LLMConfig, Subsystem

# File patterns that signal interesting subsystems
KEY_PATTERNS = [
    "*.py", "*.js", "*.ts", "*.tsx", "*.go", "*.java", "*.rs", "*.rb", "*.cs",
    "Dockerfile", "docker-compose*", "*.tf", "*.yaml", "*.yml",
    "*.toml", "*.json", "*.env*", "Makefile", "*.sh",
    "go.mod", "package.json", "requirements.txt", "Cargo.toml", "pom.xml",
    "*.proto", "*.graphql", "*.sql",
]

PLANNER_SYSTEM_PROMPT = """You are a security architect planning a STRIDE threat model analysis of a codebase.

Based on the file structure and key files provided, identify 3-7 logical subsystems to analyze for security threats. Each subsystem should represent a distinct area of functionality or infrastructure.

Good subsystem examples:
- "Authentication & Authorization" — login flows, session management, RBAC
- "API Layer" — REST/GraphQL endpoints, request validation, rate limiting
- "Data Storage" — database access, ORM models, migrations, data at rest
- "External Integrations" — third-party APIs, webhooks, message queues
- "Infrastructure" — Dockerfiles, CI/CD, Terraform, deployment configs
- "Frontend" — client-side code, input handling, state management

You must also classify the overall application type so the downstream STRIDE agent knows which OWASP reference cards apply. Choose exactly one of:

- "web" — a traditional web/CRUD/data/infra application with no LLM-driven behaviour
- "genai" — uses LLMs as a meaningful part of the application (LLM SDKs like openai/anthropic/mistralai/google-generativeai, RAG pipelines, embeddings, LLM-powered endpoints) but does NOT run autonomous agents
- "agentic" — uses agent frameworks (langchain/langgraph, crewai, autogen, pydantic-ai, smolagents, llama-index agents) OR implements a tool-use / function-calling loop OR coordinates multiple agents OR persists agent memory across sessions

Only classify as "genai" or "agentic" when the LLM/agent behaviour is core to the application's purpose — a one-off util script that calls an LLM does not promote the whole codebase. When in doubt, prefer the simpler classification.

Respond with a JSON object:
{
    "detected_app_type": "web|genai|agentic",
    "overall_description": "Brief description of the overall application architecture",
    "subsystems": [
        {
            "name": "Subsystem Name",
            "description": "What this subsystem does and why it matters for security",
            "key_files": ["path/to/relevant/file.py", "path/to/other.py"],
            "focus_areas": ["Authentication bypass", "Input validation", "etc."]
        }
    ]
}

Be specific about which files to examine. Prioritize subsystems that handle:
1. Authentication and authorization
2. Data input and validation
3. Sensitive data handling
4. External communication
5. Infrastructure and deployment"""


def create_plan(config: LLMConfig, target_path: Path) -> AnalysisPlan:
    """Scan a codebase and generate an analysis plan via LLM."""
    # Gather codebase structure
    dir_listing = list_directory(target_path, ".")
    key_files: list[str] = []
    for pattern in KEY_PATTERNS:
        results = json.loads(search_files(target_path, pattern))
        key_files.extend(r for r in results if isinstance(r, str))

    # Deduplicate and sort
    key_files = sorted(set(key_files))

    discovery_prompt = f"""Analyze this codebase structure and identify subsystems for STRIDE threat modeling.

## Directory Structure
{dir_listing}

## Key Files Found ({len(key_files)} files)
{chr(10).join(key_files[:200])}"""

    json_config = config.model_copy(update={"response_format": AnalysisPlan.model_json_schema()})
    messages = [
        {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
        {"role": "user", "content": discovery_prompt},
    ]
    response = call_llm(json_config, messages)

    data = extract_json_object(response.content)

    # Retry once with explicit JSON-only instruction if first attempt failed
    if data is None:
        retry_messages = [*messages, {"role": "assistant", "content": response.content}, {"role": "user", "content": "Your previous response was not valid JSON. Respond with ONLY a " "valid JSON object matching the schema in your instructions. " "No prose, no markdown fences, no commentary."}]
        retry_response = call_llm(json_config, retry_messages)
        data = extract_json_object(retry_response.content)

    if data is None:
        # Stash the raw response for debugging
        raw = (response.content or "")[:500].replace("\n", " ")
        return AnalysisPlan(
            target_path=str(target_path),
            overall_description=(
                f"Unable to parse plan — analyzing entire codebase as one unit. "
                f"Raw response started with: {raw!r}"
            ),
            subsystems=[
                Subsystem(
                    name="Full Codebase",
                    description="Analyze the entire codebase for STRIDE threats.",
                    key_files=[],
                    focus_areas=["All STRIDE categories"],
                )
            ],
        )

    return _build_plan(data, str(target_path))


def _build_plan(data: dict, target_path: str) -> AnalysisPlan:
    """Build an AnalysisPlan from a parsed dict."""
    from stride_gpt.core.prompts.variants import coerce_app_type

    subsystems = [
        Subsystem(
            name=s.get("name", "Unnamed"),
            description=s.get("description", ""),
            key_files=s.get("key_files", []),
            focus_areas=s.get("focus_areas", []),
        )
        for s in data.get("subsystems", [])
        if isinstance(s, dict)
    ]

    return AnalysisPlan(
        target_path=target_path,
        overall_description=data.get("overall_description", ""),
        detected_app_type=coerce_app_type(data.get("detected_app_type")),
        subsystems=subsystems or [
            Subsystem(
                name="Full Codebase",
                description="No subsystems identified.",
                key_files=[],
                focus_areas=["All STRIDE categories"],
            )
        ],
    )


_APP_TYPE_LABELS = {
    "web": "Web application",
    "genai": "Generative AI application",
    "agentic": "Agentic AI application",
}


def format_plan_for_display(plan: AnalysisPlan) -> str:
    """Format an analysis plan as a readable string."""
    type_label = _APP_TYPE_LABELS.get(plan.detected_app_type, plan.detected_app_type)
    lines = [
        f"Target: {plan.target_path}",
        f"Detected type: {type_label}",
        f"Overview: {plan.overall_description}",
        "",
        f"Subsystems ({len(plan.subsystems)}):",
    ]
    for i, sub in enumerate(plan.subsystems, 1):
        lines.append(f"  {i}. {sub.name}")
        lines.append(f"     {sub.description}")
        if sub.key_files:
            lines.append(f"     Files: {', '.join(sub.key_files[:5])}")
            if len(sub.key_files) > 5:
                lines.append(f"            ... and {len(sub.key_files) - 5} more")
        if sub.focus_areas:
            lines.append(f"     Focus: {', '.join(sub.focus_areas)}")
        lines.append("")
    return "\n".join(lines)
