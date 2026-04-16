"""Analysis planning — scan a codebase and propose subsystems for STRIDE analysis."""

from __future__ import annotations

import json
from pathlib import Path

from stride_gpt.agent.tools import list_directory, search_files
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

Respond with a JSON object:
{
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

    data = _extract_plan_json(response.content)

    # Retry once with explicit JSON-only instruction if first attempt failed
    if data is None:
        retry_messages = messages + [
            {"role": "assistant", "content": response.content},
            {
                "role": "user",
                "content": (
                    "Your previous response was not valid JSON. Respond with ONLY a "
                    "valid JSON object matching the schema in your instructions. "
                    "No prose, no markdown fences, no commentary."
                ),
            },
        ]
        retry_response = call_llm(json_config, retry_messages)
        data = _extract_plan_json(retry_response.content)

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


def _extract_plan_json(content: str) -> dict | None:
    """Extract a JSON object from an LLM response, robust to extra text/fences.

    Returns the parsed dict or None if no valid JSON object can be found.
    """
    if not content:
        return None

    cleaned = content.strip()

    # Strip markdown code fences if present
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

    # Try parsing as-is first
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    # Fallback: find embedded JSON object via first { to last }
    start = content.find("{")
    end = content.rfind("}")
    if start != -1 and end > start:
        try:
            data = json.loads(content[start : end + 1])
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    return None


def _build_plan(data: dict, target_path: str) -> AnalysisPlan:
    """Build an AnalysisPlan from a parsed dict."""
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
        subsystems=subsystems or [
            Subsystem(
                name="Full Codebase",
                description="No subsystems identified.",
                key_files=[],
                focus_areas=["All STRIDE categories"],
            )
        ],
    )


def format_plan_for_display(plan: AnalysisPlan) -> str:
    """Format an analysis plan as a readable string."""
    lines = [
        f"Target: {plan.target_path}",
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
