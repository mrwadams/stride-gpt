"""Analysis planning — scan a codebase and propose subsystems for STRIDE analysis."""

from __future__ import annotations

import fnmatch
import os
from collections import deque
from pathlib import Path

from stride_gpt.agent.tools import SKIP_DIRS, list_directory
from stride_gpt.core.json_extract import extract_json_object
from stride_gpt.core.llm import call_llm
from stride_gpt.core.schemas import AnalysisPlan, LLMConfig, Subsystem, TokenUsage

# File patterns that signal interesting subsystems
KEY_PATTERNS = [
    "*.py", "*.js", "*.ts", "*.tsx", "*.go", "*.java", "*.rs", "*.rb", "*.cs",
    "Dockerfile", "docker-compose*", "*.tf", "*.yaml", "*.yml",
    "*.toml", "*.json", "*.env*", "Makefile", "*.sh",
    "go.mod", "package.json", "requirements.txt", "Cargo.toml", "pom.xml",
    "*.proto", "*.graphql", "*.sql",
]

# Cap on how many of the discovered key files get shown to the planner LLM.
KEY_FILE_SAMPLE_LIMIT = 200

PLANNER_SYSTEM_PROMPT = """You are a security architect planning a STRIDE threat model analysis of a codebase.

Based on the file structure and key files provided, identify up to 7 subsystems to analyze for security threats. A subsystem is a deployable unit or a trust boundary: a service, a background worker, a frontend, a data store, or the deployment configuration. It is not a security concern. Authentication, input validation and secret handling are concerns that most services have, so list them as focus areas of the subsystem whose code implements them, not as subsystems of their own.

Each subsystem is analyzed separately, so give each file to exactly one subsystem. If two subsystems would list the same file, they are one subsystem. A small codebase with one service may have only one or two subsystems. A service too large to review in one pass, such as one with dozens of route or handler modules, can be split by module or directory (for example, groups of routes), as long as each file still goes to one subsystem.

Tests, test fixtures and developer tooling are not subsystems unless they ship or run in production.

Good subsystem examples:
- "Public API service" — the web process: routes, request validation, and the login and session code it calls
- "Background worker" — job consumers, schedulers, and what they do with queued data
- "Web frontend" — client-side code, input handling, state management
- "Data store" — schema, migrations, and data access code shared by several services
- "Third-party integration client" — outbound calls to external APIs, webhooks
- "Infrastructure & deployment" — Dockerfiles, CI/CD, Terraform, deployment configs

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

Be specific about which files to examine. In each subsystem's focus areas, cover the concerns its code handles:
1. Authentication and authorization
2. Data input and validation
3. Sensitive data handling
4. External communication
5. Infrastructure and deployment"""


def _discover_key_files(target_path: Path) -> list[str]:
    """Every file under ``target_path`` matching ``KEY_PATTERNS``, sorted.

    Walks the tree itself rather than calling ``search_files``, which stops
    at 50 matches per pattern in walk order: on OWASP Juice Shop the first
    50 ``*.ts`` files were all frontend, so the planner never saw the backend
    routes. ``_diverse_key_files`` caps what reaches the prompt.
    """
    root = target_path.resolve()
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        found.extend(
            str((Path(dirpath) / filename).relative_to(root))
            for filename in filenames
            if any(fnmatch.fnmatch(filename, pattern) for pattern in KEY_PATTERNS)
        )
    return sorted(found)


def _tree_round_robin(files: list[str]) -> list[str]:
    """Interleave ``files`` fairly across every level of their directory tree.

    A flat alphabetical slice privileges early-sorting directories and can
    drop a whole subsystem's files past a later cutoff (issue #175: on
    OWASP crAPI, ``services/web`` and ``services/workshop`` sorted last and
    received zero file-level signal). A single round-robin pass over leaf
    directories fixes that but starves a subsystem with many nested leaf
    directories, because the first pass through them consumes the whole
    budget before a sibling subsystem's leaf directories are ever reached.
    Grouping by a fixed depth (the first one or two path components) before
    round-robining just relocates the same failure to whatever depth the
    real subsystem boundary happens not to be at (issue #178 review: 250
    directories nested under ``web/pkg*`` still starved a flat sibling
    ``workshop/`` directory, one level up from the original report).

    Round-robin the whole path tree recursively instead: at each directory
    level, give every child (a subdirectory, or the files sitting directly
    in this directory) one turn before any child gets a second, and recurse
    into a child's own children only once it is that child's turn. This
    bounds the group count that must all get a turn in the same pass to the
    branching factor at that level, at any depth, rather than to the total
    number of leaf directories.
    """
    root: dict = {}
    for f in files:
        node = root
        for part in Path(f).parts[:-1]:
            node = node.setdefault(part, {})
        node.setdefault(None, []).append(f)

    def walk(node: dict) -> list[str]:
        streams: deque[deque[str]] = deque()
        if None in node:
            streams.append(deque(sorted(node[None])))
        for name in sorted(k for k in node if k is not None):
            streams.append(deque(walk(node[name])))
        result: list[str] = []
        while any(streams):
            result.extend(s.popleft() for s in streams if s)
        return result

    return walk(root)


def _diverse_key_files(files: list[str], limit: int) -> list[str]:
    """Cap ``files`` at ``limit`` while representing every directory, at any depth."""
    if len(files) <= limit:
        return files
    return sorted(_tree_round_robin(files)[:limit])


def create_plan(
    config: LLMConfig, target_path: Path, *, usage: TokenUsage | None = None
) -> AnalysisPlan:
    """Scan a codebase and generate an analysis plan via LLM."""
    # Gather codebase structure
    dir_listing = list_directory(target_path, ".")
    key_files = _discover_key_files(target_path)
    key_files_shown = _diverse_key_files(key_files, KEY_FILE_SAMPLE_LIMIT)

    if len(key_files_shown) < len(key_files):
        key_files_heading = (
            f"## Key Files Found ({len(key_files)} files, "
            f"showing a {len(key_files_shown)}-file sample across all directories)"
        )
    else:
        key_files_heading = f"## Key Files Found ({len(key_files)} files)"

    discovery_prompt = f"""Analyze this codebase structure and identify subsystems for STRIDE threat modeling.

## Directory Structure
{dir_listing}

{key_files_heading}
{chr(10).join(key_files_shown)}"""

    json_config = config.model_copy(update={"response_format": AnalysisPlan.model_json_schema()})
    messages = [
        {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
        {"role": "user", "content": discovery_prompt},
    ]
    response = call_llm(json_config, messages)
    if usage is not None:
        usage.record(response)

    data = extract_json_object(response.content)

    # Retry once with explicit JSON-only instruction if first attempt failed
    if data is None:
        retry_messages = [*messages, {"role": "assistant", "content": response.content}, {"role": "user", "content": "Your previous response was not valid JSON. Respond with ONLY a " "valid JSON object matching the schema in your instructions. " "No prose, no markdown fences, no commentary."}]
        retry_response = call_llm(json_config, retry_messages)
        if usage is not None:
            usage.record(retry_response)
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
