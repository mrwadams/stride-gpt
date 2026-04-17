# main.py

import base64
import json
import os
import re
from collections import defaultdict
from urllib.parse import urlparse

import requests
import streamlit as st
import streamlit.components.v1 as components
import tiktoken
from dotenv import load_dotenv
from github import Github
from openai import OpenAI

from attack_tree import (
    create_attack_tree_prompt,
    get_attack_tree,
    get_attack_tree_anthropic,
    get_attack_tree_google,
    get_attack_tree_groq,
    get_attack_tree_lm_studio,
    get_attack_tree_mistral,
)
from dread import (
    create_dread_assessment_prompt,
    dread_json_to_markdown,
    get_dread_assessment,
    get_dread_assessment_anthropic,
    get_dread_assessment_google,
    get_dread_assessment_groq,
    get_dread_assessment_lm_studio,
    get_dread_assessment_mistral,
)
from mitigations import (
    create_mitigations_prompt,
    get_mitigations,
    get_mitigations_anthropic,
    get_mitigations_google,
    get_mitigations_groq,
    get_mitigations_lm_studio,
    get_mitigations_mistral,
)
from test_cases import (
    create_test_cases_prompt,
    get_test_cases,
    get_test_cases_anthropic,
    get_test_cases_google,
    get_test_cases_groq,
    get_test_cases_lm_studio,
    get_test_cases_mistral,
)
from threat_model import (
    create_image_analysis_prompt,
    create_threat_model_prompt,
    get_image_analysis,
    get_image_analysis_anthropic,
    get_image_analysis_google,
    get_threat_model,
    get_threat_model_anthropic,
    get_threat_model_google,
    get_threat_model_groq,
    get_threat_model_lm_studio,
    get_threat_model_mistral,
    json_to_markdown,
)

# ------------------ Helper Functions ------------------ #

GUIDED_DESCRIPTION_FIELDS = [
    {
        "key": "guided_purpose",
        "label": "1) What does this application do and what are the core user actions?",
        "placeholder": "Example: Customers upload invoices, approvers review them, finance exports payments.",
    },
    {
        "key": "guided_users",
        "label": "2) Who are the primary users and what access levels do they have?",
        "placeholder": "Example: End users, support admins, finance admins, service accounts.",
    },
    {
        "key": "guided_components",
        "label": "3) What are the key components and technologies?",
        "placeholder": "Example: React frontend, FastAPI backend, PostgreSQL, Redis, S3.",
    },
    {
        "key": "guided_data",
        "label": "4) What sensitive data is processed or stored?",
        "placeholder": "Example: PII, payment details, API tokens, uploaded files.",
    },
    {
        "key": "guided_flows",
        "label": "5) How does data flow through the system?",
        "placeholder": "Example: Browser -> API -> queue -> worker -> database -> analytics system.",
    },
    {
        "key": "guided_integrations",
        "label": "6) Which external systems or third-party services are integrated?",
        "placeholder": "Example: Okta, Stripe, GitHub, Slack, cloud object storage.",
    },
    {
        "key": "guided_auth",
        "label": "7) How are authentication and authorization handled?",
        "placeholder": "Example: SSO with MFA, RBAC roles, scoped API tokens.",
    },
    {
        "key": "guided_trust_boundaries",
        "label": "8) What trust boundaries or internet-facing entry points exist?",
        "placeholder": "Example: Public API gateway, admin portal, private VPC services.",
    },
    {
        "key": "guided_deployment",
        "label": "9) Where is the application deployed and operated?",
        "placeholder": "Example: AWS ECS in two regions, managed PostgreSQL, private subnets.",
    },
    {
        "key": "guided_controls",
        "label": "10) What security controls already exist?",
        "placeholder": "Example: WAF, rate limits, encryption, audit logging, secrets manager.",
    },
]

GUIDED_REQUIRED_FIELD_KEYS = [
    "guided_purpose",
    "guided_components",
    "guided_data",
    "guided_flows",
    "guided_auth",
    "guided_trust_boundaries",
]


def build_guided_description_draft():
    """Build a structured application description from guided inputs."""

    def clean(value):
        stripped = value.strip()
        return stripped if stripped else "Not provided yet."

    lines = [
        "Guided Application Description Draft",
        "",
        f"Application Type: {st.session_state.get('app_type', 'Web application')}",
        "",
        "Application Overview",
        f"- Purpose and core user actions: {clean(st.session_state.get('guided_purpose', ''))}",
        f"- User types and access levels: {clean(st.session_state.get('guided_users', ''))}",
        "",
        "Architecture and Data Flows",
        f"- Key components and technologies: {clean(st.session_state.get('guided_components', ''))}",
        f"- Sensitive data handled: {clean(st.session_state.get('guided_data', ''))}",
        f"- Data flow summary: {clean(st.session_state.get('guided_flows', ''))}",
        "",
        "Security Context",
        f"- Authentication and authorization approach: {clean(st.session_state.get('guided_auth', ''))}",
        f"- Trust boundaries and exposed entry points: {clean(st.session_state.get('guided_trust_boundaries', ''))}",
        f"- Deployment model: {clean(st.session_state.get('guided_deployment', ''))}",
        f"- Existing security controls: {clean(st.session_state.get('guided_controls', ''))}",
        f"- External integrations: {clean(st.session_state.get('guided_integrations', ''))}",
    ]
    return "\n".join(lines)


def clear_guided_description_answers():
    """Reset all guided description answers."""
    for field in GUIDED_DESCRIPTION_FIELDS:
        st.session_state[field["key"]] = ""
    st.session_state.pop("guided_description_draft", None)


def render_guided_description_builder():
    """Render helper UI to guide users toward high-quality app descriptions."""
    with st.expander("Need help writing your app description?", expanded=False):
        st.caption(
            "Answer these prompts to generate a structured draft you can insert into the main description field."
        )

        for field in GUIDED_DESCRIPTION_FIELDS:
            st.text_area(
                label=field["label"],
                value=st.session_state.get(field["key"], ""),
                key=field["key"],
                placeholder=field["placeholder"],
                height=80,
            )

        completed_sections = sum(
            1
            for key in GUIDED_REQUIRED_FIELD_KEYS
            if st.session_state.get(key, "").strip()
        )
        completion_ratio = completed_sections / len(GUIDED_REQUIRED_FIELD_KEYS)
        st.progress(completion_ratio)
        st.caption(
            f"Guided coverage: {completed_sections}/{len(GUIDED_REQUIRED_FIELD_KEYS)} core sections completed."
        )

        missing_sections = [
            field["label"].split(") ", 1)[1]
            for field in GUIDED_DESCRIPTION_FIELDS
            if field["key"] in GUIDED_REQUIRED_FIELD_KEYS
            and not st.session_state.get(field["key"], "").strip()
        ]
        if missing_sections:
            st.info("To improve quality, add details for: " + ", ".join(missing_sections))

        insert_mode = st.radio(
            "How should the draft be applied to the description?",
            options=["Replace current description", "Append to current description"],
            key="guided_insert_mode",
            horizontal=True,
        )

        action_col1, action_col2, action_col3 = st.columns([1, 1, 1])
        with action_col1:
            if st.button("Generate Guided Draft"):
                st.session_state["guided_description_draft"] = build_guided_description_draft()
        with action_col2:
            if st.button("Apply Guided Draft"):
                draft = st.session_state.get("guided_description_draft", "").strip()
                if not draft:
                    draft = build_guided_description_draft()
                    st.session_state["guided_description_draft"] = draft

                existing_description = st.session_state.get("app_input", "").strip()
                if insert_mode == "Replace current description" or not existing_description:
                    st.session_state["app_input"] = draft
                    st.session_state["_sync_app_desc"] = True
                elif draft not in existing_description:
                    st.session_state["app_input"] = existing_description + "\n\n" + draft
                    st.session_state["_sync_app_desc"] = True
        with action_col3:
            st.button(
                "Clear Guided Answers",
                on_click=clear_guided_description_answers,
            )

        if st.session_state.get("guided_description_draft"):
            st.markdown("##### Guided Draft Preview")
            st.code(st.session_state["guided_description_draft"], language="markdown")


# Function to get available models from LM Studio Server
def get_lm_studio_models(endpoint, api_key="not-needed"):
    try:
        client = OpenAI(base_url=f"{endpoint}/v1", api_key=api_key)
        models = client.models.list()
        return [model.id for model in models.data]
    except requests.exceptions.ConnectionError:
        st.error(
            """Unable to connect to LM Studio Server. Please ensure:
1. LM Studio is running and the local server is started
2. The endpoint URL is correct (default: http://localhost:1234)
3. No firewall is blocking the connection"""
        )
        return ["local-model"]
    except Exception as e:
        st.error(
            f"""Error fetching models from LM Studio Server: {e}

Please check:
1. LM Studio is properly configured and running
2. You have loaded a model in LM Studio
3. The server is running in local inference mode
4. If using authentication, verify your API key is correct"""
        )
        return ["local-model"]



# Function to get user input for the application description and key details
def get_input():
    github_url = st.text_input(
        label="Enter GitHub repository URL (optional)",
        placeholder="https://github.com/owner/repo",
        key="github_url",
        help="Enter the URL of the GitHub repository you want to analyze.",
    )

    if github_url and github_url != st.session_state.get("last_analyzed_url", ""):
        if "github_api_key" not in st.session_state or not st.session_state["github_api_key"]:
            st.warning("Please enter a GitHub API key to analyze the repository.")
        else:
            with st.spinner("Analyzing GitHub repository..."):
                system_description = analyze_github_repo(github_url)
                st.session_state["github_analysis"] = system_description
                st.session_state["last_analyzed_url"] = github_url
                st.session_state["app_input"] = (
                    system_description + "\n\n" + st.session_state.get("app_input", "")
                )
                st.session_state["_sync_app_desc"] = True

    render_guided_description_builder()

    # Sync app_input → app_desc only on explicit external updates (GitHub, image, guided draft).
    # Never overwrite the widget key based on stale app_input — that clears user text.
    if st.session_state.pop("_sync_app_desc", False):
        st.session_state["app_desc"] = st.session_state.get("app_input", "")
    elif "app_desc" not in st.session_state:
        st.session_state["app_desc"] = st.session_state.get("app_input", "")

    input_text = st.text_area(
        label="Describe the application to be modelled",
        placeholder="Enter your application details...",
        height=300,
        key="app_desc",
        help="Please provide a detailed description of the application, including the purpose of the application, the technologies used, and any other relevant information.",
    )

    st.session_state["app_input"] = input_text

    return input_text


def estimate_tokens(text, model="gpt-5.2"):
    """
    Estimate the number of tokens in a text string.
    Uses tiktoken for OpenAI models, or falls back to a character-based approximation.

    Args:
        text: The text to estimate tokens for
        model: The model to use for estimation (default: gpt-5.2)

    Returns:
        Estimated token count
    """
    try:
        # Try to use tiktoken for accurate estimation
        enc = tiktoken.encoding_for_model(model)
        return len(enc.encode(text))
    except (ImportError, KeyError, ValueError):
        # Fall back to character-based approximation
        # Different languages have different token densities
        # English: ~4 chars per token, Chinese: ~1-2 chars per token
        return len(text) // 4  # Conservative estimate for English text


def analyze_github_repo(repo_url):
    # Extract owner and repo name from URL
    parsed_url = urlparse(repo_url)
    parts = parsed_url.path.split("/")
    owner = parts[-2]
    repo_name = parts[-1]

    # Initialize PyGithub
    g = Github(
        st.session_state.get("github_api_key", ""),
        base_url=f"{parsed_url.scheme}://{parsed_url.hostname}/api/v3",
    )

    # Get the repository
    repo = g.get_repo(f"{owner}/{repo_name}")

    # Get the default branch
    default_branch = repo.default_branch

    # Get the tree of the default branch
    tree = repo.get_git_tree(default_branch, recursive=True)

    # Analyze files
    file_summaries = defaultdict(list)
    total_tokens = 0

    # Get the configured token limit from session state, or use a default
    token_limit = st.session_state.get("token_limit", 64000)

    # Get the selected model for token estimation
    model_provider = st.session_state.get("model_provider", "OpenAI API")
    selected_model = st.session_state.get("selected_model", "gpt-5.2")

    # Determine which model to use for token estimation
    token_estimation_model = "gpt-5.2"  # Default fallback
    if model_provider == "OpenAI API":
        token_estimation_model = selected_model

    # Reserve some tokens for the model's response (typically 20-30% of the context window)
    # This ensures the model has enough space to generate a response
    analysis_token_limit = int(token_limit * 0.7)

    # Progress bar for GitHub analysis
    progress_bar = st.progress(0)
    status_text = st.empty()
    status_text.text("Analyzing repository structure...")

    # First, get the README to prioritize it
    readme_content = ""
    readme_tokens = 0
    try:
        readme_file = repo.get_contents("README.md", ref=default_branch)
        readme_content = base64.b64decode(readme_file.content).decode()
        readme_tokens = estimate_tokens(readme_content, token_estimation_model)
    except:
        try:
            # Try lowercase readme.md as fallback
            readme_file = repo.get_contents("readme.md", ref=default_branch)
            readme_content = base64.b64decode(readme_file.content).decode()
            readme_tokens = estimate_tokens(readme_content, token_estimation_model)
        except:
            st.warning("No README.md found in the repository.")

    # Calculate how many tokens we can use for code analysis
    # Reserve at least 30% of the token limit for code analysis
    max(int(analysis_token_limit * 0.3), analysis_token_limit - readme_tokens)

    # If README is too large, truncate it
    if readme_tokens > analysis_token_limit * 0.7:
        # Truncate README to 70% of the analysis token limit
        truncation_ratio = (analysis_token_limit * 0.7) / readme_tokens
        max_readme_chars = int(len(readme_content) * truncation_ratio)
        readme_content = (
            readme_content[:max_readme_chars] + "...\n(README truncated due to length)\n\n"
        )
        readme_tokens = estimate_tokens(readme_content, token_estimation_model)

    # Update progress
    progress_bar.progress(0.2)
    status_text.text("Analyzing code files...")

    # Get all code files
    code_files = [
        file
        for file in tree.tree
        if file.type == "blob"
        and file.path.endswith(
            (
                ".py",
                ".js",
                ".ts",
                ".html",
                ".css",
                ".java",
                ".go",
                ".rb",
                ".c",
                ".cpp",
                ".h",
                ".cs",
                ".php",
            )
        )
    ]

    # Sort files by importance (you can customize this logic)
    # For example, prioritize main files, configuration files, etc.
    def file_importance(file):
        # Lower score means higher importance
        if file.path.lower() in ["main.py", "app.py", "index.js", "package.json", "config.json"]:
            return 0
        if "test" in file.path.lower() or "spec" in file.path.lower():
            return 3
        if file.path.endswith((".py", ".js", ".ts", ".java", ".go")):
            return 1
        return 2

    code_files.sort(key=file_importance)

    # Process files until we reach the token limit
    total_tokens = readme_tokens
    file_count = len(code_files)
    processed_files = 0

    for i, file in enumerate(code_files):
        # Update progress
        progress_percent = 0.2 + (0.8 * (i / file_count))
        progress_bar.progress(min(progress_percent, 1.0))
        status_text.text(f"Analyzing file {i + 1}/{file_count}: {file.path}")

        try:
            content = repo.get_contents(file.path, ref=default_branch)
            decoded_content = base64.b64decode(content.content).decode()

            # Summarize the file content
            summary = summarize_file(file.path, decoded_content)
            summary_tokens = estimate_tokens(summary, token_estimation_model)

            # Check if adding this summary would exceed our token limit
            if total_tokens + summary_tokens > analysis_token_limit:
                # If we're about to exceed the limit, add a note and stop processing
                file_summaries["info"].append(
                    f"Analysis truncated: {file_count - i} more files not analyzed due to token limit."
                )
                break

            file_summaries[file.path.split(".")[-1]].append(summary)
            total_tokens += summary_tokens
            processed_files += 1
        except Exception:
            # Skip files that can't be decoded
            continue

    # Clear progress indicators
    progress_bar.empty()
    status_text.empty()

    # Compile the analysis into a system description
    system_description = f"Repository: {repo_url}\n\n"

    if readme_content:
        system_description += "README.md Content:\n"
        system_description += readme_content + "\n\n"

    for file_type, summaries in file_summaries.items():
        system_description += f"{file_type.upper()} Files:\n"
        for summary in summaries:
            system_description += summary + "\n"
        system_description += "\n"

    # Add token usage information
    estimated_total_tokens = estimate_tokens(system_description, token_estimation_model)
    system_description += "\nRepository Analysis Summary:\n"
    system_description += f"- Files analyzed: {processed_files} of {file_count} total files\n"
    system_description += f"- Token usage estimate: ~{estimated_total_tokens} tokens\n"
    system_description += f"- Token limit configured: {token_limit} tokens\n"

    # Show a warning if we're close to the token limit
    if estimated_total_tokens > token_limit * 0.9:
        st.warning(
            f"⚠️ The GitHub analysis is using approximately {estimated_total_tokens} tokens, which is close to your configured limit of {token_limit}. Consider increasing the token limit in the sidebar settings if you need more comprehensive analysis."
        )

    return system_description


def summarize_file(file_path, content):
    """
    Summarize a file's content by extracting key components.
    Adapts the level of detail based on file size and importance.

    Args:
        file_path: Path to the file
        content: Content of the file

    Returns:
        A string summary of the file
    """
    # Determine file type
    file_ext = file_path.split(".")[-1].lower() if "." in file_path else ""

    # Initialize summary
    summary = f"File: {file_path}\n"

    # For very large files, be more selective
    is_large_file = len(content) > 10000

    # Extract imports based on file type
    imports = []
    if file_ext in ["py"]:
        imports = re.findall(r"^import .*|^from .* import .*", content, re.MULTILINE)
    elif file_ext in ["js", "ts"]:
        imports = re.findall(
            r"^import .*|^const .* = require\(.*\)|^import .* from .*", content, re.MULTILINE
        )
    elif file_ext in ["java"]:
        imports = re.findall(r"^import .*;", content, re.MULTILINE)
    elif file_ext in ["go"]:
        imports = re.findall(r'^import \(.*?\)|^import ".*"', content, re.MULTILINE | re.DOTALL)

    # Extract functions based on file type
    functions = []
    if file_ext in ["py"]:
        functions = re.findall(r"def .*\(.*\):", content, re.MULTILINE)
    elif file_ext in ["js", "ts"]:
        functions = re.findall(
            r"function .*\(.*\) {|const .* = \(.*\) =>|.*: function\(.*\)", content, re.MULTILINE
        )
    elif file_ext in ["java", "c", "cpp", "cs"]:
        functions = re.findall(
            r"(public|private|protected|static|\s) +[\w\<\>\[\]]+\s+(\w+) *\([^\)]*\) *(\{?|[^;])",
            content,
            re.MULTILINE,
        )
        functions = [" ".join(f).strip() for f in functions]
    elif file_ext in ["go"]:
        functions = re.findall(r"func .*\(.*\).*{", content, re.MULTILINE)

    # Extract classes based on file type
    classes = []
    if file_ext in ["py"]:
        classes = re.findall(r"class .*:", content, re.MULTILINE)
    elif file_ext in ["js", "ts"]:
        classes = re.findall(r"class .* {", content, re.MULTILINE)
    elif file_ext in ["java", "c", "cpp", "cs"]:
        classes = re.findall(
            r"(public|private|protected|static|\s) +(class|interface) +(\w+)", content, re.MULTILINE
        )
        classes = [" ".join(c).strip() for c in classes]

    # Add imports to summary (limit based on file size)
    import_limit = 5 if not is_large_file else 3
    if imports:
        summary += "Imports:\n" + "\n".join(imports[:import_limit])
        if len(imports) > import_limit:
            summary += f"\n... ({len(imports) - import_limit} more imports)"
        summary += "\n"

    # Add classes to summary (limit based on file size)
    class_limit = 5 if not is_large_file else 3
    if classes:
        summary += "Classes:\n" + "\n".join(classes[:class_limit])
        if len(classes) > class_limit:
            summary += f"\n... ({len(classes) - class_limit} more classes)"
        summary += "\n"

    # Add functions to summary (limit based on file size)
    function_limit = 10 if not is_large_file else 5
    if functions:
        summary += "Functions:\n" + "\n".join(functions[:function_limit])
        if len(functions) > function_limit:
            summary += f"\n... ({len(functions) - function_limit} more functions)"
        summary += "\n"

    # For configuration files (JSON, YAML, etc.), try to extract key information
    if file_ext in ["json", "yaml", "yml", "toml", "ini"]:
        # Just include a snippet of the beginning for config files
        config_preview = content[:500] + ("..." if len(content) > 500 else "")
        summary += "Configuration Content Preview:\n" + config_preview + "\n"

    # For README or documentation files, include a brief excerpt
    if "readme" in file_path.lower() or file_ext in ["md", "rst", "txt"]:
        doc_preview = content[:300] + ("..." if len(content) > 300 else "")
        summary += "Content Preview:\n" + doc_preview + "\n"

    return summary


# Function to render Mermaid diagram
def mermaid(code: str, height: int = 500) -> None:
    components.html(
        f"""
        <pre class="mermaid" style="height: {height}px;">
            {code}
        </pre>

        <script type="module">
            import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
            mermaid.initialize({{ startOnLoad: true }});
        </script>
        """,
        height=height,
    )


def load_env_variables():
    # Try to load from .env file
    if os.path.exists(".env"):
        load_dotenv(".env")

    # Load GitHub API key from environment variable
    github_api_key = os.getenv("GITHUB_API_KEY")
    if github_api_key:
        st.session_state["github_api_key"] = github_api_key

    # Load other API keys if needed
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if openai_api_key:
        st.session_state["openai_api_key"] = openai_api_key

    anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
    if anthropic_api_key:
        st.session_state["anthropic_api_key"] = anthropic_api_key

    google_api_key = os.getenv("GOOGLE_API_KEY")
    if google_api_key:
        st.session_state["google_api_key"] = google_api_key

    mistral_api_key = os.getenv("MISTRAL_API_KEY")
    if mistral_api_key:
        st.session_state["mistral_api_key"] = mistral_api_key

    groq_api_key = os.getenv("GROQ_API_KEY")
    if groq_api_key:
        st.session_state["groq_api_key"] = groq_api_key

    # Add LM Studio Server endpoint configuration
    lm_studio_endpoint = os.getenv("LM_STUDIO_ENDPOINT", "http://localhost:1234")
    st.session_state["lm_studio_endpoint"] = lm_studio_endpoint


# Call this function at the start of your app
load_env_variables()

# ------------------ Model Registry ------------------ #

from stride_gpt.models import PROVIDERS as _PROVIDERS, get_model, get_models_for_provider

st.set_page_config(
    page_title="STRIDE GPT",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Define callback for model provider change
def on_model_provider_change():
    """Update token limit and selected model when model provider changes"""
    new_provider = st.session_state.model_provider

    # Set default model and token limit from registry
    models = get_models_for_provider(new_provider)
    if models:
        st.session_state.selected_model = models[0].model_id
        st.session_state.token_limit = models[0].default_tokens
    else:
        # LM Studio or unknown — conservative default
        st.session_state.token_limit = 8000

    # Reset the current_model_key to force token limit update in Advanced Settings
    if "current_model_key" in st.session_state:
        del st.session_state.current_model_key


# Define callback for model selection change
def on_model_selection_change():
    """Update token limit when specific model is selected"""
    if "model_provider" not in st.session_state or "selected_model" not in st.session_state:
        return

    model_info = get_model(st.session_state.model_provider, st.session_state.selected_model)
    if model_info:
        st.session_state.token_limit = model_info.default_tokens

    # Reset the current_model_key to force token limit update in Advanced Settings
    if "current_model_key" in st.session_state:
        del st.session_state.current_model_key


# ------------------ Sidebar ------------------ #

st.sidebar.image("stride-gpt-logo.png", width=250)

# Add instructions on how to use the app to the sidebar
st.sidebar.header("How to use STRIDE GPT")

with st.sidebar:
    # Add model selection input field to the sidebar
    # Build provider list from registry (use provider_key as selectbox values)
    _provider_keys = [p.provider_key for p in _PROVIDERS.values()]
    model_provider = st.selectbox(
        "Select your preferred model provider:",
        _provider_keys,
        key="model_provider",
        on_change=on_model_provider_change,
        help="Select the model provider you would like to use. This will determine the models available for selection.",
    )

    # --- API key session-state keys (map provider_key → session key) ---
    _API_KEY_SESSION = {
        "OpenAI API": "openai_api_key",
        "Anthropic API": "anthropic_api_key",
        "Google AI API": "google_api_key",
        "Mistral API": "mistral_api_key",
        "Groq API": "groq_api_key",
    }

    if model_provider == "LM Studio Server":
        # --- LM Studio: custom endpoint + dynamic model discovery ---
        provider_info = _PROVIDERS["LM Studio"]
        st.markdown(provider_info.setup_instructions)

        lm_studio_endpoint = st.text_input(
            "Enter your LM Studio Server endpoint:",
            value=st.session_state.get("lm_studio_endpoint", "http://localhost:1234"),
            help="The URL of your LM Studio Server instance. Default is http://localhost:1234 for local installations.",
        )

        lm_studio_api_key = st.text_input(
            "Enter your LM Studio API key (optional):",
            value=st.session_state.get("lm_studio_api_key", ""),
            type="password",
            help="Optional API key for LM Studio Server authentication. Leave empty if your server doesn't require authentication.",
        )
        if lm_studio_api_key:
            st.session_state["lm_studio_api_key"] = lm_studio_api_key

        if lm_studio_endpoint:
            if not lm_studio_endpoint.startswith(("http://", "https://")):
                st.error("Endpoint URL must start with http:// or https://")
            else:
                st.session_state["lm_studio_endpoint"] = lm_studio_endpoint
                available_models = get_lm_studio_models(
                    lm_studio_endpoint, st.session_state.get("lm_studio_api_key", "")
                )

        selected_model = st.selectbox(
            "Select the model you would like to use:",
            (
                available_models
                if lm_studio_endpoint and lm_studio_endpoint.startswith(("http://", "https://"))
                else ["local-model"]
            ),
            key="selected_model",
            on_change=on_model_selection_change,
            help="Select a model from your local LM Studio Server. If you don't see any models, make sure LM Studio Server is running with models loaded.",
        )
    else:
        # --- Cloud providers: generic rendering from registry ---
        # Find the ProviderInfo by provider_key
        _current_provider = next(p for p in _PROVIDERS.values() if p.provider_key == model_provider)
        st.markdown(_current_provider.setup_instructions)

        # API key input
        _session_key = _API_KEY_SESSION.get(model_provider, "")
        if _session_key:
            _api_key_val = st.text_input(
                f"Enter your {_current_provider.name} API key:",
                value=st.session_state.get(_session_key, ""),
                type="password",
                help=f"You can find your API key at [{_current_provider.name}]({_current_provider.api_key_url}).",
            )
            if _api_key_val:
                st.session_state[_session_key] = _api_key_val

        # Model selectbox from registry
        _model_list = get_models_for_provider(model_provider)
        _model_ids = [m.model_id for m in _model_list]
        _model_help = " | ".join(f"{m.model_id}: {m.help_text}" for m in _model_list if m.help_text)
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            _model_ids,
            key="selected_model",
            on_change=on_model_selection_change,
            help=_model_help or None,
        )

        # Anthropic-specific: Extended Thinking checkbox
        if model_provider == "Anthropic API":
            use_thinking = st.checkbox(
                "Enable Extended Thinking",
                value=st.session_state.get("use_thinking", False),
                key="use_thinking",
                help="Extended thinking gives Claude enhanced reasoning capabilities for complex tasks. This may increase response time and token usage.",
            )

    # Add GitHub API key input field to the sidebar
    github_api_key = st.text_input(
        "Enter your GitHub API key (optional):",
        value=st.session_state.get("github_api_key", ""),
        type="password",
        help="You can find or create your GitHub API key in your GitHub account settings under Developer settings > Personal access tokens.",
    )

    # Store the GitHub API key in session state
    if github_api_key:
        st.session_state["github_api_key"] = github_api_key

    # Add Advanced Settings section with token limit configuration
    with st.expander("Advanced Settings"):
        # Get token limits from registry
        current_provider = st.session_state.get("model_provider", "OpenAI API")
        current_model = st.session_state.get("selected_model", "")
        model_key = f"{current_provider}:{current_model}"

        _model_info = get_model(current_provider, current_model)
        max_token_limit = _model_info.max_tokens if _model_info else 128000
        default_token_limit = _model_info.default_tokens if _model_info else 64000

        # Store the current model and provider to detect changes
        current_model_key = st.session_state.get("current_model_key", "")

        # If token_limit is not set or the model/provider has changed, update the token limit
        if "token_limit" not in st.session_state or current_model_key != model_key:
            st.session_state.token_limit = default_token_limit
            st.session_state.current_model_key = model_key

        # Add token limit slider with fixed minimum and dynamic maximum
        token_limit = st.slider(
            "Maximum token limit for GitHub analysis:",
            min_value=4000,  # Fixed minimum as requested
            max_value=max_token_limit,
            value=st.session_state.token_limit,  # Use the current value from session state
            step=1000,
            help="Set the maximum number of tokens to use for GitHub repository analysis. This helps prevent exceeding your model's context window.",
        )

        # Store the token limit in session state
        st.session_state["token_limit"] = token_limit

    st.markdown("---")

    # Add "About" section to the sidebar
    st.header("About")

    st.markdown(
        "Welcome to STRIDE GPT, an AI-powered tool designed to help teams produce better threat models for their applications."
    )
    st.markdown(
        "Threat modelling is a key activity in the software development lifecycle, but is often overlooked or poorly executed. STRIDE GPT aims to help teams produce more comprehensive threat models by leveraging the power of Large Language Models (LLMs) to generate a threat list, attack tree and/or mitigating controls for an application based on the details provided."
    )
    st.markdown("Created by [Matt Adams](https://www.linkedin.com/in/matthewrwadams/).")
    # Add "Star on GitHub" link to the sidebar
    st.markdown(
        "⭐ Star on GitHub: [![Star on GitHub](https://img.shields.io/github/stars/mrwadams/stride-gpt?style=social)](https://github.com/mrwadams/stride-gpt)"
    )

    # Donate button - smaller version
    st.markdown(
        """
        <div style="text-align: center; margin: 10px 0;">
            <a href="https://buymeacoffee.com/mrwadams" target="_blank">
                <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png"
                     alt="Buy Me A Coffee"
                     style="height: 35px !important; width: 127px !important;">
            </a>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("""---""")


# Add "Example Application Description" section to the sidebar
st.sidebar.header("Example Application Description")

with st.sidebar:
    st.markdown("Below is an example application description that you can use to test STRIDE GPT:")
    st.markdown(
        "> A web application that allows users to create, store, and share personal notes. The application is built using the React frontend framework and a Node.js backend with a MongoDB database. Users can sign up for an account and log in using OAuth2 with Google or Facebook. The notes are encrypted at rest and are only accessible by the user who created them. The application also supports real-time collaboration on notes with other users."
    )
    st.markdown("""---""")

# Add "FAQs" section to the sidebar
st.sidebar.header("FAQs")

with st.sidebar:
    st.markdown(
        """
    ### **What is STRIDE?**
    STRIDE is a threat modeling methodology that helps to identify and categorise potential security risks in software applications. It stands for **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, and **E**levation of Privilege.
    """
    )
    st.markdown(
        """
    ### **How does STRIDE GPT work?**
    When you enter an application description and other relevant details, the tool uses advanced AI models from multiple providers (OpenAI, Anthropic, Google, Mistral, LM Studio, and Groq) to generate a threat model for your application. The selected model analyzes the application description and details to generate a list of potential threats and then categorises each threat according to the STRIDE methodology.
    """
    )
    st.markdown(
        """
    ### **Do you store the application details provided?**
    No, STRIDE GPT does not store your application description or other details. All entered data is deleted after you close the browser tab.
    """
    )
    st.markdown(
        """
    ### **Why does it take so long to generate a threat model?**
    Several factors can affect generation time:

    **API Rate Limits:** Free API keys have strict rate limits. Using a paid API key will speed up the process.

    **Reasoning Models:** If you've selected a GPT-5 series model, these models take longer because they "think" before responding to provide more thorough analysis.

    **For Faster Results:** Choose smaller/faster models like:
    - Gemini Flash instead of Gemini Pro
    - GPT-5-nano instead of GPT-5.2
    - Claude Haiku instead of Claude Sonnet
    """
    )
    st.markdown(
        """
    ### **Are the threat models 100% accurate?**
    No, the threat models are not 100% accurate. STRIDE GPT uses various Large Language Models (LLMs) from multiple AI providers to generate its output. While these models are powerful, they can sometimes make mistakes and are prone to 'hallucinations' (generating irrelevant or inaccurate content). Please use the output only as a starting point for identifying and addressing potential security risks in your applications.
    """
    )
    st.markdown(
        """
    ### **How can I improve the accuracy of the threat models?**
    You can improve the accuracy of the threat models by providing a detailed description of the application and selecting the correct application type, authentication methods, and other relevant details. The more information you provide, the more accurate the threat models will be.
    """
    )


# ------------------ Main App UI ------------------ #

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
    ["Threat Model", "Attack Tree", "Mitigations", "DREAD", "Test Cases", "Deep Analysis"]
)

with tab1:
    st.markdown(
        """
A threat model helps identify and evaluate potential security threats to applications / systems. It provides a systematic approach to
understanding possible vulnerabilities and attack vectors. Use this tab to generate a threat model using the STRIDE methodology.
"""
    )
    st.markdown("""---""")

    # Two column layout for the main app content
    col1, col2 = st.columns([1, 1])

    # Initialize app_input in the session state if it doesn't exist
    if "app_input" not in st.session_state:
        st.session_state["app_input"] = ""

    # Display image uploader for supported multimodal models
    with col1:
        supports_image = False
        # Get selected_model from session state
        selected_model = st.session_state.get("selected_model", "")

        if (
            (
                model_provider == "OpenAI API"
                and (selected_model.startswith("gpt-4") or selected_model.startswith("gpt-5"))
            )
            or model_provider == "Google AI API"
            or (model_provider == "Anthropic API" and selected_model.startswith("claude-"))
        ):
            supports_image = True

        if supports_image:
            uploaded_file = st.file_uploader(
                "Upload architecture diagram", type=["jpg", "jpeg", "png"]
            )

            if uploaded_file is not None:

                def encode_image(uploaded_file):
                    return base64.b64encode(uploaded_file.read()).decode("utf-8")

                base64_image = encode_image(uploaded_file)
                image_analysis_prompt = create_image_analysis_prompt()

                # Determine media type from file extension
                file_type = uploaded_file.type
                if file_type == "image/png":
                    media_type = "image/png"
                elif file_type in ["image/jpeg", "image/jpg"]:
                    media_type = "image/jpeg"
                else:
                    media_type = "image/jpeg"  # Default fallback

                try:
                    if model_provider == "OpenAI API":
                        if not openai_api_key:
                            st.error("Please enter your OpenAI API key to analyse the image.")
                            raise ValueError
                        image_analysis_output = get_image_analysis(
                            openai_api_key, selected_model, image_analysis_prompt, base64_image
                        )
                    elif model_provider == "Google AI API":
                        if not google_api_key:
                            st.error("Please enter your Google AI API key to analyse the image.")
                            raise ValueError
                        image_analysis_output = get_image_analysis_google(
                            google_api_key, selected_model, image_analysis_prompt, base64_image
                        )
                    elif model_provider == "Anthropic API":
                        if not anthropic_api_key:
                            st.error("Please enter your Anthropic API key to analyse the image.")
                            raise ValueError
                        image_analysis_output = get_image_analysis_anthropic(
                            anthropic_api_key,
                            selected_model,
                            image_analysis_prompt,
                            base64_image,
                            media_type,
                        )
                    else:
                        image_analysis_output = None

                    if (
                        image_analysis_output
                        and "choices" in image_analysis_output
                        and image_analysis_output["choices"][0]["message"]["content"]
                    ):
                        image_analysis_content = image_analysis_output["choices"][0]["message"][
                            "content"
                        ]
                        st.session_state.image_analysis_content = image_analysis_content
                        st.session_state["app_input"] = image_analysis_content
                        st.session_state["_sync_app_desc"] = True
                    else:
                        st.error(
                            "Failed to analyze the image. Please check the API key and try again."
                        )
                except Exception as e:
                    st.error(f"An error occurred while analyzing the image: {e!s}")

        # Use the get_input() function to get the application description and GitHub URL
        app_input = get_input()
        # Update session state only if the text area content has changed
        if app_input != st.session_state["app_input"]:
            st.session_state["app_input"] = app_input

    # Ensure app_input is always up to date in the session state
    app_input = st.session_state["app_input"]

    # Create input fields for additional details
    with col2:
        app_type = st.selectbox(
            label="Select the application type",
            options=[
                "Web application",
                "Mobile application",
                "Desktop application",
                "Cloud application",
                "IoT application",
                "Generative AI application",
                "Agentic AI application",
                "Other",
            ],
            key="app_type",
        )

        sensitive_data = st.selectbox(
            label="What is the highest sensitivity level of the data processed by the application?",
            options=[
                "Top Secret",
                "Secret",
                "Confidential",
                "Restricted",
                "Unclassified",
                "None",
            ],
            key="sensitive_data",
        )

        # Create input fields for internet_facing and authentication
        internet_facing = st.selectbox(
            label="Is the application internet-facing?",
            options=["Yes", "No"],
            key="internet_facing",
        )

        authentication = st.multiselect(
            "What authentication methods are supported by the application?",
            ["SSO", "MFA", "OAUTH2", "Basic", "None"],
            key="authentication",
        )

        # Show guidance for GenAI/Agentic applications
        if app_type == "Generative AI application":
            st.markdown("---")
            st.info(
                """**For better threat coverage, include in your description:**
- LLM provider and model (e.g., OpenAI GPT-5, Claude, fine-tuned Llama)
- Features used (RAG, function calling, code generation, embeddings)
- Data sources (documents, databases, APIs, user uploads)
- How outputs are used (displayed, stored, executed, sent externally)"""
            )

        if app_type == "Agentic AI application":
            st.markdown("---")
            st.info(
                """**For better threat coverage, include in your description:**
- Agent framework (LangChain, CrewAI, AutoGen, custom)
- Agent capabilities (tool use, code execution, web browsing, file access)
- Multi-agent details if applicable (orchestration, communication)
- Memory/state persistence mechanisms
- Human oversight level (approval required, monitoring only, fully autonomous)
- Tools and integrations (MCP servers, APIs, databases)
- Credential access (OAuth tokens, API keys, service accounts)
- Autonomous action scope (what can it do without approval?)"""
            )

    # ------------------ Threat Model Generation ------------------ #

    # Create a submit button for Threat Modelling
    threat_model_submit_button = st.button(label="Generate Threat Model")

    # If the Generate Threat Model button is clicked and the user has provided an application description
    if threat_model_submit_button and st.session_state.get("app_input"):
        app_input = st.session_state["app_input"]  # Retrieve from session state

        # Generate the prompt using the create_prompt function
        threat_model_prompt = create_threat_model_prompt(
            app_type,
            authentication,
            internet_facing,
            sensitive_data,
            app_input,
        )

        # Clear thinking content when switching models or starting a new operation
        if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
            st.session_state.pop("last_thinking_content", None)

        # Show a spinner while generating the threat model
        with st.spinner("Analysing potential threats..."):
            max_retries = 3
            retry_count = 0
            while retry_count < max_retries:
                try:
                    # Call the relevant get_threat_model function with the generated prompt
                    if model_provider == "OpenAI API":
                        model_output = get_threat_model(
                            openai_api_key, selected_model, threat_model_prompt
                        )
                    elif model_provider == "Google AI API":
                        model_output = get_threat_model_google(
                            google_api_key, google_model, threat_model_prompt
                        )
                    elif model_provider == "Mistral API":
                        model_output = get_threat_model_mistral(
                            mistral_api_key, mistral_model, threat_model_prompt
                        )
                    elif model_provider == "Anthropic API":
                        model_output = get_threat_model_anthropic(
                            anthropic_api_key, anthropic_model, threat_model_prompt
                        )
                        # Check if we got a fallback response
                        if (
                            model_output.get("threat_model")
                            and len(model_output["threat_model"]) == 1
                            and model_output["threat_model"][0].get("Threat Type") == "Error"
                        ):
                            st.warning(
                                "⚠️ There was an issue generating the threat model. The model may have returned a response in an unexpected format. You can try:"
                            )
                            st.markdown("1. Running the generation again")
                            st.markdown("2. Checking the application logs for more details")
                            st.markdown("3. Using a different model if the issue persists")
                    elif model_provider == "LM Studio Server":
                        model_output = get_threat_model_lm_studio(
                            st.session_state["lm_studio_endpoint"],
                            selected_model,
                            threat_model_prompt,
                            st.session_state.get("lm_studio_api_key", ""),
                        )
                    elif model_provider == "Groq API":
                        model_output = get_threat_model_groq(
                            groq_api_key, groq_model, threat_model_prompt
                        )

                    # Access the threat model and improvement suggestions from the parsed content
                    threat_model = model_output.get("threat_model", [])
                    improvement_suggestions = model_output.get("improvement_suggestions", [])

                    # Save the threat model and suggestions to session state for later use
                    st.session_state["threat_model"] = threat_model
                    st.session_state["improvement_suggestions"] = improvement_suggestions

                    # Convert to Markdown and store in session state for persistent display
                    st.session_state["threat_model_markdown"] = json_to_markdown(
                        threat_model, improvement_suggestions
                    )
                    break  # Exit the loop if successful
                except Exception as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        st.error(f"Error generating threat model after {max_retries} attempts: {e}")
                        threat_model = []
                        improvement_suggestions = []
                    else:
                        st.warning(
                            f"Error generating threat model. Retrying attempt {retry_count + 1}/{max_retries}..."
                        )

# Display threat model output on tab1 (must be in tab1 context to only show on that tab)
with tab1:
    # If the submit button is clicked and the user has not provided an application description
    if threat_model_submit_button and not st.session_state.get("app_input"):
        st.error("Please enter your application details before submitting.")

    # Display threat model from session state (persists across reruns)
    if st.session_state.get("threat_model_markdown"):
        # Display thinking content in an expander if available
        if (
            "last_thinking_content" in st.session_state
            and st.session_state["last_thinking_content"]
            and (
                (model_provider == "Anthropic API" and st.session_state.get("use_thinking", False))
                or (model_provider == "Google AI API" and ("gemini-2.5" in google_model.lower() or "gemini-3" in google_model.lower()))
            )
        ):
            thinking_model = "Claude" if model_provider == "Anthropic API" else "Gemini"
            with st.expander(f"View {thinking_model}'s thinking process"):
                st.markdown(st.session_state["last_thinking_content"])

        # Display the threat model in Markdown
        st.markdown(st.session_state["threat_model_markdown"])

        # Add a button to allow the user to download the output as a Markdown file
        st.download_button(
            label="Download Threat Model",
            data=st.session_state["threat_model_markdown"],
            file_name="threat_model.md",
            mime="text/markdown",
        )


# ------------------ Attack Tree Generation ------------------ #

with tab2:
    st.markdown(
        """
Attack trees are a structured way to analyse the security of a system. They represent potential attack scenarios in a hierarchical format,
with the ultimate goal of an attacker at the root and various paths to achieve that goal as branches. This helps in understanding system
vulnerabilities and prioritising mitigation efforts.
"""
    )
    st.markdown("""---""")
    if model_provider == "Mistral API" and mistral_model == "mistral-small-2506":
        st.warning(
            "⚠️ Mistral Small doesn't reliably generate syntactically correct Mermaid code. Please use Mistral Large for generating attack trees, or select a different model provider."
        )
    else:
        if model_provider == "LM Studio Server":
            st.warning(
                "⚠️ Users may encounter syntax errors when generating attack trees using local LLMs. Experiment with different local LLMs to assess their output quality, or consider using a hosted model provider to generate attack trees."
            )

        # Create a submit button for Attack Tree
        attack_tree_submit_button = st.button(label="Generate Attack Tree")

        # If the Generate Attack Tree button is clicked and the user has provided an application description
        if attack_tree_submit_button and st.session_state.get("app_input"):
            app_input = st.session_state.get("app_input")

            # Generate the prompt using the create_attack_tree_prompt function
            attack_tree_prompt = create_attack_tree_prompt(
                app_type,
                authentication,
                internet_facing,
                sensitive_data,
                app_input,
            )

            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop("last_thinking_content", None)

            # Show a spinner while generating the attack tree
            with st.spinner("Generating attack tree..."):
                try:
                    # Call the relevant get_attack_tree function with the generated prompt
                    if model_provider == "OpenAI API":
                        mermaid_code = get_attack_tree(
                            openai_api_key, selected_model, attack_tree_prompt
                        )
                    elif model_provider == "Google AI API":
                        mermaid_code = get_attack_tree_google(
                            google_api_key, google_model, attack_tree_prompt
                        )
                    elif model_provider == "Mistral API":
                        mermaid_code = get_attack_tree_mistral(
                            mistral_api_key, mistral_model, attack_tree_prompt
                        )
                    elif model_provider == "Anthropic API":
                        mermaid_code = get_attack_tree_anthropic(
                            anthropic_api_key, anthropic_model, attack_tree_prompt
                        )
                    elif model_provider == "LM Studio Server":
                        mermaid_code = get_attack_tree_lm_studio(
                            st.session_state["lm_studio_endpoint"],
                            selected_model,
                            attack_tree_prompt,
                            st.session_state.get("lm_studio_api_key", ""),
                        )
                    elif model_provider == "Groq API":
                        mermaid_code = get_attack_tree_groq(
                            groq_api_key, groq_model, attack_tree_prompt
                        )

                    # Display thinking content in an expander if available
                    if (
                        "last_thinking_content" in st.session_state
                        and st.session_state["last_thinking_content"]
                        and (
                            (
                                model_provider == "Anthropic API"
                                and "thinking" in anthropic_model.lower()
                            )
                            or (
                                model_provider == "Google AI API"
                                and ("gemini-2.5" in google_model.lower() or "gemini-3" in google_model.lower())
                            )
                        )
                    ):
                        thinking_model = "Claude" if model_provider == "Anthropic API" else "Gemini"
                        with st.expander(f"View {thinking_model}'s thinking process"):
                            st.markdown(st.session_state["last_thinking_content"])

                    # Display the generated attack tree code
                    st.write("Attack Tree Code:")
                    st.code(mermaid_code)

                    # Visualise the attack tree using the Mermaid custom component
                    st.write("Attack Tree Diagram Preview:")
                    mermaid(mermaid_code)

                    col1, col2, col3, col4, col5 = st.columns([1, 1, 1, 1, 1])

                    with col1:
                        # Add a button to allow the user to download the Mermaid code
                        st.download_button(
                            label="Download Diagram Code",
                            data=mermaid_code,
                            file_name="attack_tree.md",
                            mime="text/plain",
                            help="Download the Mermaid code for the attack tree diagram.",
                        )

                    with col2:
                        # Add a button to allow the user to open the Mermaid Live editor
                        mermaid_live_button = st.link_button(
                            "Open Mermaid Live", "https://mermaid.live"
                        )

                    with col3:
                        # Blank placeholder
                        st.write("")

                    with col4:
                        # Blank placeholder
                        st.write("")

                    with col5:
                        # Blank placeholder
                        st.write("")

                except Exception as e:
                    st.error(f"Error generating attack tree: {e}")


# ------------------ Mitigations Generation ------------------ #

with tab3:
    st.markdown(
        """
Use this tab to generate potential mitigations for the threats identified in the threat model. Mitigations are security controls or
countermeasures that can help reduce the likelihood or impact of a security threat. The generated mitigations can be used to enhance
the security posture of the application and protect against potential attacks.
"""
    )
    st.markdown("""---""")

    # Create a submit button for Mitigations
    mitigations_submit_button = st.button(label="Suggest Mitigations")

    # If the Suggest Mitigations button is clicked and the user has identified threats
    if mitigations_submit_button:
        # Check if threat_model data exists
        if st.session_state.get("threat_model"):
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state["threat_model"], [])
            # Check if this is a GenAI or agentic application
            app_type = st.session_state.get("app_type", "")
            is_genai = app_type in ["Generative AI application", "Agentic AI application"]
            is_agentic = app_type == "Agentic AI application"
            # Generate the prompt using the create_mitigations_prompt function
            mitigations_prompt = create_mitigations_prompt(threats_markdown, is_genai=is_genai, is_agentic=is_agentic)

            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop("last_thinking_content", None)

            # Show a spinner while suggesting mitigations
            with st.spinner("Suggesting mitigations..."):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call the relevant get_mitigations function with the generated prompt
                        if model_provider == "OpenAI API":
                            mitigations_markdown = get_mitigations(
                                openai_api_key, selected_model, mitigations_prompt
                            )
                        elif model_provider == "Google AI API":
                            mitigations_markdown = get_mitigations_google(
                                google_api_key, google_model, mitigations_prompt
                            )
                        elif model_provider == "Mistral API":
                            mitigations_markdown = get_mitigations_mistral(
                                mistral_api_key, mistral_model, mitigations_prompt
                            )
                        elif model_provider == "Anthropic API":
                            mitigations_markdown = get_mitigations_anthropic(
                                anthropic_api_key, anthropic_model, mitigations_prompt
                            )
                        elif model_provider == "LM Studio Server":
                            mitigations_markdown = get_mitigations_lm_studio(
                                st.session_state["lm_studio_endpoint"],
                                selected_model,
                                mitigations_prompt,
                                st.session_state.get("lm_studio_api_key", ""),
                            )
                        elif model_provider == "Groq API":
                            mitigations_markdown = get_mitigations_groq(
                                groq_api_key, groq_model, mitigations_prompt
                            )

                        # Display thinking content in an expander if available and using a model with thinking capabilities
                        if (
                            "last_thinking_content" in st.session_state
                            and st.session_state["last_thinking_content"]
                            and (
                                (
                                    model_provider == "Anthropic API"
                                    and "thinking" in anthropic_model.lower()
                                )
                                or (
                                    model_provider == "Google AI API"
                                    and ("gemini-2.5" in google_model.lower() or "gemini-3" in google_model.lower())
                                )
                            )
                        ):
                            thinking_model = (
                                "Claude" if model_provider == "Anthropic API" else "Gemini"
                            )
                            with st.expander(f"View {thinking_model}'s thinking process"):
                                st.markdown(st.session_state["last_thinking_content"])

                        # Display the suggested mitigations in Markdown
                        st.markdown(mitigations_markdown)

                        st.markdown("")

                        # Add a button to allow the user to download the mitigations as a Markdown file
                        st.download_button(
                            label="Download Mitigations",
                            data=mitigations_markdown,
                            file_name="mitigations.md",
                            mime="text/markdown",
                        )

                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(
                                f"Error suggesting mitigations after {max_retries} attempts: {e}"
                            )
                            mitigations_markdown = ""
                        else:
                            st.warning(
                                f"Error suggesting mitigations. Retrying attempt {retry_count + 1}/{max_retries}..."
                            )

            st.markdown("")
        else:
            st.error("Please generate a threat model first before suggesting mitigations.")

# ------------------ DREAD Risk Assessment Generation ------------------ #
with tab4:
    st.markdown(
        """
DREAD is a method for evaluating and prioritising risks associated with security threats. It assesses threats based on **D**amage potential,
**R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. This helps in determining the overall risk level and
focusing on the most critical threats first. Use this tab to perform a DREAD risk assessment for your application / system.
"""
    )
    st.markdown("""---""")

    # Create a submit button for DREAD Risk Assessment
    dread_assessment_submit_button = st.button(label="Generate DREAD Risk Assessment")
    # If the Generate DREAD Risk Assessment button is clicked and the user has identified threats
    if dread_assessment_submit_button:
        # Check if threat_model data exists
        if st.session_state.get("threat_model"):
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state["threat_model"], [])
            # Check if this is a GenAI or agentic application
            app_type = st.session_state.get("app_type", "")
            is_genai = app_type in ["Generative AI application", "Agentic AI application"]
            is_agentic = app_type == "Agentic AI application"
            # Generate the prompt using the create_dread_assessment_prompt function
            dread_assessment_prompt = create_dread_assessment_prompt(threats_markdown, is_genai=is_genai, is_agentic=is_agentic)
            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop("last_thinking_content", None)

            # Show a spinner while generating DREAD Risk Assessment
            with st.spinner("Generating DREAD Risk Assessment..."):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call the relevant get_dread_assessment function with the generated prompt
                        if model_provider == "OpenAI API":
                            dread_assessment = get_dread_assessment(
                                openai_api_key, selected_model, dread_assessment_prompt
                            )
                        elif model_provider == "Google AI API":
                            dread_assessment = get_dread_assessment_google(
                                google_api_key, google_model, dread_assessment_prompt
                            )
                        elif model_provider == "Mistral API":
                            dread_assessment = get_dread_assessment_mistral(
                                mistral_api_key, mistral_model, dread_assessment_prompt
                            )
                        elif model_provider == "Anthropic API":
                            dread_assessment = get_dread_assessment_anthropic(
                                anthropic_api_key, anthropic_model, dread_assessment_prompt
                            )
                        elif model_provider == "LM Studio Server":
                            dread_assessment = get_dread_assessment_lm_studio(
                                st.session_state["lm_studio_endpoint"],
                                selected_model,
                                dread_assessment_prompt,
                                st.session_state.get("lm_studio_api_key", ""),
                            )
                        elif model_provider == "Groq API":
                            dread_assessment = get_dread_assessment_groq(
                                groq_api_key, groq_model, dread_assessment_prompt
                            )

                        # Save the DREAD assessment to the session state for later use in test cases
                        st.session_state["dread_assessment"] = dread_assessment
                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(
                                f"Error generating DREAD risk assessment after {max_retries} attempts: {e}"
                            )
                            dread_assessment = {"Risk Assessment": []}
                            # Add debug information
                            st.error(
                                "Debug: No threats were found in the response. Please try generating the threat model again."
                            )
                        else:
                            st.warning(
                                f"Error generating DREAD risk assessment. Retrying attempt {retry_count + 1}/{max_retries}..."
                            )
            # Convert the DREAD assessment JSON to Markdown
            dread_assessment_markdown = dread_json_to_markdown(dread_assessment)

            # Add debug information about the assessment
            if not dread_assessment.get("Risk Assessment"):
                st.warning(
                    "Debug: The DREAD assessment response is empty. Please ensure you have generated a threat model first."
                )

            # Display thinking content in an expander if available and using a model with thinking capabilities
            if (
                "last_thinking_content" in st.session_state
                and st.session_state["last_thinking_content"]
                and (
                    (model_provider == "Anthropic API" and st.session_state.get("use_thinking", False))
                    or (model_provider == "Google AI API" and ("gemini-2.5" in google_model.lower() or "gemini-3" in google_model.lower()))
                )
            ):
                thinking_model = "Claude" if model_provider == "Anthropic API" else "Gemini"
                with st.expander(f"View {thinking_model}'s thinking process"):
                    st.markdown(st.session_state["last_thinking_content"])

            # Display the DREAD assessment with a header
            st.markdown("## DREAD Risk Assessment")
            st.markdown(
                "The table below shows the DREAD risk assessment for each identified threat. The Risk Score is calculated as the average of the five DREAD categories."
            )

            # Display the DREAD assessment in Markdown format
            st.markdown(dread_assessment_markdown, unsafe_allow_html=False)

            # Add a button to allow the user to download the DREAD assessment as a Markdown file
            st.download_button(
                label="Download DREAD Risk Assessment",
                data=dread_assessment_markdown,
                file_name="dread_assessment.md",
                mime="text/markdown",
            )
        else:
            st.error(
                "Please generate a threat model first before requesting a DREAD risk assessment."
            )


# ------------------ Test Cases Generation ------------------ #

with tab5:
    st.markdown(
        """
Test cases are used to validate the security of an application and ensure that potential vulnerabilities are identified and
addressed. This tab allows you to generate test cases using Gherkin syntax. Gherkin provides a structured way to describe application
behaviours in plain text, using a simple syntax of Given-When-Then statements. This helps in creating clear and executable test
scenarios.
"""
    )
    st.markdown("""---""")

    # Create a submit button for Test Cases
    test_cases_submit_button = st.button(label="Generate Test Cases")

    # If the Generate Test Cases button is clicked and the user has identified threats
    if test_cases_submit_button:
        # Check if threat_model data exists
        if st.session_state.get("threat_model"):
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state["threat_model"], [])
            # Check if this is a GenAI or agentic application
            app_type = st.session_state.get("app_type", "")
            is_genai = app_type in ["Generative AI application", "Agentic AI application"]
            is_agentic = app_type == "Agentic AI application"
            # Generate the prompt using the create_test_cases_prompt function
            test_cases_prompt = create_test_cases_prompt(threats_markdown, is_genai=is_genai, is_agentic=is_agentic)

            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop("last_thinking_content", None)

            # Show a spinner while generating test cases
            with st.spinner("Generating test cases..."):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call to the relevant get_test_cases function with the generated prompt
                        if model_provider == "OpenAI API":
                            test_cases_markdown = get_test_cases(
                                openai_api_key, selected_model, test_cases_prompt
                            )
                        elif model_provider == "Google AI API":
                            test_cases_markdown = get_test_cases_google(
                                google_api_key, google_model, test_cases_prompt
                            )
                        elif model_provider == "Mistral API":
                            test_cases_markdown = get_test_cases_mistral(
                                mistral_api_key, mistral_model, test_cases_prompt
                            )
                        elif model_provider == "Anthropic API":
                            test_cases_markdown = get_test_cases_anthropic(
                                anthropic_api_key, anthropic_model, test_cases_prompt
                            )
                        elif model_provider == "LM Studio Server":
                            test_cases_markdown = get_test_cases_lm_studio(
                                st.session_state["lm_studio_endpoint"],
                                selected_model,
                                test_cases_prompt,
                                st.session_state.get("lm_studio_api_key", ""),
                            )
                        elif model_provider == "Groq API":
                            test_cases_markdown = get_test_cases_groq(
                                groq_api_key, groq_model, test_cases_prompt
                            )

                        # Display thinking content in an expander if available and using a model with thinking capabilities
                        if (
                            "last_thinking_content" in st.session_state
                            and st.session_state["last_thinking_content"]
                            and (
                                (
                                    model_provider == "Anthropic API"
                                    and "thinking" in anthropic_model.lower()
                                )
                                or (
                                    model_provider == "Google AI API"
                                    and ("gemini-2.5" in google_model.lower() or "gemini-3" in google_model.lower())
                                )
                            )
                        ):
                            thinking_model = (
                                "Claude" if model_provider == "Anthropic API" else "Gemini"
                            )
                            with st.expander(f"View {thinking_model}'s thinking process"):
                                st.markdown(st.session_state["last_thinking_content"])

                        # Display the suggested mitigations in Markdown
                        st.markdown(test_cases_markdown)

                        st.markdown("")

                        # Add a button to allow the user to download the test cases as a Markdown file
                        st.download_button(
                            label="Download Test Cases",
                            data=test_cases_markdown,
                            file_name="test_cases.md",
                            mime="text/markdown",
                        )

                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(
                                f"Error generating test cases after {max_retries} attempts: {e}"
                            )
                            test_cases_markdown = ""
                        else:
                            st.warning(
                                f"Error generating test cases. Retrying attempt {retry_count + 1}/{max_retries}..."
                            )

            st.markdown("")

        else:
            st.error("Please generate a threat model first before requesting test cases.")

with tab6:
    from stride_gpt.streamlit_analysis import render_deep_analysis_tab

    render_deep_analysis_tab()
