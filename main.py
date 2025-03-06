<<<<<<< HEAD
#main.py

import base64
import streamlit as st
import streamlit.components.v1 as components
from github import Github
from git import Repo
from collections import defaultdict
import re
import os
from dotenv import load_dotenv
from openai import OpenAI
import requests
import json
import tiktoken

from threat_model import create_threat_model_prompt, get_threat_model, get_threat_model_azure, get_threat_model_google, get_threat_model_mistral, get_threat_model_ollama, json_to_markdown, get_image_analysis, create_image_analysis_prompt
from attack_tree import create_attack_tree_prompt, get_attack_tree, get_attack_tree_azure, get_attack_tree_mistral, get_attack_tree_ollama
from mitigations import create_mitigations_prompt, get_mitigations, get_mitigations_azure, get_mitigations_google, get_mitigations_mistral, get_mitigations_ollama
from test_cases import create_test_cases_prompt, get_test_cases, get_test_cases_azure, get_test_cases_google, get_test_cases_mistral, get_test_cases_ollama
from dread import create_dread_assessment_prompt, get_dread_assessment, get_dread_assessment_azure, get_dread_assessment_google, get_dread_assessment_mistral, get_dread_assessment_ollama, dread_json_to_markdown

from config import (  # Importing strings
    ABOUT_SECTION,
    EXAMPLE_APPLICATION_SECTION,
    FAQ_SECTION,
    THREAT_MODEL_SECTION,
    COMBINED_MARKDOWN,
    PROVIDERS,
    APPLICATION_TYPES,
    CLASSIFICATION_LEVELS,
    AUTHENTICATION_METHODS,
    ARG_HELPERS,
    INTERNET_FACING,
)

# ------------------ Helper Functions ------------------ #

# Function to get available models from LM Studio Server
def get_lm_studio_models(endpoint):
    try:
        client = OpenAI(
            base_url=f"{endpoint}/v1",
            api_key="not-needed"
        )
        models = client.models.list()
        return [model.id for model in models.data]
    except requests.exceptions.ConnectionError:
        st.error("""Unable to connect to LM Studio Server. Please ensure:
1. LM Studio is running and the local server is started
2. The endpoint URL is correct (default: http://localhost:1234)
3. No firewall is blocking the connection""")
        return ["local-model"]
    except Exception as e:
        st.error(f"""Error fetching models from LM Studio Server: {e}
        
Please check:
1. LM Studio is properly configured and running
2. You have loaded a model in LM Studio
3. The server is running in local inference mode""")
        return ["local-model"]

def get_ollama_models(ollama_endpoint):
    """
    Get list of available models from Ollama.
    
    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://localhost:11434')
        
    Returns:
        list: List of available model names
        
    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
    """
    if not ollama_endpoint.endswith('/'):
        ollama_endpoint = ollama_endpoint + '/'
    
    url = ollama_endpoint + "api/tags"
    
    try:
        response = requests.get(url, timeout=10)  # Add timeout
        response.raise_for_status()  # Raise exception for bad status codes
        models_data = response.json()
        
        # Extract model names from the response
        model_names = [model['name'] for model in models_data['models']]
        if not model_names:
            st.warning("""No models found in Ollama. Please ensure you have:
1. Pulled at least one model using 'ollama pull <model_name>'
2. The model download completed successfully""")
            return ["local-model"]
        return model_names
            
    except requests.exceptions.ConnectionError:
        st.error("""Unable to connect to Ollama. Please ensure:
1. Ollama is installed and running
2. The endpoint URL is correct (default: http://localhost:11434)
3. No firewall is blocking the connection""")
        return ["local-model"]
    except requests.exceptions.Timeout:
        st.error("""Request to Ollama timed out. Please check:
1. Ollama is responding and not overloaded
2. Your network connection is stable
3. The endpoint URL is accessible""")
        return ["local-model"]
    except (KeyError, json.JSONDecodeError):
        st.error("""Received invalid response from Ollama. Please verify:
1. You're running a compatible version of Ollama
2. The endpoint URL is pointing to Ollama and not another service""")
        return ["local-model"]
    except Exception as e:
        st.error(f"""Unexpected error fetching Ollama models: {str(e)}
        
Please check:
1. Ollama is properly installed and running
2. You have pulled at least one model
3. You have sufficient system resources""")
        return ["local-model"]

# Function to get user input for the application description and key details
def get_input():
    github_url = st.text_input(
        label="Enter GitHub repository URL (optional)",
        placeholder="https://github.com/owner/repo",
        key="github_url",
        help="Enter the URL of the GitHub repository you want to analyze.",
    )

    if github_url and github_url != st.session_state.get('last_analyzed_url', ''):
        if 'github_api_key' not in st.session_state or not st.session_state['github_api_key']:
            st.warning("Please enter a GitHub API key to analyze the repository.")
        else:
            with st.spinner('Analyzing GitHub repository...'):
                system_description = analyze_github_repo(github_url, st.session_state.get('github_api_key', ''))
                st.session_state['github_analysis'] = system_description
                st.session_state['last_analyzed_url'] = github_url
                st.session_state['app_input'] = system_description + "\n\n" + st.session_state.get('app_input', '')

    input_text = st.text_area(
        label="Describe the application to be modelled",
        value=st.session_state.get('app_input', ''),
        placeholder="Enter your application details...",
        height=300,
        key="app_desc",
        help="Please provide a detailed description of the application, including the purpose of the application, the technologies used, and any other relevant information.",
    )

    st.session_state['app_input'] = input_text

    return input_text

def estimate_tokens(text, model="gpt-4o"):
    """
    Estimate the number of tokens in a text string.
    Uses tiktoken for OpenAI models, or falls back to a character-based approximation.
    
    Args:
        text: The text to estimate tokens for
        model: The model to use for estimation (default: gpt-4o)
        
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
    parts = repo_url.split('/')
    owner = parts[-2]
    repo_name = parts[-1]

    # Initialize PyGithub
    g = Github(key)

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
    token_limit = st.session_state.get('token_limit', 64000)
    
    # Get the selected model for token estimation
    model_provider = st.session_state.get('model_provider', 'OpenAI API')
    selected_model = st.session_state.get('selected_model', 'gpt-4o')
    
    # Determine which model to use for token estimation
    token_estimation_model = "gpt-4o"  # Default fallback
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
    code_token_limit = max(int(analysis_token_limit * 0.3), analysis_token_limit - readme_tokens)
    
    # If README is too large, truncate it
    if readme_tokens > analysis_token_limit * 0.7:
        # Truncate README to 70% of the analysis token limit
        truncation_ratio = (analysis_token_limit * 0.7) / readme_tokens
        max_readme_chars = int(len(readme_content) * truncation_ratio)
        readme_content = readme_content[:max_readme_chars] + "...\n(README truncated due to length)\n\n"
        readme_tokens = estimate_tokens(readme_content, token_estimation_model)
    
    # Update progress
    progress_bar.progress(0.2)
    status_text.text("Analyzing code files...")
    
    # Get all code files
    code_files = [file for file in tree.tree if file.type == "blob" and file.path.endswith(
        ('.py', '.js', '.ts', '.html', '.css', '.java', '.go', '.rb', '.c', '.cpp', '.h', '.cs', '.php')
    )]
    
    # Sort files by importance (you can customize this logic)
    # For example, prioritize main files, configuration files, etc.
    def file_importance(file):
        # Lower score means higher importance
        if file.path.lower() in ['main.py', 'app.py', 'index.js', 'package.json', 'config.json']:
            return 0
        if 'test' in file.path.lower() or 'spec' in file.path.lower():
            return 3
        if file.path.endswith(('.py', '.js', '.ts', '.java', '.go')):
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
        status_text.text(f"Analyzing file {i+1}/{file_count}: {file.path}")
        
        try:
            content = repo.get_contents(file.path, ref=default_branch)
            decoded_content = base64.b64decode(content.content).decode()
            
            # Summarize the file content
            summary = summarize_file(file.path, decoded_content)
            summary_tokens = estimate_tokens(summary, token_estimation_model)
            
            # Check if adding this summary would exceed our token limit
            if total_tokens + summary_tokens > analysis_token_limit:
                # If we're about to exceed the limit, add a note and stop processing
                file_summaries["info"].append(f"Analysis truncated: {file_count - i} more files not analyzed due to token limit.")
                break
            
            file_summaries[file.path.split('.')[-1]].append(summary)
            total_tokens += summary_tokens
            processed_files += 1
        except Exception as e:
            # Skip files that can't be decoded
            continue
    
    # Clear progress indicators
    progress_bar.empty()
    status_text.empty()
    

    return get_system_description(repo_name, readme_content, file_summaries)

def analyze_local_repo(repo_path):

    # Initialize the repository object
    repo = Repo(repo_path)

    # Ensure it's a valid repository
    if not repo.bare:
        print(f"Repository at {repo_path} is loaded successfully.")

        # Get the active branch
        active_branch = repo.active_branch
        print(f"Active Branch: {active_branch}")

        # Get the latest commit
        latest_commit = repo.head.commit
        print(f"Latest Commit: {latest_commit.message.strip()} by {latest_commit.author.name}")

        # Analyze files
        file_summaries = defaultdict(list)
        total_chars = 0
        char_limit = 100000  # Adjust this based on your model's token limit
        readme_content = ""

        for item in repo.tree().traverse():
            if item.name == 'readme.md':
                with open(item.path, 'r', encoding='utf-8', errors='ignore') as file:
                    readme_content = file.read()
            elif item.type == "blob" and item.path.endswith(('.py', '.js', '.ts', '.html', '.css', '.java', '.go', '.rb')):
                with open(item.path, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()
                
                # Summarize the file content
                summary = summarize_file(file, content)
                file_summaries[file.name.split('.')[-1]].append(summary)
                
                total_chars += len(summary)
                if total_chars > char_limit:
                    break

        return get_system_description(repo, readme_content, file_summaries)

def get_system_description(repo_name, readme_content, file_summaries):

    # Compile the analysis into a system description
    system_description = f"Repository: {repo_name}\n\n"
    
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
    system_description += f"\nRepository Analysis Summary:\n"
    system_description += f"- Files analyzed: {processed_files} of {file_count} total files\n"
    system_description += f"- Token usage estimate: ~{estimated_total_tokens} tokens\n"
    system_description += f"- Token limit configured: {token_limit} tokens\n"
    
    # Show a warning if we're close to the token limit
    if estimated_total_tokens > token_limit * 0.9:
        st.warning(f"⚠️ The GitHub analysis is using approximately {estimated_total_tokens} tokens, which is close to your configured limit of {token_limit}. Consider increasing the token limit in the sidebar settings if you need more comprehensive analysis.")
    
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
    file_ext = file_path.split('.')[-1].lower() if '.' in file_path else ''
    
    # Initialize summary
    summary = f"File: {file_path}\n"
    
    # For very large files, be more selective
    is_large_file = len(content) > 10000
    
    # Extract imports based on file type
    imports = []
    if file_ext in ['py']:
        imports = re.findall(r'^import .*|^from .* import .*', content, re.MULTILINE)
    elif file_ext in ['js', 'ts']:
        imports = re.findall(r'^import .*|^const .* = require\(.*\)|^import .* from .*', content, re.MULTILINE)
    elif file_ext in ['java']:
        imports = re.findall(r'^import .*;', content, re.MULTILINE)
    elif file_ext in ['go']:
        imports = re.findall(r'^import \(.*?\)|^import ".*"', content, re.MULTILINE | re.DOTALL)
    
    # Extract functions based on file type
    functions = []
    if file_ext in ['py']:
        functions = re.findall(r'def .*\(.*\):', content, re.MULTILINE)
    elif file_ext in ['js', 'ts']:
        functions = re.findall(r'function .*\(.*\) {|const .* = \(.*\) =>|.*: function\(.*\)', content, re.MULTILINE)
    elif file_ext in ['java', 'c', 'cpp', 'cs']:
        functions = re.findall(r'(public|private|protected|static|\s) +[\w\<\>\[\]]+\s+(\w+) *\([^\)]*\) *(\{?|[^;])', content, re.MULTILINE)
        functions = [' '.join(f).strip() for f in functions]
    elif file_ext in ['go']:
        functions = re.findall(r'func .*\(.*\).*{', content, re.MULTILINE)
    
    # Extract classes based on file type
    classes = []
    if file_ext in ['py']:
        classes = re.findall(r'class .*:', content, re.MULTILINE)
    elif file_ext in ['js', 'ts']:
        classes = re.findall(r'class .* {', content, re.MULTILINE)
    elif file_ext in ['java', 'c', 'cpp', 'cs']:
        classes = re.findall(r'(public|private|protected|static|\s) +(class|interface) +(\w+)', content, re.MULTILINE)
        classes = [' '.join(c).strip() for c in classes]
    
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
    if file_ext in ['json', 'yaml', 'yml', 'toml', 'ini']:
        # Just include a snippet of the beginning for config files
        config_preview = content[:500] + ("..." if len(content) > 500 else "")
        summary += "Configuration Content Preview:\n" + config_preview + "\n"
    
    # For README or documentation files, include a brief excerpt
    if 'readme' in file_path.lower() or file_ext in ['md', 'rst', 'txt']:
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
    if os.path.exists('.env'):
        load_dotenv('.env')
    
    # Load GitHub API key from environment variable
    github_api_key = os.getenv('GITHUB_API_KEY')
    if github_api_key:
        st.session_state['github_api_key'] = github_api_key

    # Load other API keys if needed
    openai_api_key = os.getenv('OPENAI_API_KEY')
    if openai_api_key:
        st.session_state['openai_api_key'] = openai_api_key

    anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
    if anthropic_api_key:
        st.session_state['anthropic_api_key'] = anthropic_api_key

    azure_api_key = os.getenv('AZURE_API_KEY')
    if azure_api_key:
        st.session_state['azure_api_key'] = azure_api_key

    azure_api_endpoint = os.getenv('AZURE_API_ENDPOINT')
    if azure_api_endpoint:
        st.session_state['azure_api_endpoint'] = azure_api_endpoint

    azure_deployment_name = os.getenv('AZURE_DEPLOYMENT_NAME')
    if azure_deployment_name:
        st.session_state['azure_deployment_name'] = azure_deployment_name

    google_api_key = os.getenv('GOOGLE_API_KEY')
    if google_api_key:
        st.session_state['google_api_key'] = google_api_key

    mistral_api_key = os.getenv('MISTRAL_API_KEY')
    if mistral_api_key:
        st.session_state['mistral_api_key'] = mistral_api_key

    groq_api_key = os.getenv('GROQ_API_KEY')
    if groq_api_key:
        st.session_state['groq_api_key'] = groq_api_key

    # Add Ollama endpoint configuration
    ollama_endpoint = os.getenv('OLLAMA_ENDPOINT', 'http://localhost:11434')
    st.session_state['ollama_endpoint'] = ollama_endpoint

    # Add LM Studio Server endpoint configuration
    lm_studio_endpoint = os.getenv('LM_STUDIO_ENDPOINT', 'http://localhost:1234')
    st.session_state['lm_studio_endpoint'] = lm_studio_endpoint

def generate_threat_model(app_type, authentication, internet_facing, sensitive_data, app_input,
                          provider, model, key, azure_api_endpoint=None, azure_api_version=None, azure_deployment_name=None, ollama_host='localhost'):

    threat_model_prompt = create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)

    print(f"Threat Model Prompt:\n\n{threat_model_prompt}")

    max_retries = 3
    retry_count = 0
    while retry_count < max_retries:
        try:
            # Call the relevant get_threat_model function with the generated prompt
            if provider == PROVIDERS['azure']:
                model_output =  get_threat_model_azure(azure_api_endpoint, key, azure_api_version, azure_deployment_name, threat_model_prompt)
            elif provider == PROVIDERS['openai']:
                model_output =  get_threat_model(key, model, threat_model_prompt)
            elif provider == PROVIDERS['google']:
                model_output =  get_threat_model_google(key, model, threat_model_prompt)
            elif provider == PROVIDERS['mistral']:
                model_output =  get_threat_model_mistral(key, model, threat_model_prompt)
            elif provider == PROVIDERS['ollama']:
                model_output =  get_threat_model_ollama(model, threat_model_prompt,ollama_host)

            print(f"Model Ouput: \n\n {model_output}")
            
            return model_output
            
        except Exception as e:
            retry_count += 1
            if retry_count == max_retries:
                raise Exception(f"Error generating threat model after {max_retries} attempts: {e}")
            else:
                print(f"Error generating threat model. Retrying attempt {retry_count+1}/{max_retries}...")


if __name__ == "__main__":
    # Call this function at the start of your app
    load_env_variables()

# ------------------ Model Token Limits ------------------ #

# Define token limits for specific model+provider combinations
# Format: {"provider:model": {"default": default_value, "max": max_value}}
model_token_limits = {
    # OpenAI models
    "OpenAI API:gpt-4.5-preview": {"default": 64000, "max": 128000},
    "OpenAI API:gpt-4o": {"default": 64000, "max": 128000},
    "OpenAI API:gpt-4o-mini": {"default": 64000, "max": 128000},
    "OpenAI API:o1": {"default": 64000, "max": 200000},
    "OpenAI API:o3-mini": {"default": 64000, "max": 200000},
    
    # Claude models
    "Anthropic API:claude-3-7-sonnet-latest": {"default": 64000, "max": 200000},
    "Anthropic API:claude-3-7-sonnet-thinking": {"default": 64000, "max": 200000},
    "Anthropic API:claude-3-5-sonnet-latest": {"default": 64000, "max": 200000},
    "Anthropic API:claude-3-5-haiku-latest": {"default": 64000, "max": 200000},
    
    # Mistral models
    "Mistral API:mistral-large-latest": {"default": 64000, "max": 131000},
    "Mistral API:mistral-small-latest": {"default": 16000, "max": 32000},
    
    # Google models
    "Google AI API:gemini-2.0-flash": {"default": 120000, "max": 1000000},
    "Google AI API:gemini-2.0-flash-lite": {"default": 120000, "max": 1000000},
    "Google AI API:gemini-1.5-pro": {"default": 240000, "max": 2000000},
    
    # Groq models
    "Groq API:deepseek-r1-distill-llama-70b": {"default": 64000, "max": 128000},
    "Groq API:llama-3.3-70b-versatile": {"default": 64000, "max": 128000},
    "Groq API:llama-3.1-8b-instant": {"default": 64000, "max": 128000},
    "Groq API:mixtral-8x7b-32768": {"default": 16000, "max": 32000},
    "Groq API:gemma-9b-it": {"default": 4000, "max": 8192},
    
    # Azure models - conservative defaults
    "Azure OpenAI Service:default": {"default": 64000, "max": 128000},
    
    # Ollama and LM Studio - conservative defaults
    "Ollama:default": {"default": 8000, "max": 32000},
    "LM Studio Server:default": {"default": 8000, "max": 32000}
}

    st.set_page_config(
        page_title="STRIDE GPT",
        page_icon=":shield:",
        layout="wide",
        initial_sidebar_state="expanded",
    )

# Define callback for model provider change
def on_model_provider_change():
    """Update token limit and selected model when model provider changes"""
    # Get the new model provider
    new_provider = st.session_state.model_provider
    
    # Set the token limit to the default for the new provider
    provider_key = f"{new_provider}:default"
    if provider_key in model_token_limits:
        st.session_state.token_limit = model_token_limits[provider_key]["default"]
    else:
        # Fallback to a conservative default
        st.session_state.token_limit = 8000
    
    # Reset the current_model_key to force token limit update in Advanced Settings
    if 'current_model_key' in st.session_state:
        del st.session_state.current_model_key
    
    # Update the selected model based on the new provider
    # This ensures that when provider changes, we reset the model selection
    # which will trigger the on_model_selection_change callback
    if new_provider == "OpenAI API":
        st.session_state.selected_model = "gpt-4o"
    elif new_provider == "Anthropic API":
        st.session_state.selected_model = "claude-3-7-sonnet-latest"
    elif new_provider == "Azure OpenAI Service":
        # Use whatever the first Azure model is in your UI
        pass  # Will use the default selected in the UI
    elif new_provider == "Google AI API":
        st.session_state.selected_model = "gemini-2.0-flash"
    elif new_provider == "Mistral API":
        st.session_state.selected_model = "mistral-large-latest"
    elif new_provider == "Groq API":
        st.session_state.selected_model = "llama-3.3-70b-versatile"
    # For Ollama and LM Studio, we don't set a default as they depend on locally available models

# Define callback for model selection change
def on_model_selection_change():
    """Update token limit when specific model is selected"""
    # Only proceed if we have both a model provider and a selected model
    if 'model_provider' not in st.session_state or 'selected_model' not in st.session_state:
        return
    
    model_provider = st.session_state.model_provider
    selected_model = st.session_state.selected_model
    
    # Create the key for lookup
    model_key = f"{model_provider}:{selected_model}"
    
    # If we have a specific limit for this model, use it
    if model_key in model_token_limits:
        st.session_state.token_limit = model_token_limits[model_key]["default"]
    else:
        # Otherwise use a provider default
        provider_key = f"{model_provider}:default"
        if provider_key in model_token_limits:
            st.session_state.token_limit = model_token_limits[provider_key]["default"]
    
    # Reset the current_model_key to force token limit update in Advanced Settings
    if 'current_model_key' in st.session_state:
        del st.session_state.current_model_key

# ------------------ Sidebar ------------------ #

    st.sidebar.image("logo.png")

    # Add instructions on how to use the app to the sidebar
    st.sidebar.header("How to use STRIDE GPT")

with st.sidebar:
    # Add model selection input field to the sidebar
    model_provider = st.selectbox(
        "Select your preferred model provider:",
        ["OpenAI API", "Anthropic API", "Azure OpenAI Service", "Google AI API", "Mistral API", "Groq API", "Ollama", "LM Studio Server"],
        key="model_provider",
        on_change=on_model_provider_change,
        help="Select the model provider you would like to use. This will determine the models available for selection.",
    )

        if model_provider == "OpenAI API":
            st.markdown(
            """
        1. Enter your [OpenAI API key](https://platform.openai.com/account/api-keys) and chosen model below 🔑
        2. Provide details of the application that you would like to threat model  📝
        3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
        """
        )
            # Add OpenAI API key input field to the sidebar
            openai_api_key = st.text_input(
                "Enter your OpenAI API key:",
                value=st.session_state.get('openai_api_key', ''),
                type="password",
                help="You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).",
            )
            if openai_api_key:
                st.session_state['openai_api_key'] = openai_api_key

        # Add model selection input field to the sidebar
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["gpt-4.5-preview", "gpt-4o", "gpt-4o-mini", "o1", "o3-mini"],
            key="selected_model",
            on_change=on_model_selection_change,
            help="GPT-4.5 is a preview of OpenAI's latest model. o1 and o3-mini are reasoning models that perform complex reasoning before they provide a response."
        )

    if model_provider == "Anthropic API":
        st.markdown(
        """
    1. Enter your [Anthropic API key](https://console.anthropic.com/settings/keys) and chosen model below 🔑
    2. Provide details of the application that you would like to threat model  📝
    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
    """
    )
        # Add Anthropic API key input field to the sidebar
        anthropic_api_key = st.text_input(
            "Enter your Anthropic API key:",
            value=st.session_state.get('anthropic_api_key', ''),
            type="password",
            help="You can find your Anthropic API key on the [Anthropic console](https://console.anthropic.com/settings/keys).",
        )
        if anthropic_api_key:
            st.session_state['anthropic_api_key'] = anthropic_api_key

        # Add model selection input field to the sidebar
        anthropic_model = st.selectbox(
            "Select the model you would like to use:",
            ["claude-3-7-sonnet-latest", "claude-3-7-sonnet-thinking", "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest"],
            key="selected_model",
            on_change=on_model_selection_change,
            help="Select 'claude-3-7-sonnet-thinking' to use Claude's extended thinking mode for enhanced reasoning capabilities."
        )

        if model_provider == "Azure OpenAI Service":
            st.markdown(
            """
        1. Enter your Azure OpenAI API key, endpoint and deployment name below 🔑
        2. Provide details of the application that you would like to threat model  📝
        3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
        """
        )

            # Add Azure OpenAI API key input field to the sidebar
            azure_api_key = st.text_input(
                "Azure OpenAI API key:",
                value=st.session_state.get('azure_api_key', ''),
                type="password",
                help="You can find your Azure OpenAI API key on the [Azure portal](https://portal.azure.com/).",
            )
            if azure_api_key:
                st.session_state['azure_api_key'] = azure_api_key
            
            # Add Azure OpenAI endpoint input field to the sidebar
            azure_api_endpoint = st.text_input(
                "Azure OpenAI endpoint:",
                value=st.session_state.get('azure_api_endpoint', ''),
                help="Example endpoint: https://YOUR_RESOURCE_NAME.openai.azure.com/",
            )
            if azure_api_endpoint:
                st.session_state['azure_api_endpoint'] = azure_api_endpoint

            # Add Azure OpenAI deployment name input field to the sidebar
            azure_deployment_name = st.text_input(
                "Deployment name:",
                value=st.session_state.get('azure_deployment_name', ''),
            )
            if azure_deployment_name:
                st.session_state['azure_deployment_name'] = azure_deployment_name
            
            st.info("Please note that you must use an 1106-preview model deployment.")

            azure_api_version = '2023-12-01-preview' # Update this as needed

            st.write(f"Azure API Version: {azure_api_version}")

    if model_provider == "Google AI API":
        st.markdown(
        """
    1. Enter your [Google AI API key](https://makersuite.google.com/app/apikey) and chosen model below 🔑
    2. Provide details of the application that you would like to threat model  📝
    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
    """
    )
        # Add Google API key input field to the sidebar
        google_api_key = st.text_input(
            "Enter your Google AI API key:",
            value=st.session_state.get('google_api_key', ''),
            type="password",
            help="You can generate a Google AI API key in the [Google AI Studio](https://makersuite.google.com/app/apikey).",
        )
        if google_api_key:
            st.session_state['google_api_key'] = google_api_key

        # Add model selection input field to the sidebar
        google_model = st.selectbox(
            "Select the model you would like to use:",
            ["gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-pro"],
            key="selected_model",
            on_change=on_model_selection_change,
            help="Gemini 2.0 Flash is the most capable model, while Gemini 2.0 Flash Lite is more cost-effective."
        )

    if model_provider == "Mistral API":
        st.markdown(
        """
    1. Enter your [Mistral API key](https://console.mistral.ai/api-keys/) and chosen model below 🔑
    2. Provide details of the application that you would like to threat model  📝
    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
    """
    )
        # Add Mistral API key input field to the sidebar
        mistral_api_key = st.text_input(
            "Enter your Mistral API key:",
            value=st.session_state.get('mistral_api_key', ''),
            type="password",
            help="You can generate a Mistral API key in the [Mistral console](https://console.mistral.ai/api-keys/).",
        )
        if mistral_api_key:
            st.session_state['mistral_api_key'] = mistral_api_key

        # Add model selection input field to the sidebar
        mistral_model = st.selectbox(
            "Select the model you would like to use:",
            ["mistral-large-latest", "mistral-small-latest"],
            key="selected_model",
            on_change=on_model_selection_change,
            help="Mistral Large is the most capable model, while Mistral Small is more cost-effective."
        )

    if model_provider == "Ollama":
        st.markdown(
        """
    1. Configure your Ollama endpoint below (defaults to http://localhost:11434) 🔧
    2. Provide details of the application that you would like to threat model 📝
    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
    """
    )
        # Add Ollama endpoint configuration field
        ollama_endpoint = st.text_input(
            "Enter your Ollama endpoint:",
            value=st.session_state.get('ollama_endpoint', 'http://localhost:11434'),
            help="The URL of your Ollama instance. Default is http://localhost:11434 for local installations.",
        )
        if ollama_endpoint:
            # Basic URL validation
            if not ollama_endpoint.startswith(('http://', 'https://')):
                st.error("Endpoint URL must start with http:// or https://")
            else:
                st.session_state['ollama_endpoint'] = ollama_endpoint
                # Fetch available models from Ollama
                available_models = get_ollama_models(ollama_endpoint)

        # Add model selection input field
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            available_models if ollama_endpoint and ollama_endpoint.startswith(('http://', 'https://')) else ["local-model"],
            key="selected_model",
            on_change=on_model_selection_change,
            help="Select a model from your local Ollama instance. If you don't see any models, make sure Ollama is running and has models installed."
        )

    if model_provider == "LM Studio Server":
        st.markdown(
        """
    1. Configure your LM Studio Server endpoint below (defaults to http://localhost:1234) 🔧
    2. Provide details of the application that you would like to threat model 📝
    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
    """
    )
        # Add LM Studio Server endpoint configuration field
        lm_studio_endpoint = st.text_input(
            "Enter your LM Studio Server endpoint:",
            value=st.session_state.get('lm_studio_endpoint', 'http://localhost:1234'),
            help="The URL of your LM Studio Server instance. Default is http://localhost:1234 for local installations.",
        )
        if lm_studio_endpoint:
            # Basic URL validation
            if not lm_studio_endpoint.startswith(('http://', 'https://')):
                st.error("Endpoint URL must start with http:// or https://")
            else:
                st.session_state['lm_studio_endpoint'] = lm_studio_endpoint
                # Fetch available models from LM Studio Server
                available_models = get_lm_studio_models(lm_studio_endpoint)

        # Add model selection input field
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            available_models if lm_studio_endpoint and lm_studio_endpoint.startswith(('http://', 'https://')) else ["local-model"],
            key="selected_model",
            on_change=on_model_selection_change,
            help="Select a model from your local LM Studio Server. If you don't see any models, make sure LM Studio Server is running with models loaded."
        )

    if model_provider == "Groq API":
        st.markdown(
        """
    1. Enter your [Groq API key](https://console.groq.com/keys) and chosen model below 🔑
    2. Provide details of the application that you would like to threat model  📝
    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
    """
    )
        # Add Groq API key input field to the sidebar
        groq_api_key = st.text_input(
            "Enter your Groq API key:",
            value=st.session_state.get('groq_api_key', ''),
            type="password",
            help="You can find your Groq API key in the [Groq console](https://console.groq.com/keys).",
        )
        if groq_api_key:
            st.session_state['groq_api_key'] = groq_api_key

        # Add model selection input field to the sidebar
        groq_model = st.selectbox(
            "Select the model you would like to use:",
            [
                "deepseek-r1-distill-llama-70b",
                "llama-3.3-70b-versatile",
                "llama-3.1-8b-instant",
                "mixtral-8x7b-32768",
                "gemma-9b-it"
            ],
            key="selected_model",
            on_change=on_model_selection_change,
            help="Select from Groq's supported models. The Llama 3.3 70B Versatile model is recommended for best results."
        )

    # Add GitHub API key input field to the sidebar
    github_api_key = st.text_input(
        "Enter your GitHub API key (optional):",
        value=st.session_state.get('github_api_key', ''),
        type="password",
        help="You can find or create your GitHub API key in your GitHub account settings under Developer settings > Personal access tokens.",
    )

        # Store the GitHub API key in session state
        if github_api_key:
            st.session_state['github_api_key'] = github_api_key

    # Add Advanced Settings section with token limit configuration
    with st.expander("Advanced Settings"):
    
        # Get the current model provider and selected model
        current_provider = st.session_state.get('model_provider', 'OpenAI API')
        current_model = st.session_state.get('selected_model', '')
        
        # Create the key for lookup
        model_key = f"{current_provider}:{current_model}"
        
        # Get the max token limit for the current model
        max_token_limit = 128000  # Default max
        default_token_limit = 64000  # Default value
        
        if model_key in model_token_limits:
            max_token_limit = model_token_limits[model_key]["max"]
            default_token_limit = model_token_limits[model_key]["default"]
        else:
            # Try provider default
            provider_key = f"{current_provider}:default"
            if provider_key in model_token_limits:
                max_token_limit = model_token_limits[provider_key]["max"]
                default_token_limit = model_token_limits[provider_key]["default"]
        
        # Store the current model and provider to detect changes
        current_model_key = st.session_state.get('current_model_key', '')
        
        # If token_limit is not set or the model/provider has changed, update the token limit
        if 'token_limit' not in st.session_state or current_model_key != model_key:
            st.session_state.token_limit = default_token_limit
            st.session_state.current_model_key = model_key
        
        # Add token limit slider with fixed minimum and dynamic maximum
        token_limit = st.slider(
            "Maximum token limit for GitHub analysis:",
            min_value=4000,  # Fixed minimum as requested
            max_value=max_token_limit,
            value=st.session_state.token_limit,  # Use the current value from session state
            step=1000,
            help="Set the maximum number of tokens to use for GitHub repository analysis. This helps prevent exceeding your model's context window."
        )
        
        # Store the token limit in session state
        st.session_state['token_limit'] = token_limit

    st.markdown("---")

    # Add sections to the sidebar
    with st.sidebar:
        st.markdown(ABOUT_SECTION)
        st.markdown(EXAMPLE_APPLICATION_SECTION)
        st.markdown(FAQ_SECTION)

    # ------------------ Main App UI ------------------ #

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Threat Model", "Attack Tree", "Mitigations", "DREAD", "Test Cases"])

    with tab1:
        st.markdown(THREAT_MODEL_SECTION)
        st.markdown("""---""")
        
        # Two column layout for the main app content
        col1, col2 = st.columns([1, 1])

        # Initialize app_input in the session state if it doesn't exist
        if 'app_input' not in st.session_state:
            st.session_state['app_input'] = ''

    # If model provider is OpenAI API and the model is gpt-4o or gpt-4o-mini
    with col1:
        if model_provider == "OpenAI API" and selected_model in ["gpt-4o", "gpt-4o-mini"]:
            uploaded_file = st.file_uploader("Upload architecture diagram", type=["jpg", "jpeg", "png"])

                if uploaded_file is not None:
                    if not openai_api_key:
                        st.error("Please enter your OpenAI API key to analyse the image.")
                    else:
                        if 'uploaded_file' not in st.session_state or st.session_state.uploaded_file != uploaded_file:
                            st.session_state.uploaded_file = uploaded_file
                            with st.spinner("Analysing the uploaded image..."):
                                def encode_image(uploaded_file):
                                    return base64.b64encode(uploaded_file.read()).decode('utf-8')

                                base64_image = encode_image(uploaded_file)

                                image_analysis_prompt = create_image_analysis_prompt()

                            try:
                                image_analysis_output = get_image_analysis(openai_api_key, selected_model, image_analysis_prompt, base64_image)
                                if image_analysis_output and 'choices' in image_analysis_output and image_analysis_output['choices'][0]['message']['content']:
                                    image_analysis_content = image_analysis_output['choices'][0]['message']['content']
                                    st.session_state.image_analysis_content = image_analysis_content
                                    # Update app_input session state
                                    st.session_state['app_input'] = image_analysis_content
                                else:
                                    st.error("Failed to analyze the image. Please check the API key and try again.")
                            except KeyError as e:
                                st.error("Failed to analyze the image. Please check the API key and try again.")
                            except Exception as e:
                                st.error("An unexpected error occurred while analyzing the image.")

            # Use the get_input() function to get the application description and GitHub URL
            app_input = get_input()
            # Update session state only if the text area content has changed
            if app_input != st.session_state['app_input']:
                st.session_state['app_input'] = app_input

        # Ensure app_input is always up to date in the session state
        app_input = st.session_state['app_input']



            # Create input fields for additional details
        with col2:
                app_type = st.selectbox(
                    label=ARG_HELPERS['application-type'],
                    options=APPLICATION_TYPES,
                    key="app_type",
                )

                sensitive_data = st.selectbox(
                    label=ARG_HELPERS['sensitive-data'],
                    options=CLASSIFICATION_LEVELS,
                    key="sensitive_data",
                )

            # Create input fields for internet_facing and authentication
                internet_facing = st.selectbox(
                    label=ARG_HELPERS['internet-facing'],
                    options=INTERNET_FACING,
                    key="internet_facing",
                )

                authentication = st.multiselect(
                    ARG_HELPERS['authentication'],
                    AUTHENTICATION_METHODS,
                    key="authentication",
                )



        # ------------------ Threat Model Generation ------------------ #

        # Create a submit button for Threat Modelling
        threat_model_submit_button = st.button(label="Generate Threat Model")

        # If the Generate Threat Model button is clicked and the user has provided an application description
        if threat_model_submit_button and st.session_state.get('app_input'):
            app_input = st.session_state['app_input']  # Retrieve from session state

        # Clear thinking content when switching models or starting a new operation
        if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
            st.session_state.pop('last_thinking_content', None)

        # Show a spinner while generating the threat model
        with st.spinner("Analysing potential threats..."):
            max_retries = 3
            retry_count = 0
            while retry_count < max_retries:
                try:
                    # Call the relevant get_threat_model function with the generated prompt
                    if model_provider == "Azure OpenAI Service":
                        model_output = get_threat_model_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, threat_model_prompt)
                    elif model_provider == "OpenAI API":
                        model_output = get_threat_model(openai_api_key, selected_model, threat_model_prompt)
                    elif model_provider == "Google AI API":
                        model_output = get_threat_model_google(google_api_key, google_model, threat_model_prompt)
                    elif model_provider == "Mistral API":
                        model_output = get_threat_model_mistral(mistral_api_key, mistral_model, threat_model_prompt)
                    elif model_provider == "Ollama":
                        model_output = get_threat_model_ollama(st.session_state['ollama_endpoint'], selected_model, threat_model_prompt)
                    elif model_provider == "Anthropic API":
                        model_output = get_threat_model_anthropic(anthropic_api_key, anthropic_model, threat_model_prompt)
                        # Check if we got a fallback response
                        if model_output.get("threat_model") and len(model_output["threat_model"]) == 1 and model_output["threat_model"][0].get("Threat Type") == "Error":
                            st.warning("⚠️ There was an issue generating the threat model. The model may have returned a response in an unexpected format. You can try:")
                            st.markdown("1. Running the generation again")
                            st.markdown("2. Checking the application logs for more details")
                            st.markdown("3. Using a different model if the issue persists")
                    elif model_provider == "LM Studio Server":
                        model_output = get_threat_model_lm_studio(st.session_state['lm_studio_endpoint'], selected_model, threat_model_prompt)
                    elif model_provider == "Groq API":
                        model_output = get_threat_model_groq(groq_api_key, groq_model, threat_model_prompt)

                    # Access the threat model and improvement suggestions from the parsed content
                    threat_model = model_output.get("threat_model", [])
                    improvement_suggestions = model_output.get("improvement_suggestions", [])

                    # Save the threat model to the session state for later use in mitigations
                    st.session_state['threat_model'] = threat_model

                    # Convert the threat model JSON to Markdown
                    markdown_output = json_to_markdown(threat_model, improvement_suggestions)

        # Display thinking content in an expander if available and using Claude thinking mode
        if ('last_thinking_content' in st.session_state and 
            st.session_state['last_thinking_content'] and 
            model_provider == "Anthropic API" and 
            "thinking" in anthropic_model.lower()):
            with st.expander("View Claude's thinking process"):
                st.markdown(st.session_state['last_thinking_content'])

        # Display the threat model in Markdown
        st.markdown(markdown_output)
        
        # Add a button to allow the user to download the output as a Markdown file
        st.download_button(
            label="Download Threat Model",
            data=markdown_output,
            file_name="threat_model.md",
            mime="text/markdown",
        )
        
# If the submit button is clicked and the user has not provided an application description
if threat_model_submit_button and not st.session_state.get('app_input'):
    st.error("Please enter your application details before submitting.")



    # ------------------ Attack Tree Generation ------------------ #

with tab2:
    st.markdown("""
Attack trees are a structured way to analyse the security of a system. They represent potential attack scenarios in a hierarchical format, 
with the ultimate goal of an attacker at the root and various paths to achieve that goal as branches. This helps in understanding system 
vulnerabilities and prioritising mitigation efforts.
""")
    st.markdown("""---""")
    if model_provider == "Mistral API" and mistral_model == "mistral-small-latest":
        st.warning("⚠️ Mistral Small doesn't reliably generate syntactically correct Mermaid code. Please use the Mistral Large model for generating attack trees, or select a different model provider.")
    else:
        if model_provider in ["Ollama", "LM Studio Server"]:
            st.warning("⚠️ Users may encounter syntax errors when generating attack trees using local LLMs. Experiment with different local LLMs to assess their output quality, or consider using a hosted model provider to generate attack trees.")
        
        # Create a submit button for Attack Tree
        attack_tree_submit_button = st.button(label="Generate Attack Tree")
        
        # If the Generate Attack Tree button is clicked and the user has provided an application description
        if attack_tree_submit_button and st.session_state.get('app_input'):
            app_input = st.session_state.get('app_input')
            # Generate the prompt using the create_attack_tree_prompt function
            attack_tree_prompt = create_attack_tree_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)

            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop('last_thinking_content', None)

            # Show a spinner while generating the attack tree
            with st.spinner("Generating attack tree..."):
                try:
                    # Call the relevant get_attack_tree function with the generated prompt
                    if model_provider == "Azure OpenAI Service":
                        mermaid_code = get_attack_tree_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, attack_tree_prompt)
                    elif model_provider == "OpenAI API":
                        mermaid_code = get_attack_tree(openai_api_key, selected_model, attack_tree_prompt)
                    elif model_provider == "Google AI API":
                        mermaid_code = get_attack_tree_google(google_api_key, google_model, attack_tree_prompt)
                    elif model_provider == "Mistral API":
                        mermaid_code = get_attack_tree_mistral(mistral_api_key, mistral_model, attack_tree_prompt)
                    elif model_provider == "Ollama":
                        mermaid_code = get_attack_tree_ollama(st.session_state['ollama_endpoint'], selected_model, attack_tree_prompt)
                    elif model_provider == "Anthropic API":
                        mermaid_code = get_attack_tree_anthropic(anthropic_api_key, anthropic_model, attack_tree_prompt)
                    elif model_provider == "LM Studio Server":
                        mermaid_code = get_attack_tree_lm_studio(st.session_state['lm_studio_endpoint'], selected_model, attack_tree_prompt)
                    elif model_provider == "Groq API":
                        mermaid_code = get_attack_tree_groq(groq_api_key, groq_model, attack_tree_prompt)

                    # Display thinking content in an expander if available and using Claude thinking mode
                    if ('last_thinking_content' in st.session_state and 
                        st.session_state['last_thinking_content'] and 
                        model_provider == "Anthropic API" and 
                        "thinking" in anthropic_model.lower()):
                        with st.expander("View Claude's thinking process"):
                            st.markdown(st.session_state['last_thinking_content'])

                        # Display the generated attack tree code
                        st.write("Attack Tree Code:")
                        st.code(mermaid_code)

                        # Visualise the attack tree using the Mermaid custom component
                        st.write("Attack Tree Diagram Preview:")
                        mermaid(mermaid_code)
                        
                        col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
                        
                        with col1:              
                            # Add a button to allow the user to download the Mermaid code
                            st.download_button(
                                label="Download Diagram Code",
                                data=mermaid_code,
                                file_name="attack_tree.md",
                                mime="text/plain",
                                help="Download the Mermaid code for the attack tree diagram."
                            )

                    with col2:
                        # Add a button to allow the user to open the Mermaid Live editor
                        mermaid_live_button = st.link_button("Open Mermaid Live", "https://mermaid.live")
                    
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
        st.markdown("""
    Use this tab to generate potential mitigations for the threats identified in the threat model. Mitigations are security controls or
    countermeasures that can help reduce the likelihood or impact of a security threat. The generated mitigations can be used to enhance
    the security posture of the application and protect against potential attacks.
    """)
        st.markdown("""---""")
        
        # Create a submit button for Mitigations
        mitigations_submit_button = st.button(label="Suggest Mitigations")

        # If the Suggest Mitigations button is clicked and the user has identified threats
        if mitigations_submit_button:
            # Check if threat_model data exists
            if 'threat_model' in st.session_state and st.session_state['threat_model']:
                # Convert the threat_model data into a Markdown list
                threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
                # Generate the prompt using the create_mitigations_prompt function
                mitigations_prompt = create_mitigations_prompt(threats_markdown)

            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop('last_thinking_content', None)

            # Show a spinner while suggesting mitigations
            with st.spinner("Suggesting mitigations..."):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call the relevant get_mitigations function with the generated prompt
                        if model_provider == "Azure OpenAI Service":
                            mitigations_markdown = get_mitigations_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, mitigations_prompt)
                        elif model_provider == "OpenAI API":
                            mitigations_markdown = get_mitigations(openai_api_key, selected_model, mitigations_prompt)
                        elif model_provider == "Google AI API":
                            mitigations_markdown = get_mitigations_google(google_api_key, google_model, mitigations_prompt)
                        elif model_provider == "Mistral API":
                            mitigations_markdown = get_mitigations_mistral(mistral_api_key, mistral_model, mitigations_prompt)
                        elif model_provider == "Ollama":
                            mitigations_markdown = get_mitigations_ollama(st.session_state['ollama_endpoint'], selected_model, mitigations_prompt)
                        elif model_provider == "Anthropic API":
                            mitigations_markdown = get_mitigations_anthropic(anthropic_api_key, anthropic_model, mitigations_prompt)
                        elif model_provider == "LM Studio Server":
                            mitigations_markdown = get_mitigations_lm_studio(st.session_state['lm_studio_endpoint'], selected_model, mitigations_prompt)
                        elif model_provider == "Groq API":
                            mitigations_markdown = get_mitigations_groq(groq_api_key, groq_model, mitigations_prompt)

                        # Display thinking content in an expander if available and using Claude thinking mode
                        if ('last_thinking_content' in st.session_state and 
                            st.session_state['last_thinking_content'] and 
                            model_provider == "Anthropic API" and 
                            "thinking" in anthropic_model.lower()):
                            with st.expander("View Claude's thinking process"):
                                st.markdown(st.session_state['last_thinking_content'])

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
                            st.error(f"Error suggesting mitigations after {max_retries} attempts: {e}")
                            mitigations_markdown = ""
                        else:
                            st.warning(f"Error suggesting mitigations. Retrying attempt {retry_count+1}/{max_retries}...")
            
            st.markdown("")
        else:
            st.error("Please generate a threat model first before suggesting mitigations.")

# ------------------ DREAD Risk Assessment Generation ------------------ #
with tab4:
    st.markdown("""
DREAD is a method for evaluating and prioritising risks associated with security threats. It assesses threats based on **D**amage potential, 
**R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. This helps in determining the overall risk level and 
focusing on the most critical threats first. Use this tab to perform a DREAD risk assessment for your application / system.
""")
    st.markdown("""---""")
    
    # Create a submit button for DREAD Risk Assessment
    dread_assessment_submit_button = st.button(label="Generate DREAD Risk Assessment")
    # If the Generate DREAD Risk Assessment button is clicked and the user has identified threats
    if dread_assessment_submit_button:
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
            # Generate the prompt using the create_dread_assessment_prompt function
            dread_assessment_prompt = create_dread_assessment_prompt(threats_markdown)
            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop('last_thinking_content', None)

            # Show a spinner while generating DREAD Risk Assessment
            with st.spinner("Generating DREAD Risk Assessment..."):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call the relevant get_dread_assessment function with the generated prompt
                        if model_provider == "Azure OpenAI Service":
                            dread_assessment = get_dread_assessment_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, dread_assessment_prompt)
                        elif model_provider == "OpenAI API":
                            dread_assessment = get_dread_assessment(openai_api_key, selected_model, dread_assessment_prompt)
                        elif model_provider == "Google AI API":
                            dread_assessment = get_dread_assessment_google(google_api_key, google_model, dread_assessment_prompt)
                        elif model_provider == "Mistral API":
                            dread_assessment = get_dread_assessment_mistral(mistral_api_key, mistral_model, dread_assessment_prompt)
                        elif model_provider == "Ollama":
                            dread_assessment = get_dread_assessment_ollama(st.session_state['ollama_endpoint'], selected_model, dread_assessment_prompt)
                        elif model_provider == "Anthropic API":
                            dread_assessment = get_dread_assessment_anthropic(anthropic_api_key, anthropic_model, dread_assessment_prompt)
                        elif model_provider == "LM Studio Server":
                            dread_assessment = get_dread_assessment_lm_studio(st.session_state['lm_studio_endpoint'], selected_model, dread_assessment_prompt)
                        elif model_provider == "Groq API":
                            dread_assessment = get_dread_assessment_groq(groq_api_key, groq_model, dread_assessment_prompt)
                        
                        # Save the DREAD assessment to the session state for later use in test cases
                        st.session_state['dread_assessment'] = dread_assessment
                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(f"Error generating DREAD risk assessment after {max_retries} attempts: {e}")
                            dread_assessment = {"Risk Assessment": []}
                            # Add debug information
                            st.error("Debug: No threats were found in the response. Please try generating the threat model again.")
                        else:
                            st.warning(f"Error generating DREAD risk assessment. Retrying attempt {retry_count+1}/{max_retries}...")
            # Convert the DREAD assessment JSON to Markdown
            dread_assessment_markdown = dread_json_to_markdown(dread_assessment)
            
            # Add debug information about the assessment
            if not dread_assessment.get("Risk Assessment"):
                st.warning("Debug: The DREAD assessment response is empty. Please ensure you have generated a threat model first.")
            
            # Display thinking content in an expander if available and using Claude thinking mode
            if ('last_thinking_content' in st.session_state and 
                st.session_state['last_thinking_content'] and 
                model_provider == "Anthropic API" and 
                "thinking" in anthropic_model.lower()):
                with st.expander("View Claude's thinking process"):
                    st.markdown(st.session_state['last_thinking_content'])
                    
            # Display the DREAD assessment with a header
            st.markdown("## DREAD Risk Assessment")
            st.markdown("The table below shows the DREAD risk assessment for each identified threat. The Risk Score is calculated as the average of the five DREAD categories.")
            
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
            st.error("Please generate a threat model first before requesting a DREAD risk assessment.")


    # ------------------ Test Cases Generation ------------------ #

    with tab5:
        st.markdown("""
    Test cases are used to validate the security of an application and ensure that potential vulnerabilities are identified and 
    addressed. This tab allows you to generate test cases using Gherkin syntax. Gherkin provides a structured way to describe application 
    behaviours in plain text, using a simple syntax of Given-When-Then statements. This helps in creating clear and executable test 
    scenarios.
    """)
        st.markdown("""---""")
                    
        # Create a submit button for Test Cases
        test_cases_submit_button = st.button(label="Generate Test Cases")

        # If the Generate Test Cases button is clicked and the user has identified threats
        if test_cases_submit_button:
            # Check if threat_model data exists
            if 'threat_model' in st.session_state and st.session_state['threat_model']:
                # Convert the threat_model data into a Markdown list
                threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
                # Generate the prompt using the create_test_cases_prompt function
                test_cases_prompt = create_test_cases_prompt(threats_markdown)

            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop('last_thinking_content', None)

            # Show a spinner while generating test cases
            with st.spinner("Generating test cases..."):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call to the relevant get_test_cases function with the generated prompt
                        if model_provider == "Azure OpenAI Service":
                            test_cases_markdown = get_test_cases_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, test_cases_prompt)
                        elif model_provider == "OpenAI API":
                            test_cases_markdown = get_test_cases(openai_api_key, selected_model, test_cases_prompt)
                        elif model_provider == "Google AI API":
                            test_cases_markdown = get_test_cases_google(google_api_key, google_model, test_cases_prompt)
                        elif model_provider == "Mistral API":
                            test_cases_markdown = get_test_cases_mistral(mistral_api_key, mistral_model, test_cases_prompt)
                        elif model_provider == "Ollama":
                            test_cases_markdown = get_test_cases_ollama(st.session_state['ollama_endpoint'], selected_model, test_cases_prompt)
                        elif model_provider == "Anthropic API":
                            test_cases_markdown = get_test_cases_anthropic(anthropic_api_key, anthropic_model, test_cases_prompt)
                        elif model_provider == "LM Studio Server":
                            test_cases_markdown = get_test_cases_lm_studio(st.session_state['lm_studio_endpoint'], selected_model, test_cases_prompt)
                        elif model_provider == "Groq API":
                            test_cases_markdown = get_test_cases_groq(groq_api_key, groq_model, test_cases_prompt)

                        # Display thinking content in an expander if available and using Claude thinking mode
                        if ('last_thinking_content' in st.session_state and 
                            st.session_state['last_thinking_content'] and 
                            model_provider == "Anthropic API" and 
                            "thinking" in anthropic_model.lower()):
                            with st.expander("View Claude's thinking process"):
                                st.markdown(st.session_state['last_thinking_content'])

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
                            st.error(f"Error generating test cases after {max_retries} attempts: {e}")
                            test_cases_markdown = ""
                        else:
                            st.warning(f"Error generating test cases. Retrying attempt {retry_count+1}/{max_retries}...")
            
            st.markdown("")

        else:
            st.error("Please generate a threat model first before requesting test cases.")
=======
#main.py

import base64
import requests
import streamlit as st
import streamlit.components.v1 as components
from github import Github
from git import Repo
from collections import defaultdict
import re
import os
from dotenv import load_dotenv

from threat_model import create_threat_model_prompt, get_threat_model, get_threat_model_azure, get_threat_model_google, get_threat_model_mistral, get_threat_model_ollama, json_to_markdown, get_image_analysis, create_image_analysis_prompt
from attack_tree import create_attack_tree_prompt, get_attack_tree, get_attack_tree_azure, get_attack_tree_mistral, get_attack_tree_ollama
from mitigations import create_mitigations_prompt, get_mitigations, get_mitigations_azure, get_mitigations_google, get_mitigations_mistral, get_mitigations_ollama
from test_cases import create_test_cases_prompt, get_test_cases, get_test_cases_azure, get_test_cases_google, get_test_cases_mistral, get_test_cases_ollama
from dread import create_dread_assessment_prompt, get_dread_assessment, get_dread_assessment_azure, get_dread_assessment_google, get_dread_assessment_mistral, get_dread_assessment_ollama, dread_json_to_markdown

from config import (  # Importing strings
    ABOUT_SECTION,
    EXAMPLE_APPLICATION_SECTION,
    FAQ_SECTION,
    THREAT_MODEL_SECTION,
    COMBINED_MARKDOWN,
    PROVIDERS,
    APPLICATION_TYPES,
    CLASSIFICATION_LEVELS,
    AUTHENTICATION_METHODS,
    ARG_HELPERS,
    INTERNET_FACING,
)

# ------------------ Helper Functions ------------------ #

# Function to get user input for the application description and key details
def get_input():
    github_url = st.text_input(
        label="Enter GitHub repository URL (optional)",
        placeholder="https://github.com/owner/repo",
        key="github_url",
        help="Enter the URL of the GitHub repository you want to analyze.",
    )

    if github_url and github_url != st.session_state.get('last_analyzed_url', ''):
        if 'github_api_key' not in st.session_state or not st.session_state['github_api_key']:
            st.warning("Please enter a GitHub API key to analyze the repository.")
        else:
            with st.spinner('Analyzing GitHub repository...'):
                system_description = analyze_github_repo(github_url, st.session_state.get('github_api_key', ''))
                st.session_state['github_analysis'] = system_description
                st.session_state['last_analyzed_url'] = github_url
                st.session_state['app_input'] = system_description + "\n\n" + st.session_state.get('app_input', '')

    input_text = st.text_area(
        label="Describe the application to be modelled",
        value=st.session_state.get('app_input', ''),
        placeholder="Enter your application details...",
        height=300,
        key="app_desc",
        help="Please provide a detailed description of the application, including the purpose of the application, the technologies used, and any other relevant information.",
    )

    st.session_state['app_input'] = input_text

    return input_text

def analyze_github_repo(repo_url, key):
    # Extract owner and repo name from URL
    parts = repo_url.split('/')
    owner = parts[-2]
    repo_name = parts[-1]

    # Initialize PyGithub
    g = Github(key)

    # Get the repository
    repo = g.get_repo(f"{owner}/{repo_name}")

    # Get the default branch
    default_branch = repo.default_branch

    # Get the tree of the default branch
    tree = repo.get_git_tree(default_branch, recursive=True)

    # Analyze files
    file_summaries = defaultdict(list)
    total_chars = 0
    char_limit = 100000  # Adjust this based on your model's token limit
    readme_content = ""

    for file in tree.tree:
        if file.path.lower() == 'readme.md':
            content = repo.get_contents(file.path, ref=default_branch)
            readme_content = base64.b64decode(content.content).decode()
        elif file.type == "blob" and file.path.endswith(('.py', '.js', '.ts', '.html', '.css', '.java', '.go', '.rb')):
            content = repo.get_contents(file.path, ref=default_branch)
            decoded_content = base64.b64decode(content.content).decode()
            
            # Summarize the file content
            summary = summarize_file(file.path, decoded_content)
            file_summaries[file.path.split('.')[-1]].append(summary)
            
            total_chars += len(summary)
            if total_chars > char_limit:
                break

    return get_system_description(repo_name, readme_content, file_summaries)

def analyze_local_repo(repo_path):

    # Initialize the repository object
    repo = Repo(repo_path)

    # Ensure it's a valid repository
    if not repo.bare:
        print(f"Repository at {repo_path} is loaded successfully.")

        # Get the active branch
        active_branch = repo.active_branch
        print(f"Active Branch: {active_branch}")

        # Get the latest commit
        latest_commit = repo.head.commit
        print(f"Latest Commit: {latest_commit.message.strip()} by {latest_commit.author.name}")

        # Analyze files
        file_summaries = defaultdict(list)
        total_chars = 0
        char_limit = 100000  # Adjust this based on your model's token limit
        readme_content = ""

        for item in repo.tree().traverse():
            if item.name == 'readme.md':
                with open(item.path, 'r', encoding='utf-8', errors='ignore') as file:
                    readme_content = file.read()
            elif item.type == "blob" and item.path.endswith(('.py', '.js', '.ts', '.html', '.css', '.java', '.go', '.rb')):
                with open(item.path, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()
                
                # Summarize the file content
                summary = summarize_file(file, content)
                file_summaries[file.name.split('.')[-1]].append(summary)
                
                total_chars += len(summary)
                if total_chars > char_limit:
                    break

        return get_system_description(repo, readme_content, file_summaries)

def get_system_description(repo_name, readme_content, file_summaries):

    # Compile the analysis into a system description
    system_description = f"Repository: {repo_name}\n\n"
    
    if readme_content:
        system_description += "README.md Content:\n"
        # Truncate README if it's too long
        if len(readme_content) > 5000:
            system_description += readme_content[:5000] + "...\n(README truncated due to length)\n\n"
        else:
            system_description += readme_content + "\n\n"

    for file_type, summaries in file_summaries.items():
        system_description += f"{file_type.upper()} Files:\n"
        for summary in summaries:
            system_description += summary + "\n"
        system_description += "\n"

    return system_description

def summarize_file(file_path, content):
    # Extract important parts of the file
    imports = re.findall(r'^import .*|^from .* import .*', content, re.MULTILINE)
    functions = re.findall(r'def .*\(.*\):', content)
    classes = re.findall(r'class .*:', content)

    summary = f"File: {file_path}\n"
    if imports:
        summary += "Imports:\n" + "\n".join(imports[:5]) + "\n"  # Limit to first 5 imports
    if functions:
        summary += "Functions:\n" + "\n".join(functions[:5]) + "\n"  # Limit to first 5 functions
    if classes:
        summary += "Classes:\n" + "\n".join(classes[:5]) + "\n"  # Limit to first 5 classes

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
    if os.path.exists('.env'):
        load_dotenv('.env')
    
    # Load GitHub API key from environment variable
    github_api_key = os.getenv('GITHUB_API_KEY')
    if github_api_key:
        st.session_state['github_api_key'] = github_api_key

    # Load other API keys if needed
    openai_api_key = os.getenv('OPENAI_API_KEY')
    if openai_api_key:
        st.session_state['openai_api_key'] = openai_api_key

    azure_api_key = os.getenv('AZURE_API_KEY')
    if azure_api_key:
        st.session_state['azure_api_key'] = azure_api_key

    azure_api_endpoint = os.getenv('AZURE_API_ENDPOINT')
    if azure_api_endpoint:
        st.session_state['azure_api_endpoint'] = azure_api_endpoint

    azure_deployment_name = os.getenv('AZURE_DEPLOYMENT_NAME')
    if azure_deployment_name:
        st.session_state['azure_deployment_name'] = azure_deployment_name

    google_api_key = os.getenv('GOOGLE_API_KEY')
    if google_api_key:
        st.session_state['google_api_key'] = google_api_key

    mistral_api_key = os.getenv('MISTRAL_API_KEY')
    if mistral_api_key:
        st.session_state['mistral_api_key'] = mistral_api_key

def generate_threat_model(app_type, authentication, internet_facing, sensitive_data, app_input,
                          provider, model, key, azure_api_endpoint=None, azure_api_version=None, azure_deployment_name=None, host='localhost'):

    threat_model_prompt = create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)

    print(f"Threat Model Prompt:\n\n{threat_model_prompt}")

    max_retries = 3
    retry_count = 0
    while retry_count < max_retries:
        try:
            # Call the relevant get_threat_model function with the generated prompt
            if provider == PROVIDERS['azure']:
                model_output =  get_threat_model_azure(azure_api_endpoint, key, azure_api_version, azure_deployment_name, threat_model_prompt)
            elif provider == PROVIDERS['openai']:
                model_output =  get_threat_model(key, model, threat_model_prompt)
            elif provider == PROVIDERS['google']:
                model_output =  get_threat_model_google(key, model, threat_model_prompt)
            elif provider == PROVIDERS['mistral']:
                model_output =  get_threat_model_mistral(key, model, threat_model_prompt)
            elif provider == PROVIDERS['ollama']:
                model_output =  get_threat_model_ollama(model, threat_model_prompt,host)

            print(f"Model Ouput: \n\n {model_output}")
            
            return model_output
            
        except Exception as e:
            retry_count += 1
            if retry_count == max_retries:
                raise Exception(f"Error generating threat model after {max_retries} attempts: {e}")
            else:
                print(f"Error generating threat model. Retrying attempt {retry_count+1}/{max_retries}...")


if __name__ == "__main__":
    # Call this function at the start of your app
    load_env_variables()

    # ------------------ Streamlit UI Configuration ------------------ #

    st.set_page_config(
        page_title="STRIDE GPT",
        page_icon=":shield:",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # ------------------ Sidebar ------------------ #

    st.sidebar.image("logo.png")

    # Add instructions on how to use the app to the sidebar
    st.sidebar.header("How to use STRIDE GPT")

    with st.sidebar:
        # Add model selection input field to the sidebar
        model_provider = st.selectbox(
            "Select your preferred model provider:",
            ["OpenAI API", "Azure OpenAI Service", "Google AI API", "Mistral API", "Ollama"],
            key="model_provider",
            help="Select the model provider you would like to use. This will determine the models available for selection.",
        )

        if model_provider == "OpenAI API":
            st.markdown(
            """
        1. Enter your [OpenAI API key](https://platform.openai.com/account/api-keys) and chosen model below 🔑
        2. Provide details of the application that you would like to threat model  📝
        3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
        """
        )
            # Add OpenAI API key input field to the sidebar
            openai_api_key = st.text_input(
                "Enter your OpenAI API key:",
                value=st.session_state.get('openai_api_key', ''),
                type="password",
                help="You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).",
            )
            if openai_api_key:
                st.session_state['openai_api_key'] = openai_api_key

            # Add model selection input field to the sidebar
            selected_model = st.selectbox(
                "Select the model you would like to use:",
                ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
                key="selected_model",
                help="GPT-4o and GPT-4o mini are OpenAI's latest models and are recommended."
            )

        if model_provider == "Azure OpenAI Service":
            st.markdown(
            """
        1. Enter your Azure OpenAI API key, endpoint and deployment name below 🔑
        2. Provide details of the application that you would like to threat model  📝
        3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
        """
        )

            # Add Azure OpenAI API key input field to the sidebar
            azure_api_key = st.text_input(
                "Azure OpenAI API key:",
                value=st.session_state.get('azure_api_key', ''),
                type="password",
                help="You can find your Azure OpenAI API key on the [Azure portal](https://portal.azure.com/).",
            )
            if azure_api_key:
                st.session_state['azure_api_key'] = azure_api_key
            
            # Add Azure OpenAI endpoint input field to the sidebar
            azure_api_endpoint = st.text_input(
                "Azure OpenAI endpoint:",
                value=st.session_state.get('azure_api_endpoint', ''),
                help="Example endpoint: https://YOUR_RESOURCE_NAME.openai.azure.com/",
            )
            if azure_api_endpoint:
                st.session_state['azure_api_endpoint'] = azure_api_endpoint

            # Add Azure OpenAI deployment name input field to the sidebar
            azure_deployment_name = st.text_input(
                "Deployment name:",
                value=st.session_state.get('azure_deployment_name', ''),
            )
            if azure_deployment_name:
                st.session_state['azure_deployment_name'] = azure_deployment_name
            
            st.info("Please note that you must use an 1106-preview model deployment.")

            azure_api_version = '2023-12-01-preview' # Update this as needed

            st.write(f"Azure API Version: {azure_api_version}")

        if model_provider == "Google AI API":
            st.markdown(
            """
        1. Enter your [Google AI API key](https://makersuite.google.com/app/apikey) and chosen model below 🔑
        2. Provide details of the application that you would like to threat model  📝
        3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
        """
        )
            # Add OpenAI API key input field to the sidebar
            google_api_key = st.text_input(
                "Enter your Google AI API key:",
                value=st.session_state.get('google_api_key', ''),
                type="password",
                help="You can generate a Google AI API key in the [Google AI Studio](https://makersuite.google.com/app/apikey).",
            )
            if google_api_key:
                st.session_state['google_api_key'] = google_api_key

            # Add model selection input field to the sidebar
            google_model = st.selectbox(
                "Select the model you would like to use:",
                ["gemini-1.5-pro-latest", "gemini-1.5-pro"],
                key="selected_model",
            )

        if model_provider == "Mistral API":
            st.markdown(
            """
        1. Enter your [Mistral API key](https://console.mistral.ai/api-keys/) and chosen model below 🔑
        2. Provide details of the application that you would like to threat model  📝
        3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
        """
        )
            # Add OpenAI API key input field to the sidebar
            mistral_api_key = st.text_input(
                "Enter your Mistral API key:",
                value=st.session_state.get('mistral_api_key', ''),
                type="password",
                help="You can generate a Mistral API key in the [Mistral console](https://console.mistral.ai/api-keys/).",
            )
            if mistral_api_key:
                st.session_state['mistral_api_key'] = mistral_api_key

            # Add model selection input field to the sidebar
            mistral_model = st.selectbox(
                "Select the model you would like to use:",
                ["mistral-large-latest", "mistral-small-latest"],
                key="selected_model",
            )

        if model_provider == "Ollama":
            # Make a request to the Ollama API to get the list of available models
            try:
                response = requests.get("http://localhost:11434/api/tags")
                response.raise_for_status() # Raise an exception for 4xx/5xx status codes
            except requests.exceptions.RequestException as e:
                st.error("Ollama endpoint not found, please select a different model provider.")
                response = None
            
            if response:
                data = response.json()
                available_models = [model["name"] for model in data["models"]]
                # Add model selection input field to the sidebar
                ollama_model = st.selectbox(
                    "Select the model you would like to use:",
                    available_models,
                    key="selected_model",
                )

        # Add GitHub API key input field to the sidebar
        github_api_key = st.sidebar.text_input(
            "Enter your GitHub API key (optional):",
            value=st.session_state.get('github_api_key', ''),
            type="password",
            help="You can find or create your GitHub API key in your GitHub account settings under Developer settings > Personal access tokens.",
        )

        # Store the GitHub API key in session state
        if github_api_key:
            st.session_state['github_api_key'] = github_api_key

        st.markdown("""---""")

    # Add sections to the sidebar
    with st.sidebar:
        st.markdown(ABOUT_SECTION)
        st.markdown(EXAMPLE_APPLICATION_SECTION)
        st.markdown(FAQ_SECTION)

    # ------------------ Main App UI ------------------ #

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Threat Model", "Attack Tree", "Mitigations", "DREAD", "Test Cases"])

    with tab1:
        st.markdown(THREAT_MODEL_SECTION)
        st.markdown("""---""")
        
        # Two column layout for the main app content
        col1, col2 = st.columns([1, 1])

        # Initialize app_input in the session state if it doesn't exist
        if 'app_input' not in st.session_state:
            st.session_state['app_input'] = ''

        # If model provider is OpenAI API and the model is gpt-4-turbo or gpt-4o
        with col1:
            if model_provider == "OpenAI API" and selected_model in ["gpt-4-turbo", "gpt-4o", "gpt-4o-mini"]:
                uploaded_file = st.file_uploader("Upload architecture diagram", type=["jpg", "jpeg", "png"])

                if uploaded_file is not None:
                    if not openai_api_key:
                        st.error("Please enter your OpenAI API key to analyse the image.")
                    else:
                        if 'uploaded_file' not in st.session_state or st.session_state.uploaded_file != uploaded_file:
                            st.session_state.uploaded_file = uploaded_file
                            with st.spinner("Analysing the uploaded image..."):
                                def encode_image(uploaded_file):
                                    return base64.b64encode(uploaded_file.read()).decode('utf-8')

                                base64_image = encode_image(uploaded_file)

                                image_analysis_prompt = create_image_analysis_prompt()

                                try:
                                    image_analysis_output = get_image_analysis(openai_api_key, selected_model, image_analysis_prompt, base64_image)
                                    if image_analysis_output and 'choices' in image_analysis_output and image_analysis_output['choices'][0]['message']['content']:
                                        image_analysis_content = image_analysis_output['choices'][0]['message']['content']
                                        st.session_state.image_analysis_content = image_analysis_content
                                        # Update app_input session state
                                        st.session_state['app_input'] = image_analysis_content
                                    else:
                                        st.error("Failed to analyze the image. Please check the API key and try again.")
                                except KeyError as e:
                                    st.error("Failed to analyze the image. Please check the API key and try again.")
                                    print(f"Error: {e}")
                                except Exception as e:
                                    st.error("An unexpected error occurred while analyzing the image.")
                                    print(f"Error: {e}")

            # Use the get_input() function to get the application description and GitHub URL
            app_input = get_input()
            # Update session state only if the text area content has changed
            if app_input != st.session_state['app_input']:
                st.session_state['app_input'] = app_input

        # Ensure app_input is always up to date in the session state
        app_input = st.session_state['app_input']



            # Create input fields for additional details
        with col2:
                app_type = st.selectbox(
                    label=ARG_HELPERS['application-type'],
                    options=APPLICATION_TYPES,
                    key="app_type",
                )

                sensitive_data = st.selectbox(
                    label=ARG_HELPERS['sensitive-data'],
                    options=CLASSIFICATION_LEVELS,
                    key="sensitive_data",
                )

            # Create input fields for internet_facing and authentication
                internet_facing = st.selectbox(
                    label=ARG_HELPERS['internet-facing'],
                    options=INTERNET_FACING,
                    key="internet_facing",
                )

                authentication = st.multiselect(
                    ARG_HELPERS['authentication'],
                    AUTHENTICATION_METHODS,
                    key="authentication",
                )



        # ------------------ Threat Model Generation ------------------ #

        # Create a submit button for Threat Modelling
        threat_model_submit_button = st.button(label="Generate Threat Model")

        # If the Generate Threat Model button is clicked and the user has provided an application description
        if threat_model_submit_button and st.session_state.get('app_input'):
            app_input = st.session_state['app_input']  # Retrieve from session state

            # Show a spinner while generating the threat model
            with st.spinner("Analysing potential threats..."):
            
                try:
                    # Call the relevant get_threat_model function with the generated prompt
                    if model_provider == PROVIDERS['azure']:
                        model_output = generate_threat_model(app_type, authentication, internet_facing, sensitive_data, app_input, provider=model_provider, model=None, key=azure_api_key,
                                                            azure_api_endpoint=azure_api_endpoint, azure_api_version=azure_api_version, azure_deployment_name=azure_deployment_name)
                    elif model_provider == PROVIDERS['openai']:
                        model_output = generate_threat_model(app_type, authentication, internet_facing, sensitive_data, app_input, provider=model_provider, model=selected_model, key=openai_api_key)
                    elif model_provider == PROVIDERS['google']:
                        model_output = generate_threat_model(app_type, authentication, internet_facing, sensitive_data, app_input, provider=model_provider, model=google_model, key=google_api_key)
                    elif model_provider == PROVIDERS['mistral']:
                        model_output = generate_threat_model(app_type, authentication, internet_facing, sensitive_data, app_input, provider=model_provider, model=mistral_model, key=mistral_api_key)
                    elif model_provider == PROVIDERS['ollama']:
                        model_output = generate_threat_model(app_type, authentication, internet_facing, sensitive_data, app_input, provider=model_provider, model=ollama_model, key=None)
                
                    # Access the threat model and improvement suggestions from the parsed content
                    threat_model = model_output.get("threat_model", [])
                    improvement_suggestions = model_output.get("improvement_suggestions", [])

                    # Save the threat model to the session state for later use in mitigations
                    st.session_state['threat_model'] = threat_model

                    # Convert the threat model JSON to Markdown
                    markdown_output = json_to_markdown(threat_model, improvement_suggestions)

                    # Display the threat model in Markdown
                    st.markdown(markdown_output)

                    # Add a button to allow the user to download the output as a Markdown file
                    st.download_button(
                        label="Download Threat Model",
                        data=markdown_output,  # Use the Markdown output
                        file_name="stride_gpt_threat_model.md",
                        mime="text/markdown",
                    )

                except Exception as e:
                    st.error(f"An unexpected error occurred while generating the threat model. {e}")
                    print(f"Error: {e}")

    # If the submit button is clicked and the user has not provided an application description
    if threat_model_submit_button and not st.session_state.get('app_input'):
        st.error("Please enter your application details before submitting.")



    # ------------------ Attack Tree Generation ------------------ #

    with tab2:
        st.markdown("""
    Attack trees are a structured way to analyse the security of a system. They represent potential attack scenarios in a hierarchical format, 
    with the ultimate goal of an attacker at the root and various paths to achieve that goal as branches. This helps in understanding system 
    vulnerabilities and prioritising mitigation efforts.
    """)
        st.markdown("""---""")
        if model_provider == "Google AI API":
            st.warning("⚠️ Google's safety filters prevent the reliable generation of attack trees. Please use a different model provider.")
        elif model_provider == "Mistral API" and mistral_model == "mistral-small-latest":
                st.warning("⚠️ Mistral Small doesn't reliably generate syntactically correct Mermaid code. Please use the Mistral Large model for generating attack trees, or select a different model provider.")
        else:
            if model_provider == "Ollama":
                st.warning("⚠️ Users are likely to encounter syntax errors when generating attack trees using local LLMs. Experiment with different local LLMs to assess their output quality, or consider using a hosted model provider to generate attack trees.")
            
            # Create a submit button for Attack Tree
            attack_tree_submit_button = st.button(label="Generate Attack Tree")
            
            # If the Generate Attack Tree button is clicked and the user has provided an application description
            if attack_tree_submit_button and st.session_state.get('app_input'):
                app_input = st.session_state.get('app_input')
                # Generate the prompt using the create_attack_tree_prompt function
                attack_tree_prompt = create_attack_tree_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)

                # Show a spinner while generating the attack tree
                with st.spinner("Generating attack tree..."):
                    try:
                        # Call the relevant get_attack_tree function with the generated prompt
                        if model_provider == "Azure OpenAI Service":
                            mermaid_code = get_attack_tree_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, attack_tree_prompt)
                        elif model_provider == "OpenAI API":
                            mermaid_code = get_attack_tree(openai_api_key, selected_model, attack_tree_prompt)
                        elif model_provider == "Mistral API":
                            mermaid_code = get_attack_tree_mistral(mistral_api_key, mistral_model, attack_tree_prompt)
                        elif model_provider == "Ollama":
                            mermaid_code = get_attack_tree_ollama(ollama_model, attack_tree_prompt)

                        # Display the generated attack tree code
                        st.write("Attack Tree Code:")
                        st.code(mermaid_code)

                        # Visualise the attack tree using the Mermaid custom component
                        st.write("Attack Tree Diagram Preview:")
                        mermaid(mermaid_code)
                        
                        col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
                        
                        with col1:              
                            # Add a button to allow the user to download the Mermaid code
                            st.download_button(
                                label="Download Diagram Code",
                                data=mermaid_code,
                                file_name="attack_tree.md",
                                mime="text/plain",
                                help="Download the Mermaid code for the attack tree diagram."
                            )

                        with col2:
                            # Add a button to allow the user to open the Mermaid Live editor
                            mermaid_live_button = st.link_button("Open Mermaid Live", "https://mermaid.live")
                        
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
        st.markdown("""
    Use this tab to generate potential mitigations for the threats identified in the threat model. Mitigations are security controls or
    countermeasures that can help reduce the likelihood or impact of a security threat. The generated mitigations can be used to enhance
    the security posture of the application and protect against potential attacks.
    """)
        st.markdown("""---""")
        
        # Create a submit button for Mitigations
        mitigations_submit_button = st.button(label="Suggest Mitigations")

        # If the Suggest Mitigations button is clicked and the user has identified threats
        if mitigations_submit_button:
            # Check if threat_model data exists
            if 'threat_model' in st.session_state and st.session_state['threat_model']:
                # Convert the threat_model data into a Markdown list
                threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
                # Generate the prompt using the create_mitigations_prompt function
                mitigations_prompt = create_mitigations_prompt(threats_markdown)

                # Show a spinner while suggesting mitigations
                with st.spinner("Suggesting mitigations..."):
                    max_retries = 3
                    retry_count = 0
                    while retry_count < max_retries:
                        try:
                            # Call the relevant get_mitigations function with the generated prompt
                            if model_provider == "Azure OpenAI Service":
                                mitigations_markdown = get_mitigations_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, mitigations_prompt)
                            elif model_provider == "OpenAI API":
                                mitigations_markdown = get_mitigations(openai_api_key, selected_model, mitigations_prompt)
                            elif model_provider == "Google AI API":
                                mitigations_markdown = get_mitigations_google(google_api_key, google_model, mitigations_prompt)
                            elif model_provider == "Mistral API":
                                mitigations_markdown = get_mitigations_mistral(mistral_api_key, mistral_model, mitigations_prompt)
                            elif model_provider == "Ollama":
                                mitigations_markdown = get_mitigations_ollama(ollama_model, mitigations_prompt)

                            # Display the suggested mitigations in Markdown
                            st.markdown(mitigations_markdown)
                            break  # Exit the loop if successful
                        except Exception as e:
                            retry_count += 1
                            if retry_count == max_retries:
                                st.error(f"Error suggesting mitigations after {max_retries} attempts: {e}")
                                mitigations_markdown = ""
                            else:
                                st.warning(f"Error suggesting mitigations. Retrying attempt {retry_count+1}/{max_retries}...")
                
                st.markdown("")

                # Add a button to allow the user to download the mitigations as a Markdown file
                st.download_button(
                    label="Download Mitigations",
                    data=mitigations_markdown,
                    file_name="mitigations.md",
                    mime="text/markdown",
                )
            else:
                st.error("Please generate a threat model first before suggesting mitigations.")

    # ------------------ DREAD Risk Assessment Generation ------------------ #
    with tab4:
        st.markdown("""
    DREAD is a method for evaluating and prioritising risks associated with security threats. It assesses threats based on **D**amage potential, 
    **R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. This helps in determining the overall risk level and 
    focusing on the most critical threats first. Use this tab to perform a DREAD risk assessment for your application / system.
    """)
        st.markdown("""---""")
        
        # Create a submit button for DREAD Risk Assessment
        dread_assessment_submit_button = st.button(label="Generate DREAD Risk Assessment")
        # If the Generate DREAD Risk Assessment button is clicked and the user has identified threats
        if dread_assessment_submit_button:
            # Check if threat_model data exists
            if 'threat_model' in st.session_state and st.session_state['threat_model']:
                # Convert the threat_model data into a Markdown list
                threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
                # Generate the prompt using the create_dread_assessment_prompt function
                dread_assessment_prompt = create_dread_assessment_prompt(threats_markdown)
                # Show a spinner while generating DREAD Risk Assessment
                with st.spinner("Generating DREAD Risk Assessment..."):
                    max_retries = 3
                    retry_count = 0
                    while retry_count < max_retries:
                        try:
                            # Call the relevant get_dread_assessment function with the generated prompt
                            if model_provider == "Azure OpenAI Service":
                                dread_assessment = get_dread_assessment_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, dread_assessment_prompt)
                            elif model_provider == "OpenAI API":
                                dread_assessment = get_dread_assessment(openai_api_key, selected_model, dread_assessment_prompt)
                            elif model_provider == "Google AI API":
                                dread_assessment = get_dread_assessment_google(google_api_key, google_model, dread_assessment_prompt)
                            elif model_provider == "Mistral API":
                                dread_assessment = get_dread_assessment_mistral(mistral_api_key, mistral_model, dread_assessment_prompt)
                            elif model_provider == "Ollama":
                                dread_assessment = get_dread_assessment_ollama(ollama_model, dread_assessment_prompt)
                            # Save the DREAD assessment to the session state for later use in test cases
                            st.session_state['dread_assessment'] = dread_assessment
                            break  # Exit the loop if successful
                        except Exception as e:
                            retry_count += 1
                            if retry_count == max_retries:
                                st.error(f"Error generating DREAD risk assessment after {max_retries} attempts: {e}")
                                dread_assessment = []
                            else:
                                st.warning(f"Error generating DREAD risk assessment. Retrying attempt {retry_count+1}/{max_retries}...")
                # Convert the DREAD assessment JSON to Markdown
                dread_assessment_markdown = dread_json_to_markdown(dread_assessment)
                # Display the DREAD assessment in Markdown
                st.markdown(dread_assessment_markdown)
                # Add a button to allow the user to download the test cases as a Markdown file
                st.download_button(
                    label="Download DREAD Risk Assessment",
                    data=dread_assessment_markdown,
                    file_name="dread_assessment.md",
                    mime="text/markdown",
                )
            else:
                st.error("Please generate a threat model first before requesting a DREAD risk assessment.")


    # ------------------ Test Cases Generation ------------------ #

    with tab5:
        st.markdown("""
    Test cases are used to validate the security of an application and ensure that potential vulnerabilities are identified and 
    addressed. This tab allows you to generate test cases using Gherkin syntax. Gherkin provides a structured way to describe application 
    behaviours in plain text, using a simple syntax of Given-When-Then statements. This helps in creating clear and executable test 
    scenarios.
    """)
        st.markdown("""---""")
                    
        # Create a submit button for Test Cases
        test_cases_submit_button = st.button(label="Generate Test Cases")

        # If the Generate Test Cases button is clicked and the user has identified threats
        if test_cases_submit_button:
            # Check if threat_model data exists
            if 'threat_model' in st.session_state and st.session_state['threat_model']:
                # Convert the threat_model data into a Markdown list
                threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
                # Generate the prompt using the create_test_cases_prompt function
                test_cases_prompt = create_test_cases_prompt(threats_markdown)

                # Show a spinner while generating test cases
                with st.spinner("Generating test cases..."):
                    max_retries = 3
                    retry_count = 0
                    while retry_count < max_retries:
                        try:
                            # Call to the relevant get_test_cases function with the generated prompt
                            if model_provider == "Azure OpenAI Service":
                                test_cases_markdown = get_test_cases_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, test_cases_prompt)
                            elif model_provider == "OpenAI API":
                                test_cases_markdown = get_test_cases(openai_api_key, selected_model, test_cases_prompt)
                            elif model_provider == "Google AI API":
                                test_cases_markdown = get_test_cases_google(google_api_key, google_model, test_cases_prompt)
                            elif model_provider == "Mistral API":
                                test_cases_markdown = get_test_cases_mistral(mistral_api_key, mistral_model, test_cases_prompt)
                            elif model_provider == "Ollama":
                                test_cases_markdown = get_test_cases_ollama(ollama_model, test_cases_prompt)

                            # Display the suggested mitigations in Markdown
                            st.markdown(test_cases_markdown)
                            break  # Exit the loop if successful
                        except Exception as e:
                            retry_count += 1
                            if retry_count == max_retries:
                                st.error(f"Error generating test cases after {max_retries} attempts: {e}")
                                test_cases_markdown = ""
                            else:
                                st.warning(f"Error generating test cases. Retrying attempt {retry_count+1}/{max_retries}...")
                
                st.markdown("")

                # Add a button to allow the user to download the test cases as a Markdown file
                st.download_button(
                    label="Download Test Cases",
                    data=test_cases_markdown,
                    file_name="test_cases.md",
                    mime="text/markdown",
                )
            else:
                st.error("Please generate a threat model first before requesting test cases.")
>>>>>>> 65659ea (Generalized ollama_host to host for later potential use.)
