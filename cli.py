#cli.py

import argparse
import json

from rich.logging import RichHandler
from rich.console import Console
from rich.markdown import Markdown
import logging

from threat_model import json_to_markdown
from main import generate_threat_model, analyze_github_repo, analyze_local_repo

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
    ARG_HELPERS
)

# Combine all sections into one constant
COMBINED_MARKDOWN = f"{ABOUT_SECTION}\n---\n{EXAMPLE_APPLICATION_SECTION}\n---\n{FAQ_SECTION}"

# Configure logging with RichHandler
console = Console()
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger("rich")

# Create the main argument parser
parser = argparse.ArgumentParser(
    description=COMBINED_MARKDOWN,
    formatter_class=argparse.RawTextHelpFormatter  # This preserves line breaks and markdown formatting
)

# Create subparsers for the main parser
subparsers = parser.add_subparsers(dest='command')

# Create the 'threat-model' sub-command
threat_model_parser = subparsers.add_parser('threat-model', help="Generate a threat model.", description=THREAT_MODEL_SECTION)

# Argument definitions in a list of dicts
arguments = [
    ("provider", str, {"choices": PROVIDERS.keys(), "required": True}),
    ("model", str, {"required": True}),
    ("key", str, {}),
    ("azure_api_endpoint", str, {}),
    ("azure_api_version", str, {}),
    ("azure_deployment_name", str, {}),
    ("application-type", str, {"choices": APPLICATION_TYPES, "required": True}),
    ("sensitive-data", str, {"choices": CLASSIFICATION_LEVELS, "required": True}),
    ("internet-facing", bool, {"action": "store_true"}),
    ("authentication", str, {"choices": AUTHENTICATION_METHODS, "nargs": "+", "required": True}),
    ("application-input", str, {"required": True}),
    ("output-file", str, {}),
    ("output-format", str, {"choices": ['markdown', 'json'], "default": 'markdown'}) 
]

# Loop to add arguments dynamically
for arg_name, arg_type, arg_kwargs in arguments:
    help_message = ARG_HELPERS.get(arg_name, f"Help message for {arg_name}.")

    # Handle flag-style arguments separately (store_true))
    if arg_type == bool:
        # For boolean flags, no 'type' argument should be passed
        threat_model_parser.add_argument(f"--{arg_name}", action="store_true", help=help_message)
    else:
        # For other arguments, use 'type' and other kwargs
        threat_model_parser.add_argument(f"--{arg_name}", type=arg_type, help=help_message, **arg_kwargs)

# Create the 'analyze-github-repo' sub-command
analyze_github_repo_parser = subparsers.add_parser('analyze-github-repo', help="Analyze a GitHub repository.")
analyze_github_repo_parser.add_argument("--repo-url", type=str, required=True, help="The URL of the GitHub repository to analyze.")
analyze_github_repo_parser.add_argument("--github-api-key", type=str, required=True, help="The GitHub API key for authentication.")
analyze_github_repo_parser.add_argument("--output-file", type=str, help="Analized Github repository Description")

# Create the 'analyze-local-repo' sub-command
analyze_local_repo_parser = subparsers.add_parser('analyze-local-repo', help="Analyze a Local repository.")
analyze_local_repo_parser.add_argument("--repo-path", type=str, required=True, help="The path to Local repository to analyze")
analyze_local_repo_parser.add_argument("--output-file", type=str, help="Analized Local repository Description")

# Parse the arguments
args = parser.parse_args()


# Command to generate Threat Model
if args.command == 'threat-model':

    logging.info("Analysing potential threats...")

    provider = args.provider
    model = args.model
    key = args.key
    app_type = args.application_type
    sensitive_data = args.sensitive_data
    internet_facing = args.internet_facing
    authentication = args.authentication
    app_input = args.application_input
    output_file= args.output_file
    output_format= args.output_format

    model_output = generate_threat_model(app_type, authentication, internet_facing, sensitive_data, app_input, PROVIDERS[provider], model, key)

    # Access the threat model and improvement suggestions from the parsed content
    threat_model = model_output.get("threat_model", [])
    improvement_suggestions = model_output.get("improvement_suggestions", [])
    
    # Convert the threat model JSON to Markdown
    markdown_output = json_to_markdown(threat_model, improvement_suggestions)

    # Display the threat model in Markdown
    console.print(Markdown(markdown_output))

    # If the output-file argument is provided, save the content
    if output_file:
        # Write to the file based on the output format chosen
        if output_format == 'markdown':
            with open(output_file, 'w') as f:
                f.write(markdown_output)
            logging.info(f"Markdown content has been written to {output_file}")
        
        elif output_format == 'json':
            with open(args.output_file, 'w') as f:
                json.dump(threat_model + improvement_suggestions, f, indent=4)
            logging.info(f"JSON content has been written to {output_file}")

    else:
        logging.info("No output file specified. You can use --output-file to save the content to a file.")
  

elif args.command == 'analyze-github-repo':

    logging.info("Analysing Github Repo...")

    output_file = args.output_file

    # Analyze the Github repo and generate an applciation description
    app_input = analyze_github_repo(args.repo_url, args.github_api_key)

    console.print(app_input)

    # If the output-file argument is provided, save the content
    if output_file:
        with open(args.output_file, 'w') as file:
            file.write(app_input)
            logging.info(f"Content has been written to {output_file}")
    else:
        logging.info("No output file specified. You can use --output-file to save the content to a file.")

elif args.command == 'analyze-local-repo':

    logging.info("Analysing Local Repo...")

    output_file = args.output_file

    # Analyze the Local repo and generate an applciation description
    app_input = analyze_local_repo(args.repo_path)

    console.print(app_input)

    # If the output-file argument is provided, save the content
    if output_file:
        with open(args.output_file, 'w') as file:
            file.write(app_input)
            logging.info(f"Content has been written to {output_file}")
    else:
        logging.info("No output file specified. You can use --output-file to save the content to a file.")