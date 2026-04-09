"""Persistent configuration — setup wizard, load/save, provider catalog."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

CONFIG_DIR = Path.home() / ".stride-gpt"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Provider catalog: provider name → {models, needs_api_key, needs_api_base}
PROVIDERS: dict[str, dict[str, Any]] = {
    "Anthropic": {
        "provider_key": "Anthropic API",
        "models": [
            "claude-sonnet-4-5-20250929",
            "claude-opus-4-5-20250414",
            "claude-haiku-4-5-20251001",
        ],
        "env_var": "ANTHROPIC_API_KEY",
        "needs_api_key": True,
        "needs_api_base": False,
    },
    "OpenAI": {
        "provider_key": "OpenAI API",
        "models": ["gpt-5.2", "gpt-5-mini", "gpt-5-nano"],
        "env_var": "OPENAI_API_KEY",
        "needs_api_key": True,
        "needs_api_base": False,
    },
    "Google AI": {
        "provider_key": "Google AI API",
        "models": ["gemini-2.5-pro", "gemini-2.5-flash"],
        "env_var": "GOOGLE_API_KEY",
        "needs_api_key": True,
        "needs_api_base": False,
    },
    "Mistral": {
        "provider_key": "Mistral API",
        "models": ["mistral-large-latest", "mistral-small-latest"],
        "env_var": "MISTRAL_API_KEY",
        "needs_api_key": True,
        "needs_api_base": False,
    },
    "Groq": {
        "provider_key": "Groq API",
        "models": ["llama-3.3-70b-versatile", "deepseek-r1-distill-llama-70b"],
        "env_var": "GROQ_API_KEY",
        "needs_api_key": True,
        "needs_api_base": False,
    },
    "Ollama": {
        "provider_key": "Ollama",
        "models": ["llama3", "mistral", "codellama", "deepseek-coder"],
        "env_var": None,
        "needs_api_key": False,
        "needs_api_base": True,
        "default_api_base": "http://localhost:11434",
    },
    "LM Studio": {
        "provider_key": "LM Studio Server",
        "models": [],
        "env_var": None,
        "needs_api_key": False,
        "needs_api_base": True,
        "default_api_base": "http://localhost:1234",
    },
}


def load_config() -> dict[str, Any] | None:
    """Load config from ~/.stride-gpt/config.json. Returns None if not found."""
    if not CONFIG_FILE.is_file():
        return None
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def save_config(config: dict[str, Any]) -> None:
    """Save config to ~/.stride-gpt/config.json."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n")


def run_setup(console: Console) -> dict[str, Any]:
    """Interactive first-run setup wizard. Returns config dict."""
    console.print()
    console.print(
        Panel(
            "[bold]Welcome to STRIDE-GPT[/bold]\n\n"
            "Let's set up your threat modeling agent.\n"
            "You can change these settings anytime with [cyan]/config[/cyan].",
            style="blue",
        )
    )
    console.print()

    # Step 1: Pick provider
    provider_names = list(PROVIDERS.keys())
    table = Table(show_header=False, box=None, padding=(0, 2))
    for i, name in enumerate(provider_names, 1):
        info = PROVIDERS[name]
        detail = ""
        if not info["needs_api_key"]:
            detail = " [dim](local)[/dim]"
        table.add_row(f"  [bold]{i}[/bold]", f"{name}{detail}")

    console.print("[bold]Select a provider:[/bold]")
    console.print(table)
    console.print()

    while True:
        choice = Prompt.ask(
            "Provider",
            default="1",
        )
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(provider_names):
                provider_name = provider_names[idx]
                break
        except ValueError:
            # Try matching by name
            for name in provider_names:
                if choice.lower() in name.lower():
                    provider_name = name
                    break
            else:
                console.print(f"[red]Invalid choice. Enter 1-{len(provider_names)}.[/red]")
                continue
            break

    provider = PROVIDERS[provider_name]
    console.print(f"  [green]Selected: {provider_name}[/green]")
    console.print()

    # Step 2: Pick model
    if provider["models"]:
        console.print("[bold]Select a model:[/bold]")
        for i, model in enumerate(provider["models"], 1):
            console.print(f"  [bold]{i}[/bold]  {model}")
        console.print(f"  [bold]{len(provider['models']) + 1}[/bold]  [dim]Custom (enter model name)[/dim]")
        console.print()

        while True:
            model_choice = Prompt.ask("Model", default="1")
            try:
                midx = int(model_choice) - 1
                if 0 <= midx < len(provider["models"]):
                    model_name = provider["models"][midx]
                    break
                elif midx == len(provider["models"]):
                    model_name = Prompt.ask("Enter model name")
                    break
            except ValueError:
                model_name = model_choice  # Treat as raw model name
                break
    else:
        model_name = Prompt.ask("Enter model name")

    console.print(f"  [green]Model: {model_name}[/green]")
    console.print()

    # Step 3: API key — read from .env file or environment variables
    if provider["needs_api_key"]:
        import os

        env_var = provider["env_var"]
        env_key = os.environ.get(env_var or "")
        if env_key:
            masked = env_key[:8] + "..." + env_key[-4:]
            console.print(f"  [green]Found {env_var} ({masked})[/green]")
        else:
            console.print(
                Panel(
                    f"Add your API key to [bold cyan]{CONFIG_DIR / '.env'}[/bold cyan]:\n\n"
                    f"  {env_var}=your-api-key-here\n\n"
                    f"This file is loaded automatically on startup.",
                    title="[bold yellow]API Key Required[/bold yellow]",
                    style="yellow",
                )
            )
            if not Confirm.ask("Continue setup without the key for now?", default=True):
                return run_setup(console)

    # Step 4: API base (for Ollama/LM Studio)
    api_base = None
    if provider["needs_api_base"]:
        default_base = provider.get("default_api_base", "http://localhost:11434")
        api_base = Prompt.ask("API base URL", default=default_base)

    config = {
        "provider": provider_name,
        "provider_key": provider["provider_key"],
        "model": model_name,
        "api_base": api_base,
    }

    save_config(config)
    console.print()
    console.print(f"[green]Config saved to {CONFIG_FILE}[/green]")
    return config


def show_config(console: Console, config: dict[str, Any]) -> None:
    """Display current configuration."""
    import os

    table = Table(title="Current Configuration", show_header=False, box=None, padding=(0, 2))
    table.add_row("[bold]Provider[/bold]", config.get("provider", "Unknown"))
    table.add_row("[bold]Model[/bold]", config.get("model", "Unknown"))

    # Show env var status
    provider_info = PROVIDERS.get(config.get("provider", ""))
    if provider_info and provider_info.get("env_var"):
        env_var = provider_info["env_var"]
        env_val = os.environ.get(env_var, "")
        if env_val:
            masked = env_val[:8] + "..." + env_val[-4:] if len(env_val) > 12 else "***"
            table.add_row("[bold]API Key[/bold]", f"{env_var} = {masked}")
        else:
            table.add_row("[bold]API Key[/bold]", f"[red]{env_var} not set[/red]")

    if config.get("api_base"):
        table.add_row("[bold]API Base[/bold]", config["api_base"])
    table.add_row("[bold]Config file[/bold]", str(CONFIG_FILE))
    console.print(table)


def get_api_key(config: dict[str, Any]) -> str:
    """Resolve the API key from environment variables for the configured provider."""
    import os

    provider_info = PROVIDERS.get(config.get("provider", ""))
    if provider_info and provider_info.get("env_var"):
        key = os.environ.get(provider_info["env_var"], "")
        if key:
            return key

    # Fallback: check common env vars
    for var in ("STRIDE_GPT_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"):
        key = os.environ.get(var, "")
        if key:
            return key

    return ""


def config_to_llm_config(config: dict[str, Any]):
    """Convert a saved config dict to an LLMConfig. Reads API key from environment."""
    from stride_gpt.core.schemas import LLMConfig

    return LLMConfig(
        provider=config["provider_key"],
        model_name=config["model"],
        api_key=get_api_key(config),
        api_base=config.get("api_base"),
    )
