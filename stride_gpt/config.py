"""Persistent configuration — setup wizard, load/save, provider catalog."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

CONFIG_DIR = Path.home() / ".stride-gpt"
CONFIG_FILE = CONFIG_DIR / "config.json"
REPORTS_DIR = CONFIG_DIR / "reports"

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
        "models": [],
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


def fetch_local_models(provider_name: str, api_base: str) -> list[str]:
    """Discover available models from a local Ollama or LM Studio instance.

    Returns a list of model name strings, or an empty list on failure.
    """
    try:
        if provider_name == "Ollama":
            url = api_base.rstrip("/") + "/api/tags"
            resp = httpx.get(url, timeout=5)
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
        elif provider_name == "LM Studio":
            url = api_base.rstrip("/") + "/v1/models"
            resp = httpx.get(url, timeout=5)
            resp.raise_for_status()
            return [m["id"] for m in resp.json().get("data", [])]
    except (httpx.HTTPError, KeyError, TypeError):
        pass
    return []


MIN_CONTEXT_LENGTH = 16384  # Minimum context length recommended for agentic analysis


def check_lm_studio_context(
    api_base: str, model_name: str, console: Console | None = None,
) -> bool:
    """Check whether an LM Studio model has adequate context for agentic analysis.

    Queries the native /api/v1/models endpoint for the loaded context length.
    Returns True if context is sufficient or unknown. Returns False if too small.
    """
    try:
        url = api_base.rstrip("/") + "/api/v1/models"
        resp = httpx.get(url, timeout=5)
        resp.raise_for_status()
        for model in resp.json().get("models", []):
            if model.get("key") != model_name:
                continue
            max_ctx = model.get("max_context_length", 0)
            loaded_instances = model.get("loaded_instances", [])
            if not loaded_instances:
                continue
            loaded_ctx = loaded_instances[0].get("config", {}).get("context_length", 0)
            if loaded_ctx >= MIN_CONTEXT_LENGTH:
                return True
            if console:
                console.print(
                    f"\n[bold red]Context window too small.[/bold red] "
                    f"'{model_name}' is loaded with [bold]{loaded_ctx:,}[/bold] tokens "
                    f"(max supported: {max_ctx:,}).\n"
                    f"[yellow]Agentic analysis needs at least {MIN_CONTEXT_LENGTH:,} tokens "
                    f"(32,768+ recommended). Increase the context length in LM Studio's "
                    f"model settings and reload the model.[/yellow]\n"
                )
            return False
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        pass
    return True  # Can't check — proceed optimistically


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

    # Step 2: Pick model (cloud providers only — local providers pick after endpoint discovery)
    model_name = ""
    if not provider["needs_api_base"]:
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

        # Auto-discover models from the local server
        console.print(f"  [dim]Checking {api_base} for available models...[/dim]")
        discovered = fetch_local_models(provider_name, api_base)
        if discovered:
            console.print(f"  [green]Found {len(discovered)} model(s)[/green]")
            console.print()
            console.print("[bold]Select a model:[/bold]")
            for i, m in enumerate(discovered, 1):
                console.print(f"  [bold]{i}[/bold]  {m}")
            console.print(f"  [bold]{len(discovered) + 1}[/bold]  [dim]Custom (enter model name)[/dim]")
            console.print()

            while True:
                model_choice = Prompt.ask("Model", default="1")
                try:
                    midx = int(model_choice) - 1
                    if 0 <= midx < len(discovered):
                        model_name = discovered[midx]
                        break
                    elif midx == len(discovered):
                        model_name = Prompt.ask("Enter model name")
                        break
                except ValueError:
                    model_name = model_choice
                    break

            console.print(f"  [green]Model: {model_name}[/green]")
            console.print()
        else:
            console.print("  [yellow]Could not connect or no models found.[/yellow]")
            if not model_name:
                model_name = Prompt.ask("Enter model name")

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
