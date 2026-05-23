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

from stride_gpt.models import PROVIDERS, get_models_for_provider

CONFIG_DIR = Path.home() / ".stride-gpt"
CONFIG_FILE = CONFIG_DIR / "config.json"
# Reports are split by kind so a coding agent pointed at the "analyze" folder
# only sees codebase-grounded reports (which all relate to the same project),
# not unrelated /quick analyses of arbitrary application descriptions. The
# subdir accessors below are computed at call time (not module-load) so tests
# that monkeypatch REPORTS_DIR redirect the kind-specific dirs too.
REPORTS_DIR = CONFIG_DIR / "reports"


def analyze_reports_dir() -> Path:
    """Return the directory holding codebase-grounded reports (/analyze)."""
    return REPORTS_DIR / "analyze"


def quick_reports_dir() -> Path:
    """Return the directory holding description-based reports (/quick)."""
    return REPORTS_DIR / "quick"


def fetch_local_models(provider_name: str, api_base: str) -> list[str]:
    """Discover available models from a local LM Studio instance.

    Returns a list of model name strings, or an empty list on failure.
    """
    try:
        if provider_name == "LM Studio":
            url = api_base.rstrip("/") + "/v1/models"
            resp = httpx.get(url, timeout=5)
            resp.raise_for_status()
            return [m["id"] for m in resp.json().get("data", [])]
    except (httpx.HTTPError, KeyError, TypeError):
        pass
    return []


MIN_CONTEXT_LENGTH = 16384  # Minimum context length recommended for agentic analysis
DEFAULT_LM_STUDIO_MAX_TOKENS = 8000  # Output cap when context length is unknown


def get_lm_studio_context_length(api_base: str, model_name: str) -> int | None:
    """Return the loaded context length for an LM Studio model, or None if unknown."""
    try:
        url = api_base.rstrip("/") + "/api/v1/models"
        resp = httpx.get(url, timeout=5)
        resp.raise_for_status()
        for model in resp.json().get("models", []):
            if model.get("key") != model_name:
                continue
            loaded_instances = model.get("loaded_instances", [])
            if not loaded_instances:
                return None
            loaded = loaded_instances[0].get("config", {}).get("context_length")
            return int(loaded) if loaded else None
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        return None
    return None


def suggest_max_tokens(context_length: int | None) -> int:
    """Pick a sensible output token budget given a context window.

    Defaults to ~25% of context, floored at DEFAULT_LM_STUDIO_MAX_TOKENS. Users
    can override in the wizard or via --max-tokens.
    """
    if not context_length:
        return DEFAULT_LM_STUDIO_MAX_TOKENS
    return max(DEFAULT_LM_STUDIO_MAX_TOKENS, context_length // 4)


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


def _is_quit(value: str) -> bool:
    """Check if the user wants to cancel setup."""
    return value.strip().lower() in ("q", "quit", "cancel")


def _cancel(console: Console) -> None:
    console.print("\n[dim]Setup cancelled.[/dim]")


def run_setup(console: Console) -> dict[str, Any] | None:
    """Interactive first-run setup wizard. Returns config dict, or None if cancelled."""
    console.print()
    console.print(
        Panel(
            "[bold]Welcome to STRIDE-GPT[/bold]\n\n"
            "Let's set up your threat modeling agent.\n"
            "You can change these settings anytime with [cyan]/config[/cyan].\n"
            "Type [dim]q[/dim] at any prompt to cancel.",
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
        if not info.needs_api_key:
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
        if _is_quit(choice):
            _cancel(console)
            return None
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
    if not provider.needs_api_base:
        models = [m.model_id for m in get_models_for_provider(provider.provider_key)]
        if models:
            console.print("[bold]Select a model:[/bold]")
            for i, model in enumerate(models, 1):
                console.print(f"  [bold]{i}[/bold]  {model}")
            console.print(f"  [bold]{len(models) + 1}[/bold]  [dim]Custom (enter model name)[/dim]")
            console.print()

            while True:
                model_choice = Prompt.ask("Model", default="1")
                if _is_quit(model_choice):
                    _cancel(console)
                    return None
                try:
                    midx = int(model_choice) - 1
                    if 0 <= midx < len(models):
                        model_name = models[midx]
                        break
                    elif midx == len(models):
                        model_name = Prompt.ask("Enter model name")
                        if _is_quit(model_name):
                            _cancel(console)
                            return None
                        break
                except ValueError:
                    model_name = model_choice  # Treat as raw model name
                    break
        else:
            model_name = Prompt.ask("Enter model name")
            if _is_quit(model_name):
                _cancel(console)
                return None

        console.print(f"  [green]Model: {model_name}[/green]")
        console.print()

    # Step 3: API key — read from .env file or environment variables
    if provider.needs_api_key:
        import os

        env_var = provider.env_var
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
                _cancel(console)
                return None

    # Step 4: API base (for LM Studio)
    api_base = None
    if provider.needs_api_base:
        default_base = provider.default_api_base or "http://localhost:11434"
        api_base = Prompt.ask("API base URL", default=default_base)
        if _is_quit(api_base):
            _cancel(console)
            return None

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
                if _is_quit(model_choice):
                    _cancel(console)
                    return None
                try:
                    midx = int(model_choice) - 1
                    if 0 <= midx < len(discovered):
                        model_name = discovered[midx]
                        break
                    elif midx == len(discovered):
                        model_name = Prompt.ask("Enter model name")
                        if _is_quit(model_name):
                            _cancel(console)
                            return None
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
                if _is_quit(model_name):
                    _cancel(console)
                    return None

    # Step 5: Max output tokens (LM Studio only — cloud providers have sane defaults)
    max_tokens: int | None = None
    if provider.needs_api_base and model_name:
        ctx = get_lm_studio_context_length(api_base, model_name) if api_base else None
        suggested = suggest_max_tokens(ctx)
        if ctx:
            console.print(
                f"  [dim]Loaded context window: {ctx:,} tokens. "
                f"Suggested output budget: {suggested:,}.[/dim]"
            )
        else:
            console.print(
                f"  [dim]Could not read context length from LM Studio. "
                f"Suggested output budget: {suggested:,}.[/dim]"
            )
        raw = Prompt.ask("Max output tokens", default=str(suggested))
        if _is_quit(raw):
            _cancel(console)
            return None
        try:
            max_tokens = int(raw)
        except ValueError:
            console.print(f"  [yellow]Invalid number — using {suggested}.[/yellow]")
            max_tokens = suggested
        console.print()

    config = {
        "provider": provider_name,
        "provider_key": provider.provider_key,
        "model": model_name,
        "api_base": api_base,
        "max_tokens": max_tokens,
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
    if provider_info and provider_info.env_var:
        env_var = provider_info.env_var
        env_val = os.environ.get(env_var, "")
        if env_val:
            masked = env_val[:8] + "..." + env_val[-4:] if len(env_val) > 12 else "***"
            table.add_row("[bold]API Key[/bold]", f"{env_var} = {masked}")
        else:
            table.add_row("[bold]API Key[/bold]", f"[red]{env_var} not set[/red]")

    if config.get("api_base"):
        table.add_row("[bold]API Base[/bold]", config["api_base"])
    if config.get("max_tokens"):
        table.add_row("[bold]Max output tokens[/bold]", f"{config['max_tokens']:,}")
    table.add_row("[bold]Config file[/bold]", str(CONFIG_FILE))
    console.print(table)


def get_api_key(config: dict[str, Any]) -> str:
    """Resolve the API key from environment variables for the configured provider."""
    import os

    provider_info = PROVIDERS.get(config.get("provider", ""))
    if provider_info and provider_info.env_var:
        key = os.environ.get(provider_info.env_var, "")
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
        max_tokens=config.get("max_tokens"),
    )
