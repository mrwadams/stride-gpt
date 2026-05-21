"""Interactive REPL prompt — tab completion, history, status line.

Wraps prompt_toolkit so the rest of the CLI doesn't depend on it directly.
Rich is still used for all output; prompt_toolkit only handles input.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import (
    CompleteEvent,
    Completer,
    Completion,
    PathCompleter,
)
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.styles import Style

from stride_gpt.config import CONFIG_DIR

# Slash commands available in the REPL. Order matters for menu display.
COMMANDS: list[tuple[str, str]] = [
    ("/analyze", "Analyze a codebase for STRIDE threats"),
    ("/quick", "Quick threat model from a text description"),
    ("/reports", "List or view previous analysis reports"),
    ("/config", "View or change settings"),
    ("/help", "Show available commands"),
    ("/quit", "Exit"),
]

# Commands whose first argument is a filesystem path.
PATH_COMMANDS = {"/analyze"}

# Flags whose value should complete as a filesystem path.
PATH_FLAGS = {"-o", "--output", "-i", "--input"}


class StrideCompleter(Completer):
    """Composite completer: slash commands at start, paths after path commands."""

    def __init__(self) -> None:
        self._path = PathCompleter(expanduser=True)

    def get_completions(self, document: Document, complete_event: CompleteEvent):
        text = document.text_before_cursor
        stripped = text.lstrip()

        # 1) Slash command completion at the start of the line
        if stripped.startswith("/") and " " not in stripped:
            word = stripped
            for cmd, desc in COMMANDS:
                if cmd.startswith(word):
                    yield Completion(
                        cmd,
                        start_position=-len(word),
                        display=cmd,
                        display_meta=desc,
                    )
            return

        # 2) Path completion in two cases:
        #    (a) after a /analyze (first positional arg)
        #    (b) after a path-accepting flag like -o or -i
        parts = stripped.split()
        if not parts:
            return

        cmd = parts[0]
        last_token_start = text.rfind(" ") + 1
        last_token = text[last_token_start:]

        # Path after a path-accepting flag
        if len(parts) >= 2 and parts[-2] in PATH_FLAGS:
            yield from self._yield_paths(last_token)
            return

        # Path as first arg of /analyze (and not after a flag)
        if cmd in PATH_COMMANDS and not last_token.startswith("-"):
            # Look back: is this still the first positional arg?
            tokens_before = parts[1:-1] if last_token else parts[1:]
            non_flag_args = [t for t in tokens_before if not t.startswith("-")]
            # Skip flag values
            skip_next = False
            count = 0
            for t in tokens_before:
                if skip_next:
                    skip_next = False
                    continue
                if t in PATH_FLAGS:
                    skip_next = True
                    continue
                if not t.startswith("-"):
                    count += 1
            if count == 0:
                yield from self._yield_paths(last_token)

    def _yield_paths(self, last_token: str):
        """Delegate to PathCompleter for the current token."""
        sub_doc = Document(last_token, cursor_position=len(last_token))
        for c in self._path.get_completions(sub_doc, CompleteEvent()):
            yield c


def _build_keybindings() -> KeyBindings:
    """Bind a couple of nice-to-have shortcuts."""
    kb = KeyBindings()

    @kb.add("c-l")
    def _clear(event):
        """Ctrl+L — clear the screen."""
        event.app.renderer.clear()

    return kb


def build_session(
    config_provider: Callable[[], dict[str, Any]],
) -> PromptSession:
    """Build the interactive PromptSession.

    `config_provider` is a callable so the bottom toolbar always reflects
    the current config (it can change mid-session via /config).
    """
    history_path = CONFIG_DIR / "history"
    history_path.parent.mkdir(parents=True, exist_ok=True)

    def bottom_toolbar() -> HTML:
        cfg = config_provider() or {}
        provider = cfg.get("provider", "not configured")
        model = cfg.get("model", "—")
        cwd = Path.cwd().name or str(Path.cwd())
        return HTML(
            f" <b>{provider}</b> / <ansigreen>{model}</ansigreen>  "
            f"<ansicyan>cwd:</ansicyan> {cwd}  "
            f"<ansibrightblack>·  Tab to complete  ·  Ctrl+L to clear  ·  /help</ansibrightblack>"
        )

    style = Style.from_dict({
        "prompt": "ansigreen bold",
        "bottom-toolbar": "bg:#222222 #aaaaaa",
        "completion-menu.completion": "bg:#1a1a1a #ffffff",
        "completion-menu.completion.current": "bg:#005f87 #ffffff bold",
        "completion-menu.meta.completion": "bg:#1a1a1a #888888",
        "completion-menu.meta.completion.current": "bg:#005f87 #cccccc",
    })

    return PromptSession(
        message=HTML("<prompt>stride-gpt&gt;</prompt> "),
        history=FileHistory(str(history_path)),
        auto_suggest=AutoSuggestFromHistory(),
        completer=StrideCompleter(),
        complete_while_typing=True,
        bottom_toolbar=bottom_toolbar,
        key_bindings=_build_keybindings(),
        style=style,
        mouse_support=False,  # Mouse interferes with terminal text selection
    )
