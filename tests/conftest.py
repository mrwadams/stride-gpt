"""Shared fixtures for stride-gpt tests."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from stride_gpt.core.schemas import (
    AnalysisPlan,
    AnalysisReport,
    LLMConfig,
    ModelPair,
    Subsystem,
    SubsystemFinding,
)


@pytest.fixture(scope="session", autouse=True)
def _cli_dotenv_loaded_up_front():
    """Trigger ``stride_gpt.cli``'s import-time ``load_dotenv`` before any test.

    The CLI calls ``load_dotenv(~/.stride-gpt/.env)`` at module scope, which puts
    the developer's real API keys into os.environ. A test that imports the CLI
    inside its own body would run that *after* ``_hermetic_api_keys`` had cleared
    the keys, putting them straight back. Importing the module here means it is
    already in ``sys.modules``, so a later import is a no-op and the clearing
    holds.

    Session-scoped so it is set up before the function-scoped fixture below, and
    written as an explicit call rather than a bare ``import`` for its side effect,
    which reads as dead code to both ruff and CodeQL.
    """
    importlib.import_module("stride_gpt.cli")


@pytest.fixture(scope="session", autouse=True)
def _hermetic_config_dir(tmp_path_factory, _cli_dotenv_loaded_up_front):
    """Point every ``~/.stride-gpt`` path at a temp dir for the whole suite.

    ``CONFIG_DIR`` and the paths derived from it are evaluated at import, so
    setting ``HOME`` in a test is too late: without this, anything that
    auto-saves a report (or config, or REPL history) writes into the
    developer's real ``~/.stride-gpt`` and shows up in ``stride-gpt reports``.
    Autouse so a new test cannot reintroduce the leak by forgetting to opt in.
    Tests that monkeypatch these paths themselves still win for their duration.

    Depends on the dotenv fixture so the CLI's import-time ``load_dotenv`` has
    already read the real ``.env`` (whose keys ``_hermetic_api_keys`` clears)
    rather than racing this redirect.
    """
    config_dir = tmp_path_factory.mktemp("stride-gpt-home") / ".stride-gpt"
    mp = pytest.MonkeyPatch()
    mp.setattr("stride_gpt.config.CONFIG_DIR", config_dir)
    mp.setattr("stride_gpt.config.CONFIG_FILE", config_dir / "config.json")
    mp.setattr("stride_gpt.config.REPORTS_DIR", config_dir / "reports")
    # prompt.py binds CONFIG_DIR by name and builds the history path from it.
    mp.setattr("stride_gpt.prompt.CONFIG_DIR", config_dir)
    yield config_dir
    mp.undo()


@pytest.fixture(autouse=True)
def _hermetic_api_keys(monkeypatch):
    """Run every test as if no provider credentials were configured.

    Without this the suite reads whatever is in the developer's own
    ``~/.stride-gpt/.env``, so a key-resolution test can pass locally and fail
    in CI, or pass for the wrong reason because a real key happened to be
    present. Tests that need a key set it themselves.

    Derived from ``PROVIDERS`` rather than hardcoded so a newly added provider
    is covered without anyone remembering to update this list.
    """
    from stride_gpt.config import PROVIDERS

    names = {info.env_var for info in PROVIDERS.values() if getattr(info, "env_var", None)}
    # Not a provider's own variable, but the worker tier's last-resort fallback
    # reads it, so a stale value here reaches the same code paths.
    names.add("STRIDE_GPT_API_KEY")
    for name in sorted(names):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def llm_config() -> LLMConfig:
    """Minimal LLMConfig for tests — no real API calls."""
    return LLMConfig(
        provider="Anthropic API",
        model_name="claude-sonnet-4-5-20250929",
        api_key="sk-test-fake-key",
    )


@pytest.fixture
def architect_config() -> LLMConfig:
    """Architect-tier LLMConfig — a distinct model so tier routing is observable."""
    return LLMConfig(
        provider="Anthropic API",
        model_name="claude-opus-4-7",
        api_key="sk-test-fake-key-architect",
    )


@pytest.fixture
def model_pair(llm_config) -> ModelPair:
    """Single-tier ModelPair — worker only, no architect."""
    return ModelPair(worker=llm_config)


@pytest.fixture
def tiered_pair(llm_config, architect_config) -> ModelPair:
    """Two-tier ModelPair — distinct worker and architect."""
    return ModelPair(worker=llm_config, architect=architect_config)


@pytest.fixture
def sample_plan() -> AnalysisPlan:
    return AnalysisPlan(
        target_path="/tmp/test-app",
        overall_description="A test web application.",
        subsystems=[
            Subsystem(
                name="Auth",
                description="Authentication and session management",
                key_files=["auth.py", "login.py"],
                focus_areas=["Spoofing", "Elevation of Privilege"],
            ),
            Subsystem(
                name="API",
                description="REST API endpoints",
                key_files=["api.py", "routes.py"],
                focus_areas=["Tampering", "Information Disclosure"],
            ),
        ],
    )


@pytest.fixture
def sample_finding() -> SubsystemFinding:
    return SubsystemFinding(
        subsystem="Auth",
        threats=[
            {
                "Threat Type": "Spoofing",
                "Scenario": "No rate limiting on login allows brute-force attacks",
                "Potential Impact": "Account takeover",
            },
            {
                "Threat Type": "Information Disclosure",
                "Scenario": "Error messages reveal whether email exists",
                "Potential Impact": "User enumeration",
            },
        ],
        improvement_suggestions=["Add rate limiting", "Use generic error messages"],
        files_analyzed=["auth.py", "login.py"],
    )


@pytest.fixture
def sample_report(sample_plan, sample_finding) -> AnalysisReport:
    return AnalysisReport(
        plan=sample_plan,
        findings=[sample_finding],
        cross_cutting_threats=[
            {
                "Threat Type": "Tampering",
                "Scenario": "No CSRF protection across subsystems",
                "Potential Impact": "Cross-site request forgery",
                "Affected Subsystems": ["Auth", "API"],
            }
        ],
        metadata={
            "worker_model": "claude-sonnet-4-5-20250929",
            "worker_provider": "Anthropic API",
            "architect_model": None,
            "architect_provider": None,
            "llm_calls": 5,
            "tool_calls": 12,
            "subsystems_analyzed": 2,
        },
    )


@pytest.fixture
def sandbox_dir(tmp_path) -> Path:
    """Create a small fake project tree for tool tests."""
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    (tmp_path / "config.yaml").write_text("debug: true\nsecret_key: hunter2\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "auth.py").write_text(
        "def login(user, password):\n    return check_db(user, password)\n"
    )
    (tmp_path / "src" / "utils.py").write_text("import os\nSECRET = os.environ['SECRET']\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("should be skipped")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main")
    # A large file for truncation tests
    (tmp_path / "big.txt").write_text("x" * 100_000)
    # A binary-extension file
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n")
    # CRLF line endings, so evidence matching is exercised against them
    (tmp_path / "crlf.py").write_bytes(
        b"import os\r\n\r\ndef run(cmd):\r\n    os.system(cmd)\r\n"
    )
    return tmp_path
