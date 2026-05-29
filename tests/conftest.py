"""Shared fixtures for stride-gpt tests."""

from __future__ import annotations

import pytest
from pathlib import Path

from stride_gpt.core.schemas import (
    AnalysisPlan,
    AnalysisReport,
    LLMConfig,
    ModelPair,
    SubsystemFinding,
    Subsystem,
    ToolCallResult,
)


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
    return tmp_path
