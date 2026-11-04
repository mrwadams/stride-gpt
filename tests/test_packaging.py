"""Tests for what the published wheel declares, read from pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _dependencies() -> dict[str, Requirement]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    reqs = (Requirement(spec) for spec in data["project"]["dependencies"])
    return {req.name: req for req in reqs}


def test_litellm_declares_the_mcp_extra():
    """From litellm 1.106.0 every tool-calling completion() imports mcp, which
    only the mcp extra installs. uv.lock alone doesn't reach pip users (#330)."""
    assert "mcp" in _dependencies()["litellm"].extras
