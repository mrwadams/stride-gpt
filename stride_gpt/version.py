"""Version helpers for STRIDE-GPT."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

PACKAGE_NAME = "stride-gpt"


def get_version() -> str:
    """Return the installed STRIDE-GPT package version.

    Package metadata is the release source of truth. Editable/source-tree runs
    normally still expose metadata, but keep a readable fallback for unusual
    environments where the package has not been installed yet.
    """
    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        return "unknown"
