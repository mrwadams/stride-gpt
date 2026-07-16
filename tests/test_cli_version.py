"""Tests for `stride-gpt --version` and the version helper.

`--version` is the first thing a bug report reaches for, so its output
contract (`stride-gpt <version>`, exit 0) is pinned here. The metadata-missing
fallback is exercised too, since editable/source runs have no package metadata.
"""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError

from typer.testing import CliRunner

from stride_gpt import cli

runner = CliRunner()


class TestVersionFlag:
    def test_version_prints_and_exits_zero(self):
        result = runner.invoke(cli.app, ["--version"])
        assert result.exit_code == 0
        assert result.stdout.strip() == f"stride-gpt {cli.__version__}"

    def test_version_output_format(self):
        """Output is `stride-gpt <version>` with a non-empty version token."""
        result = runner.invoke(cli.app, ["--version"])
        match = re.match(r"^stride-gpt (\S+)$", result.stdout.strip())
        assert match is not None
        assert match.group(1)


class TestGetVersion:
    def test_returns_installed_version(self):
        assert cli._get_version() == cli._pkg_version("stride-gpt")

    def test_missing_metadata_falls_back(self, monkeypatch):
        def _raise(_name):
            raise PackageNotFoundError

        monkeypatch.setattr(cli, "_pkg_version", _raise)
        assert cli._get_version() == "unknown"
