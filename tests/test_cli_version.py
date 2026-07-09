"""Tests for CLI version reporting."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError

from typer.testing import CliRunner

from stride_gpt import cli
from stride_gpt import version as version_module

runner = CliRunner()


def test_version_flag_prints_package_version_and_exits(monkeypatch):
    monkeypatch.setattr(cli, "get_version", lambda: "9.8.7")

    result = runner.invoke(cli.app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == "stride-gpt 9.8.7"


def test_version_flag_skips_config_loading(monkeypatch):
    monkeypatch.setattr(cli, "get_version", lambda: "9.8.7")

    def fail_if_called():
        raise AssertionError("config should not load for --version")

    monkeypatch.setattr(cli, "load_config", fail_if_called)

    result = runner.invoke(cli.app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == "stride-gpt 9.8.7"


def test_get_version_falls_back_when_package_metadata_is_missing(monkeypatch):
    def missing(_: str) -> str:
        raise PackageNotFoundError

    monkeypatch.setattr(version_module, "version", missing)

    assert version_module.get_version() == "unknown"
