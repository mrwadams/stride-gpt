"""The test suite must not depend on the developer's own credentials.

``stride_gpt.cli`` runs ``load_dotenv(~/.stride-gpt/.env)`` at import, so simply
collecting the suite pulls real API keys into ``os.environ``. Key-resolution
tests then pass or fail depending on which providers the developer happens to
have configured, which is how a green local run can hide a CI failure.
"""

from __future__ import annotations

import os
import sys

from stride_gpt.config import PROVIDERS


def _credential_vars() -> set[str]:
    names = {info.env_var for info in PROVIDERS.values() if getattr(info, "env_var", None)}
    names.add("STRIDE_GPT_API_KEY")
    return names


def test_no_provider_credentials_are_visible():
    """Fails on a developer machine with a real ``~/.stride-gpt/.env`` if the
    autouse fixture stops clearing keys, and is a no-op in CI."""
    leaked = sorted(name for name in _credential_vars() if os.environ.get(name))
    assert not leaked, (
        "the autouse _hermetic_api_keys fixture is not clearing these: "
        f"{leaked}. Tests would run against real credentials."
    )


def test_every_provider_env_var_is_covered():
    """A provider added to ``PROVIDERS`` must not need a manual edit here."""
    assert _credential_vars() >= {
        info.env_var for info in PROVIDERS.values() if getattr(info, "env_var", None)
    }


def test_a_test_can_still_set_a_key():
    """Clearing is per-test, so setting one is unaffected."""
    assert os.environ.get("ANTHROPIC_API_KEY") in (None, "")


def test_the_cli_is_imported_before_any_test_runs():
    """The session fixture must win the ordering, or the clearing is defeated."""
    assert "stride_gpt.cli" in sys.modules


def test_importing_the_cli_mid_test_cannot_reinstate_keys():
    """The exact pattern that broke before: a test-body import of the CLI re-ran
    ``load_dotenv`` after the fixture had cleared the keys and put them back."""
    from stride_gpt import cli

    assert cli is not None
    leaked = sorted(name for name in _credential_vars() if os.environ.get(name))
    assert not leaked, f"an in-test import of the CLI reinstated: {leaked}"


def test_config_dir_is_redirected_away_from_home(_hermetic_config_dir):
    """Module-level paths derive from ``Path.home()`` at import, so only the
    autouse redirect keeps the suite out of the developer's ``~/.stride-gpt``."""
    from pathlib import Path

    from stride_gpt import config, prompt

    real = Path.home() / ".stride-gpt"
    for path in (config.CONFIG_DIR, config.CONFIG_FILE, config.REPORTS_DIR, prompt.CONFIG_DIR):
        assert not path.is_relative_to(real), f"{path} still points under {real}"
    assert config.analyze_reports_dir().is_relative_to(_hermetic_config_dir)
    assert config.quick_reports_dir().is_relative_to(_hermetic_config_dir)


def test_auto_saved_report_lands_in_the_redirected_dir(_hermetic_config_dir, sample_report):
    """A test that does not opt in still auto-saves into the temp dir."""
    from stride_gpt.agent.report import save_report

    path = save_report(sample_report)
    assert path.is_relative_to(_hermetic_config_dir / "reports" / "analyze")
    assert path.is_file()
    assert path.with_suffix(".html").is_file()


def test_config_dir_redirect_applies_without_opting_in(request):
    """Guards ``autouse``: this test does not name the fixture, so it is only
    active here if pytest applies it to every test. The tests above request it
    by name, which would activate it (for the whole session) even without
    autouse and leave a leak from earlier tests unnoticed."""
    assert "_hermetic_config_dir" in request.fixturenames
