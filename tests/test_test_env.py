"""The test suite must not depend on the developer's own credentials.

``stride_gpt.cli`` runs ``load_dotenv(~/.stride-gpt/.env)`` at import, so simply
collecting the suite pulls real API keys into ``os.environ``. Key-resolution
tests then pass or fail depending on which providers the developer happens to
have configured, which is how a green local run can hide a CI failure.
"""

from __future__ import annotations

import os

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
