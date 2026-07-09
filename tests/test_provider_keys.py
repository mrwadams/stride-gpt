"""Tripwire tests for the provider -> session-state API-key mapping.

The web UI resolves each provider's API key from ``st.session_state`` via
``apps/web/provider_keys.PROVIDER_API_KEY_STATE`` (used by the sidebar, the DFD
tab, and the guided-draft resolver). If a provider is added to the registry in
``stride_gpt.models`` but not to that map, its guided draft / key lookup would
silently fall back or fail. These tests fail if the two ever drift.
"""

from __future__ import annotations

import sys
from pathlib import Path

# apps/web isn't a package on the default path; add it so we can import the map.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps" / "web"))

from provider_keys import PROVIDER_API_KEY_STATE  # noqa: E402
from stride_gpt.models import PROVIDERS  # noqa: E402


def test_every_api_key_provider_is_mapped():
    """Every registry provider that authenticates with an API key is mapped."""
    for info in PROVIDERS.values():
        # LM Studio authenticates via a custom endpoint (api_base) plus an
        # optional key, and is handled separately by callers.
        if info.needs_api_base or not info.needs_api_key:
            continue
        assert info.provider_key in PROVIDER_API_KEY_STATE, (
            f"Provider {info.provider_key!r} is in stride_gpt.models.PROVIDERS but "
            f"missing from PROVIDER_API_KEY_STATE (apps/web/provider_keys.py). "
            f"Add its session-state key."
        )


def test_no_stale_mappings():
    """Every mapped provider still exists in the registry."""
    valid_provider_keys = {info.provider_key for info in PROVIDERS.values()}
    for provider_key in PROVIDER_API_KEY_STATE:
        assert provider_key in valid_provider_keys, (
            f"PROVIDER_API_KEY_STATE maps {provider_key!r}, which is not a known "
            f"provider in stride_gpt.models.PROVIDERS."
        )
