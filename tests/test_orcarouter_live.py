"""Live checks against the OrcaRouter Cyber Inference gateway.

Skipped unless an OrcaRouter API key is present in the environment. These
tests make real gateway calls (one catalogue read, one chat completion), so
they are excluded from ordinary CI runs and only exercise the paths that a
mock cannot prove: endpoint reachability, auth acceptance, and that the
capability metadata we filter on is what the live catalogue actually reports.
"""

from __future__ import annotations

import os

import pytest

from stride_gpt.core.llm import call_llm
from stride_gpt.core.orcarouter import DEFAULT_MODEL, fetch_models, load_catalog
from stride_gpt.core.schemas import LLMConfig

API_KEY = os.environ.get("ORCAROUTER_API_KEY", "")
PREFERRED_CHAT_MODEL = "orca/orcacyber-zero-1.5"

pytestmark = pytest.mark.skipif(
    not API_KEY, reason="OrcaRouter API key not configured in the environment"
)


def test_live_catalogue_reports_chat_models():
    models = fetch_models(API_KEY)
    assert models, "live catalogue returned no models"
    chat_models = [m for m in models if m.supports_chat]
    assert chat_models, "live catalogue exposed no chat-capable models"
    assert DEFAULT_MODEL in {m.model_id for m in chat_models}


def test_live_image_models_declare_image_input():
    catalog = load_catalog(API_KEY)
    assert catalog.source == "live"
    assert not catalog.degraded
    for model in catalog.image_models:
        assert model.supports_image_input
        assert "image" in model.input_modalities


def test_live_chat_completion_routes_through_provider():
    available = [m.model_id for m in fetch_models(API_KEY) if m.supports_chat]
    preferred = [PREFERRED_CHAT_MODEL, DEFAULT_MODEL, "orcarouter/fusion"]
    candidates = [m for m in preferred if m in available] + [
        m for m in available if m not in preferred
    ][:3]
    failures = []
    for model_name in candidates:
        config = LLMConfig(
            provider="OrcaRouter Cyber Inference",
            model_name=model_name,
            api_key=API_KEY,
            max_tokens=32,
        )
        try:
            response = call_llm(config, [{"role": "user", "content": "Reply with the word ok."}])
        except Exception as exc:
            # A key can be scoped to a subset of the catalogue; try the next
            # reachable model instead of failing on an access error.
            failures.append(f"{model_name}: {type(exc).__name__}")
            continue
        assert response.content.strip()
        return
    pytest.fail("no live chat model was reachable through the provider: " + "; ".join(failures))
