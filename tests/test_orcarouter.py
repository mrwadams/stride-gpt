"""Tests for the OrcaRouter Cyber Inference provider integration.

Covers the provider registration, API-key plumbing, bounded catalogue
discovery, capability filters, error behaviour, and the web dispatch helpers.
No test here performs network I/O: every catalogue read uses a mock transport.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from stride_gpt.config import get_api_key
from stride_gpt.core.llm import _build_litellm_kwargs
from stride_gpt.core.orcarouter import (
    DEFAULT_API_BASE,
    DEFAULT_MODEL,
    MAX_CATALOG_BYTES,
    VERIFIED_FALLBACK_MODELS,
    CatalogResult,
    OrcaRouterCatalogError,
    OrcaRouterModel,
    fetch_models,
    load_catalog,
    parse_catalog,
    parse_model,
    resolve_api_base,
    seed_model_ids,
    validate_api_base,
)
from stride_gpt.core.schemas import LLMConfig, LLMResponse
from stride_gpt.models import PROVIDERS, get_litellm_prefix, get_model

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps" / "web"))

PROVIDER_KEY = "OrcaRouter Cyber Inference"


def _transport(status: int, payload: object | bytes) -> httpx.MockTransport:
    if isinstance(payload, (bytes, bytearray)):
        content = bytes(payload)
    else:
        content = json.dumps(payload).encode()
    return httpx.MockTransport(lambda request: httpx.Response(status, content=content))


def _catalog_payload(*items: dict) -> dict:
    return {"object": "list", "success": True, "data": list(items)}


def _model(
    model_id: str,
    endpoints: list[str] | None = None,
    modalities: list[str] | None = None,
    context_length: int | None = None,
) -> dict:
    record: dict = {"id": model_id, "object": "model", "owned_by": "test"}
    if endpoints is not None:
        record["supported_endpoint_types"] = endpoints
    if modalities is not None:
        record["architecture"] = {"input_modalities": modalities, "output_modalities": ["text"]}
    if context_length is not None:
        record["context_length"] = context_length
    return record


# ---------------------------------------------------------------------------
# Provider registration and API key
# ---------------------------------------------------------------------------


class TestProviderRegistration:
    def test_provider_is_a_named_first_class_entry(self):
        info = PROVIDERS[PROVIDER_KEY]
        assert info.provider_key == PROVIDER_KEY
        assert info.litellm_prefix == "openai/"
        assert info.env_var == "ORCAROUTER_API_KEY"
        assert info.needs_api_key is True
        assert info.needs_api_base is False
        assert info.default_api_base == "https://api.orcarouter.ai/v1"
        assert "orcarouter.ai" in info.api_key_url

    def test_litellm_prefix_is_openai_compatible(self):
        assert get_litellm_prefix(PROVIDER_KEY) == "openai/"

    def test_verified_models_are_registered_with_token_metadata(self):
        for model_id in seed_model_ids():
            info = get_model(PROVIDER_KEY, model_id)
            assert info is not None, f"{model_id} missing from the model registry"
            assert info.default_tokens > 0
            assert info.max_tokens >= info.default_tokens

    def test_session_state_mapping_is_declared(self):
        from provider_keys import PROVIDER_API_KEY_STATE

        assert PROVIDER_API_KEY_STATE[PROVIDER_KEY] == "orcarouter_api_key"

    def test_api_key_resolves_from_provider_env_var(self, monkeypatch):
        monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-test-key")
        config = {"worker_provider": PROVIDER_KEY}
        assert get_api_key(config, tier="worker") == "sk-orca-test-key"


# ---------------------------------------------------------------------------
# Endpoint resolution
# ---------------------------------------------------------------------------


class TestEndpointResolution:
    def test_default_base(self, monkeypatch):
        monkeypatch.delenv("ORCA_API_BASE_URL", raising=False)
        monkeypatch.delenv("ORCAROUTER_API_BASE_URL", raising=False)
        assert resolve_api_base() == DEFAULT_API_BASE

    def test_explicit_override_wins(self, monkeypatch):
        monkeypatch.setenv("ORCA_API_BASE_URL", "https://shared.example/v1")
        assert resolve_api_base("https://explicit.example/api/v1") == (
            "https://explicit.example/api/v1"
        )

    def test_shared_env_override(self, monkeypatch):
        monkeypatch.delenv("ORCA_API_BASE_URL", raising=False)
        monkeypatch.setenv("ORCAROUTER_API_BASE_URL", "https://self.example/v1")
        assert resolve_api_base() == "https://self.example/v1"

    def test_trailing_slash_is_normalised(self):
        assert validate_api_base("https://api.orcarouter.ai/v1/") == (
            "https://api.orcarouter.ai/v1"
        )

    def test_remote_http_is_rejected(self):
        with pytest.raises(OrcaRouterCatalogError):
            validate_api_base("http://api.orcarouter.ai/v1")

    def test_loopback_http_is_allowed(self):
        assert validate_api_base("http://127.0.0.1:8080/v1") == "http://127.0.0.1:8080/v1"
        assert validate_api_base("http://localhost:8080/v1") == "http://localhost:8080/v1"

    def test_query_string_is_rejected(self):
        with pytest.raises(OrcaRouterCatalogError):
            validate_api_base("https://api.orcarouter.ai/v1?x=1")


# ---------------------------------------------------------------------------
# Catalogue parsing and capability filters
# ---------------------------------------------------------------------------


class TestCatalogueParsing:
    def test_parses_text_chat_model(self):
        model = parse_model(
            _model("orcarouter/auto", ["openai", "anthropic"], ["text"], 200000)
        )
        assert model is not None
        assert model.model_id == "orcarouter/auto"
        assert model.supports_chat is True
        assert model.supports_image_input is False
        assert model.context_length == 200000

    def test_parses_image_input_chat_model(self):
        model = parse_model(
            _model("deepseek/deepseek-v4.1-flash", ["openai"], ["text", "image"])
        )
        assert model is not None
        assert model.supports_chat is True
        assert model.supports_image_input is True

    @pytest.mark.parametrize(
        "endpoints",
        [
            ["image-generation"],
            ["openai-video"],
            ["jina-rerank"],
            ["embeddings"],
            ["rerank"],
            ["openai", "image-generation"],
        ],
    )
    def test_non_chat_endpoints_are_excluded(self, endpoints):
        model = parse_model(_model("vendor/model", endpoints, ["text"]))
        assert model is not None
        assert model.supports_chat is False
        assert model.supports_image_input is False

    def test_missing_endpoint_metadata_fails_closed(self):
        model = parse_model(_model("vendor/unproven", None, ["text"]))
        assert model is not None
        assert model.supports_chat is False

    def test_missing_modalities_fails_closed_for_images(self):
        model = parse_model(_model("vendor/chat", ["openai"], None))
        assert model is not None
        assert model.supports_chat is True
        assert model.supports_image_input is False

    def test_rejects_malformed_records(self):
        assert parse_model({"no_id": True}) is None
        assert parse_model("not-a-dict") is None
        assert parse_model({"id": "  "}) is None

    def test_catalog_requires_data_list(self):
        with pytest.raises(OrcaRouterCatalogError):
            parse_catalog({"data": "nope"})
        with pytest.raises(OrcaRouterCatalogError):
            parse_catalog([])

    def test_catalog_dedupes_and_caps(self):
        items = [_model(f"vendor/model-{i}", ["openai"], ["text"]) for i in range(600)]
        items.append(_model("vendor/model-0", ["openai"], ["text"]))
        parsed = parse_catalog(_catalog_payload(*items))
        assert len(parsed) == 500
        assert len({m.model_id for m in parsed}) == 500


class TestCatalogResultFilters:
    def test_chat_and_image_lists(self):
        result = CatalogResult(
            models=(
                OrcaRouterModel("vendor/text", ("openai",), ("text",)),
                OrcaRouterModel("vendor/vision", ("openai",), ("text", "image")),
                OrcaRouterModel("vendor/embed", ("embeddings",), ()),
            ),
            degraded=False,
            source="live",
        )
        assert [m.model_id for m in result.chat_models] == ["vendor/text", "vendor/vision"]
        assert [m.model_id for m in result.image_models] == ["vendor/vision"]

    def test_default_model_prefers_auto(self):
        result = CatalogResult(
            models=(
                OrcaRouterModel("vendor/other", ("openai",), ("text",)),
                OrcaRouterModel(DEFAULT_MODEL, ("openai",), ()),
            ),
            degraded=False,
            source="live",
        )
        assert result.default_model == DEFAULT_MODEL

    def test_default_model_falls_back_to_first_chat_model(self):
        result = CatalogResult(
            models=(OrcaRouterModel("vendor/other", ("openai",), ("text",)),),
            degraded=False,
            source="live",
        )
        assert result.default_model == "vendor/other"


# ---------------------------------------------------------------------------
# Discovery: request shape, bounds, live authority, fallback
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_request_uses_bearer_auth_and_models_path(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json=_catalog_payload(_model("orcarouter/auto", ["openai"])))

        models = fetch_models(
            "sk-orca-test-key", transport=httpx.MockTransport(handler)
        )
        assert seen["url"] == "https://api.orcarouter.ai/v1/models"
        assert seen["auth"] == "Bearer sk-orca-test-key"
        assert [m.model_id for m in models] == ["orcarouter/auto"]

    def test_auth_error_is_reported_without_the_key(self):
        transport = _transport(401, {"error": "invalid key"})
        with pytest.raises(OrcaRouterCatalogError) as excinfo:
            fetch_models("sk-orca-super-secret", transport=transport)
        message = str(excinfo.value)
        assert "401" in message
        assert "sk-orca-super-secret" not in message

    @pytest.mark.parametrize("status", [403, 429, 500, 503])
    def test_http_errors_are_catalog_errors(self, status):
        with pytest.raises(OrcaRouterCatalogError):
            fetch_models("sk-orca-test", transport=_transport(status, {}))

    def test_network_error_is_wrapped(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        with pytest.raises(OrcaRouterCatalogError) as excinfo:
            fetch_models("sk-orca-test", transport=httpx.MockTransport(handler))
        assert "sk-orca-test" not in str(excinfo.value)

    def test_invalid_json_is_catalog_error(self):
        with pytest.raises(OrcaRouterCatalogError):
            fetch_models("sk-orca-test", transport=_transport(200, b"not json"))

    def test_oversized_response_is_rejected(self):
        payload = b"{" + b" " * MAX_CATALOG_BYTES + b"}"
        with pytest.raises(OrcaRouterCatalogError) as excinfo:
            fetch_models("sk-orca-test", transport=_transport(200, payload))
        assert "size limit" in str(excinfo.value)

    def test_live_result_is_authoritative_and_not_merged_with_seed(self):
        transport = _transport(
            200, _catalog_payload(_model("vendor/only-live", ["openai"], ["text"]))
        )
        result = load_catalog("sk-orca-test", transport=transport)
        assert result.degraded is False
        assert result.source == "live"
        assert [m.model_id for m in result.models] == ["vendor/only-live"]
        assert DEFAULT_MODEL not in [m.model_id for m in result.models]

    def test_failure_returns_verified_fallback(self):
        transport = _transport(500, {})
        result = load_catalog("sk-orca-test", transport=transport)
        assert result.degraded is True
        assert result.source == "fallback"
        assert result.models == VERIFIED_FALLBACK_MODELS
        assert result.error

    def test_no_key_returns_verified_fallback_without_network(self):
        result = load_catalog(None)
        assert result.degraded is True
        assert result.source == "fallback"
        assert result.models == VERIFIED_FALLBACK_MODELS
        assert DEFAULT_MODEL in [m.model_id for m in result.chat_models]

    def test_fallback_seed_is_brand_and_metadata_complete(self):
        assert seed_model_ids() == [
            "orcarouter/auto",
            "orca/orcacyber-ultra-1.0",
            "orca/orcacyber-zero-1.5",
            "orcarouter/fusion",
        ]
        ultra = next(m for m in VERIFIED_FALLBACK_MODELS if m.model_id.endswith("ultra-1.0"))
        assert ultra.context_length == 1048576
        assert ultra.supports_image_input is False


# ---------------------------------------------------------------------------
# LiteLLM routing
# ---------------------------------------------------------------------------


class TestLiteLLMRouting:
    def test_routes_to_orcarouter_base_with_openai_adapter(self):
        cfg = LLMConfig(provider=PROVIDER_KEY, model_name="orcarouter/auto", api_key="fake")
        kwargs = _build_litellm_kwargs(cfg)
        assert kwargs["model"] == "openai/orcarouter/auto"
        assert kwargs["api_base"] == "https://api.orcarouter.ai/v1"
        assert kwargs["api_key"] == "fake"

    def test_explicit_base_override_wins(self):
        cfg = LLMConfig(
            provider=PROVIDER_KEY,
            model_name="orcarouter/fusion",
            api_key="fake",
            api_base="https://selfhosted.example/v1",
        )
        kwargs = _build_litellm_kwargs(cfg)
        assert kwargs["api_base"] == "https://selfhosted.example/v1"

    def test_other_providers_do_not_gain_an_api_base(self):
        cfg = LLMConfig(provider="OpenAI API", model_name="gpt-6-sol", api_key="fake")
        assert "api_base" not in _build_litellm_kwargs(cfg)

    def test_lm_studio_keeps_its_v1_suffix(self):
        cfg = LLMConfig(provider="LM Studio Server", model_name="local", api_key="not-needed")
        kwargs = _build_litellm_kwargs(cfg)
        assert kwargs["api_base"] == "http://localhost:1234/v1"


# ---------------------------------------------------------------------------
# Web dispatch: every AI entry point uses the same provider key
# ---------------------------------------------------------------------------


class TestWebDispatch:
    def _capture(self, monkeypatch, module, attr, response):
        captured = {}

        def fake(config, *args, **kwargs):
            captured["config"] = config
            return response

        monkeypatch.setattr(module, attr, fake)
        return captured

    def test_threat_model_dispatch(self, monkeypatch):
        import threat_model as web_threat_model

        result = SimpleNamespace(threat_model=[], improvement_suggestions=[])
        captured = self._capture(
            monkeypatch,
            web_threat_model,
            "generate_threat_model",
            (result, LLMResponse(content="{}")),
        )
        web_threat_model.get_threat_model_orcarouter("sk-orca-test", "orcarouter/auto", "p")
        assert captured["config"].provider == PROVIDER_KEY
        assert captured["config"].model_name == "orcarouter/auto"

    def test_image_analysis_dispatch(self, monkeypatch):
        import threat_model as web_threat_model

        captured = self._capture(
            monkeypatch, web_threat_model, "analyze_image", LLMResponse(content="diagram")
        )
        out = web_threat_model.get_image_analysis_orcarouter(
            "sk-orca-test", "deepseek/deepseek-v4.1-flash", "p", "aGVsbG8=", "image/png"
        )
        assert out["choices"][0]["message"]["content"] == "diagram"
        assert captured["config"].provider == PROVIDER_KEY

    def test_attack_tree_dispatch(self, monkeypatch):
        import attack_tree as web_attack_tree

        captured = self._capture(
            monkeypatch, web_attack_tree, "generate_attack_tree", ("graph TD", LLMResponse(content=""))
        )
        web_attack_tree.get_attack_tree_orcarouter("sk-orca-test", "orcarouter/auto", "p")
        assert captured["config"].provider == PROVIDER_KEY

    def test_dfd_dispatch(self, monkeypatch):
        import dfd as web_dfd

        captured = self._capture(
            monkeypatch, web_dfd, "generate_dfd", ("graph TD", LLMResponse(content=""))
        )
        web_dfd.get_dfd_orcarouter("sk-orca-test", "orcarouter/auto", "p")
        assert captured["config"].provider == PROVIDER_KEY

    def test_dfd_image_dispatch(self, monkeypatch):
        import dfd as web_dfd

        captured = self._capture(
            monkeypatch, web_dfd, "parse_dfd_from_image", ("graph TD", LLMResponse(content=""))
        )
        web_dfd.get_dfd_from_image_orcarouter("sk-orca-test", "vendor/vision", "aGVsbG8=")
        assert captured["config"].provider == PROVIDER_KEY

    def test_mitigations_dispatch(self, monkeypatch):
        import mitigations as web_mitigations

        captured = self._capture(
            monkeypatch, web_mitigations, "generate_mitigations", ("- control", LLMResponse(content=""))
        )
        web_mitigations.get_mitigations_orcarouter("sk-orca-test", "orcarouter/auto", "p")
        assert captured["config"].provider == PROVIDER_KEY

    def test_dread_dispatch(self, monkeypatch):
        import dread as web_dread

        captured = self._capture(
            monkeypatch, web_dread, "generate_dread_assessment", ({}, LLMResponse(content=""))
        )
        web_dread.get_dread_assessment_orcarouter("sk-orca-test", "orcarouter/auto", "p")
        assert captured["config"].provider == PROVIDER_KEY

    def test_test_cases_dispatch(self, monkeypatch):
        import test_cases as web_test_cases

        captured = self._capture(
            monkeypatch, web_test_cases, "generate_test_cases", ("Feature: x", LLMResponse(content=""))
        )
        web_test_cases.get_test_cases_orcarouter("sk-orca-test", "orcarouter/auto", "p")
        assert captured["config"].provider == PROVIDER_KEY
