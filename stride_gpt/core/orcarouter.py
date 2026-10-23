"""OrcaRouter Cyber Inference — provider catalogue and endpoint resolution.

OrcaRouter is an OpenAI-compatible AI gateway for security teams.  This module
owns the provider's fixed inference endpoint, the bounded live model discovery
call, and the capability filters the UI applies to its model pickers.  All
inference traffic still goes through :mod:`stride_gpt.core.llm`; nothing here
sends a completion request.

The live catalogue (``GET {base}/models``) is authoritative whenever it can be
read.  ``VERIFIED_FALLBACK_MODELS`` is a small, hand-verified cold-start list
used only when discovery fails, so a fresh install still has a usable picker
during an outage instead of degrading to free-text model entry.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

DEFAULT_API_BASE = "https://api.orcarouter.ai/v1"
DEFAULT_MODEL = "orcarouter/auto"

#: Endpoint types the application can actually speak (OpenAI-compatible chat).
CHAT_ENDPOINT_TYPES = frozenset({"openai", "openai-response", "anthropic", "gemini"})

#: Endpoint types that mark a model as something other than a text chat model.
NON_CHAT_ENDPOINT_TYPES = frozenset(
    {
        "image-generation",
        "openai-video",
        "jina-rerank",
        "rerank",
        "embedding",
        "embeddings",
        "audio",
        "transcription",
        "speech",
    }
)

MAX_CATALOG_BYTES = 1_000_000
MAX_CATALOG_MODELS = 500
DEFAULT_CATALOG_TIMEOUT = 8.0

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class OrcaRouterCatalogError(RuntimeError):
    """The live catalogue could not be read or parsed.

    The message never contains credentials; it names the failure class so the
    UI can show a useful degraded-state hint.
    """


@dataclass(frozen=True)
class OrcaRouterModel:
    """One model record from the OrcaRouter catalogue."""

    model_id: str
    supported_endpoint_types: tuple[str, ...] = ()
    input_modalities: tuple[str, ...] = ()
    context_length: int | None = None
    owned_by: str = ""

    @property
    def supports_chat(self) -> bool:
        """True only when the catalogue proves this is a text chat model.

        Fail closed: with no endpoint metadata we cannot prove the model speaks
        one of the chat protocols this application uses, and a model that also
        advertises a non-chat endpoint (image generation, video, rerank,
        embeddings) is kept out of the chat picker.
        """
        endpoints = set(self.supported_endpoint_types)
        if not endpoints:
            return False
        if endpoints & NON_CHAT_ENDPOINT_TYPES:
            return False
        return bool(endpoints & CHAT_ENDPOINT_TYPES)

    @property
    def supports_image_input(self) -> bool:
        """True only when the catalogue explicitly declares image input."""
        return self.supports_chat and "image" in self.input_modalities


#: Cold-start list.  Every entry is a documented OrcaRouter offering:
#: https://www.orcarouter.ai/models?tier=cyber and https://www.orcarouter.ai/cyber
#: Used only when live discovery fails; never merged into a live result.
VERIFIED_FALLBACK_MODELS: tuple[OrcaRouterModel, ...] = (
    OrcaRouterModel(
        model_id="orcarouter/auto",
        supported_endpoint_types=("openai", "openai-response", "anthropic", "gemini"),
        owned_by="orcarouter",
    ),
    OrcaRouterModel(
        model_id="orca/orcacyber-ultra-1.0",
        supported_endpoint_types=("openai",),
        input_modalities=("text",),
        context_length=1_048_576,
        owned_by="orca",
    ),
    OrcaRouterModel(
        model_id="orca/orcacyber-zero-1.5",
        supported_endpoint_types=("openai",),
        input_modalities=("text",),
        context_length=1_000_000,
        owned_by="orca",
    ),
    OrcaRouterModel(
        model_id="orcarouter/fusion",
        supported_endpoint_types=("openai", "openai-response", "anthropic", "gemini"),
        context_length=1_000_000,
        owned_by="orcarouter",
    ),
)


@dataclass(frozen=True)
class CatalogResult:
    """Outcome of one catalogue load.

    ``degraded`` is True only when the live call failed; ``models`` is then the
    verified fallback list.  ``error`` is a short, credential-free description
    suitable for a UI hint.
    """

    models: tuple[OrcaRouterModel, ...]
    degraded: bool
    source: str  # "live" | "fallback"
    error: str | None = None

    @property
    def chat_models(self) -> list[OrcaRouterModel]:
        return [m for m in self.models if m.supports_chat]

    @property
    def image_models(self) -> list[OrcaRouterModel]:
        return [m for m in self.models if m.supports_image_input]

    @property
    def default_model(self) -> str | None:
        """Prefer ``orcarouter/auto``; otherwise the first chat model."""
        chat = self.chat_models
        for model in chat:
            if model.model_id == DEFAULT_MODEL:
                return model.model_id
        return chat[0].model_id if chat else None


def resolve_api_base(explicit: str | None = None) -> str:
    """Return the configured inference base, validating it before use.

    Precedence: explicit argument, ``ORCA_API_BASE_URL``,
    ``ORCAROUTER_API_BASE_URL``, then the public default.  The value is the
    complete API base including ``/v1``; it is never derived from an auth
    origin.  HTTPS is required for remote hosts; HTTP is allowed only for
    loopback development servers.
    """
    candidate = (
        explicit
        or os.environ.get("ORCA_API_BASE_URL")
        or os.environ.get("ORCAROUTER_API_BASE_URL")
        or DEFAULT_API_BASE
    )
    return validate_api_base(candidate)


def validate_api_base(url: str) -> str:
    """Validate and normalise an inference base URL (no trailing slash)."""
    candidate = (url or "").strip().rstrip("/")
    if not candidate:
        raise OrcaRouterCatalogError("OrcaRouter API base URL is empty")
    parts = urlsplit(candidate)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise OrcaRouterCatalogError(
            "OrcaRouter API base URL must be an absolute http(s) URL"
        )
    if parts.scheme == "http" and parts.hostname not in _LOOPBACK_HOSTS:
        raise OrcaRouterCatalogError(
            "OrcaRouter API base URL must use HTTPS unless it points at loopback"
        )
    if parts.query or parts.fragment:
        raise OrcaRouterCatalogError(
            "OrcaRouter API base URL must not contain a query string or fragment"
        )
    return candidate


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item.strip().lower() for item in value if isinstance(item, str) and item.strip())


def parse_model(item: Any) -> OrcaRouterModel | None:
    """Parse one catalogue record, or return None when it is unusable."""
    if not isinstance(item, dict):
        return None
    model_id = item.get("id")
    if not isinstance(model_id, str):
        return None
    model_id = model_id.strip()
    if not model_id or len(model_id) > 200:
        return None

    endpoints = _as_str_tuple(
        item.get("supported_endpoint_types") or item.get("supported_endpoints")
    )
    architecture = item.get("architecture")
    modalities: tuple[str, ...] = ()
    if isinstance(architecture, dict):
        modalities = _as_str_tuple(architecture.get("input_modalities"))
    if not modalities:
        modalities = _as_str_tuple(item.get("input_modalities"))

    context_length = item.get("context_length")
    try:
        context_length = int(context_length) if context_length is not None else None
    except (TypeError, ValueError):
        context_length = None
    if context_length is not None and context_length <= 0:
        context_length = None

    owned_by = item.get("owned_by")
    return OrcaRouterModel(
        model_id=model_id,
        supported_endpoint_types=endpoints,
        input_modalities=modalities,
        context_length=context_length,
        owned_by=owned_by if isinstance(owned_by, str) else "",
    )


def parse_catalog(payload: Any) -> list[OrcaRouterModel]:
    """Parse an OpenAI-style ``{"data": [...]}`` catalogue payload."""
    if not isinstance(payload, dict):
        raise OrcaRouterCatalogError("OrcaRouter catalogue response was not an object")
    data = payload.get("data")
    if not isinstance(data, list):
        raise OrcaRouterCatalogError("OrcaRouter catalogue response has no model list")
    models: list[OrcaRouterModel] = []
    seen: set[str] = set()
    for item in data[:MAX_CATALOG_MODELS]:
        model = parse_model(item)
        if model is None or model.model_id in seen:
            continue
        seen.add(model.model_id)
        models.append(model)
    if not models:
        raise OrcaRouterCatalogError("OrcaRouter catalogue returned no usable models")
    return models


def fetch_models(
    api_key: str,
    *,
    api_base: str | None = None,
    timeout: float = DEFAULT_CATALOG_TIMEOUT,
    transport: httpx.BaseTransport | None = None,
) -> list[OrcaRouterModel]:
    """Read the live OrcaRouter model catalogue.

    The request is bounded by a timeout, a byte cap and a model-count cap.  The
    API key is sent only in the ``Authorization`` header and is never included
    in an exception or log line.
    """
    if not api_key:
        raise OrcaRouterCatalogError("An OrcaRouter API key is required to list models")
    base = resolve_api_base(api_base)
    url = f"{base}/models"
    try:
        with httpx.Client(
            timeout=timeout, follow_redirects=False, transport=transport
        ) as client:
            response = client.get(url, headers={"Authorization": f"Bearer {api_key}"})
    except httpx.HTTPError as exc:
        raise OrcaRouterCatalogError(
            f"Could not reach the OrcaRouter catalogue ({type(exc).__name__})"
        ) from None

    if response.status_code == 401:
        raise OrcaRouterCatalogError(
            "OrcaRouter rejected the API key (HTTP 401); check or replace the key"
        )
    if response.status_code == 403:
        raise OrcaRouterCatalogError(
            "OrcaRouter denied catalogue access for this key (HTTP 403)"
        )
    if response.status_code == 429:
        raise OrcaRouterCatalogError("OrcaRouter rate-limited the catalogue request (HTTP 429)")
    if response.status_code >= 400:
        raise OrcaRouterCatalogError(
            f"OrcaRouter catalogue request failed (HTTP {response.status_code})"
        )
    if len(response.content) > MAX_CATALOG_BYTES:
        raise OrcaRouterCatalogError("OrcaRouter catalogue response exceeded the size limit")

    try:
        payload = response.json()
    except ValueError:
        raise OrcaRouterCatalogError("OrcaRouter catalogue response was not valid JSON") from None
    return parse_catalog(payload)


def load_catalog(
    api_key: str | None,
    *,
    api_base: str | None = None,
    timeout: float = DEFAULT_CATALOG_TIMEOUT,
    transport: httpx.BaseTransport | None = None,
) -> CatalogResult:
    """Load the catalogue, falling back to the verified seed on failure.

    A successful live read is authoritative: the seed is never merged into it.
    """
    if api_key:
        try:
            models = fetch_models(
                api_key, api_base=api_base, timeout=timeout, transport=transport
            )
            return CatalogResult(models=tuple(models), degraded=False, source="live")
        except OrcaRouterCatalogError as exc:
            return CatalogResult(
                models=VERIFIED_FALLBACK_MODELS,
                degraded=True,
                source="fallback",
                error=str(exc),
            )
    return CatalogResult(
        models=VERIFIED_FALLBACK_MODELS,
        degraded=True,
        source="fallback",
        error="No OrcaRouter API key yet — showing the verified seed catalogue",
    )


def seed_model_ids() -> list[str]:
    """Model IDs from the verified fallback list, in display order."""
    return [m.model_id for m in VERIFIED_FALLBACK_MODELS]
