"""Classify a subsystem failure from the exception, not from its message.

The agent loop used to decide what went wrong by searching the error text for
``"n_keep"`` or ``"crashed"``. That only ever recognised two local-model
failures, and it silently reclassified anything whose wording changed. Every
provider call goes through litellm, which raises typed exceptions carrying an
HTTP status, so the type is the reliable signal and the text is the fallback.
"""

from __future__ import annotations

import json
import re
from typing import Any

from stride_gpt.core.schemas import ErrorClass

_REASONS: dict[ErrorClass, str] = {
    "context_overflow": (
        "Context window exceeded — model ran out of space for this subsystem."
    ),
    "rate_limited": "Rate limited by the provider.",
    "auth": "The provider rejected the credentials for this model.",
    "provider_error": "The provider failed to answer.",
}


def _by_type(exc: BaseException) -> ErrorClass | None:
    """Map a litellm exception class to an error class.

    Imported lazily: litellm is a heavy import and the CLI only pays for it
    when a call is actually made. A failure classifier is the last place that
    should force it.
    """
    try:
        import litellm
    except ImportError:  # pragma: no cover - litellm is a hard dependency
        return None

    if isinstance(exc, litellm.ContextWindowExceededError):
        return "context_overflow"
    if isinstance(exc, litellm.RateLimitError):
        return "rate_limited"
    if isinstance(exc, litellm.AuthenticationError | litellm.PermissionDeniedError):
        return "auth"
    return None


def _by_provider_error(exc: BaseException) -> ErrorClass | None:
    """Whether ``exc`` is a failed provider call of some unclassified kind.

    Tested against ``openai.APIError`` rather than ``litellm.APIError`` —
    litellm's typed exceptions subclass openai's hierarchy, not its own
    ``APIError``, so that is the only base that catches all of them.
    """
    try:
        import openai
    except ImportError:  # pragma: no cover - openai is a hard dependency
        return None
    # Connection errors, timeouts, 5xx, and malformed requests.
    return "provider_error" if isinstance(exc, openai.APIError) else None


def _by_status(exc: BaseException) -> ErrorClass | None:
    """Map an HTTP status carried on the exception, whatever raised it."""
    status: Any = getattr(exc, "status_code", None)
    try:
        code = int(status)
    except (TypeError, ValueError):
        return None
    if code == 429:
        return "rate_limited"
    if code in (401, 403):
        return "auth"
    if 500 <= code < 600:
        return "provider_error"
    return None


# litellm renders a provider failure as "litellm.<Class>: <Provider>Exception -
# <body>", where the body is often the provider's JSON error response.
_LITELLM_PREFIX = re.compile(r"^litellm\.\w+:\s*")
_PROVIDER_PREFIX = re.compile(r"^\w+Exception\s*-\s*")
_REQUEST_ID = re.compile(r"\s*\(request[_ ]id:[^)]*\)", re.IGNORECASE)


def provider_message(exc: BaseException) -> str:
    """The provider's own error message, without litellm's wrapping.

    Falls back to the exception text, minus the prefixes, when the body isn't
    a JSON error with a message. Request ids are dropped: they mean nothing to
    the user and make the line long.
    """
    text = _PROVIDER_PREFIX.sub("", _LITELLM_PREFIX.sub("", str(exc), count=1), count=1)
    try:
        body = json.loads(text)
    except ValueError:
        body = None
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            text = error["message"]
        elif isinstance(error, str):
            text = error
        elif isinstance(body.get("message"), str):
            text = body["message"]
    return _REQUEST_ID.sub("", text).strip()


def classify_error(exc: BaseException) -> tuple[ErrorClass, str]:
    """Return the error class for ``exc`` and the reason to show the user."""
    err_str = str(exc)

    # Status before the generic provider check: litellm doesn't always pick the
    # exception class the status implies — DeepSeek's "api key is invalid"
    # arrives as a BadRequestError carrying 401, which is an auth failure, not
    # a malformed request.
    error_class = _by_type(exc) or _by_status(exc) or _by_provider_error(exc)

    # llama.cpp says "n_keep"/"n_ctx" when the prompt won't fit. That arrives as
    # a plain string, or wrapped in a generic litellm exception with whatever
    # status the runtime chose, so the text refines a generic failure. It never
    # overrides a specific class.
    if error_class in (None, "provider_error") and "n_keep" in err_str and "n_ctx" in err_str:
        error_class = "context_overflow"

    if error_class is not None:
        reason = _REASONS[error_class]
        message = provider_message(exc)
        return error_class, f"{reason} ({message})" if message else reason

    # Last resort — a provider that wraps its errors, or a local runtime that
    # reports them as plain strings. LM Studio says the model "crashed" when it
    # is killed for memory.
    if "crashed" in err_str.lower():
        return "provider_error", "The model crashed, likely due to memory constraints."

    return "unexpected", f"Unexpected error: {err_str}"
