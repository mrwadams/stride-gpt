"""Tests for stride_gpt.agent.errors — classifying a subsystem failure."""

from __future__ import annotations

import inspect

import httpx
import litellm
import pytest

from stride_gpt.agent.errors import classify_error


def _litellm(exc_class, message="boom", status=400):
    """Build a litellm exception, whose constructors take provider metadata."""
    kwargs = {"message": message, "model": "m", "llm_provider": "openai"}
    if "response" in inspect.signature(exc_class.__init__).parameters:
        kwargs["response"] = httpx.Response(
            status, request=httpx.Request("POST", "https://example.invalid")
        )
    return exc_class(**kwargs)


class TestClassifyByType:
    @pytest.mark.parametrize(
        ("exc_class", "expected"),
        [
            (litellm.ContextWindowExceededError, "context_overflow"),
            (litellm.RateLimitError, "rate_limited"),
            (litellm.AuthenticationError, "auth"),
            (litellm.PermissionDeniedError, "auth"),
            (litellm.APIConnectionError, "provider_error"),
            (litellm.ServiceUnavailableError, "provider_error"),
            (litellm.InternalServerError, "provider_error"),
            (litellm.BadRequestError, "provider_error"),
        ],
    )
    def test_each_litellm_error_maps_to_its_class(self, exc_class, expected):
        error_class, reason = classify_error(_litellm(exc_class))
        assert error_class == expected
        # The reason is what the console and the report show, so it has to
        # carry the provider's own wording too.
        assert "boom" in reason

    def test_the_type_wins_over_a_misleading_message(self):
        """A rate limit that happens to mention a crash is still a rate limit."""
        exc = _litellm(litellm.RateLimitError, message="the worker crashed")
        assert classify_error(exc)[0] == "rate_limited"


class TestStatusBeatsTheExceptionClass:
    """litellm doesn't always raise the class the HTTP status implies."""

    def test_deepseek_reports_a_bad_key_as_a_400_class_carrying_401(self):
        """The real shape: a bad DeepSeek key arrives as BadRequestError/401.

        Classifying it "provider_error" sends the user looking at the provider
        when the fix is their API key.
        """
        exc = _litellm(
            litellm.BadRequestError,
            message='DeepseekException - {"message":"Your api key is invalid"}',
            status=401,
        )

        assert classify_error(exc)[0] == "auth"


class TestClassifyByStatus:
    @pytest.mark.parametrize(
        ("status", "expected"),
        [(429, "rate_limited"), (401, "auth"), (403, "auth"), (503, "provider_error")],
    )
    def test_a_wrapped_error_is_classified_by_its_status(self, status, expected):
        exc = RuntimeError("gateway said no")
        exc.status_code = status
        assert classify_error(exc)[0] == expected

    def test_a_status_we_do_not_recognise_falls_through(self):
        exc = RuntimeError("teapot")
        exc.status_code = 418
        assert classify_error(exc)[0] == "unexpected"

    def test_a_non_numeric_status_is_ignored(self):
        exc = RuntimeError("weird")
        exc.status_code = "not a number"
        assert classify_error(exc)[0] == "unexpected"


class TestClassifyByMessage:
    """The last resort — local runtimes that report failures as plain strings."""

    def test_llama_cpp_context_overflow(self):
        exc = RuntimeError("n_keep = 4 exceeds n_ctx = 4096")
        error_class, reason = classify_error(exc)
        assert error_class == "context_overflow"
        assert "Context window exceeded" in reason

    def test_a_crashed_local_model(self):
        error_class, reason = classify_error(RuntimeError("Model has crashed"))
        assert error_class == "provider_error"
        assert "memory constraints" in reason

    def test_anything_else_is_unexpected(self):
        error_class, reason = classify_error(ValueError("something odd"))
        assert error_class == "unexpected"
        assert reason == "Unexpected error: something odd"
