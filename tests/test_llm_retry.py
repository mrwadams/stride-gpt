"""Retries on provider errors in stride_gpt.core.llm (issue #255).

litellm's own ``num_retries`` path imports tenacity, which isn't a dependency,
so every provider error crashed on the import and nothing was ever retried.
``_completion`` now retries transient errors itself.
"""

from __future__ import annotations

import httpx
import litellm
import pytest

from stride_gpt.core import llm
from stride_gpt.core.llm import MAX_RETRIES, _build_litellm_kwargs, call_llm
from stride_gpt.core.schemas import LLMConfig

_MESSAGES = [{"role": "user", "content": "hi"}]
_REAL_COMPLETION = litellm.completion


def _config() -> LLMConfig:
    return LLMConfig(provider="OpenAI API", model_name="gpt-4o", api_key="sk-test")


def _error(exc_class, status: int, headers: dict | None = None):
    response = httpx.Response(
        status, headers=headers, request=httpx.Request("POST", "https://example.invalid")
    )
    return exc_class(message="boom", model="gpt-4o", llm_provider="openai", response=response)


def _ok(**kwargs):
    """A real litellm response, without network."""
    return _REAL_COMPLETION(mock_response="ok", **kwargs)


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    slept: list[float] = []
    monkeypatch.setattr(llm.time, "sleep", slept.append)
    return slept


def _script(monkeypatch, outcomes: list) -> list[dict]:
    """Patch litellm.completion to raise or succeed in order. Returns the calls."""
    calls: list[dict] = []

    def fake(**kwargs):
        calls.append(kwargs)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return _ok(**kwargs)

    monkeypatch.setattr(litellm, "completion", fake)
    return calls


class TestProviderErrorReachesCaller:
    def test_provider_error_with_repo_kwargs_does_not_need_tenacity(self, monkeypatch, sleeps):
        """The real litellm.completion, with the kwargs the repo sends, must raise
        the provider's error, not litellm's "tenacity import failed"."""
        error = litellm.AuthenticationError(
            message="bad key", model="gpt-4o", llm_provider="openai"
        )
        monkeypatch.setattr(
            litellm, "completion", lambda **kw: _REAL_COMPLETION(mock_response=error, **kw)
        )
        with pytest.raises(litellm.AuthenticationError):
            call_llm(_config(), _MESSAGES)

    def test_num_retries_not_passed_to_litellm(self):
        assert "num_retries" not in _build_litellm_kwargs(_config())


class TestRetries:
    @pytest.mark.parametrize(
        ("exc_class", "status"),
        [
            (litellm.RateLimitError, 429),
            (litellm.InternalServerError, 500),
            (litellm.ServiceUnavailableError, 503),
        ],
    )
    def test_transient_error_is_retried_and_call_succeeds(
        self, monkeypatch, sleeps, exc_class, status
    ):
        calls = _script(monkeypatch, [_error(exc_class, status), "ok"])
        response = call_llm(_config(), _MESSAGES)
        assert response.content == "ok"
        assert len(calls) == 2
        assert len(sleeps) == 1

    def test_connection_error_is_retried(self, monkeypatch, sleeps):
        error = litellm.APIConnectionError(message="reset", model="gpt-4o", llm_provider="openai")
        calls = _script(monkeypatch, [error, "ok"])
        assert call_llm(_config(), _MESSAGES).content == "ok"
        assert len(calls) == 2

    def test_auth_error_is_not_retried(self, monkeypatch, sleeps):
        calls = _script(monkeypatch, [_error(litellm.AuthenticationError, 401)])
        with pytest.raises(litellm.AuthenticationError):
            call_llm(_config(), _MESSAGES)
        assert len(calls) == 1
        assert sleeps == []

    def test_gives_up_after_max_retries(self, monkeypatch, sleeps):
        errors = [_error(litellm.RateLimitError, 429) for _ in range(MAX_RETRIES + 1)]
        calls = _script(monkeypatch, errors)
        with pytest.raises(litellm.RateLimitError):
            call_llm(_config(), _MESSAGES)
        assert len(calls) == MAX_RETRIES + 1
        assert sleeps == [2.0, 4.0, 8.0]

    def test_retry_after_header_sets_the_delay(self, monkeypatch, sleeps):
        error = _error(litellm.RateLimitError, 429, headers={"retry-after": "17"})
        _script(monkeypatch, [error, "ok"])
        call_llm(_config(), _MESSAGES)
        assert sleeps == [17.0]
