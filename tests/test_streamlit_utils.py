"""Tests for stride_gpt.streamlit_utils — config bridge between Streamlit and agent."""

from __future__ import annotations

from unittest.mock import patch, MagicMock


class TestBuildLlmConfigFromSession:
    @patch("stride_gpt.streamlit_utils.st")
    def test_openai_config(self, mock_st):
        from stride_gpt.streamlit_utils import build_llm_config_from_session

        mock_st.session_state = {
            "model_provider": "OpenAI API",
            "selected_model": "gpt-5.2",
            "openai_api_key": "sk-test-123",
        }
        config = build_llm_config_from_session()
        assert config.provider == "OpenAI API"
        assert config.model_name == "gpt-5.2"
        assert config.api_key == "sk-test-123"
        assert config.api_base is None
        assert config.use_thinking is False

    @patch("stride_gpt.streamlit_utils.st")
    def test_anthropic_with_thinking(self, mock_st):
        from stride_gpt.streamlit_utils import build_llm_config_from_session

        mock_st.session_state = {
            "model_provider": "Anthropic API",
            "selected_model": "claude-sonnet-4-5-20250929",
            "anthropic_api_key": "sk-ant-test",
            "use_thinking": True,
        }
        config = build_llm_config_from_session()
        assert config.provider == "Anthropic API"
        assert config.api_key == "sk-ant-test"
        assert config.use_thinking is True

    @patch("stride_gpt.streamlit_utils.st")
    def test_lm_studio_config(self, mock_st):
        from stride_gpt.streamlit_utils import build_llm_config_from_session

        mock_st.session_state = {
            "model_provider": "LM Studio Server",
            "selected_model": "local-model",
            "lm_studio_endpoint": "http://localhost:1234",
            "lm_studio_api_key": "lm-key",
        }
        config = build_llm_config_from_session()
        assert config.provider == "LM Studio Server"
        assert config.api_base == "http://localhost:1234"
        assert config.api_key == "lm-key"

    @patch("stride_gpt.streamlit_utils.st")
    def test_missing_key_returns_empty(self, mock_st):
        from stride_gpt.streamlit_utils import build_llm_config_from_session

        mock_st.session_state = {
            "model_provider": "OpenAI API",
            "selected_model": "gpt-5.2",
        }
        config = build_llm_config_from_session()
        assert config.api_key == ""
