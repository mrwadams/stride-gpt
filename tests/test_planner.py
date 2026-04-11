"""Tests for stride_gpt.agent.planner — JSON extraction and retry logic."""

from __future__ import annotations

import json
from unittest.mock import patch

from stride_gpt.agent.planner import (
    _build_plan,
    _extract_plan_json,
    create_plan,
)
from stride_gpt.core.schemas import LLMResponse


# ---------------------------------------------------------------------------
# _extract_plan_json
# ---------------------------------------------------------------------------


class TestExtractPlanJson:
    def test_clean_json(self):
        result = _extract_plan_json('{"overall_description": "x", "subsystems": []}')
        assert result == {"overall_description": "x", "subsystems": []}

    def test_markdown_fence(self):
        content = '```json\n{"overall_description": "x", "subsystems": []}\n```'
        result = _extract_plan_json(content)
        assert result is not None
        assert result["overall_description"] == "x"

    def test_embedded_in_prose(self):
        content = (
            "Here is the analysis plan:\n"
            '{"overall_description": "A Flask app", "subsystems": [{"name": "Auth"}]}\n'
            "Let me know if you need more detail."
        )
        result = _extract_plan_json(content)
        assert result is not None
        assert result["overall_description"] == "A Flask app"
        assert len(result["subsystems"]) == 1

    def test_invalid_returns_none(self):
        assert _extract_plan_json("Sorry, I cannot produce JSON right now.") is None

    def test_empty_returns_none(self):
        assert _extract_plan_json("") is None

    def test_array_returns_none(self):
        # Top-level arrays are not valid plans
        assert _extract_plan_json("[1, 2, 3]") is None


# ---------------------------------------------------------------------------
# _build_plan
# ---------------------------------------------------------------------------


class TestBuildPlan:
    def test_well_formed(self):
        data = {
            "overall_description": "Test app",
            "subsystems": [
                {"name": "Auth", "description": "auth", "key_files": ["a.py"], "focus_areas": ["Spoofing"]},
                {"name": "API", "description": "api", "key_files": ["b.py"]},
            ],
        }
        plan = _build_plan(data, "/tmp/test")
        assert plan.target_path == "/tmp/test"
        assert plan.overall_description == "Test app"
        assert len(plan.subsystems) == 2
        assert plan.subsystems[0].focus_areas == ["Spoofing"]

    def test_falls_back_when_no_subsystems(self):
        plan = _build_plan({"subsystems": []}, "/tmp/test")
        assert len(plan.subsystems) == 1
        assert plan.subsystems[0].name == "Full Codebase"

    def test_skips_non_dict_subsystems(self):
        data = {"subsystems": [{"name": "Real"}, "garbage", None]}
        plan = _build_plan(data, "/tmp/test")
        assert len(plan.subsystems) == 1
        assert plan.subsystems[0].name == "Real"


# ---------------------------------------------------------------------------
# create_plan retry behavior
# ---------------------------------------------------------------------------


class TestCreatePlanRetry:
    @patch("stride_gpt.agent.planner.call_llm")
    def test_succeeds_on_first_try(self, mock_call_llm, llm_config, sandbox_dir):
        mock_call_llm.return_value = LLMResponse(
            content=json.dumps({
                "overall_description": "Test",
                "subsystems": [{"name": "App", "description": "Main", "key_files": ["app.py"]}],
            }),
            thinking=None, reasoning=None, model="test",
        )
        plan = create_plan(llm_config, sandbox_dir)
        assert plan.subsystems[0].name == "App"
        assert mock_call_llm.call_count == 1

    @patch("stride_gpt.agent.planner.call_llm")
    def test_retries_on_bad_json(self, mock_call_llm, llm_config, sandbox_dir):
        bad = LLMResponse(content="I cannot answer", thinking=None, reasoning=None, model="t")
        good = LLMResponse(
            content=json.dumps({
                "overall_description": "Test",
                "subsystems": [{"name": "Recovered", "description": "ok"}],
            }),
            thinking=None, reasoning=None, model="t",
        )
        mock_call_llm.side_effect = [bad, good]
        plan = create_plan(llm_config, sandbox_dir)
        assert plan.subsystems[0].name == "Recovered"
        assert mock_call_llm.call_count == 2

    @patch("stride_gpt.agent.planner.call_llm")
    def test_falls_back_after_two_failures(self, mock_call_llm, llm_config, sandbox_dir):
        bad = LLMResponse(content="not json", thinking=None, reasoning=None, model="t")
        mock_call_llm.side_effect = [bad, bad]
        plan = create_plan(llm_config, sandbox_dir)
        assert plan.subsystems[0].name == "Full Codebase"
        assert "not json" in plan.overall_description
        assert mock_call_llm.call_count == 2
