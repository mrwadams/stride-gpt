"""Tests for stride_gpt.agent.planner — JSON extraction and retry logic."""

from __future__ import annotations

import json
from unittest.mock import patch

from stride_gpt.agent.planner import (
    _build_plan,
    _diverse_key_files,
    create_plan,
)
from stride_gpt.core.schemas import LLMResponse

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

    def test_app_type_defaults_to_web(self):
        plan = _build_plan({"subsystems": [{"name": "A"}]}, "/tmp/test")
        assert plan.detected_app_type == "web"

    def test_app_type_passes_through_canonical_values(self):
        for value in ("web", "genai", "agentic"):
            plan = _build_plan(
                {"detected_app_type": value, "subsystems": [{"name": "A"}]},
                "/tmp/test",
            )
            assert plan.detected_app_type == value

    def test_app_type_coerces_legacy_labels(self):
        plan = _build_plan(
            {"detected_app_type": "Agentic AI application",
             "subsystems": [{"name": "A"}]},
            "/tmp/test",
        )
        assert plan.detected_app_type == "agentic"

    def test_app_type_falls_back_when_unknown(self):
        plan = _build_plan(
            {"detected_app_type": "Quantum mainframe",
             "subsystems": [{"name": "A"}]},
            "/tmp/test",
        )
        assert plan.detected_app_type == "web"


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


# ---------------------------------------------------------------------------
# _diverse_key_files
# ---------------------------------------------------------------------------


class TestDiverseKeyFiles:
    def test_list_under_limit_is_unchanged(self):
        files = ["a/one.py", "b/two.py"]
        assert _diverse_key_files(files, 200) == files

    def test_round_robins_across_directories(self):
        early = [f"aaa/f{i:03d}.py" for i in range(200)]
        late = [f"zzz/f{i:03d}.py" for i in range(10)]
        sample = _diverse_key_files(early + late, 200)
        assert len(sample) == 200
        assert set(late).issubset(sample)

    def test_round_robins_when_directory_count_exceeds_the_limit(self):
        # PR #178 review: 250 nested leaf directories under one subsystem
        # must not starve a sibling subsystem of every file, the same
        # failure as #175 moved from file granularity to directory
        # granularity.
        web = [f"services/web/src/mod{i:03d}/index.js" for i in range(250)]
        workshop = [f"services/workshop/f{i:03d}.py" for i in range(56)]
        sample = _diverse_key_files(web + workshop, 200)
        web_count = sum(1 for f in sample if f.startswith("services/web/"))
        workshop_count = sum(1 for f in sample if f.startswith("services/workshop/"))
        assert len(sample) == 200
        assert web_count == 144
        assert workshop_count == 56


# ---------------------------------------------------------------------------
# create_plan key-file coverage (issue #175)
# ---------------------------------------------------------------------------


class TestCreatePlanKeyFileCoverage:
    @patch("stride_gpt.agent.planner.call_llm")
    def test_late_sorting_directory_reaches_the_prompt(self, mock_call_llm, llm_config, tmp_path):
        mock_call_llm.return_value = LLMResponse(
            content=json.dumps({
                "overall_description": "Test",
                "subsystems": [{"name": "App", "description": "Main", "key_files": ["app.py"]}],
            }),
            thinking=None, reasoning=None, model="test",
        )
        extensions = [".py", ".js", ".ts", ".go", ".rs"]
        (tmp_path / "service_early").mkdir()
        for ext in extensions:
            for i in range(40):
                (tmp_path / "service_early" / f"f{i:03d}{ext}").write_text("x\n")
        (tmp_path / "service_late").mkdir()
        for ext in extensions:
            for i in range(2):
                (tmp_path / "service_late" / f"f{i:03d}{ext}").write_text("x\n")

        create_plan(llm_config, tmp_path)

        prompt = mock_call_llm.call_args[0][1][1]["content"]
        assert "service_late/f000.py" in prompt
