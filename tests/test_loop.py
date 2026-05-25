"""Tests for stride_gpt.agent.loop — agent loop and helper functions."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from stride_gpt.agent.loop import (
    _parse_subsystem_finding,
    _prepare_for_plain_llm,
    _strip_tool_artifacts,
    _summarize_for_analysis,
    _synthesize,
    create_analysis_plan,
    run_analysis,
)
from stride_gpt.agent.progress import RichProgress
from stride_gpt.core.schemas import (
    AnalysisPlan,
    LLMResponse,
    Subsystem,
    SubsystemFinding,
    ToolCallResult,
)


# ---------------------------------------------------------------------------
# _parse_subsystem_finding
# ---------------------------------------------------------------------------


class TestParseSubsystemFinding:
    def test_valid_json(self):
        content = json.dumps({
            "threats": [{"Threat Type": "Spoofing", "Scenario": "test", "Potential Impact": "bad"}],
            "improvement_suggestions": ["fix it"],
            "files_analyzed": ["auth.py"],
        })
        finding = _parse_subsystem_finding("Auth", content)
        assert finding is not None
        assert finding.subsystem == "Auth"
        assert len(finding.threats) == 1
        assert finding.files_analyzed == ["auth.py"]

    def test_json_in_markdown_code_fence(self):
        content = '```json\n{"threats": [], "improvement_suggestions": []}\n```'
        finding = _parse_subsystem_finding("Test", content)
        assert finding is not None
        assert finding.threats == []

    def test_json_embedded_in_text(self):
        content = 'Here is my analysis:\n{"threats": [{"Threat Type": "Tampering"}], "improvement_suggestions": []}\nThat is all.'
        finding = _parse_subsystem_finding("Test", content)
        assert finding is not None
        assert len(finding.threats) == 1

    def test_no_json_returns_none(self):
        finding = _parse_subsystem_finding("Test", "I found some threats but here is no JSON")
        assert finding is None

    def test_missing_keys_default_to_empty(self):
        content = json.dumps({"threats": []})
        finding = _parse_subsystem_finding("Test", content)
        assert finding is not None
        assert finding.improvement_suggestions == []
        assert finding.files_analyzed == []


# ---------------------------------------------------------------------------
# _strip_tool_artifacts
# ---------------------------------------------------------------------------


class TestStripToolArtifacts:
    def test_removes_tool_messages(self):
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "assistant", "content": "calling tool", "tool_calls": [{"id": "1"}]},
            {"role": "tool", "tool_call_id": "1", "content": "result"},
            {"role": "user", "content": "next"},
        ]
        result = _strip_tool_artifacts(msgs)
        assert len(result) == 3  # system + cleaned assistant + user
        assert all(m["role"] != "tool" for m in result)
        assert "tool_calls" not in result[1]

    def test_preserves_assistant_content(self):
        msgs = [
            {"role": "assistant", "content": "thinking...", "tool_calls": [{"id": "1"}]},
        ]
        result = _strip_tool_artifacts(msgs)
        assert result[0]["content"] == "thinking..."

    def test_noop_on_clean_messages(self):
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hello"},
        ]
        result = _strip_tool_artifacts(msgs)
        assert result == msgs


# ---------------------------------------------------------------------------
# _summarize_for_analysis / _prepare_for_plain_llm
# ---------------------------------------------------------------------------


class TestSummarizeForAnalysis:
    @patch("stride_gpt.agent.loop.call_llm")
    def test_builds_summary_from_tool_results(self, mock_call_llm, llm_config):
        mock_call_llm.return_value = LLMResponse(content="Summary of findings")
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "analyze auth"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "1", "type": "function", "function": {"name": "read_file", "arguments": '{"path":"auth.py"}'}}
            ]},
            {"role": "tool", "tool_call_id": "1", "name": "read_file", "content": "def login(): pass"},
        ]
        result = _summarize_for_analysis(llm_config, messages)
        assert result == "Summary of findings"
        # Verify the LLM was called with the summary prompt
        call_args = mock_call_llm.call_args
        sent_messages = call_args[0][1]
        assert "security-focused" in sent_messages[0]["content"].lower()
        # Tool results should appear in the conversation sent to the summarizer
        assert "def login(): pass" in sent_messages[1]["content"]

    @patch("stride_gpt.agent.loop.call_llm")
    def test_skips_empty_content(self, mock_call_llm, llm_config):
        mock_call_llm.return_value = LLMResponse(content="Summary")
        messages = [
            {"role": "assistant", "content": ""},
            {"role": "tool", "tool_call_id": "1", "name": "read_file", "content": "data"},
        ]
        _summarize_for_analysis(llm_config, messages)
        sent_content = mock_call_llm.call_args[0][1][1]["content"]
        # Empty assistant content should be skipped, tool content included
        assert "data" in sent_content


class TestPrepareForPlainLlm:
    @patch("stride_gpt.agent.loop._summarize_for_analysis")
    def test_preserves_system_and_user(self, mock_summarize, llm_config):
        mock_summarize.return_value = "Security findings here"
        messages = [
            {"role": "system", "content": "You are a security expert"},
            {"role": "user", "content": "Analyze auth subsystem"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "1"}]},
            {"role": "tool", "tool_call_id": "1", "name": "read_file", "content": "file data"},
        ]
        result = _prepare_for_plain_llm(llm_config, messages)
        assert result[0]["role"] == "system"
        assert result[0]["content"] == "You are a security expert"
        assert result[1]["role"] == "user"
        assert result[1]["content"] == "Analyze auth subsystem"
        assert result[2]["role"] == "user"
        assert "Security findings here" in result[2]["content"]

    @patch("stride_gpt.agent.loop._summarize_for_analysis")
    def test_no_tool_results_skips_summarization(self, mock_summarize, llm_config):
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "response"},
        ]
        result = _prepare_for_plain_llm(llm_config, messages)
        mock_summarize.assert_not_called()
        assert all(m.get("role") != "tool" for m in result)

    @patch("stride_gpt.agent.loop._summarize_for_analysis")
    def test_falls_back_on_summarization_failure(self, mock_summarize, llm_config):
        mock_summarize.side_effect = Exception("LLM error")
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "analyze"},
            {"role": "tool", "tool_call_id": "1", "name": "read_file", "content": "data"},
        ]
        result = _prepare_for_plain_llm(llm_config, messages)
        # Should fall back to _strip_tool_artifacts (lossy but doesn't crash)
        assert all(m.get("role") != "tool" for m in result)

    @patch("stride_gpt.agent.loop._summarize_for_analysis")
    def test_output_has_no_tool_artifacts(self, mock_summarize, llm_config):
        mock_summarize.return_value = "findings"
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "task"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "1"}]},
            {"role": "tool", "tool_call_id": "1", "name": "grep", "content": "matches"},
            {"role": "assistant", "content": "I found something interesting"},
        ]
        result = _prepare_for_plain_llm(llm_config, messages)
        for msg in result:
            assert msg.get("role") != "tool"
            assert "tool_calls" not in msg


# ---------------------------------------------------------------------------
# _synthesize
# ---------------------------------------------------------------------------


class TestSynthesize:
    @patch("stride_gpt.agent.loop.call_llm")
    def test_returns_cross_cutting_threats(self, mock_call_llm, model_pair):
        mock_call_llm.return_value = LLMResponse(
            content=json.dumps({
                "cross_cutting_threats": [
                    {"Threat Type": "Tampering", "Scenario": "No CSRF", "Potential Impact": "bad",
                     "Affected Subsystems": ["Auth", "API"]}
                ]
            }),
            thinking=None,
            reasoning=None,
            model="test",
        )
        findings = [
            SubsystemFinding(subsystem="Auth", threats=[{"Threat Type": "Spoofing"}]),
            SubsystemFinding(subsystem="API", threats=[{"Threat Type": "Tampering"}]),
        ]
        result = _synthesize(model_pair, findings)
        assert len(result) == 1
        assert result[0]["Threat Type"] == "Tampering"

    @patch("stride_gpt.agent.loop.call_llm")
    def test_returns_empty_on_parse_failure(self, mock_call_llm, model_pair):
        mock_call_llm.return_value = LLMResponse(
            content="I can't produce valid JSON right now",
            thinking=None, reasoning=None, model="test",
        )
        findings = [SubsystemFinding(subsystem="A", threats=[])]
        result = _synthesize(model_pair, findings)
        assert result == []


# ---------------------------------------------------------------------------
# run_analysis (integration, fully mocked)
# ---------------------------------------------------------------------------


class TestRunAnalysis:
    @patch("stride_gpt.agent.loop.call_llm")
    @patch("stride_gpt.agent.loop.call_llm_with_tools")
    def test_full_analysis_with_plan(self, mock_llm_tools, mock_llm, model_pair, tmp_path):
        """Test analysis with a pre-approved plan (the split API)."""
        plan = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="Test app",
            subsystems=[
                Subsystem(name="Auth", description="Auth module",
                          key_files=["auth.py"], focus_areas=["Spoofing"]),
            ],
        )

        # Agent loop: return findings directly (no tool calls)
        finding_json = json.dumps({
            "threats": [{"Threat Type": "Spoofing", "Scenario": "Weak auth", "Potential Impact": "Takeover"}],
            "improvement_suggestions": ["Use MFA"],
            "files_analyzed": ["auth.py"],
        })
        mock_llm_tools.return_value = LLMResponse(
            content=finding_json, thinking=None, reasoning=None, model="test", tool_calls=None,
        )

        # Synthesis skipped (only 1 subsystem)
        progress = MagicMock()
        report = run_analysis(model_pair, tmp_path, plan=plan, progress=progress)

        assert len(report.findings) == 1
        assert report.findings[0].subsystem == "Auth"
        assert len(report.findings[0].threats) == 1
        assert report.metadata["subsystems_analyzed"] == 1
        # Verify progress callbacks were invoked
        progress.phase_start.assert_called()
        progress.subsystem_start.assert_called()
        progress.subsystem_done.assert_called_with("Auth", 1)
        progress.complete.assert_called()

    @patch("stride_gpt.agent.loop.call_llm")
    @patch("stride_gpt.agent.loop.call_llm_with_tools")
    def test_tool_call_flow(self, mock_llm_tools, mock_llm, model_pair, sandbox_dir):
        """Test that the agent executes tool calls before producing findings."""
        plan = AnalysisPlan(
            target_path=str(sandbox_dir),
            overall_description="Test app",
            subsystems=[
                Subsystem(name="App", description="Main app",
                          key_files=["app.py"], focus_areas=["Spoofing"]),
            ],
        )

        # First call: agent makes a tool call
        tool_call_response = LLMResponse(
            content="Let me read the file",
            thinking=None, reasoning=None, model="test",
            tool_calls=[ToolCallResult(id="tc1", function_name="read_file", arguments={"path": "app.py"})],
        )
        # Second call: agent returns findings
        finding_json = json.dumps({
            "threats": [{"Threat Type": "Information Disclosure", "Scenario": "Debug mode", "Potential Impact": "Leak"}],
            "improvement_suggestions": ["Disable debug"],
            "files_analyzed": ["app.py"],
        })
        final_response = LLMResponse(
            content=finding_json, thinking=None, reasoning=None, model="test", tool_calls=None,
        )
        mock_llm_tools.side_effect = [tool_call_response, final_response]

        progress = MagicMock()
        report = run_analysis(model_pair, sandbox_dir, plan=plan, progress=progress)

        assert len(report.findings) == 1
        assert report.findings[0].threats[0]["Threat Type"] == "Information Disclosure"
        assert report.metadata["tool_calls"] >= 1
        # Verify tool call was reported to progress
        progress.tool_call.assert_called()

    @patch("stride_gpt.agent.loop._synthesize", return_value=[])
    @patch("stride_gpt.agent.loop._analyze_subsystem")
    def test_per_subsystem_budget_is_remaining_not_global(
        self, mock_analyze, _mock_synth, model_pair, tmp_path
    ):
        """Each subsystem should receive the remaining global budget, not the
        original limit — otherwise N subsystems could each spend the full
        budget independently."""
        plan = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="Test app",
            subsystems=[
                Subsystem(name="A", description="A", key_files=[], focus_areas=[]),
                Subsystem(name="B", description="B", key_files=[], focus_areas=[]),
            ],
        )

        # Each subsystem "spends" 3 LLM calls and 2 tool calls.
        def fake_analyze(**kwargs):
            kwargs["call_counts"]["llm"] = 3
            kwargs["call_counts"]["tool"] = 2
            return SubsystemFinding(subsystem=kwargs["subsystem_name"], threats=[])

        mock_analyze.side_effect = fake_analyze

        progress = MagicMock()
        run_analysis(
            model_pair,
            tmp_path,
            plan=plan,
            max_llm_calls=10,
            max_tool_calls=8,
            progress=progress,
        )

        # First subsystem call: full budget (10 llm, 8 tool) remains.
        # Second subsystem call: 10-3=7 llm, 8-2=6 tool should be passed.
        assert mock_analyze.call_count == 2
        first_kwargs = mock_analyze.call_args_list[0].kwargs
        second_kwargs = mock_analyze.call_args_list[1].kwargs
        assert first_kwargs["max_llm_calls"] == 10
        assert first_kwargs["max_tool_calls"] == 8
        assert second_kwargs["max_llm_calls"] == 7
        assert second_kwargs["max_tool_calls"] == 6

    @patch("stride_gpt.agent.loop._synthesize", return_value=[])
    @patch("stride_gpt.agent.loop._analyze_subsystem")
    def test_unlimited_budget_passes_zero(
        self, mock_analyze, _mock_synth, model_pair, tmp_path
    ):
        """When global budget is 0 (unlimited), each subsystem should also
        receive 0 — not a negative remainder."""
        plan = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="Test app",
            subsystems=[
                Subsystem(name="A", description="A", key_files=[], focus_areas=[]),
                Subsystem(name="B", description="B", key_files=[], focus_areas=[]),
            ],
        )

        def fake_analyze(**kwargs):
            kwargs["call_counts"]["llm"] = 5
            kwargs["call_counts"]["tool"] = 5
            return SubsystemFinding(subsystem=kwargs["subsystem_name"], threats=[])

        mock_analyze.side_effect = fake_analyze

        progress = MagicMock()
        run_analysis(model_pair, tmp_path, plan=plan, progress=progress)

        for call in mock_analyze.call_args_list:
            assert call.kwargs["max_llm_calls"] == 0
            assert call.kwargs["max_tool_calls"] == 0

    @patch("stride_gpt.agent.loop.create_plan")
    def test_cancelled_analysis(self, mock_plan, model_pair, tmp_path):
        """Test cancellation via console.input (backward compat path)."""
        mock_plan.return_value = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="Test",
            subsystems=[Subsystem(name="A", description="A", key_files=[], focus_areas=[])],
        )

        console = MagicMock()
        console.input.return_value = "n"

        report = run_analysis(model_pair, tmp_path, auto_approve=False, console=console)
        assert report.metadata.get("status") == "cancelled"
        assert report.findings == []


# ---------------------------------------------------------------------------
# App-type propagation (planner hint → agent prompt → metadata)
# ---------------------------------------------------------------------------


class TestAppTypeFlow:
    @pytest.mark.parametrize("app_type", ["agentic", "genai", "web"])
    @patch("stride_gpt.agent.loop.call_llm")
    @patch("stride_gpt.agent.loop.call_llm_with_tools")
    def test_user_prompt_carries_no_card_hints(
        self, mock_llm_tools, _mock_llm, app_type, model_pair, tmp_path,
    ):
        """The per-subsystem user prompt must not hardcode card-specific hints
        regardless of the planner's `detected_app_type`. Card discovery is
        the agent's job — it calls `list_references` (advertised in the
        system prompt) and decides which cards apply from the catalogue.
        Hardcoding hints here would re-introduce the coupling the
        frontmatter-driven refactor removed."""
        plan = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="X",
            detected_app_type=app_type,
            subsystems=[
                Subsystem(name="A", description="A",
                          key_files=["a.py"], focus_areas=["S"]),
            ],
        )
        mock_llm_tools.return_value = LLMResponse(
            content='{"threats": [], "improvement_suggestions": [], "files_analyzed": []}',
            thinking=None, reasoning=None, model="t", tool_calls=None,
        )

        run_analysis(model_pair, tmp_path, plan=plan, progress=MagicMock())

        messages = mock_llm_tools.call_args_list[0].args[1]
        user_msg = next(m for m in messages if m.get("role") == "user")
        assert "load_reference" not in user_msg["content"]
        assert "genai" not in user_msg["content"]
        assert "agentic" not in user_msg["content"]

    @patch("stride_gpt.agent.loop.call_llm")
    @patch("stride_gpt.agent.loop.call_llm_with_tools")
    def test_metadata_records_app_type(
        self, mock_llm_tools, _mock_llm, model_pair, tmp_path,
    ):
        plan = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="X",
            detected_app_type="agentic",
            subsystems=[
                Subsystem(name="A", description="A", key_files=[], focus_areas=[]),
            ],
        )
        mock_llm_tools.return_value = LLMResponse(
            content='{"threats": [], "improvement_suggestions": [], "files_analyzed": []}',
            thinking=None, reasoning=None, model="t", tool_calls=None,
        )

        report = run_analysis(model_pair, tmp_path, plan=plan, progress=MagicMock())
        assert report.metadata["app_type"] == "agentic"

    @patch("stride_gpt.agent.loop.call_llm")
    @patch("stride_gpt.agent.loop.call_llm_with_tools")
    def test_agent_can_call_load_reference_tool(
        self, mock_llm_tools, _mock_llm, model_pair, tmp_path,
    ):
        """End-to-end: agent calls load_reference, gets the card, then emits
        findings. Verifies the tool is actually reachable via the dispatch."""
        plan = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="agentic",
            detected_app_type="agentic",
            subsystems=[
                Subsystem(name="A", description="A", key_files=[], focus_areas=[]),
            ],
        )

        tool_call_response = LLMResponse(
            content="I need the agentic card",
            thinking=None, reasoning=None, model="t",
            tool_calls=[ToolCallResult(
                id="tc1", function_name="load_reference",
                arguments={"name": "agentic"},
            )],
        )
        final_response = LLMResponse(
            content='{"threats": [{"Threat Type": "Tampering", "Scenario": "ASI06 memory poisoning", "Potential Impact": "Bad", "OWASP_ASI": "ASI06"}], "improvement_suggestions": [], "files_analyzed": []}',
            thinking=None, reasoning=None, model="t", tool_calls=None,
        )
        mock_llm_tools.side_effect = [tool_call_response, final_response]

        report = run_analysis(model_pair, tmp_path, plan=plan, progress=MagicMock())

        assert len(report.findings) == 1
        assert report.findings[0].threats[0]["OWASP_ASI"] == "ASI06"
        # The card content should now be in the messages history of the
        # second call.
        second_call_messages = mock_llm_tools.call_args_list[1].args[1]
        tool_results = [m for m in second_call_messages if m.get("role") == "tool"]
        assert any("ASI01" in m["content"] for m in tool_results)


# ---------------------------------------------------------------------------
# Tier routing — verify which LLMConfig reaches which call site
# ---------------------------------------------------------------------------


class TestTierRouting:
    """When the user configures a separate architect, the architect must drive
    planning, synthesis, and compression — the worker must drive per-subsystem
    tool-use iteration and the JSON-coercion fallback. With no architect set,
    every call falls through to the worker."""

    @patch("stride_gpt.agent.loop.create_plan")
    @patch("stride_gpt.agent.loop.call_llm")
    @patch("stride_gpt.agent.loop.call_llm_with_tools")
    def test_tiered_routes_to_correct_tiers(
        self, mock_llm_tools, mock_llm, mock_plan, tiered_pair, tmp_path,
    ):
        """planner → architect; tool-loop → worker; synthesis → architect."""
        mock_plan.return_value = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="X",
            subsystems=[
                Subsystem(name="A", description="A", key_files=[], focus_areas=[]),
                Subsystem(name="B", description="B", key_files=[], focus_areas=[]),
            ],
        )
        mock_llm_tools.return_value = LLMResponse(
            content='{"threats": [], "improvement_suggestions": [], "files_analyzed": []}',
            thinking=None, reasoning=None, model="t", tool_calls=None,
        )
        # Synthesis call returns JSON
        mock_llm.return_value = LLMResponse(
            content='{"cross_cutting_threats": []}',
            thinking=None, reasoning=None, model="t",
        )

        run_analysis(tiered_pair, tmp_path, progress=MagicMock(), auto_approve=True)

        # planner.create_plan called with architect
        assert mock_plan.call_args.args[0].model_name == tiered_pair.architect.model_name

        # Per-subsystem call_llm_with_tools always uses worker
        for call in mock_llm_tools.call_args_list:
            assert call.args[0].model_name == tiered_pair.worker.model_name

        # _synthesize call (via call_llm in JSON mode) uses architect
        # The synthesis call is the only call_llm invocation when no
        # JSON-fallback fires; assert at least one is architect.
        architect_models = {c.args[0].model_name for c in mock_llm.call_args_list}
        assert tiered_pair.architect.model_name in architect_models

    @patch("stride_gpt.agent.loop.create_plan")
    @patch("stride_gpt.agent.loop.call_llm")
    @patch("stride_gpt.agent.loop.call_llm_with_tools")
    def test_single_tier_uses_worker_everywhere(
        self, mock_llm_tools, mock_llm, mock_plan, model_pair, tmp_path,
    ):
        """With architect=None, every call routes to worker."""
        mock_plan.return_value = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="X",
            subsystems=[
                Subsystem(name="A", description="A", key_files=[], focus_areas=[]),
                Subsystem(name="B", description="B", key_files=[], focus_areas=[]),
            ],
        )
        mock_llm_tools.return_value = LLMResponse(
            content='{"threats": [], "improvement_suggestions": [], "files_analyzed": []}',
            thinking=None, reasoning=None, model="t", tool_calls=None,
        )
        mock_llm.return_value = LLMResponse(
            content='{"cross_cutting_threats": []}',
            thinking=None, reasoning=None, model="t",
        )

        run_analysis(model_pair, tmp_path, progress=MagicMock(), auto_approve=True)

        worker_name = model_pair.worker.model_name
        assert mock_plan.call_args.args[0].model_name == worker_name
        for call in mock_llm_tools.call_args_list:
            assert call.args[0].model_name == worker_name
        for call in mock_llm.call_args_list:
            assert call.args[0].model_name == worker_name

    def test_metadata_records_both_tiers(self, tiered_pair, model_pair, tmp_path):
        """Metadata shape is worker_*/architect_* for both tier states."""
        from stride_gpt.agent.loop import _build_metadata

        plan = AnalysisPlan(
            target_path=str(tmp_path), overall_description="X",
            subsystems=[Subsystem(name="A", description="A", key_files=[], focus_areas=[])],
        )

        m1 = _build_metadata(tiered_pair, plan, llm_calls=2, tool_calls=3, subsystems_analyzed=1)
        assert m1["worker_model"] == tiered_pair.worker.model_name
        assert m1["worker_provider"] == tiered_pair.worker.provider
        assert m1["architect_model"] == tiered_pair.architect.model_name
        assert m1["architect_provider"] == tiered_pair.architect.provider

        m2 = _build_metadata(model_pair, plan, llm_calls=0, tool_calls=0, subsystems_analyzed=0)
        assert m2["worker_model"] == model_pair.worker.model_name
        assert m2["architect_model"] is None
        assert m2["architect_provider"] is None
