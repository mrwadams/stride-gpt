"""Tests for stride_gpt.agent.loop — agent loop and helper functions."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from stride_gpt.agent.context import ContextManager
from stride_gpt.agent.loop import (
    _append_user,
    _parse_subsystem_finding,
    _prepare_for_plain_llm,
    _strip_tool_artifacts,
    _summarize_for_analysis,
    _synthesize,
    run_analysis,
)
from stride_gpt.core.schemas import (
    AnalysisPlan,
    Subsystem,
    SubsystemFinding,
    ToolCallResult,
)
from tests.fakes import AGENT_TOOL_NAMES, ScriptedLLM, call_tools, fail, reply

# The system-level DFD call at the end of run_analysis.
_DFD = reply("```mermaid\nflowchart LR\n  A --> B\n```")

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

    def test_drops_empty_assistants_and_merges_neighbours(self):
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "task"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "1"}]},
            {"role": "tool", "tool_call_id": "1", "content": "r1"},
            {"role": "assistant", "content": "reading", "tool_calls": [{"id": "2"}]},
            {"role": "tool", "tool_call_id": "2", "content": "r2"},
            {"role": "assistant", "content": "grepping", "tool_calls": [{"id": "3"}]},
            {"role": "tool", "tool_call_id": "3", "content": "r3"},
        ]
        result = _strip_tool_artifacts(msgs)
        assert [m["role"] for m in result] == ["system", "user", "assistant"]
        assert result[2]["content"] == "reading\n\ngrepping"


class TestAppendUser:
    def test_joins_trailing_user_message(self):
        msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "task"}]
        result = _append_user(msgs, "now answer")
        assert result == [msgs[0], {"role": "user", "content": "task\n\nnow answer"}]
        assert msgs[1]["content"] == "task"  # input not mutated

    def test_adds_message_after_assistant(self):
        msgs = [{"role": "user", "content": "task"}, {"role": "assistant", "content": "notes"}]
        result = _append_user(msgs, "now answer")
        assert result[-1] == {"role": "user", "content": "now answer"}
        assert len(result) == 3


# ---------------------------------------------------------------------------
# _summarize_for_analysis / _prepare_for_plain_llm
# ---------------------------------------------------------------------------


class TestSummarizeForAnalysis:
    def test_builds_summary_from_tool_results(self, llm_config):
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "analyze auth"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "1", "type": "function", "function": {"name": "read_file", "arguments": '{"path":"auth.py"}'}}
            ]},
            {"role": "tool", "tool_call_id": "1", "name": "read_file", "content": "def login(): pass"},
        ]
        with ScriptedLLM([reply("Summary of findings")]) as fake:
            result = _summarize_for_analysis(llm_config, messages)
        assert result == "Summary of findings"
        # Verify the LLM was called with the summary prompt
        sent_messages = fake.requests[0].messages
        assert "security-focused" in sent_messages[0]["content"].lower()
        # Tool results should appear in the conversation sent to the summarizer
        assert "def login(): pass" in sent_messages[1]["content"]

    def test_skips_empty_content(self, llm_config):
        messages = [
            {"role": "assistant", "content": ""},
            {"role": "tool", "tool_call_id": "1", "name": "read_file", "content": "data"},
        ]
        with ScriptedLLM([reply("Summary")]) as fake:
            _summarize_for_analysis(llm_config, messages)
        sent_content = fake.requests[0].messages[1]["content"]
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
        # The findings join the task message so user and assistant alternate
        assert [m["role"] for m in result] == ["system", "user"]
        assert result[1]["content"].startswith("Analyze auth subsystem\n\n")
        assert "Security findings here" in result[1]["content"]

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
    def test_returns_cross_cutting_threats(self, model_pair):
        synthesis = reply(json.dumps({
            "cross_cutting_threats": [
                {"Threat Type": "Tampering", "Scenario": "No CSRF", "Potential Impact": "bad",
                 "Affected Subsystems": ["Auth", "API"]}
            ]
        }))
        findings = [
            SubsystemFinding(subsystem="Auth", threats=[{"Threat Type": "Spoofing"}]),
            SubsystemFinding(subsystem="API", threats=[{"Threat Type": "Tampering"}]),
        ]
        with ScriptedLLM([synthesis]):
            result = _synthesize(model_pair, findings)
        assert len(result) == 1
        assert result[0]["Threat Type"] == "Tampering"

    def test_returns_empty_on_parse_failure(self, model_pair):
        findings = [SubsystemFinding(subsystem="A", threats=[])]
        with ScriptedLLM([
            reply("I can't produce valid JSON right now"),
            reply("Still no JSON"),
        ]) as fake:
            result = _synthesize(model_pair, findings)
        assert result == []
        # The retry carries the failed answer, then asks again
        assert [m["role"] for m in fake.requests[1].messages] == [
            "system", "user", "assistant", "user",
        ]


# ---------------------------------------------------------------------------
# run_analysis (integration, scripted LLM)
# ---------------------------------------------------------------------------


class TestRunAnalysis:
    def test_full_analysis_with_plan(self, model_pair, tmp_path):
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

        # Synthesis skipped (only 1 subsystem)
        progress = MagicMock()
        with ScriptedLLM([reply(finding_json, tools=AGENT_TOOL_NAMES), _DFD]):
            report = run_analysis(model_pair, tmp_path, plan=plan, progress=progress)

        assert len(report.findings) == 1
        assert report.findings[0].subsystem == "Auth"
        assert len(report.findings[0].threats) == 1
        assert report.metadata["subsystems_analyzed"] == 1
        assert report.data_flow_diagram
        # Verify progress callbacks were invoked
        progress.phase_start.assert_called()
        progress.subsystem_start.assert_called()
        progress.subsystem_done.assert_called_with("Auth", 1)
        progress.complete.assert_called()

    def test_tool_call_flow(self, model_pair, sandbox_dir):
        """Test that the agent executes tool calls before producing findings."""
        plan = AnalysisPlan(
            target_path=str(sandbox_dir),
            overall_description="Test app",
            subsystems=[
                Subsystem(name="App", description="Main app",
                          key_files=["app.py"], focus_areas=["Spoofing"]),
            ],
        )

        finding_json = json.dumps({
            "threats": [{"Threat Type": "Information Disclosure", "Scenario": "Debug mode", "Potential Impact": "Leak"}],
            "improvement_suggestions": ["Disable debug"],
            "files_analyzed": ["app.py"],
        })
        steps = [
            # First call: agent makes a tool call
            call_tools(
                ToolCallResult(id="tc1", function_name="read_file", arguments={"path": "app.py"}),
                content="Let me read the file", tools=AGENT_TOOL_NAMES,
            ),
            # Second call: agent returns findings
            reply(finding_json, tools=AGENT_TOOL_NAMES),
            _DFD,
        ]

        progress = MagicMock()
        with ScriptedLLM(steps) as fake:
            report = run_analysis(model_pair, sandbox_dir, plan=plan, progress=progress)

        assert len(report.findings) == 1
        assert report.findings[0].threats[0]["Threat Type"] == "Information Disclosure"
        assert report.metadata["tool_calls"] >= 1
        tool_msgs = [m for m in fake.requests[1].messages if m["role"] == "tool"]
        assert "Flask" in tool_msgs[0]["content"]
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
        # Only the DFD pass reaches the LLM: subsystems and synthesis are patched.
        with ScriptedLLM([_DFD]):
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
        with ScriptedLLM([_DFD]):
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

_EMPTY_FINDING = '{"threats": [], "improvement_suggestions": [], "files_analyzed": []}'


class TestAppTypeFlow:
    @pytest.mark.parametrize("app_type", ["agentic", "genai", "web"])
    def test_user_prompt_carries_no_card_hints(self, app_type, model_pair, tmp_path):
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

        with ScriptedLLM([reply(_EMPTY_FINDING, tools=AGENT_TOOL_NAMES), _DFD]) as fake:
            run_analysis(model_pair, tmp_path, plan=plan, progress=MagicMock())

        messages = fake.requests[0].messages
        user_msg = next(m for m in messages if m.get("role") == "user")
        assert "load_reference" not in user_msg["content"]
        assert "genai" not in user_msg["content"]
        assert "agentic" not in user_msg["content"]

    def test_metadata_records_app_type(self, model_pair, tmp_path):
        plan = AnalysisPlan(
            target_path=str(tmp_path),
            overall_description="X",
            detected_app_type="agentic",
            subsystems=[
                Subsystem(name="A", description="A", key_files=[], focus_areas=[]),
            ],
        )

        with ScriptedLLM([reply(_EMPTY_FINDING, tools=AGENT_TOOL_NAMES), _DFD]):
            report = run_analysis(model_pair, tmp_path, plan=plan, progress=MagicMock())
        assert report.metadata["app_type"] == "agentic"

    def test_agent_can_call_load_reference_tool(self, model_pair, tmp_path):
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

        steps = [
            call_tools(
                ToolCallResult(id="tc1", function_name="load_reference",
                               arguments={"name": "agentic"}),
                content="I need the agentic card", tools=AGENT_TOOL_NAMES,
            ),
            reply(
                '{"threats": [{"Threat Type": "Tampering", "Scenario": "ASI06 memory poisoning", "Potential Impact": "Bad", "OWASP_ASI": "ASI06"}], "improvement_suggestions": [], "files_analyzed": []}',
                tools=AGENT_TOOL_NAMES,
            ),
            _DFD,
        ]
        with ScriptedLLM(steps) as fake:
            report = run_analysis(model_pair, tmp_path, plan=plan, progress=MagicMock())

        assert len(report.findings) == 1
        assert report.findings[0].threats[0]["OWASP_ASI"] == "ASI06"
        # The card content should now be in the messages history of the
        # second call.
        tool_results = [m for m in fake.requests[1].messages if m.get("role") == "tool"]
        assert any("ASI01" in m["content"] for m in tool_results)


# ---------------------------------------------------------------------------
# Tier routing — verify which LLMConfig reaches which call site
# ---------------------------------------------------------------------------


def _two_subsystem_run() -> list:
    """Planner → two subsystems that answer at once → synthesis → DFD."""
    plan = reply(json.dumps({
        "overall_description": "X",
        "detected_app_type": "web",
        "subsystems": [
            {"name": "A", "description": "A", "key_files": [], "focus_areas": []},
            {"name": "B", "description": "B", "key_files": [], "focus_areas": []},
        ],
    }))
    return [
        plan,
        reply(_EMPTY_FINDING, tools=AGENT_TOOL_NAMES),
        reply(_EMPTY_FINDING, tools=AGENT_TOOL_NAMES),
        reply('{"cross_cutting_threats": []}'),
        _DFD,
    ]


class TestTierRouting:
    """When the user configures a separate architect, the architect must drive
    planning, synthesis, and compression — the worker must drive per-subsystem
    tool-use iteration and the JSON-coercion fallback. With no architect set,
    every call falls through to the worker."""

    def test_tiered_routes_to_correct_tiers(self, tiered_pair, tmp_path):
        """planner → architect; tool-loop → worker; synthesis and DFD → architect."""
        with ScriptedLLM(_two_subsystem_run()) as fake:
            report = run_analysis(tiered_pair, tmp_path, progress=MagicMock(), auto_approve=True)

        assert [f.subsystem for f in report.findings] == ["A", "B"]
        worker = tiered_pair.worker.model_name
        architect = tiered_pair.architect.model_name
        assert [(r.kind, r.config.model_name) for r in fake.requests] == [
            ("plain", architect),  # planner
            ("tools", worker),  # subsystem A
            ("tools", worker),  # subsystem B
            ("plain", architect),  # synthesis
            ("plain", architect),  # DFD
        ]

    def test_single_tier_uses_worker_everywhere(self, model_pair, tmp_path):
        """With architect=None, every call routes to worker."""
        with ScriptedLLM(_two_subsystem_run()) as fake:
            run_analysis(model_pair, tmp_path, progress=MagicMock(), auto_approve=True)

        worker_name = model_pair.worker.model_name
        assert len(fake.requests) == 5
        assert {r.config.model_name for r in fake.requests} == {worker_name}

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


# ---------------------------------------------------------------------------
# _analyze_subsystem — driven directly with a scripted LLM
# ---------------------------------------------------------------------------


def _run_subsystem(model_pair, target, steps, ctx=None, *, max_llm_calls=0, max_tool_calls=0):
    """Drive _analyze_subsystem with scripted steps.

    Returns ``(fake, counts, finding)``; ``fake.requests`` holds every request.
    """
    from stride_gpt.agent.loop import _analyze_subsystem

    if ctx is None:
        ctx = MagicMock()
        ctx.needs_compression.return_value = False
    counts: dict[str, int] = {}
    with ScriptedLLM(steps) as fake:
        finding = _analyze_subsystem(
            models=model_pair, target_path=target, subsystem_name="App",
            subsystem_description="Main app", key_files=[], focus_areas=[],
            ctx=ctx, max_llm_calls=max_llm_calls, max_tool_calls=max_tool_calls,
            progress=MagicMock(), call_counts=counts,
        )
    return fake, counts, finding


def _last_tools_messages(fake) -> list[dict]:
    return [r for r in fake.requests if r.kind == "tools"][-1].messages


def _tool_turn(*calls: ToolCallResult, content: str = ""):
    return call_tools(*calls, tools=AGENT_TOOL_NAMES, content=content)


_FINAL = reply(_EMPTY_FINDING, tools=AGENT_TOOL_NAMES)

_THREAT_FINDING = json.dumps({
    "threats": [{"Threat Type": "Spoofing", "Scenario": "s", "Potential Impact": "i"}],
    "improvement_suggestions": [],
    "files_analyzed": ["app.py"],
})


def _read(tc_id: str, path: str = "app.py") -> ToolCallResult:
    return ToolCallResult(id=tc_id, function_name="read_file", arguments={"path": path})


class TestAnalyzeSubsystemToolHandling:
    def test_repeat_call_served_from_cache(self, model_pair, sandbox_dir):
        fake, _, _ = _run_subsystem(
            model_pair, sandbox_dir,
            [_tool_turn(_read("a")), _tool_turn(_read("b")), _FINAL],
        )
        tool_msgs = [m for m in _last_tools_messages(fake) if m["role"] == "tool"]
        assert "Flask" in tool_msgs[0]["content"]
        assert "already have this result" in tool_msgs[1]["content"]

    def test_cache_cleared_after_compression(self, model_pair, sandbox_dir):
        """Once compression has summarised the earlier result away, a repeat
        call must return the file again, not point at a message that's gone."""
        ctx = MagicMock()
        ctx.needs_compression.side_effect = [True, False]
        ctx.compress.side_effect = lambda _cfg, msgs: [
            msgs[0], {"role": "user", "content": "task + summary"},
        ]

        fake, _, _ = _run_subsystem(
            model_pair, sandbox_dir,
            [_tool_turn(_read("a")), _tool_turn(_read("b")), _FINAL], ctx,
        )
        tool_msgs = [m for m in _last_tools_messages(fake) if m["role"] == "tool"]
        assert [m["tool_call_id"] for m in tool_msgs] == ["b"]
        assert "Flask" in tool_msgs[0]["content"]

    def test_cache_kept_when_compression_is_a_noop(self, model_pair, sandbox_dir):
        ctx = MagicMock()
        ctx.needs_compression.side_effect = [True, False]
        ctx.compress.side_effect = lambda _cfg, msgs: msgs

        fake, _, _ = _run_subsystem(
            model_pair, sandbox_dir,
            [_tool_turn(_read("a")), _tool_turn(_read("b")), _FINAL], ctx,
        )
        assert "already have this result" in _last_tools_messages(fake)[-1]["content"]

    def test_malformed_arguments_reported_to_model(self, model_pair, sandbox_dir):
        bad = ToolCallResult(
            id="bad", function_name="list_directory", arguments={},
            parse_error="arguments were not valid JSON (Expecting value: line 1 column 1)",
        )
        good = ToolCallResult(id="good", function_name="list_directory", arguments={})

        fake, counts, _ = _run_subsystem(
            model_pair, sandbox_dir, [_tool_turn(bad), _tool_turn(good), _FINAL],
        )

        tool_msgs = {
            m["tool_call_id"]: m["content"]
            for m in _last_tools_messages(fake) if m["role"] == "tool"
        }
        assert tool_msgs["bad"].startswith("Error: arguments were not valid JSON")
        assert "valid JSON object" in tool_msgs["bad"]
        # The failed call wasn't cached as list_directory({}), so the retry runs
        assert "app.py" in tool_msgs["good"]
        assert counts["tool"] == 2


class TestAgentLoopProtocol:
    """Every request the loop sends must be one a strict provider accepts.

    The scripted LLM checks this on each request, so these tests mostly just
    drive a path through the loop and let the fake fail them.
    """

    def test_compression_keeps_tool_turns_whole(self, model_pair, sandbox_dir):
        """#187: compressing mid-exploration must not orphan tool results.

        A one-token window makes the loop compress after every turn, keeping
        only the newest. Three calls per turn is what broke the old
        keep-the-last-6-messages cut.
        """
        ctx = ContextManager(model_pair.worker, context_window=1)
        steps = [
            _tool_turn(
                ToolCallResult(id="a0", function_name="list_directory", arguments={"path": "."}),
                _read("b0", "app.py"),
                _read("c0", "config.yaml"),
            ),
            _tool_turn(
                ToolCallResult(id="a1", function_name="list_directory", arguments={"path": "src"}),
                _read("b1", "src/auth.py"),
                _read("c1", "src/utils.py"),
            ),
            reply("summary of the first turn"),  # compression
            _FINAL,
        ]

        fake, _, _ = _run_subsystem(model_pair, sandbox_dir, steps, ctx)

        assert "summary of the first turn" in _last_tools_messages(fake)[1]["content"]

    def test_budget_cap_path_alternates_roles(self, model_pair, sandbox_dir):
        """Hitting the tool cap summarises, then asks for JSON in one user turn."""
        steps = [
            _tool_turn(_read("a"), _read("b", "config.yaml")),
            reply("exploration summary"),
            reply(_THREAT_FINDING),
        ]

        fake, _, finding = _run_subsystem(model_pair, sandbox_dir, steps, max_tool_calls=1)

        assert len(finding.threats) == 1
        final = fake.requests[-1]
        assert final.config.response_format == "json"
        assert [m["role"] for m in final.messages] == ["system", "user"]
        assert "exploration summary" in final.messages[1]["content"]
        assert "tool call limit" in final.messages[1]["content"]

    def test_json_retry_path_alternates_roles(self, model_pair, sandbox_dir):
        steps = [
            _tool_turn(_read("a")),
            reply("I found some issues but forgot the JSON", tools=AGENT_TOOL_NAMES),
            reply("exploration summary"),
            reply(_THREAT_FINDING),
        ]

        fake, _, finding = _run_subsystem(model_pair, sandbox_dir, steps)

        assert len(finding.threats) == 1
        final = fake.requests[-1].messages
        assert [m["role"] for m in final] == ["system", "user"]
        assert "ONLY a valid JSON object" in final[1]["content"]

    def test_failed_summary_falls_back_to_stripped_history(self, model_pair, sandbox_dir):
        """With no summary, tool artifacts are stripped and the assistant's
        notes from separate turns merge into one message."""
        steps = [
            _tool_turn(_read("a"), content="Reading the app"),
            _tool_turn(_read("b", "config.yaml"), content="Now the config"),
            reply("no JSON here", tools=AGENT_TOOL_NAMES),
            fail(RuntimeError("summariser down")),
            reply(_THREAT_FINDING),
        ]

        fake, _, finding = _run_subsystem(model_pair, sandbox_dir, steps)

        assert len(finding.threats) == 1
        final = fake.requests[-1].messages
        assert [m["role"] for m in final] == ["system", "user", "assistant", "user"]
        assert final[2]["content"] == "Reading the app\n\nNow the config"
