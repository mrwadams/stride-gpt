"""Tests for stride_gpt.agent.loop — agent loop and helper functions."""

from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from stride_gpt.agent.context import ContextManager
from stride_gpt.agent.loop import (
    MAX_THREATS_PER_SUBSYSTEM,
    _append_user,
    _synthesize,
    run_analysis,
)
from stride_gpt.core.schemas import (
    AnalysisPlan,
    Subsystem,
    SubsystemFinding,
    ToolCallResult,
)
from tests.fakes import (
    REPORTING_TOOL_NAMES,
    SUBSYSTEM_TOOL_NAMES,
    ScriptedLLM,
    call_tools,
    reply,
)

# The system-level DFD call at the end of run_analysis.
_DFD = reply("```mermaid\nflowchart LR\n  A --> B\n```")


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
        with ScriptedLLM([reply(finding_json, tools=SUBSYSTEM_TOOL_NAMES), _DFD]):
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
                content="Let me read the file", tools=SUBSYSTEM_TOOL_NAMES,
            ),
            # Second call: agent returns findings
            reply(finding_json, tools=SUBSYSTEM_TOOL_NAMES),
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

        with ScriptedLLM([reply(_EMPTY_FINDING, tools=SUBSYSTEM_TOOL_NAMES), _DFD]) as fake:
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

        with ScriptedLLM([reply(_EMPTY_FINDING, tools=SUBSYSTEM_TOOL_NAMES), _DFD]):
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
                content="I need the agentic card", tools=SUBSYSTEM_TOOL_NAMES,
            ),
            reply(
                '{"threats": [{"Threat Type": "Tampering", "Scenario": "ASI06 memory poisoning", "Potential Impact": "Bad", "OWASP_ASI": "ASI06"}], "improvement_suggestions": [], "files_analyzed": []}',
                tools=SUBSYSTEM_TOOL_NAMES,
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
        reply(_EMPTY_FINDING, tools=SUBSYSTEM_TOOL_NAMES),
        reply(_EMPTY_FINDING, tools=SUBSYSTEM_TOOL_NAMES),
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
    return call_tools(*calls, tools=SUBSYSTEM_TOOL_NAMES, content=content)


def _grace_turn(*calls: ToolCallResult, content: str = ""):
    """A turn in the final round, where only the reporting tools are offered."""
    return call_tools(*calls, tools=REPORTING_TOOL_NAMES, content=content)


def _read(tc_id: str, path: str = "app.py") -> ToolCallResult:
    return ToolCallResult(id=tc_id, function_name="read_file", arguments={"path": path})


def _report(
    tc_id: str,
    *,
    threat_type: str = "Spoofing",
    scenario: str = "Weak auth",
    impact: str = "Takeover",
    evidence: list[dict] | None = None,
    **extra,
) -> ToolCallResult:
    return ToolCallResult(
        id=tc_id,
        function_name="report_threat",
        arguments={
            "Threat Type": threat_type,
            "Scenario": scenario,
            "Potential Impact": impact,
            "evidence": evidence if evidence is not None else [],
            **extra,
        },
    )


def _finish(tc_id: str, *suggestions: str) -> ToolCallResult:
    return ToolCallResult(
        id=tc_id,
        function_name="finish",
        arguments={"improvement_suggestions": list(suggestions)},
    )


# The model reports one threat and stops. Most tests only care about what
# happened before this.
_FINAL = _tool_turn(_report("r0"), _finish("f0", "Use MFA"))

_AUTH_SNIPPET = "def login(user, password):\n    return check_db(user, password)"

_THREAT_FINDING = json.dumps({
    "threats": [{"Threat Type": "Spoofing", "Scenario": "s", "Potential Impact": "i"}],
    "improvement_suggestions": [],
    "files_analyzed": ["app.py"],
})


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
        # A malformed call still cost the model a turn, so it still costs
        # budget. _FINAL's report_threat and finish count as tool calls but
        # not as exploration — the tool cap bounds reading the code, not
        # reporting what was found in it.
        assert (counts["tool"], counts["explore"]) == (4, 2)


class TestSubsystemRunToolHandling:
    """What each reporting tool answers the model with.

    Driven directly, because the results of the final batch are appended
    after the last request and so never appear in ``fake.requests``.
    """

    @pytest.fixture
    def run(self, sandbox_dir):
        from stride_gpt.agent.loop import _SubsystemRun

        return _SubsystemRun(
            target_path=sandbox_dir, subsystem_name="App", progress=MagicMock(),
            max_tool_calls=0, loaded_refs=None,
        )

    def test_verified_evidence_is_reported_back(self, run):
        result = run.handle(
            _report("r", evidence=[{"path": "src/auth.py", "snippet": _AUTH_SNIPPET}])
        )
        assert result.startswith("Recorded threat #1 (Spoofing).")
        assert "src/auth.py lines 1-2 verified" in result

    def test_unverified_evidence_says_the_threat_survived(self, run):
        result = run.handle(
            _report("r", evidence=[{"path": "app.py", "snippet": "not in the file"}])
        )
        assert "NOT verified" in result
        assert "kept" in result
        assert "Do not re-report" in result
        assert len(run.threats) == 1

    def test_missing_scenario_is_refused(self, run):
        assert "non-empty 'Scenario'" in run.handle(_report("r", scenario="  "))
        assert run.threats == []

    def test_duplicate_is_refused(self, run):
        run.handle(_report("r1", scenario="Same  thing"))
        assert "already recorded" in run.handle(_report("r2", scenario="same thing"))
        assert len(run.threats) == 1

    def test_threat_limit(self, run):
        for i in range(MAX_THREATS_PER_SUBSYSTEM):
            run.handle(_report(f"r{i}", scenario=f"Threat {i}"))
        result = run.handle(_report("over", scenario="One too many"))
        assert "limit" in result
        assert len(run.threats) == MAX_THREATS_PER_SUBSYSTEM

    def test_finish_summarises_and_tells_the_model_to_stop(self, run):
        run.handle(_report("r", evidence=[{"path": "src/auth.py", "snippet": _AUTH_SNIPPET}]))
        result = run.handle(_finish("f", "Do x", "Do y"))
        assert "1 threats recorded (1 with verified evidence)" in result
        assert "2 improvement suggestions" in result
        assert "do not call any more tools" in result

    def test_finish_twice_is_refused(self, run):
        run.handle(_finish("f1"))
        assert "already been called" in run.handle(_finish("f2"))

    def test_exploration_is_refused_in_the_final_round(self, run):
        run.reporting_only = True
        result = run.handle(_read("late"))
        assert "not available in the final round" in result
        assert run.explore_calls == 0

    def test_over_budget_exploration_still_answers(self, sandbox_dir):
        from stride_gpt.agent.loop import _SubsystemRun

        run = _SubsystemRun(
            target_path=sandbox_dir, subsystem_name="App", progress=MagicMock(),
            max_tool_calls=1, loaded_refs=None,
        )
        assert "Flask" in run.handle(_read("a"))
        assert "budget for this analysis is exhausted" in run.handle(_read("b", "config.yaml"))
        assert run.explore_calls == 1


class TestToolReportedThreats:
    """Threats arrive through report_threat, not as a JSON blob at the end."""

    def test_threat_dict_keeps_its_old_shape_and_gains_evidence(
        self, model_pair, sandbox_dir
    ):
        """One turn carrying a read, a report and a finish — the mixed batch."""
        steps = [
            _tool_turn(_read("a", "src/auth.py")),
            _tool_turn(
                _report(
                    "r",
                    threat_type="Information Disclosure",
                    scenario="Credentials compared in the clear",
                    impact="Account takeover",
                    OWASP_LLM="LLM02",
                    evidence=[{"path": "src/auth.py", "snippet": _AUTH_SNIPPET}],
                ),
                _finish("f", "Hash the password"),
            ),
        ]

        _, counts, finding = _run_subsystem(model_pair, sandbox_dir, steps)

        (threat,) = finding.threats
        assert threat == {
            "Threat Type": "Information Disclosure",
            "Scenario": "Credentials compared in the clear",
            "Potential Impact": "Account takeover",
            "OWASP_LLM": "LLM02",
            "evidence": [
                {
                    "path": "src/auth.py",
                    "snippet": _AUTH_SNIPPET,
                    "verified": True,
                    "start_line": 1,
                    "end_line": 2,
                }
            ],
        }
        assert finding.improvement_suggestions == ["Hash the password"]
        assert (counts["tool"], counts["explore"]) == (3, 1)  # read + report + finish

    def test_files_analyzed_comes_from_what_was_read(self, model_pair, sandbox_dir):
        """Not from the model's claim, and not from grep hits."""
        steps = [
            _tool_turn(
                _read("a", "app.py"),
                ToolCallResult(
                    id="g", function_name="grep_content",
                    arguments={"pattern": "SECRET", "path": "src"},
                ),
                _read("b", "src/auth.py"),
                _read("c", "does-not-exist.py"),
            ),
            _FINAL,
        ]

        _, _, finding = _run_subsystem(model_pair, sandbox_dir, steps)

        assert finding.files_analyzed == ["app.py", "src/auth.py"]

    def test_no_evidence_threat_is_shaped_like_a_pre_change_one(
        self, model_pair, sandbox_dir
    ):
        """An absence-of-control threat has nothing to quote."""
        _, _, finding = _run_subsystem(
            model_pair, sandbox_dir,
            [_tool_turn(_report("r", evidence=[]), _finish("f"))],
        )
        assert "evidence" not in finding.threats[0]

    def test_report_mid_exploration(self, model_pair, sandbox_dir):
        """A threat can be filed the moment it's found, then work continues."""
        steps = [
            _tool_turn(_read("a", "app.py"), _report("r1", scenario="First")),
            _tool_turn(_read("b", "src/auth.py")),
            _tool_turn(_report("r2", scenario="Second"), _finish("f")),
        ]

        _, _, finding = _run_subsystem(model_pair, sandbox_dir, steps)

        assert [t["Scenario"] for t in finding.threats] == ["First", "Second"]

    def test_duplicate_report_is_dropped(self, model_pair, sandbox_dir):
        """Compression can summarise away the model's own report turns."""
        steps = [
            _tool_turn(_report("r1", scenario="Same  thing"), _report("r2", scenario="same thing")),
            _tool_turn(_finish("f")),
        ]

        _, _, finding = _run_subsystem(model_pair, sandbox_dir, steps)

        assert len(finding.threats) == 1

    def test_threats_survive_compression(self, model_pair, sandbox_dir):
        """Reported threats live in loop state, not in the conversation."""
        ctx = ContextManager(model_pair.worker, context_window=1)
        steps = [
            _tool_turn(_read("a"), _report("r", scenario="Found early")),
            _tool_turn(_read("b", "src/auth.py")),
            reply("summary of the first turn"),  # compression
            _tool_turn(_finish("f")),
        ]

        _, _, finding = _run_subsystem(model_pair, sandbox_dir, steps, ctx)

        assert [t["Scenario"] for t in finding.threats] == ["Found early"]



class TestGraceRound:
    """When the budget runs out, one last round on the real conversation."""

    def test_offers_only_the_reporting_tools_and_does_not_summarise(
        self, model_pair, sandbox_dir
    ):
        steps = [
            _tool_turn(_read("a"), _read("b", "config.yaml")),
            _grace_turn(_report("r", scenario="Found late"), _finish("f", "Do x")),
        ]

        fake, counts, finding = _run_subsystem(
            model_pair, sandbox_dir, steps, max_tool_calls=1
        )

        # Two tool-using calls and nothing else: the old cap path spent a
        # plain summarisation call plus a forced-JSON call here.
        assert [r.kind for r in fake.requests] == ["tools", "tools"]
        assert fake.requests[1].tools == REPORTING_TOOL_NAMES
        assert "final round" in fake.requests[1].messages[-1]["content"]
        assert [t["Scenario"] for t in finding.threats] == ["Found late"]
        assert finding.improvement_suggestions == ["Do x"]
        assert counts["llm"] == 2

    def test_grace_round_replays_the_real_conversation(self, model_pair, sandbox_dir):
        """Not a summarised copy — the tool results are still there."""
        steps = [
            _tool_turn(_read("a")),
            _grace_turn(_finish("f")),
        ]

        fake, _, _ = _run_subsystem(model_pair, sandbox_dir, steps, max_tool_calls=1)

        final = fake.requests[1].messages
        assert any(m["role"] == "tool" and "Flask" in m["content"] for m in final)

    def test_over_budget_tool_calls_still_get_a_result(self, model_pair, sandbox_dir):
        """A tool call with no result is a conversation a provider rejects.

        The loop used to break mid-batch and leave one dangling, which only
        worked because the cap path threw the history away.
        """
        steps = [
            _tool_turn(_read("a"), _read("b", "config.yaml")),
            _grace_turn(_finish("f")),
        ]

        fake, counts, _ = _run_subsystem(
            model_pair, sandbox_dir, steps, max_tool_calls=1
        )

        results = {
            m["tool_call_id"]: m["content"]
            for m in fake.requests[1].messages if m["role"] == "tool"
        }
        assert set(results) == {"a", "b"}
        assert "budget for this analysis is exhausted" in results["b"]
        assert counts["explore"] == 1

    def test_llm_budget_exhaustion_also_gets_a_final_round(
        self, model_pair, sandbox_dir
    ):
        steps = [
            _tool_turn(_read("a")),
            _grace_turn(_report("r"), _finish("f")),
        ]

        _, counts, finding = _run_subsystem(
            model_pair, sandbox_dir, steps, max_llm_calls=1
        )

        # One over the cap, where the old path went two over.
        assert counts["llm"] == 2
        assert len(finding.threats) == 1

    def test_plain_text_in_the_final_round_falls_back_to_json(
        self, model_pair, sandbox_dir, caplog
    ):
        steps = [
            _tool_turn(_read("a")),
            reply(_THREAT_FINDING, tools=REPORTING_TOOL_NAMES),
        ]

        with caplog.at_level(logging.WARNING):
            fake, _, finding = _run_subsystem(
                model_pair, sandbox_dir, steps, max_tool_calls=1
            )

        assert len(finding.threats) == 1
        assert len(fake.requests) == 2  # no second attempt
        assert "deprecated fallback" in caplog.text

    def test_reporting_without_finishing_keeps_the_threats(
        self, model_pair, sandbox_dir
    ):
        steps = [
            _tool_turn(_read("a")),
            _grace_turn(_report("r", scenario="Last gasp")),
        ]

        _, _, finding = _run_subsystem(model_pair, sandbox_dir, steps, max_tool_calls=1)

        assert [t["Scenario"] for t in finding.threats] == ["Last gasp"]



class TestPlainTextFallback:
    """Deprecated transition path for models with weak tool calling."""

    def test_json_in_text_is_still_parsed(self, model_pair, sandbox_dir, caplog):
        with caplog.at_level(logging.WARNING):
            fake, _, finding = _run_subsystem(
                model_pair, sandbox_dir,
                [reply(_THREAT_FINDING, tools=SUBSYSTEM_TOOL_NAMES)],
            )

        assert len(finding.threats) == 1
        assert finding.files_analyzed == ["app.py"]
        assert len(fake.requests) == 1
        assert "deprecated fallback" in caplog.text

    def test_text_without_json_is_nudged_once(self, model_pair, sandbox_dir):
        """One nudge on the real history, where the old retry spent two calls
        on a summarised copy of it."""
        steps = [
            _tool_turn(_read("a")),
            reply("I found some issues but forgot to call anything", tools=SUBSYSTEM_TOOL_NAMES),
            _tool_turn(_report("r"), _finish("f")),
        ]

        fake, _, finding = _run_subsystem(model_pair, sandbox_dir, steps)

        assert len(finding.threats) == 1
        nudge = fake.requests[2].messages[-1]
        assert nudge["role"] == "user"
        assert "did not call finish" in nudge["content"]
        # The nudge went onto the real conversation, tool results intact.
        assert any(m["role"] == "tool" for m in fake.requests[2].messages)

    def test_a_second_text_turn_ends_the_subsystem(self, model_pair, sandbox_dir):
        steps = [
            reply("no tools here", tools=SUBSYSTEM_TOOL_NAMES),
            reply("still nothing", tools=SUBSYSTEM_TOOL_NAMES),
        ]

        fake, _, finding = _run_subsystem(model_pair, sandbox_dir, steps)

        assert finding.threats == []
        assert len(fake.requests) == 2

    def test_tool_reported_threats_are_not_doubled_by_the_text(
        self, model_pair, sandbox_dir
    ):
        """A belt-and-braces model that reports AND writes the JSON blob."""
        steps = [
            _tool_turn(_report("r", scenario="Reported by tool")),
            reply(_THREAT_FINDING, tools=SUBSYSTEM_TOOL_NAMES),
        ]

        _, _, finding = _run_subsystem(model_pair, sandbox_dir, steps)

        assert [t["Scenario"] for t in finding.threats] == ["Reported by tool"]

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
