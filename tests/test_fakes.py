"""Tests for tests/fakes.py — the scripted fake LLM and its protocol check."""

from __future__ import annotations

import contextlib

import pytest

import stride_gpt.agent.loop as loop_module
from stride_gpt.agent.tools import AGENT_TOOLS
from stride_gpt.core.schemas import ToolCallResult
from tests.fakes import (
    AGENT_TOOL_NAMES,
    QUICK_TOOL_NAMES,
    ProtocolError,
    ScriptedLLM,
    call_tools,
    check_protocol,
    fail,
    reply,
)

SYS = {"role": "system", "content": "s"}
USER = {"role": "user", "content": "u"}


def _assistant(*ids: str) -> dict:
    return {
        "role": "assistant", "content": "",
        "tool_calls": [{"id": i, "type": "function", "function": {"name": "x", "arguments": "{}"}}
                       for i in ids],
    }


def _tool(tc_id: str) -> dict:
    return {"role": "tool", "tool_call_id": tc_id, "name": "x", "content": "r"}


def _problems(messages: list[dict], tools_offered: bool = True) -> str:
    return "\n".join(check_protocol(messages, tools_offered=tools_offered))


class TestCheckProtocolAccepts:
    def test_plain_conversation(self):
        assert check_protocol([SYS, USER], tools_offered=False) == []

    def test_multi_call_turns(self):
        msgs = [SYS, USER, _assistant("a", "b", "c"), _tool("a"), _tool("b"), _tool("c"),
                _assistant("d"), _tool("d")]
        assert check_protocol(msgs, tools_offered=True) == []

    def test_results_in_a_different_order(self):
        msgs = [SYS, USER, _assistant("a", "b"), _tool("b"), _tool("a")]
        assert check_protocol(msgs, tools_offered=True) == []

    def test_user_after_tool_results(self):
        msgs = [SYS, USER, _assistant("a"), _tool("a"), {"role": "user", "content": "more"}]
        assert check_protocol(msgs, tools_offered=True) == []


class TestCheckProtocolFlags:
    def test_orphaned_tool_results(self):
        """The shape #187's count-based compression produced."""
        msgs = [SYS, USER, _tool("b2"), _tool("c2"), _assistant("a3"), _tool("a3")]
        problems = _problems(msgs)
        assert "'b2'" in problems and "'c2'" in problems
        assert "no matching tool_calls" in problems
        assert "tool:b2, tool:c2" in problems  # the role trace

    def test_missing_result(self):
        assert "'b' has no tool result" in _problems([SYS, USER, _assistant("a", "b"), _tool("a")])

    def test_duplicate_result(self):
        assert "more than one result" in _problems(
            [SYS, USER, _assistant("a"), _tool("a"), _tool("a")]
        )

    def test_reused_id(self):
        msgs = [SYS, USER, _assistant("a"), _tool("a"), _assistant("a"), _tool("a")]
        assert "used more than once" in _problems(msgs)

    def test_message_between_calls_and_results(self):
        msgs = [SYS, USER, _assistant("a"), {"role": "user", "content": "x"}, _tool("a")]
        problems = _problems(msgs)
        assert "'a' has no tool result" in problems
        assert "no matching tool_calls" in problems

    def test_consecutive_users(self):
        assert "consecutive 'user'" in _problems([SYS, USER, USER], tools_offered=False)

    def test_consecutive_assistants(self):
        msgs = [SYS, USER, {"role": "assistant", "content": "a"},
                {"role": "assistant", "content": "b"}]
        assert "consecutive 'assistant'" in _problems(msgs, tools_offered=False)

    def test_system_mid_conversation(self):
        assert "not at the start" in _problems([SYS, USER, SYS], tools_offered=False)

    def test_first_message_not_user(self):
        msgs = [SYS, {"role": "assistant", "content": "hi"}]
        assert "not 'user'" in _problems(msgs, tools_offered=False)

    def test_tool_artifacts_in_plain_call(self):
        problems = _problems([SYS, USER, _assistant("a"), _tool("a")], tools_offered=False)
        assert "tool_calls at position 2 in a call without tools" in problems
        assert "tool results in a call without tools" in problems


class TestScriptedLLM:
    def test_replays_steps_and_records_requests(self, llm_config):
        with ScriptedLLM([
            call_tools(ToolCallResult(id="a", function_name="x", arguments={}),
                       tools=AGENT_TOOL_NAMES),
            reply("done"),
        ]) as fake:
            first = loop_module.call_llm_with_tools(llm_config, [SYS, USER], AGENT_TOOLS)
            second = loop_module.call_llm(llm_config, [SYS, USER])

        assert first.tool_calls[0].id == "a"
        assert second.content == "done"
        assert [r.kind for r in fake.requests] == ["tools", "plain"]
        assert fake.requests[0].tools == AGENT_TOOL_NAMES
        assert fake.requests[1].config is llm_config

    def test_messages_are_copied(self, llm_config):
        msgs = [SYS, USER]
        with ScriptedLLM([reply("ok")]) as fake:
            loop_module.call_llm(llm_config, msgs)
        msgs.append({"role": "assistant", "content": "later"})
        assert len(fake.requests[0].messages) == 2

    def test_replays_exceptions(self, llm_config):
        with ScriptedLLM([fail(RuntimeError("boom"))]), pytest.raises(RuntimeError, match="boom"):
            loop_module.call_llm(llm_config, [SYS, USER])

    def test_leftover_steps_fail(self, llm_config):
        with pytest.raises(AssertionError, match="1 scripted step"), ScriptedLLM(
            [reply("a"), reply("b")]
        ):
            loop_module.call_llm(llm_config, [SYS, USER])

    def test_exhausted_script_fails_even_when_swallowed(self, llm_config):
        with (
            pytest.raises(ProtocolError, match="no steps left"),
            ScriptedLLM([]),
            contextlib.suppress(Exception),
        ):
            loop_module.call_llm(llm_config, [SYS, USER])

    def test_violation_fails_even_when_swallowed(self, llm_config):
        with (
            pytest.raises(ProtocolError, match="consecutive 'user'"),
            ScriptedLLM([reply("x")]),
            contextlib.suppress(Exception),
        ):
            loop_module.call_llm(llm_config, [SYS, USER, USER])

    def test_wrong_kind_fails(self, llm_config):
        with pytest.raises(ProtocolError, match="expected a plain call_llm"), ScriptedLLM(
            [reply("x")]
        ):
            loop_module.call_llm_with_tools(llm_config, [SYS, USER], AGENT_TOOLS)

    def test_wrong_tool_set_fails(self, llm_config):
        with pytest.raises(ProtocolError, match="offered tools"), ScriptedLLM(
            [reply("x", tools=QUICK_TOOL_NAMES)]
        ):
            loop_module.call_llm_with_tools(llm_config, [SYS, USER], AGENT_TOOLS)

    def test_patches_are_removed(self, llm_config):
        original = loop_module.call_llm
        with ScriptedLLM([reply("x")]):
            assert loop_module.call_llm is not original
            loop_module.call_llm(llm_config, [SYS, USER])
        assert loop_module.call_llm is original
