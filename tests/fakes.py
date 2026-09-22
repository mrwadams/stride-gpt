"""A scripted fake LLM that replays responses and checks the message protocol.

``ScriptedLLM`` stands in for ``call_llm`` and ``call_llm_with_tools``. It
plays back a fixed list of steps and records every request. On each request
it checks that the conversation is one a strict provider would accept, so a
test fails when the loop sends something malformed, even if the loop swallows
the error.

    with ScriptedLLM([call_tools(read, tools=AGENT_TOOL_NAMES), reply("{}")]) as fake:
        run_something()
    assert fake.requests[0].messages[1]["role"] == "user"
"""

from __future__ import annotations

import copy
import importlib
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

from stride_gpt.agent.quick import QUICK_TOOLS
from stride_gpt.agent.tools import AGENT_TOOLS, REPORTING_TOOLS, SUBSYSTEM_TOOLS
from stride_gpt.core.schemas import LLMConfig, LLMResponse, ToolCallResult


def tool_names(tools: list[dict]) -> frozenset[str]:
    return frozenset(t["function"]["name"] for t in tools)


AGENT_TOOL_NAMES = tool_names(AGENT_TOOLS)
QUICK_TOOL_NAMES = tool_names(QUICK_TOOLS)
# The subsystem loop offers exploration plus report_threat / finish; the grace
# round offers only the latter two. ``check_protocol`` needs no special case
# for them — they are ordinary tool calls with ordinary results, which is the
# payoff of handling them in the loop instead of in the tool dispatch table.
SUBSYSTEM_TOOL_NAMES = tool_names(SUBSYSTEM_TOOLS)
REPORTING_TOOL_NAMES = tool_names(REPORTING_TOOLS)

# Every module on the agent path that imports the LLM calls by name.
PATCH_TARGETS = (
    "stride_gpt.agent.loop",
    "stride_gpt.agent.context",
    "stride_gpt.agent.quick",
    "stride_gpt.agent.planner",
    "stride_gpt.core.dfd",
)


class ProtocolError(AssertionError):
    """The code under test sent a request a real provider would reject."""


@dataclass(frozen=True)
class Step:
    """One scripted response.

    ``tools`` is ``None`` when a plain ``call_llm`` is expected; otherwise a
    ``call_llm_with_tools`` call offering exactly these tool names.
    """

    response: LLMResponse | BaseException
    tools: frozenset[str] | None = None


@dataclass
class Request:
    kind: str  # "plain" or "tools"
    config: LLMConfig
    messages: list[dict]  # deep copy taken at call time
    tools: frozenset[str] | None


def reply(
    content: str,
    *,
    tools: frozenset[str] | None = None,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
) -> Step:
    return Step(
        LLMResponse(
            content=content, model="fake",
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
        ),
        tools,
    )


def call_tools(
    *calls: ToolCallResult,
    tools: frozenset[str],
    content: str = "",
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
) -> Step:
    return Step(
        LLMResponse(
            content=content, model="fake", tool_calls=list(calls),
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
        ),
        tools,
    )


def fail(exc: BaseException, *, tools: frozenset[str] | None = None) -> Step:
    return Step(exc, tools)


def _trace(messages: list[dict]) -> str:
    return ", ".join(
        f"tool:{m.get('tool_call_id')}" if m.get("role") == "tool" else str(m.get("role"))
        for m in messages
    )


def check_protocol(messages: list[dict], *, tools_offered: bool) -> list[str]:
    """Return the ways ``messages`` breaks the chat protocol (empty if valid)."""
    problems: list[str] = []
    seen_ids: set[str] = set()
    # Roles in order, with each block of tool results as one "tool" entry. A
    # tool block answers the assistant, so an assistant message may follow it.
    turns: list[str] = []
    i = 0
    while i < len(messages):
        msg = messages[i]
        role = msg.get("role")
        if role == "system":
            if turns:
                problems.append(f"system message at position {i} is not at the start")
        elif role == "tool":
            problems.append(
                f"tool result {msg.get('tool_call_id')!r} at position {i} has no matching "
                "tool_calls entry in the assistant message before it"
            )
        elif role in ("user", "assistant"):
            if not turns and role != "user":
                problems.append(f"first non-system message is {role!r}, not 'user'")
            if turns and turns[-1] == role:
                problems.append(f"consecutive {role!r} messages at position {i}")
            turns.append(role)
            calls = msg.get("tool_calls") or []
            if calls and not tools_offered:
                problems.append(f"assistant tool_calls at position {i} in a call without tools")
            if calls:
                ids = [c.get("id") for c in calls]
                reused = {x for x in ids if ids.count(x) > 1 or x in seen_ids}
                problems.extend(f"tool call id {x!r} is used more than once" for x in reused)
                seen_ids.update(ids)
                results: list[str] = []
                while i + 1 < len(messages) and messages[i + 1].get("role") == "tool":
                    i += 1
                    results.append(messages[i].get("tool_call_id"))
                if results:
                    turns.append("tool")
                if not tools_offered and results:
                    problems.append("tool results in a call without tools")
                missing = sorted(set(ids) - set(results), key=str)
                problems.extend(f"tool call {x!r} has no tool result after it" for x in missing)
                for tc_id in results:
                    if tc_id not in ids:
                        problems.append(
                            f"tool result {tc_id!r} has no matching tool_calls entry "
                            "in the assistant message before it"
                        )
                    elif results.count(tc_id) > 1:
                        problems.append(f"tool call {tc_id!r} has more than one result")
        else:
            problems.append(f"unknown role {role!r} at position {i}")
        i += 1

    if problems:
        trace = _trace(messages)
        problems = [f"{p} [{trace}]" for p in dict.fromkeys(problems)]
    return problems


class ScriptedLLM:
    """Replay scripted steps in place of the LLM calls; see the module docstring."""

    def __init__(self, steps: list[Step]):
        self.steps = list(steps)
        self.requests: list[Request] = []
        self.errors: list[str] = []
        self._stack: ExitStack | None = None

    def call_llm(self, config: LLMConfig, messages: list[dict]) -> LLMResponse:
        return self._handle("plain", config, messages, None)

    def call_llm_with_tools(
        self, config: LLMConfig, messages: list[dict], tools: list[dict]
    ) -> LLMResponse:
        return self._handle("tools", config, messages, tool_names(tools))

    def _handle(
        self, kind: str, config: LLMConfig, messages: list[dict], tools: frozenset[str] | None
    ) -> LLMResponse:
        n = len(self.requests)
        self.requests.append(Request(kind, config, copy.deepcopy(messages), tools))
        label = f"request {n} ({'call_llm_with_tools' if kind == 'tools' else 'call_llm'})"

        problems = check_protocol(messages, tools_offered=kind == "tools")
        if not self.steps:
            problems.append("the script has no steps left")
        else:
            expected = self.steps[0].tools
            if expected is None and kind == "tools":
                problems.append("expected a plain call_llm call")
            elif expected is not None and kind == "plain":
                problems.append("expected a call_llm_with_tools call")
            elif expected is not None and tools != expected:
                problems.append(
                    f"offered tools {sorted(tools or ())} but the step expects {sorted(expected)}"
                )
        if problems:
            self.errors.extend(f"{label}: {p}" for p in problems)
            raise ProtocolError("\n".join(self.errors))

        response = self.steps.pop(0).response
        if isinstance(response, BaseException):
            raise response
        return response

    def __enter__(self) -> ScriptedLLM:
        self._stack = ExitStack()
        for name in PATCH_TARGETS:
            module = importlib.import_module(name)
            for attr in ("call_llm", "call_llm_with_tools"):
                if hasattr(module, attr):
                    self._stack.enter_context(patch.object(module, attr, getattr(self, attr)))
        return self

    def __exit__(self, exc_type: Any, exc: BaseException | None, tb: Any) -> bool:
        assert self._stack is not None
        self._stack.close()
        if self.errors:
            raise ProtocolError("\n".join(self.errors)) from exc
        if exc_type is None and self.steps:
            raise AssertionError(
                f"{len(self.steps)} scripted step(s) left over: "
                + ", ".join(repr(s.response) for s in self.steps)
            )
        return False
