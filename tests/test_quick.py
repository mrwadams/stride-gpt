"""Tests for stride_gpt.agent.quick — description-driven threat model loop."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from stride_gpt.agent.quick import (
    QUICK_TOOLS,
    _build_user_content,
    _flatten_for_plain_call,
    _parse_threat_model,
    _retry_as_json,
    run_quick_analysis,
)
from stride_gpt.core.prompts.variants import load_reference
from stride_gpt.core.schemas import LLMResponse, ToolCallResult
from tests.fakes import QUICK_TOOL_NAMES, ScriptedLLM, call_tools, check_protocol, reply

# ---------------------------------------------------------------------------
# Tool set
# ---------------------------------------------------------------------------


class TestQuickTools:
    def test_only_reference_tools(self):
        """Quick analysis must not expose filesystem tools — there's no
        codebase, so read_file / grep / list_directory would be invitations to
        hallucinate. Restrict to the reference-card tools."""
        names = {t["function"]["name"] for t in QUICK_TOOLS}
        assert names == {"load_reference", "list_references"}


# ---------------------------------------------------------------------------
# User content construction (hint vs no hint)
# ---------------------------------------------------------------------------


class TestUserContent:
    def test_no_hint(self):
        text = _build_user_content("A flask app.", None)
        assert "A flask app." in text
        assert "hint" not in text.lower()

    def test_hint_included(self):
        text = _build_user_content("A LangGraph agent.", "Agentic AI application")
        assert "Agentic AI application" in text
        assert "A LangGraph agent." in text


# ---------------------------------------------------------------------------
# Loop behaviour
# ---------------------------------------------------------------------------


def _final_response(threats=None, suggestions=None) -> LLMResponse:
    payload = json.dumps({
        "threat_model": threats or [],
        "improvement_suggestions": suggestions or [],
    })
    return LLMResponse(content=payload, thinking=None, reasoning=None,
                       model="t", tool_calls=None)


class TestRunQuickAnalysis:
    @patch("stride_gpt.agent.quick.call_llm_with_tools")
    def test_single_turn_emits_threats(self, mock_tools, model_pair):
        """A web-shaped description should produce findings in one turn —
        the model has no reason to load LLM/agentic reference cards."""
        mock_tools.return_value = _final_response(
            threats=[{"Threat Type": "Spoofing", "Scenario": "s", "Potential Impact": "i"}],
            suggestions=["clarify auth"],
        )
        out = run_quick_analysis(model_pair, "A Flask CRUD app.")
        assert len(out.threat_model) == 1
        assert out.improvement_suggestions == ["clarify auth"]
        assert mock_tools.call_count == 1

    @patch("stride_gpt.agent.quick.call_llm_with_tools")
    def test_two_turn_with_load_reference(self, mock_tools, model_pair):
        """End-to-end: agent calls load_reference, then on the next turn emits
        a threat carrying an OWASP_LLM code derived from the loaded card."""
        turn1 = LLMResponse(
            content="I'll load the genai card first.",
            thinking=None, reasoning=None, model="t",
            tool_calls=[ToolCallResult(
                id="tc1", function_name="load_reference",
                arguments={"name": "genai"},
            )],
        )
        turn2 = _final_response(threats=[{
            "Threat Type": "Tampering",
            "Scenario": "Prompt injection via uploaded doc",
            "Potential Impact": "Bad",
            "OWASP_LLM": "LLM01",
        }])
        mock_tools.side_effect = [turn1, turn2]

        out = run_quick_analysis(model_pair, "A RAG-backed chatbot using OpenAI.")
        assert mock_tools.call_count == 2
        assert out.threat_model[0]["OWASP_LLM"] == "LLM01"
        # The tool result should be in the messages list on the second call.
        second_messages = mock_tools.call_args_list[1].args[1]
        tool_results = [m for m in second_messages if m.get("role") == "tool"]
        assert any("LLM01" in m["content"] for m in tool_results)

    @patch("stride_gpt.agent.quick.call_llm_with_tools")
    def test_repeated_load_reference_uses_cache(self, mock_tools, model_pair):
        """If the model calls load_reference for the same card twice in one
        turn, the second call should be served from cache, not re-execute the
        tool. Stops the model burning context on duplicated 13 KB cards."""
        turn1 = LLMResponse(
            content="",
            thinking=None, reasoning=None, model="t",
            tool_calls=[
                ToolCallResult(id="tc1", function_name="load_reference",
                               arguments={"name": "genai"}),
                ToolCallResult(id="tc2", function_name="load_reference",
                               arguments={"name": "genai"}),
            ],
        )
        turn2 = _final_response()
        mock_tools.side_effect = [turn1, turn2]

        run_quick_analysis(model_pair, "Any description.")
        # Inspect tool messages in the second call's message list.
        msgs = mock_tools.call_args_list[1].args[1]
        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
        assert len(tool_msgs) == 2
        # First is the real card; second should be the cache-hit notice.
        assert "LLM01" in tool_msgs[0]["content"]
        assert "already loaded" in tool_msgs[1]["content"]

    @patch("stride_gpt.agent.quick.call_llm")
    @patch("stride_gpt.agent.quick.call_llm_with_tools")
    def test_bad_json_triggers_retry(self, mock_tools, mock_llm, model_pair):
        """If the model's final response isn't parseable JSON, we retry once
        with forced JSON mode."""
        mock_tools.return_value = LLMResponse(
            content="Sorry I cannot answer in JSON.",
            thinking=None, reasoning=None, model="t", tool_calls=None,
        )
        mock_llm.return_value = LLMResponse(
            content=json.dumps({
                "threat_model": [{"Threat Type": "Spoofing", "Scenario": "x", "Potential Impact": "y"}],
                "improvement_suggestions": [],
            }),
            thinking=None, reasoning=None, model="t",
        )
        out = run_quick_analysis(model_pair, "Anything.")
        assert mock_llm.call_count == 1
        assert len(out.threat_model) == 1

    @patch("stride_gpt.agent.quick.call_llm_with_tools")
    def test_records_call_counts_and_tool_breakdown(self, mock_tools, model_pair):
        """Output must record llm_calls, tool_calls, and a per-tool breakdown.
        Without these, a model that skips list_references / load_reference is
        invisible in the saved report — exactly the bug that motivated this."""
        turn1 = LLMResponse(
            content="discovering",
            thinking=None, reasoning=None, model="t",
            tool_calls=[ToolCallResult(
                id="t1", function_name="list_references", arguments={},
            )],
        )
        turn2 = LLMResponse(
            content="loading",
            thinking=None, reasoning=None, model="t",
            tool_calls=[ToolCallResult(
                id="t2", function_name="load_reference",
                arguments={"name": "genai"},
            )],
        )
        turn3 = _final_response()
        mock_tools.side_effect = [turn1, turn2, turn3]

        out = run_quick_analysis(model_pair, "A RAG chatbot.")

        assert out.llm_calls == 3
        assert out.tool_calls == 2
        assert out.tools_used == {"list_references": 1, "load_reference": 1}

    @patch("stride_gpt.agent.quick.call_llm_with_tools")
    def test_zero_tool_calls_recorded_when_model_skips_discovery(
        self, mock_tools, model_pair,
    ):
        """When the model emits a final JSON directly without loading any
        cards, tool_calls is 0 and tools_used is empty — the smoking gun for
        the discovery-skip regression should be unambiguous in the report."""
        mock_tools.return_value = _final_response()
        out = run_quick_analysis(model_pair, "A LangGraph agent.")
        assert out.llm_calls == 1
        assert out.tool_calls == 0
        assert out.tools_used == {}

    @patch("stride_gpt.agent.quick.call_llm")
    @patch("stride_gpt.agent.quick.call_llm_with_tools")
    def test_hits_max_llm_calls_coerces_final(self, mock_tools, mock_llm, model_pair):
        """If the model keeps calling tools forever, we cap it and force a
        final JSON output."""
        looper = LLMResponse(
            content="",
            thinking=None, reasoning=None, model="t",
            tool_calls=[ToolCallResult(id="tc", function_name="load_reference",
                                       arguments={"name": "genai"})],
        )
        # Always return a tool call — the loop must give up at max_llm_calls.
        mock_tools.return_value = looper
        mock_llm.return_value = LLMResponse(
            content=json.dumps({
                "threat_model": [], "improvement_suggestions": ["partial"],
            }),
            thinking=None, reasoning=None, model="t",
        )
        out = run_quick_analysis(model_pair, "Description.", max_llm_calls=2)
        # One tool-using turn, then the forced JSON call — the cap holds.
        assert mock_tools.call_count == 1
        assert mock_llm.call_count == 1
        assert out.improvement_suggestions == ["partial"]


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


class TestParseThreatModel:
    def test_clean_json(self):
        out = _parse_threat_model('{"threat_model": [], "improvement_suggestions": []}')
        assert out is not None
        assert out.threat_model == []

    def test_markdown_fence(self):
        text = '```json\n{"threat_model": [], "improvement_suggestions": []}\n```'
        out = _parse_threat_model(text)
        assert out is not None

    def test_embedded_in_prose(self):
        text = 'Here is the model:\n{"threat_model": [], "improvement_suggestions": []}\nDone.'
        out = _parse_threat_model(text)
        assert out is not None

    def test_invalid_returns_none(self):
        assert _parse_threat_model("not json at all") is None


class TestFlattenForPlainCall:
    def test_tool_results_become_text_in_a_valid_conversation(self):
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "1"}]},
            {"role": "tool", "tool_call_id": "1", "name": "load_reference", "content": "CARD ONE"},
            {"role": "assistant", "content": "next card", "tool_calls": [{"id": "2"}]},
            {"role": "tool", "tool_call_id": "2", "name": "load_reference", "content": "CARD TWO"},
            {"role": "user", "content": "next"},
        ]
        flat = _flatten_for_plain_call(msgs)

        assert check_protocol(flat, tools_offered=False) == []
        assert not any("tool_calls" in m for m in flat)
        assert all(m["content"] for m in flat)
        text = "\n".join(m["content"] for m in flat)
        for kept in ("hi", "CARD ONE", "next card", "CARD TWO", "next"):
            assert kept in text

    def test_does_not_modify_the_conversation_it_was_given(self):
        msgs = [
            {"role": "user", "content": "one"},
            {"role": "user", "content": "two"},
        ]
        _flatten_for_plain_call(msgs)
        assert msgs == [
            {"role": "user", "content": "one"},
            {"role": "user", "content": "two"},
        ]


# ---------------------------------------------------------------------------
# Tier routing — main call → architect; retry → worker
# ---------------------------------------------------------------------------


class TestTierRouting:
    @patch("stride_gpt.agent.quick.call_llm")
    @patch("stride_gpt.agent.quick.call_llm_with_tools")
    def test_main_call_uses_architect_retry_uses_worker(
        self, mock_tools, mock_llm, tiered_pair,
    ):
        """The main single-shot judgment hits the architect tier. If JSON
        parse fails, the retry hits the worker tier (same task, stricter
        formatting — no reason to escalate)."""
        mock_tools.return_value = LLMResponse(
            content="not parseable",
            thinking=None, reasoning=None, model="t", tool_calls=None,
        )
        mock_llm.return_value = LLMResponse(
            content=json.dumps({"threat_model": [], "improvement_suggestions": []}),
            thinking=None, reasoning=None, model="t",
        )

        run_quick_analysis(tiered_pair, "Anything.")

        assert mock_tools.call_args.args[0].model_name == tiered_pair.architect.model_name
        assert mock_llm.call_args.args[0].model_name == tiered_pair.worker.model_name

    @patch("stride_gpt.agent.quick.call_llm")
    @patch("stride_gpt.agent.quick.call_llm_with_tools")
    def test_single_tier_uses_worker_everywhere(
        self, mock_tools, mock_llm, model_pair,
    ):
        mock_tools.return_value = LLMResponse(
            content="not parseable",
            thinking=None, reasoning=None, model="t", tool_calls=None,
        )
        mock_llm.return_value = LLMResponse(
            content=json.dumps({"threat_model": [], "improvement_suggestions": []}),
            thinking=None, reasoning=None, model="t",
        )

        run_quick_analysis(model_pair, "Anything.")

        worker_name = model_pair.worker.model_name
        assert mock_tools.call_args.args[0].model_name == worker_name
        assert mock_llm.call_args.args[0].model_name == worker_name


# ---------------------------------------------------------------------------
# _retry_as_json — forced-JSON retry fallback
# ---------------------------------------------------------------------------


class TestRetryAsJson:
    @patch("stride_gpt.agent.quick.call_llm")
    def test_retry_success_returns_parsed_model(self, mock_llm, llm_config):
        mock_llm.return_value = LLMResponse(
            content=json.dumps({
                "threat_model": [{"Threat Type": "Spoofing", "Scenario": "s"}],
                "improvement_suggestions": ["x"],
            }),
            thinking=None, reasoning=None, model="t",
        )
        out = _retry_as_json(llm_config, [{"role": "user", "content": "hi"}])
        assert len(out.threat_model) == 1
        assert out.improvement_suggestions == ["x"]

    @patch("stride_gpt.agent.quick.call_llm")
    def test_double_failure_returns_empty_with_message(self, mock_llm, llm_config):
        """When even the forced-JSON retry can't be parsed, the user gets an
        empty threat model carrying a specific 'failed to parse' note rather
        than an exception."""
        mock_llm.return_value = LLMResponse(
            content="still not json {{{",
            thinking=None, reasoning=None, model="t",
        )
        out = _retry_as_json(llm_config, [{"role": "user", "content": "hi"}])
        assert out.threat_model == []
        assert out.improvement_suggestions == ["Failed to parse model response as JSON."]


class TestMalformedToolArguments:
    @patch("stride_gpt.agent.quick.call_llm_with_tools")
    def test_parse_error_returned_as_tool_result(self, mock_tools, model_pair):
        bad = ToolCallResult(
            id="bad", function_name="load_reference", arguments={},
            parse_error="arguments were not valid JSON (Unterminated string)",
        )
        turn1 = LLMResponse(content="", model="t", tool_calls=[bad])
        mock_tools.side_effect = [turn1, _final_response()]

        out = run_quick_analysis(model_pair, "Any description.")

        msgs = mock_tools.call_args_list[1].args[1]
        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
        assert tool_msgs[0]["tool_call_id"] == "bad"
        assert tool_msgs[0]["content"].startswith("Error: arguments were not valid JSON")
        assert out.tool_calls == 1


# ---------------------------------------------------------------------------
# Call cap and the forced-JSON call
# ---------------------------------------------------------------------------


_EMPTY_MODEL = json.dumps({"threat_model": [], "improvement_suggestions": []})
_CARDS = ("genai", "agentic", "insider_threat", "mitre_atlas")


def _load_round(card: str):
    tc = ToolCallResult(id=f"id-{card}", function_name="load_reference", arguments={"name": card})
    return call_tools(tc, tools=QUICK_TOOL_NAMES)


def _sent_text(request) -> str:
    return "\n".join(m["content"] for m in request.messages)


class TestCallCap:
    @pytest.mark.parametrize("cap", [1, 2, 4])
    def test_the_cap_includes_the_forced_json_call(self, model_pair, cap):
        """A model that never stops calling tools uses exactly ``cap`` calls,
        the last of them the forced-JSON call."""
        steps = [_load_round(card) for card in _CARDS[:cap - 1]]

        with ScriptedLLM([*steps, reply(_EMPTY_MODEL)]) as fake:
            out = run_quick_analysis(model_pair, "A RAG chatbot.", max_llm_calls=cap)

        assert len(fake.requests) == cap
        assert out.llm_calls == cap
        assert fake.requests[-1].kind == "plain"

    def test_a_parse_failure_on_the_last_turn_still_fits_inside_the_cap(self, model_pair):
        steps = [
            _load_round("genai"),
            _load_round("agentic"),
            reply("Here is my analysis in prose.", tools=QUICK_TOOL_NAMES),
            reply(_EMPTY_MODEL),
        ]

        with ScriptedLLM(steps) as fake:
            out = run_quick_analysis(model_pair, "A RAG chatbot.", max_llm_calls=4)

        assert len(fake.requests) == 4
        assert out.llm_calls == 4


class TestForcedJsonKeepsCards:
    def test_cards_reach_the_final_call_when_the_cap_is_hit(self, model_pair):
        steps = [_load_round(card) for card in _CARDS[:3]]

        with ScriptedLLM([*steps, reply(_EMPTY_MODEL)]) as fake:
            out = run_quick_analysis(model_pair, "A RAG chatbot.")

        final = fake.requests[-1]
        assert final.kind == "plain"
        assert all(m["content"] for m in final.messages)
        for card in _CARDS[:3]:
            assert load_reference(card) in _sent_text(final)
        assert out.references_loaded == sorted(_CARDS[:3])

    def test_cards_reach_the_retry_after_a_parse_failure(self, model_pair):
        steps = [
            _load_round("genai"),
            _load_round("agentic"),
            reply("not json", tools=QUICK_TOOL_NAMES),
            reply(_EMPTY_MODEL),
        ]

        with ScriptedLLM(steps) as fake:
            out = run_quick_analysis(model_pair, "A RAG chatbot.")

        for card in ("genai", "agentic"):
            assert load_reference(card) in _sent_text(fake.requests[-1])
        assert out.references_loaded == ["agentic", "genai"]

    def test_a_failed_load_is_not_claimed_as_loaded(self, model_pair):
        steps = [
            _load_round("genai"),
            _load_round("no_such_card"),
            reply("not json", tools=QUICK_TOOL_NAMES),
            reply(_EMPTY_MODEL),
        ]

        with ScriptedLLM(steps):
            out = run_quick_analysis(model_pair, "A RAG chatbot.")

        assert out.references_loaded == ["genai"]
