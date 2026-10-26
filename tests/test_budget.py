"""Per-subsystem LLM call budget: the run's ceiling and the approval prompt (#226)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from stride_gpt.agent.budget import (
    DEFAULT_MAX_LLM_CALLS,
    format_llm_call_ceiling,
    llm_call_ceiling,
    prompt_plan_approval,
)


def test_default_cap_is_non_zero():
    assert DEFAULT_MAX_LLM_CALLS > 0


def test_ceiling_is_subsystems_times_cap_plus_grace_and_synthesis():
    # 6 subsystems x (25 rounds + 1 grace round) + synthesis and its retry + DFD.
    assert llm_call_ceiling(6, 25) == 6 * 26 + 3


def test_no_ceiling_when_the_cap_is_disabled():
    assert llm_call_ceiling(6, 0) is None
    assert "none" in format_llm_call_ceiling(6, 0)


def test_ceiling_line_is_labelled_as_a_ceiling_not_an_estimate():
    line = format_llm_call_ceiling(4, 10)
    assert "ceiling" in line
    assert "not an estimate" in line
    assert "47" in line


@pytest.mark.parametrize(("answer", "approved"), [
    ("y", True), ("YES", True), (" y ", True),
    ("n", False), ("no", False), ("q", False), ("quit", False),
])
def test_approval_answers(answer, approved):
    console = MagicMock()
    console.input.return_value = answer
    assert prompt_plan_approval(console) is approved


def test_unrecognised_answer_asks_again_instead_of_cancelling():
    console = MagicMock()
    console.input.side_effect = ["yse", "", "y"]
    assert prompt_plan_approval(console) is True
    assert console.input.call_count == 3
