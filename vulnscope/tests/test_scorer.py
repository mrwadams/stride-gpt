"""Tests for the scoring engine — both the heuristic and the LLM path."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscope.config import Weights
from vulnscope.parsers.findings import Finding, parse_findings
from vulnscope.parsers.threat_model import parse_threat_model
from vulnscope.prompts import SCORING_SYSTEM_PROMPT
from vulnscope.scorer import (
    composite_score,
    infer_stride_category,
    score_finding_heuristic,
    score_finding_llm,
    score_findings,
    synthesize_summary,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _tm():
    return parse_threat_model(FIXTURES / "sample_threat_model.json")


def _findings():
    return parse_findings(FIXTURES / "sample_findings.json")


class FakeClient:
    """Records calls and returns canned responses keyed by system prompt."""

    def __init__(self, scoring_response: str, synthesis_response: str = "Summary text."):
        self.scoring_response = scoring_response
        self.synthesis_response = synthesis_response
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if system == SCORING_SYSTEM_PROMPT:
            return self.scoring_response
        return self.synthesis_response


class TestComposite:
    def test_weighted_average(self):
        scores = {
            "asset_criticality": 10,
            "threat_alignment": 0,
            "trust_boundary_exposure": 0,
            "stride_category_weight": 0,
        }
        # Default asset weight 0.35 of 10 = 3.5
        assert composite_score(scores, Weights()) == 3.5

    def test_weights_are_normalised(self):
        scores = {d: 8 for d in (
            "asset_criticality",
            "threat_alignment",
            "trust_boundary_exposure",
            "stride_category_weight",
        )}
        # Non-normalised weights still yield a 0-10 composite (all dims = 8 -> 8).
        weird = Weights(2.0, 2.0, 2.0, 2.0)
        assert composite_score(scores, weird) == 8.0


class TestStrideInference:
    def test_cwe_mapping(self):
        f = Finding(id="x", title="SQLi", cwe="CWE-89")
        assert infer_stride_category(f) == "Tampering"

    def test_keyword_fallback(self):
        f = Finding(id="x", title="No rate limiting on authentication endpoint")
        assert infer_stride_category(f) == "Spoofing"


class TestHeuristicScoring:
    def test_corroborated_sql_injection(self):
        tm = _tm()
        sqli = next(f for f in _findings() if f.id == "FINDING-001")
        scored = score_finding_heuristic(sqli, tm, Weights())
        assert scored.classification == "CORROBORATED"
        # Reasoning must cite a named threat model element (criterion #5).
        assert "TM-014" in scored.reasoning
        assert scored.composite_score >= 7.0

    def test_novel_when_component_known_category_uncovered(self):
        tm = _tm()
        # PaymentService is modelled, but has no Information Disclosure threat.
        f = next(f for f in _findings() if f.id == "FINDING-003")
        scored = score_finding_heuristic(f, tm, Weights())
        assert scored.classification == "NOVEL"
        assert "PaymentService" in scored.reasoning

    def test_out_of_scope_when_component_absent(self):
        tm = _tm()
        f = next(f for f in _findings() if f.id == "FINDING-017")
        scored = score_finding_heuristic(f, tm, Weights())
        assert scored.classification == "OUT_OF_SCOPE"
        assert "LoggingService" in scored.reasoning

    def test_all_classifications_present(self):
        tm = _tm()
        scored = score_findings(_findings(), tm, weights=Weights(), client=None)
        classes = {s.classification for s in scored}
        assert {"CORROBORATED", "NOVEL", "OUT_OF_SCOPE"} == classes

    def test_results_sorted_descending(self):
        tm = _tm()
        scored = score_findings(_findings(), tm, weights=Weights(), client=None)
        composites = [s.composite_score for s in scored]
        assert composites == sorted(composites, reverse=True)

    def test_every_finding_has_reasoning(self):
        tm = _tm()
        scored = score_findings(_findings(), tm, weights=Weights(), client=None)
        assert all(s.reasoning.strip() for s in scored)


class TestLLMScoring:
    def test_parses_well_formed_response(self):
        tm = _tm()
        f = next(f for f in _findings() if f.id == "FINDING-001")
        response = json.dumps(
            {
                "asset_criticality": 9,
                "threat_alignment": 8,
                "trust_boundary_exposure": 8,
                "stride_category_weight": 7,
                "classification": "CORROBORATED",
                "reasoning": "Corroborates TM-014 on UserService.",
            }
        )
        client = FakeClient(scoring_response=response)
        scored = score_finding_llm(f, tm, Weights(), client)
        assert scored.classification == "CORROBORATED"
        assert scored.scores["asset_criticality"] == 9
        assert "TM-014" in scored.reasoning
        # 9*.35 + 8*.30 + 8*.25 + 7*.10 = 3.15+2.4+2.0+0.7 = 8.25 -> 8.2/8.3
        assert 8.0 <= scored.composite_score <= 8.3

    def test_clamps_out_of_range_scores(self):
        tm = _tm()
        f = _findings()[0]
        response = json.dumps(
            {
                "asset_criticality": 99,
                "threat_alignment": -5,
                "trust_boundary_exposure": "high",
                "stride_category_weight": 7,
                "classification": "CORROBORATED",
                "reasoning": "cites UserService",
            }
        )
        scored = score_finding_llm(f, tm, Weights(), FakeClient(response))
        assert scored.scores["asset_criticality"] == 10.0
        assert scored.scores["threat_alignment"] == 0.0
        assert scored.scores["trust_boundary_exposure"] == 0.0

    def test_invalid_classification_inferred(self):
        tm = _tm()
        f = next(f for f in _findings() if f.id == "FINDING-017")  # LoggingService
        response = json.dumps(
            {
                "asset_criticality": 2,
                "threat_alignment": 1,
                "trust_boundary_exposure": 2,
                "stride_category_weight": 3,
                "classification": "BOGUS",
                "reasoning": "n/a",
            }
        )
        scored = score_finding_llm(f, tm, Weights(), FakeClient(response))
        # Component absent -> inferred OUT_OF_SCOPE.
        assert scored.classification == "OUT_OF_SCOPE"

    def test_unparseable_response_falls_back_to_heuristic(self):
        tm = _tm()
        f = next(f for f in _findings() if f.id == "FINDING-001")
        scored = score_finding_llm(f, tm, Weights(), FakeClient("not json at all"))
        # Heuristic still classifies the SQLi as corroborated.
        assert scored.classification == "CORROBORATED"
        assert "TM-014" in scored.reasoning

    def test_synthesis_uses_client(self):
        tm = _tm()
        scored = score_findings(_findings(), tm, weights=Weights(), client=None)
        client = FakeClient(scoring_response="{}", synthesis_response="Exec summary.")
        summary = synthesize_summary(scored, tm, client=client)
        assert summary == "Exec summary."

    def test_synthesis_offline_is_templated(self):
        tm = _tm()
        scored = score_findings(_findings(), tm, weights=Weights(), client=None)
        summary = synthesize_summary(scored, tm, client=None)
        assert "PaymentAPI" in summary
