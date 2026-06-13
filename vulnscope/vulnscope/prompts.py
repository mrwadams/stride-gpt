"""LLM prompt templates.

All prompts live here so the scoring rubric is reviewable in one place and the
scorer stays free of prose.
"""

from __future__ import annotations

SCORING_SYSTEM_PROMPT = (
    "You are a security analyst scoring a vulnerability finding against a threat "
    "model. You reason carefully about how the specific system's architecture "
    "changes a finding's importance. You output only valid JSON — no commentary "
    "outside the JSON block."
)

# Called once per finding, with the full threat model injected as context.
SCORING_PROMPT = """\
THREAT MODEL:
{threat_model_json}

FINDING:
{finding_json}

Score this finding on four dimensions (0-10 each) and classify it.
Return valid JSON only, no commentary outside the JSON block.

Scoring criteria:
- asset_criticality: How critical is the affected component in this threat \
model? Components the model marks external-facing, in a DMZ, or handling \
high-value data/assets score higher.
- threat_alignment: Does this finding corroborate an existing threat model \
threat (same STRIDE category and component)? Corroborated findings score high. \
Findings with no matching threat score lower.
- trust_boundary_exposure: Is the component on or near a threat model trust \
boundary, or does it receive untrusted input across one? Deep internal services \
with no boundary crossings score lower.
- stride_category_weight: What is the aggregate DREAD weight for this finding's \
STRIDE category in the model? Categories the model already assessed as \
high-DREAD score higher. Use the stride_dread_aggregates field when present.

Classification must be exactly one of:
- CORROBORATED: directly validates an existing threat model threat
- NOVEL: affects a component in the model, but a category/threat it does not cover
- OUT_OF_SCOPE: affects a component not present in the threat model at all

The reasoning field must be 2-3 sentences and must cite at least one specific, \
named threat model element: a component name, a threat id (e.g. TM-014), or a \
STRIDE category.

Return JSON in exactly this shape:
{{
  "asset_criticality": <0-10>,
  "threat_alignment": <0-10>,
  "trust_boundary_exposure": <0-10>,
  "stride_category_weight": <0-10>,
  "classification": "CORROBORATED" | "NOVEL" | "OUT_OF_SCOPE",
  "reasoning": "<2-3 sentences citing a named threat model element>"
}}"""

# Called once after all findings are scored, for the executive summary.
SYNTHESIS_PROMPT = """\
You are a security analyst. Below are {n} vulnerability findings scored against \
a threat model for {application_name}.

SCORED FINDINGS:
{scored_findings_json}

Write a 3-paragraph executive summary:
1. Overall security posture implication of these findings given the threat model.
2. The 3 most urgent findings and why (cite threat model elements).
3. What the novel findings suggest about threat model coverage gaps.

Plain prose, no bullet points, no headers. Max 250 words."""

SYNTHESIS_SYSTEM_PROMPT = (
    "You are a senior security analyst writing a concise executive summary for "
    "engineering and security leadership. Write plain prose only."
)


def build_scoring_prompt(threat_model_json: str, finding_json: str) -> str:
    return SCORING_PROMPT.format(
        threat_model_json=threat_model_json, finding_json=finding_json
    )


def build_synthesis_prompt(
    n: int, application_name: str, scored_findings_json: str
) -> str:
    return SYNTHESIS_PROMPT.format(
        n=n,
        application_name=application_name,
        scored_findings_json=scored_findings_json,
    )
