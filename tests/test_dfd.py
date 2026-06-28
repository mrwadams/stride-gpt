"""Tests for Data Flow Diagram generation, parsing, and rendering."""

from __future__ import annotations

import json
from unittest.mock import patch

from stride_gpt.core.dfd import (
    _parse_dfd_response,
    convert_dfd_to_mermaid,
    generate_dfd,
    parse_dfd_from_image,
)
from stride_gpt.core.prompts.builder import (
    create_dfd_image_analysis_prompt,
    create_dfd_prompt,
    create_threat_model_prompt,
    dfd_to_prompt_section,
)
from stride_gpt.core.schemas import (
    AnalysisReport,
    LLMResponse,
)

# ---------------------------------------------------------------------------
# convert_dfd_to_mermaid
# ---------------------------------------------------------------------------


class TestConvertDfdToMermaid:
    def test_basic_three_nodes_two_edges(self):
        dfd = {
            "nodes": [
                {"id": "user", "label": "End User", "type": "external_entity"},
                {"id": "api", "label": "API Server", "type": "process"},
                {"id": "db", "label": "User Database", "type": "data_store"},
            ],
            "edges": [
                {"from": "user", "to": "api", "label": "Login request"},
                {"from": "api", "to": "db", "label": "User lookup"},
            ],
        }
        result = convert_dfd_to_mermaid(dfd)

        assert result.startswith("flowchart TD")
        # External entity → rectangle
        assert 'user["End User"]' in result
        # Process → circle
        assert 'api(("API Server"))' in result
        # Data store → cylinder
        assert 'db[("User Database")]' in result
        # Edges keep their labels
        assert "user -->|Login request| api" in result
        assert "api -->|User lookup| db" in result

    def test_trust_boundary_emits_subgraph(self):
        dfd = {
            "nodes": [
                {"id": "user", "label": "User", "type": "external_entity"},
                {"id": "api", "label": "API", "type": "process"},
                {"id": "db", "label": "DB", "type": "data_store"},
            ],
            "edges": [
                {"from": "user", "to": "api", "label": "Request"},
                {"from": "api", "to": "db", "label": "Query"},
            ],
            "trust_boundaries": [
                {"name": "Internal VPC", "node_ids": ["api", "db"]},
            ],
        }
        result = convert_dfd_to_mermaid(dfd)

        assert 'subgraph tb0["Internal VPC"]' in result
        assert "end" in result
        # Boundary styling
        assert "stroke-dasharray" in result
        assert "class tb0 trustBoundary" in result
        # User is outside the boundary
        user_idx = result.find("user[")
        subgraph_idx = result.find("subgraph tb0")
        end_idx = result.find("\n    end")
        assert user_idx > end_idx or user_idx < subgraph_idx

    def test_handles_label_with_special_chars(self):
        """LLM-supplied labels with pipes or quotes shouldn't break Mermaid syntax.

        The outer `"..."` are Mermaid's label delimiters — what matters is that
        the *content* between them is free of pipes and stray inner quotes
        (we replace `"` with `'` so the label text doesn't terminate early).
        """
        dfd = {
            "nodes": [{"id": "api", "label": 'Has "quotes" | and pipe', "type": "process"}],
            "edges": [],
        }
        result = convert_dfd_to_mermaid(dfd)
        # Extract the label content between Mermaid's `(("..."))` delimiters.
        between = result.split('api(("')[1].split('"))')[0]
        assert '"' not in between, f"Inner quotes survived sanitization: {between!r}"
        assert "|" not in between, f"Pipe survived sanitization: {between!r}"

    def test_boundary_referencing_unknown_node_is_skipped(self):
        """A trust boundary that references a node id which doesn't exist must
        not crash — the dangling reference is skipped, real nodes still render."""
        dfd = {
            "nodes": [{"id": "api", "label": "API", "type": "process"}],
            "edges": [],
            "trust_boundaries": [
                {"name": "VPC", "node_ids": ["api", "ghost"]},
            ],
        }
        result = convert_dfd_to_mermaid(dfd)
        assert 'subgraph tb0["VPC"]' in result
        assert 'api(("API"))' in result
        # The non-existent node produces no node line.
        assert "ghost" not in result

    def test_edges_missing_from_or_to_are_skipped(self):
        """Malformed edges (missing endpoint) are dropped rather than rendered
        as broken Mermaid."""
        dfd = {
            "nodes": [
                {"id": "a", "label": "A", "type": "process"},
                {"id": "b", "label": "B", "type": "process"},
            ],
            "edges": [
                {"from": "a", "to": "b", "label": "ok"},
                {"from": "a", "label": "no-to"},
                {"to": "b", "label": "no-from"},
            ],
        }
        result = convert_dfd_to_mermaid(dfd)
        assert "a -->|ok| b" in result
        assert "no-to" not in result
        assert "no-from" not in result


# ---------------------------------------------------------------------------
# _parse_dfd_response
# ---------------------------------------------------------------------------


class TestParseDfdResponse:
    def test_json_path(self):
        payload = json.dumps({
            "nodes": [{"id": "a", "label": "A", "type": "process"}],
            "edges": [],
        })
        result = _parse_dfd_response(payload)
        assert result.startswith("flowchart TD")
        assert 'a(("A"))' in result

    def test_json_fenced(self):
        content = '```json\n{"nodes": [{"id":"x","label":"X","type":"data_store"}], "edges": []}\n```'
        result = _parse_dfd_response(content)
        assert 'x[("X")]' in result

    def test_mermaid_fallback_when_json_fails(self):
        # Model emitted raw Mermaid instead of JSON — fallback should extract
        # the diagram code (`clean_mermaid_syntax` is best-effort and adds
        # default-label brackets, matching the attack-tree path's behaviour).
        content = "```mermaid\nflowchart TD\n    a-->b\n```"
        result = _parse_dfd_response(content)
        # Fallback returned the body of the fence, not the original wrapped text.
        assert "```" not in result
        assert "a" in result and "b" in result
        assert "flowchart" in result


# ---------------------------------------------------------------------------
# generate_dfd / parse_dfd_from_image
# ---------------------------------------------------------------------------


class TestGenerateDfd:
    def test_uses_json_response_format(self, llm_config):
        """generate_dfd must force JSON response_format so providers honour it."""
        captured: dict = {}

        def fake_call(config, messages):
            captured["config"] = config
            return LLMResponse(
                content=json.dumps({
                    "nodes": [{"id": "a", "label": "A", "type": "process"}],
                    "edges": [],
                })
            )

        with patch("stride_gpt.core.dfd.call_llm", side_effect=fake_call):
            mermaid, _ = generate_dfd(llm_config, "Describe the system.")

        assert captured["config"].response_format == "json"
        # Original config must NOT be mutated.
        assert llm_config.response_format == "text"
        assert "flowchart TD" in mermaid

    def test_parse_dfd_from_image_uses_call_llm_with_image(self, llm_config):
        captured: dict = {}

        def fake_image_call(config, prompt, base64_image, media_type):
            captured["config"] = config
            captured["media_type"] = media_type
            return LLMResponse(
                content=json.dumps({
                    "nodes": [{"id": "u", "label": "User", "type": "external_entity"}],
                    "edges": [],
                })
            )

        with patch(
            "stride_gpt.core.dfd.call_llm_with_image", side_effect=fake_image_call
        ):
            mermaid, _ = parse_dfd_from_image(llm_config, "Zm9v", media_type="image/png")

        assert captured["media_type"] == "image/png"
        assert captured["config"].response_format == "json"
        assert 'u["User"]' in mermaid


# ---------------------------------------------------------------------------
# Prompt builders — confirmed_dfd wiring (the iteration loop)
# ---------------------------------------------------------------------------


class TestPromptWiring:
    def test_dfd_section_appears_when_confirmed_dfd_set(self):
        mermaid = "flowchart TD\n    user-->api"
        prompt = create_threat_model_prompt(
            app_type="Web application",
            authentication="OAuth2",
            internet_facing="Yes",
            sensitive_data="PII",
            app_input="A web app.",
            confirmed_dfd=mermaid,
        )
        assert "CONFIRMED DATA FLOW DIAGRAM" in prompt
        assert "user-->api" in prompt

    def test_dfd_section_absent_when_no_confirmed_dfd(self):
        prompt = create_threat_model_prompt(
            app_type="Web application",
            authentication="OAuth2",
            internet_facing="Yes",
            sensitive_data="PII",
            app_input="A web app.",
        )
        assert "CONFIRMED DATA FLOW DIAGRAM" not in prompt

    def test_dfd_to_prompt_section_contains_mermaid_fence(self):
        section = dfd_to_prompt_section("flowchart TD\n    a-->b")
        assert "```mermaid" in section
        assert "flowchart TD" in section

    def test_create_dfd_prompt_carries_application_context(self):
        prompt = create_dfd_prompt(
            "Web application", "OAuth2", "Yes", "PII", "My description."
        )
        assert "APPLICATION TYPE: Web application" in prompt
        assert "My description." in prompt

    def test_image_analysis_prompt_requests_canonical_json(self):
        prompt = create_dfd_image_analysis_prompt()
        # Names the three node-type values so the model can't invent its own.
        assert "external_entity" in prompt
        assert "process" in prompt
        assert "data_store" in prompt


# ---------------------------------------------------------------------------
# Agent report rendering — DFD section
# ---------------------------------------------------------------------------


class TestAgentReportRendersDfd:
    def test_renders_mermaid_fence_when_dfd_present(self, sample_plan, sample_finding):
        from stride_gpt.agent.report import render_markdown

        report = AnalysisReport(
            plan=sample_plan,
            findings=[sample_finding],
            data_flow_diagram="flowchart TD\n    user --> api",
            metadata={},
        )
        md = render_markdown(report)
        assert "## Data Flow Diagram" in md
        assert "```mermaid" in md
        assert "flowchart TD" in md

    def test_no_section_when_dfd_absent(self, sample_report):
        from stride_gpt.agent.report import render_markdown

        # sample_report is constructed without data_flow_diagram → defaults to None
        assert sample_report.data_flow_diagram is None
        md = render_markdown(sample_report)
        assert "## Data Flow Diagram" not in md

    def test_render_json_carries_dfd(self, sample_plan, sample_finding):
        from stride_gpt.agent.report import render_json, render_markdown_from_json

        report = AnalysisReport(
            plan=sample_plan,
            findings=[sample_finding],
            data_flow_diagram="flowchart TD\n    a --> b",
            metadata={},
        )
        data = render_json(report)
        assert data["data_flow_diagram"] == "flowchart TD\n    a --> b"
        # And the from-JSON markdown renderer surfaces it too (replay path).
        md = render_markdown_from_json(data)
        assert "## Data Flow Diagram" in md
