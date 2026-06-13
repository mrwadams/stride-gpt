"""Tests for the threat model and findings parsers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnscope.parsers.findings import parse_findings
from vulnscope.parsers.threat_model import parse_threat_model

FIXTURES = Path(__file__).parent / "fixtures"


class TestThreatModelParser:
    def test_parses_minimal_schema(self):
        tm = parse_threat_model(FIXTURES / "sample_threat_model.json")
        assert tm.application_name == "PaymentAPI"
        assert tm.source_format == "minimal-json"
        assert tm.component_names() == {
            "UserService",
            "AuthService",
            "PaymentService",
            "InternalCache",
        }
        assert len(tm.threats) == 3

    def test_preserves_explicit_threat_ids(self):
        tm = parse_threat_model(FIXTURES / "sample_threat_model.json")
        ids = {t.threat_id for t in tm.threats}
        assert "TM-014" in ids

    def test_dread_aggregates_per_category(self):
        tm = parse_threat_model(FIXTURES / "sample_threat_model.json")
        aggregates = tm.stride_dread_aggregates()
        assert aggregates["Tampering"] == 7.2
        assert aggregates["Spoofing"] == 6.5

    def test_find_component_is_substring_tolerant(self):
        tm = parse_threat_model(FIXTURES / "sample_threat_model.json")
        # A scanner path that embeds the component name should still match.
        assert tm.find_component("src/user_service/api.py UserService") is not None
        assert tm.find_component("UnknownService") is None

    def test_parses_stride_gpt_export(self, tmp_path):
        export = {
            "version": "1.0",
            "target": "/home/dev/payment-api",
            "overview": "A payments service.",
            "subsystems": [
                {
                    "name": "UserService",
                    "threats": [
                        {
                            "Threat Type": "Tampering",
                            "Scenario": "SQL injection via the id parameter.",
                            "Potential Impact": "Data modification",
                        }
                    ],
                    "improvement_suggestions": [],
                    "files_analyzed": ["api.py"],
                }
            ],
            "cross_cutting_threats": [
                {"Threat Type": "Spoofing", "Scenario": "No CSRF protection."}
            ],
        }
        path = tmp_path / "tm.json"
        path.write_text(json.dumps(export))
        tm = parse_threat_model(path)
        assert tm.source_format == "stride-gpt-json"
        assert tm.application_name == "payment-api"
        assert "UserService" in tm.component_names()
        assert "cross-cutting" in tm.component_names()
        categories = {t.stride_category for t in tm.threats}
        assert {"Tampering", "Spoofing"} <= categories

    def test_markdown_rejected_with_clear_error(self, tmp_path):
        path = tmp_path / "tm.md"
        path.write_text("# threat model")
        with pytest.raises(ValueError, match="markdown"):
            parse_threat_model(path)

    def test_unrecognised_format_raises(self, tmp_path):
        path = tmp_path / "tm.json"
        path.write_text(json.dumps({"something": "else"}))
        with pytest.raises(ValueError, match="Unrecognised"):
            parse_threat_model(path)


class TestFindingsParser:
    def test_parses_simple_json_array(self):
        findings = parse_findings(FIXTURES / "sample_findings.json")
        assert len(findings) == 4
        first = findings[0]
        assert first.id == "FINDING-001"
        assert first.component == "UserService"
        assert first.cwe == "CWE-89"
        assert first.severity == "HIGH"

    def test_parses_sarif(self):
        findings = parse_findings(FIXTURES / "sample_findings.sarif")
        assert len(findings) == 4
        by_component = {f.component for f in findings}
        assert {"UserService", "AuthService", "PaymentService", "LoggingService"} == by_component

    def test_sarif_extracts_cwe_from_relationship(self):
        findings = parse_findings(FIXTURES / "sample_findings.sarif")
        sqli = next(f for f in findings if f.component == "UserService")
        assert sqli.cwe == "CWE-89"

    def test_sarif_extracts_cwe_from_tags(self):
        findings = parse_findings(FIXTURES / "sample_findings.sarif")
        # missing-rate-limit has no relationship, only an external/cwe tag.
        rl = next(f for f in findings if f.component == "AuthService")
        assert rl.cwe == "CWE-287"

    def test_sarif_security_severity_maps_to_band(self):
        findings = parse_findings(FIXTURES / "sample_findings.sarif")
        sqli = next(f for f in findings if f.component == "UserService")
        # security-severity 8.6 -> HIGH
        assert sqli.severity == "HIGH"
        log = next(f for f in findings if f.component == "LoggingService")
        # security-severity 3.1 -> LOW
        assert log.severity == "LOW"

    def test_unrecognised_findings_format_raises(self, tmp_path):
        path = tmp_path / "f.json"
        path.write_text(json.dumps({"not": "a list or sarif"}))
        with pytest.raises(ValueError, match="Unrecognised"):
            parse_findings(path)
