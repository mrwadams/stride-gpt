"""Tests for SARIF sanitization helpers and report listing in
stride_gpt.agent.report.

SARIF is consumed by CI / code-scanning tools, so the ruleId and message
fields must be bounded and stripped of LLM-supplied control characters.
list_reports must survive a corrupt file on disk without crashing /reports.
"""

from __future__ import annotations

import json
import re

from stride_gpt.agent.report import (
    _SARIF_MESSAGE_MAX,
    _make_sarif_rule_id,
    _sarif_mitre_ids,
    _sarif_text,
    list_reports,
)

# ---------------------------------------------------------------------------
# _make_sarif_rule_id — ruleId sanitization
# ---------------------------------------------------------------------------


class TestMakeSarifRuleId:
    def test_clean_type(self):
        assert _make_sarif_rule_id("Spoofing") == "STRIDE/SPOOFING"

    def test_hostile_chars_are_stripped(self):
        rule_id = _make_sarif_rule_id("../etc/passwd <script>")
        # Everything after the STRIDE/ prefix is [A-Z0-9_] only.
        suffix = rule_id.split("/", 1)[1]
        assert re.fullmatch(r"[A-Z0-9_]+", suffix)
        assert "/" not in suffix
        assert "<" not in rule_id and ">" not in rule_id

    def test_empty_becomes_unknown(self):
        assert _make_sarif_rule_id("") == "STRIDE/UNKNOWN"

    def test_none_becomes_unknown(self):
        assert _make_sarif_rule_id(None) == "STRIDE/UNKNOWN"

    def test_punctuation_only_becomes_unknown(self):
        # Strips to empty after removing non-alphanumerics -> UNKNOWN fallback.
        assert _make_sarif_rule_id("///") == "STRIDE/UNKNOWN"

    def test_truncated_to_64_chars(self):
        rule_id = _make_sarif_rule_id("A" * 100)
        suffix = rule_id.split("/", 1)[1]
        assert len(suffix) == 64


# ---------------------------------------------------------------------------
# _sarif_text — message bounding
# ---------------------------------------------------------------------------


class TestSarifText:
    def test_none_is_empty_string(self):
        assert _sarif_text(None) == ""

    def test_short_text_unchanged(self):
        assert _sarif_text("hello") == "hello"

    def test_long_text_truncated_with_suffix(self):
        text = "x" * (_SARIF_MESSAGE_MAX + 500)
        result = _sarif_text(text)
        assert result.endswith("…[truncated]")
        assert result.startswith("x" * 100)
        assert len(result) == _SARIF_MESSAGE_MAX + len("…[truncated]")

    def test_exactly_at_limit_not_truncated(self):
        text = "y" * _SARIF_MESSAGE_MAX
        assert _sarif_text(text) == text


# ---------------------------------------------------------------------------
# _sarif_mitre_ids — list-of-objects + list-of-strings shapes
# ---------------------------------------------------------------------------


class TestSarifMitreIds:
    def test_list_of_objects(self):
        value = [{"id": "T1059"}, {"id": "T1078"}]
        assert _sarif_mitre_ids(value) == ["T1059", "T1078"]

    def test_list_of_strings_fallback(self):
        assert _sarif_mitre_ids(["T1059", "T1078"]) == ["T1059", "T1078"]

    def test_non_list_returns_empty(self):
        assert _sarif_mitre_ids("T1059") == []
        assert _sarif_mitre_ids(None) == []

    def test_skips_malformed_and_empty_entries(self):
        value = [{"id": "T1"}, {"id": ""}, 42, {"no_id": "x"}, "  ", "T2"]
        assert _sarif_mitre_ids(value) == ["T1", "T2"]


# ---------------------------------------------------------------------------
# list_reports — corrupt-file resilience
# ---------------------------------------------------------------------------


class TestListReportsCorruptSkip:
    def test_corrupt_file_is_skipped(self, tmp_path, monkeypatch):
        """A corrupt JSON file in the reports dir must not crash /reports — it's
        skipped, and the valid reports are still returned."""
        analyze_dir = tmp_path / "analyze"
        analyze_dir.mkdir()
        empty = tmp_path / "empty"  # used for quick + legacy roots

        valid = {
            "generated_at": "2026-06-27T10:00:00",
            "target": "myapp",
            "subsystems": [{"threats": [{"a": 1}, {"b": 2}]}],
            "cross_cutting_threats": [{"c": 3}],
            "metadata": {"worker_model": "sonnet"},
        }
        (analyze_dir / "good.json").write_text(json.dumps(valid))
        (analyze_dir / "bad.json").write_text("{ this is not valid json ")

        # list_reports does `from stride_gpt.config import ...` at call time, so
        # the patch targets must live on the config module.
        monkeypatch.setattr("stride_gpt.config.analyze_reports_dir", lambda: analyze_dir)
        monkeypatch.setattr("stride_gpt.config.quick_reports_dir", lambda: empty)
        monkeypatch.setattr("stride_gpt.config.REPORTS_DIR", empty)

        results = list_reports(kind="analyze")

        assert len(results) == 1
        _, path, summary = results[0]
        assert path.name == "good.json"
        assert summary["target"] == "myapp"
        # 2 subsystem threats + 1 cross-cutting threat.
        assert summary["threat_count"] == 3
