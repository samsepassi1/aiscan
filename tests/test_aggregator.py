"""Tests for the aggregator module (merge, dedup, suppression)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aiscan.aggregator import merge
from aiscan.ast_layer import ParsedFile
from aiscan.models import DetectionMethod, Finding, Severity


def _finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="AI-SEC-001",
        rule_name="Test Rule",
        severity=Severity.HIGH,
        file_path="src/app.py",
        line_start=10,
        line_end=10,
        message="Test finding",
        cwe_ids=["CWE-259"],
        detection_method=DetectionMethod.AST,
        confidence=0.9,
        remediation="Fix it.",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _parsed_file(path: str, lines: list[str]) -> ParsedFile:
    mock_tree = MagicMock()
    return ParsedFile(
        path=Path(path),
        language="python",
        source="\n".join(lines).encode(),
        tree=mock_tree,
        lines=lines,
    )


class TestMergeDeduplication:
    def test_no_findings(self):
        result = merge([], [])
        assert result == []

    def test_ast_only(self):
        f = _finding()
        result = merge([f], [])
        assert len(result) == 1
        assert result[0].detection_method == DetectionMethod.AST

    def test_llm_only(self):
        f = _finding(detection_method=DetectionMethod.LLM)
        result = merge([], [f])
        assert len(result) == 1

    def test_same_key_becomes_hybrid(self):
        ast_f = _finding(severity=Severity.HIGH, detection_method=DetectionMethod.AST)
        llm_f = _finding(severity=Severity.MEDIUM, detection_method=DetectionMethod.LLM)
        result = merge([ast_f], [llm_f])
        assert len(result) == 1
        assert result[0].detection_method == DetectionMethod.HYBRID

    def test_higher_severity_wins_in_dedup(self):
        low_f = _finding(severity=Severity.LOW, detection_method=DetectionMethod.AST)
        high_f = _finding(severity=Severity.CRITICAL, detection_method=DetectionMethod.LLM)
        result = merge([low_f], [high_f])
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL
        assert result[0].detection_method == DetectionMethod.HYBRID

    def test_different_lines_not_deduped(self):
        f1 = _finding(line_start=10, line_end=10)
        f2 = _finding(line_start=20, line_end=20)
        result = merge([f1], [f2])
        assert len(result) == 2

    def test_different_rule_ids_not_deduped(self):
        f1 = _finding(rule_id="AI-SEC-001")
        f2 = _finding(rule_id="AI-SEC-003")
        result = merge([f1, f2], [])
        assert len(result) == 2


class TestSuppressionByAggregator:
    def test_suppressed_finding_marked(self):
        f = _finding(file_path="src/app.py", line_start=5, line_end=5)
        pf = _parsed_file("src/app.py", [
            "x = 1",
            "y = 2",
            "z = 3",
            "a = 4",
            "api_key = 'real_secret'  # aiscan: suppress false positive",
        ])
        result = merge([f], [], [pf])
        assert len(result) == 1
        assert result[0].suppressed is True
        assert "false positive" in result[0].suppression_reason

    def test_unsuppressed_finding_not_marked(self):
        f = _finding(file_path="src/app.py", line_start=1, line_end=1)
        pf = _parsed_file("src/app.py", [
            "api_key = 'real_secret'",
            "# aiscan: suppress",
        ])
        result = merge([f], [], [pf])
        assert result[0].suppressed is False

    def test_suppression_reason_empty_when_no_annotation(self):
        f = _finding(file_path="src/app.py", line_start=1, line_end=1)
        pf = _parsed_file("src/app.py", ["api_key = 'x'  # aiscan: suppress"])
        result = merge([f], [], [pf])
        assert result[0].suppressed is True
        assert result[0].suppression_reason == ""


class TestSortOrder:
    def test_unsuppressed_before_suppressed(self):
        active = _finding(severity=Severity.LOW, line_start=1)
        suppressed = _finding(severity=Severity.CRITICAL, line_start=2)
        pf = _parsed_file("src/app.py", [
            "x = 1",
            "api_key = 'real_secret'  # aiscan: suppress",
        ])
        result = merge([active, suppressed], [], [pf])
        assert result[0].suppressed is False
        assert result[1].suppressed is True

    def test_sorted_by_severity_descending(self):
        low = _finding(rule_id="AI-SEC-004", severity=Severity.LOW, line_start=1)
        critical = _finding(rule_id="AI-SEC-001", severity=Severity.CRITICAL, line_start=2)
        medium = _finding(rule_id="AI-SEC-003", severity=Severity.MEDIUM, line_start=3)
        result = merge([low, critical, medium], [])
        severities = [f.severity for f in result]
        assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]
