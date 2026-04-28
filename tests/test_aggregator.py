"""Tests for the aggregator module (merge, dedup, suppression)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock


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


_EXT_TO_LANG = {".py": "python", ".js": "javascript", ".jsx": "javascript",
                ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".java": "java"}


def _parsed_file(path: str, lines: list[str], language: str | None = None) -> ParsedFile:
    mock_tree = MagicMock()
    if language is None:
        language = _EXT_TO_LANG.get(Path(path).suffix, "python")
    return ParsedFile(
        path=Path(path),
        language=language,
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

    def test_duplicate_ast_findings_stay_ast(self):
        """Same-tier duplicates should not be labeled HYBRID."""
        f1 = _finding(detection_method=DetectionMethod.AST, confidence=0.8)
        f2 = _finding(detection_method=DetectionMethod.AST, confidence=0.9)
        result = merge([f1, f2], [])
        assert len(result) == 1
        assert result[0].detection_method == DetectionMethod.AST

    def test_duplicate_llm_findings_stay_llm(self):
        f1 = _finding(detection_method=DetectionMethod.LLM)
        f2 = _finding(detection_method=DetectionMethod.LLM)
        result = merge([], [f1, f2])
        assert len(result) == 1
        assert result[0].detection_method == DetectionMethod.LLM

    def test_three_way_merge_keeps_hybrid(self):
        """Two AST findings collide first, then an LLM finding lands on the
        same dedup key. The final detection_method must be HYBRID — the
        AST→AST collision must not strip the eventual cross-tier signal."""
        ast_a = _finding(severity=Severity.LOW, detection_method=DetectionMethod.AST)
        ast_b = _finding(severity=Severity.MEDIUM, detection_method=DetectionMethod.AST)
        llm = _finding(severity=Severity.HIGH, detection_method=DetectionMethod.LLM)
        result = merge([ast_a, ast_b], [llm])
        assert len(result) == 1
        assert result[0].detection_method == DetectionMethod.HYBRID
        assert result[0].severity == Severity.HIGH


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

    def test_js_line_comment_suppression(self):
        """// aiscan: suppress should work for JS/TS files."""
        f = _finding(file_path="src/app.js", line_start=1, line_end=1)
        pf = _parsed_file("src/app.js", [
            "const token = process.env.TOKEN; // aiscan: suppress env-sourced",
        ])
        result = merge([f], [], [pf])
        assert result[0].suppressed is True
        assert "env-sourced" in result[0].suppression_reason

    def test_js_block_comment_suppression(self):
        """/* aiscan: suppress */ block comments should also suppress."""
        f = _finding(file_path="src/app.ts", line_start=1, line_end=1)
        pf = _parsed_file("src/app.ts", [
            "const key = process.env.KEY; /* aiscan: suppress already-safe */",
        ])
        result = merge([f], [], [pf])
        assert result[0].suppressed is True
        assert "already-safe" in result[0].suppression_reason

    def test_js_suppression_without_reason(self):
        f = _finding(file_path="src/app.js", line_start=1, line_end=1)
        pf = _parsed_file("src/app.js", [
            "const k = v; // aiscan: suppress",
        ])
        result = merge([f], [], [pf])
        assert result[0].suppressed is True
        assert result[0].suppression_reason == ""

    def test_python_slash_comment_does_not_suppress(self):
        """// is not a Python comment; it's integer division. Must NOT suppress."""
        f = _finding(file_path="src/app.py", line_start=1, line_end=1)
        pf = _parsed_file("src/app.py", [
            "x = a // aiscan: suppress",  # integer division, not a comment
        ])
        result = merge([f], [], [pf])
        assert result[0].suppressed is False

    def test_js_hash_does_not_suppress(self):
        """# is not a JS/TS line comment; must NOT suppress in JS files."""
        f = _finding(file_path="src/app.js", line_start=1, line_end=1)
        pf = _parsed_file("src/app.js", [
            "const pattern = '# aiscan: suppress';",  # # inside a string
        ])
        result = merge([f], [], [pf])
        assert result[0].suppressed is False

    def test_typescript_line_comment_suppression(self):
        f = _finding(file_path="src/app.ts", line_start=1, line_end=1)
        pf = _parsed_file("src/app.ts", [
            "const x: string = y; // aiscan: suppress typed-already",
        ])
        result = merge([f], [], [pf])
        assert result[0].suppressed is True
        assert "typed-already" in result[0].suppression_reason

    def test_js_line_comment_allows_asterisk_in_reason(self):
        """// comments should allow any reason text, including asterisks."""
        f = _finding(file_path="src/app.js", line_start=1, line_end=1)
        pf = _parsed_file("src/app.js", [
            "const k = v; // aiscan: suppress has *star* in reason",
        ])
        result = merge([f], [], [pf])
        assert result[0].suppressed is True
        assert "*star*" in result[0].suppression_reason

    def test_unknown_language_skips_suppression_safely(self):
        """A language not in _SUPPRESS_BY_LANG should return findings, not crash."""
        f = _finding(file_path="src/app.rb", line_start=1, line_end=1)
        pf = _parsed_file("src/app.rb", [
            "# aiscan: suppress this works in ruby but rule is not wired",
        ], language="ruby")
        result = merge([f], [], [pf])
        assert len(result) == 1
        assert result[0].suppressed is False


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
