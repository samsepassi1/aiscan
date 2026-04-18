"""Tests for the reporter module (SARIF, JSON, terminal output)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from io import StringIO

import pytest

from aiscan.models import DetectionMethod, Finding, ScanResult, Severity
from aiscan.reporter import generate_sarif, write_json, write_sarif, write_terminal
from rich.console import Console


def make_sample_result() -> ScanResult:
    findings = [
        Finding(
            rule_id="AI-SEC-001",
            rule_name="Hardcoded Secret",
            severity=Severity.CRITICAL,
            file_path="src/app.py",
            line_start=10,
            line_end=10,
            message="Hardcoded API key detected.",
            cwe_ids=["CWE-259"],
            detection_method=DetectionMethod.AST,
            confidence=0.9,
            remediation="Move to environment variable.",
            code_snippet="API_KEY = 'abc123...'",
        ),
        Finding(
            rule_id="AI-SEC-003",
            rule_name="Weak Crypto",
            severity=Severity.HIGH,
            file_path="src/utils.py",
            line_start=25,
            line_end=25,
            message="MD5 used for hashing.",
            cwe_ids=["CWE-327"],
            detection_method=DetectionMethod.AST,
            confidence=0.95,
            remediation="Use SHA-256.",
        ),
    ]
    return ScanResult(
        scan_id="test-scan-001",
        target_path="src/",
        timestamp=datetime.now(timezone.utc).isoformat(),
        total_files_scanned=5,
        findings=findings,
        duration_seconds=1.23,
        llm_enabled=False,
    )


class TestSARIFOutput:
    def test_sarif_schema_version(self):
        result = make_sample_result()
        sarif = generate_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert "sarif-schema-2.1.0.json" in sarif["$schema"]

    def test_sarif_has_runs(self):
        result = make_sample_result()
        sarif = generate_sarif(result)
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "aiscan"

    def test_sarif_results_count(self):
        result = make_sample_result()
        sarif = generate_sarif(result)
        assert len(sarif["runs"][0]["results"]) == 2

    def test_sarif_severity_mapping(self):
        result = make_sample_result()
        sarif = generate_sarif(result)
        results = sarif["runs"][0]["results"]
        critical_result = next(r for r in results if r["ruleId"] == "AI-SEC-001")
        assert critical_result["level"] == "error"

    def test_sarif_physical_location(self):
        result = make_sample_result()
        sarif = generate_sarif(result)
        result_obj = sarif["runs"][0]["results"][0]
        loc = result_obj["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "region" in loc
        assert loc["region"]["startLine"] >= 1

    def test_sarif_rules_array(self):
        result = make_sample_result()
        sarif = generate_sarif(result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "AI-SEC-001" in rule_ids
        assert "AI-SEC-003" in rule_ids

    def test_write_sarif_to_string(self):
        result = make_sample_result()
        out = StringIO()
        sarif_str = write_sarif(result, output=out)
        parsed = json.loads(sarif_str)
        assert parsed["version"] == "2.1.0"


class TestJSONOutput:
    def test_write_json_is_valid(self):
        result = make_sample_result()
        json_str = write_json(result)
        data = json.loads(json_str)
        assert data["scan_id"] == "test-scan-001"
        assert len(data["findings"]) == 2

    def test_write_json_to_file(self, tmp_path):
        result = make_sample_result()
        output_path = tmp_path / "results.json"
        write_json(result, path=output_path)
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["total_files_scanned"] == 5


class TestTerminalOutput:
    def test_terminal_does_not_raise(self):
        result = make_sample_result()
        console = Console(file=StringIO(), force_terminal=False)
        write_terminal(result, console=console)

    def test_terminal_no_findings(self):
        result = make_sample_result()
        result.findings = []
        console = Console(file=StringIO(), force_terminal=False)
        write_terminal(result, console=console)

    def test_terminal_with_suppressed(self):
        result = make_sample_result()
        result.findings[0] = result.findings[0].model_copy(update={
            "suppressed": True,
            "suppression_reason": "test suppression",
        })
        console = Console(file=StringIO(), force_terminal=False)
        write_terminal(result, console=console)
