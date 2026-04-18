"""Integration tests for the Scanner orchestrator."""

from __future__ import annotations

from pathlib import Path

import pytest

from aiscan.scanner import Scanner
from aiscan.models import ScanResult


class TestScannerIntegration:
    def test_scan_returns_scan_result(self, vulnerable_dir: Path):
        scanner = Scanner(llm_enabled=False)
        result = scanner.scan(vulnerable_dir)
        assert isinstance(result, ScanResult)
        assert result.scan_id
        assert result.total_files_scanned >= 1
        assert isinstance(result.findings, list)
        assert result.duration_seconds > 0

    def test_scan_finds_vulnerabilities(self, vulnerable_dir: Path):
        scanner = Scanner(llm_enabled=False)
        result = scanner.scan(vulnerable_dir)
        assert result.finding_count > 0

    def test_scan_single_file(self, vulnerable_dir: Path):
        scanner = Scanner(llm_enabled=False)
        result = scanner.scan(vulnerable_dir / "secrets_test.py")
        assert result.total_files_scanned == 1
        rule_ids = [f.rule_id for f in result.findings]
        assert "AI-SEC-001" in rule_ids

    def test_scan_empty_directory(self, tmp_path: Path):
        scanner = Scanner(llm_enabled=False)
        result = scanner.scan(tmp_path)
        assert result.total_files_scanned == 0
        assert result.findings == []

    def test_scan_llm_disabled_metadata(self, vulnerable_dir: Path):
        scanner = Scanner(llm_enabled=False)
        result = scanner.scan(vulnerable_dir)
        assert result.llm_enabled is False
        assert result.llm_provider is None
        assert result.llm_model is None

    def test_scan_finding_count_excludes_suppressed(self, tmp_path: Path):
        src = tmp_path / "app.py"
        src.write_text(
            "api_key = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'  # aiscan: suppress\n"
            "password = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'\n"
        )
        scanner = Scanner(llm_enabled=False)
        result = scanner.scan(src)
        assert result.finding_count < len(result.findings)

    def test_diff_only_falls_back_on_non_git_dir(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("password = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'\n")
        scanner = Scanner(llm_enabled=False, diff_only=True)
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = scanner.scan(tmp_path)
        assert isinstance(result, ScanResult)
        assert any("diff-only" in str(warning.message) for warning in w)
