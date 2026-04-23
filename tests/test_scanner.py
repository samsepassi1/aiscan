"""Integration tests for the Scanner orchestrator."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

from aiscan.scanner import Scanner
from aiscan.models import ScanResult


_SECRET_LINE = "password = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'\n"


def _git(cwd: Path, *args: str) -> None:
    """Run a git command in cwd, failing the test on non-zero exit.

    Inherits the parent env (so locale/PATH/etc. work on any CI) but
    overrides HOME to isolate from the user's global gitconfig and sets
    author/committer identity so `git commit` doesn't prompt.
    """
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "HOME": str(cwd),  # isolates from global ~/.gitconfig
        "GIT_CONFIG_GLOBAL": "/dev/null",  # belt & braces for newer git
        "GIT_CONFIG_SYSTEM": "/dev/null",
    })
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        env=env,
    )


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


class TestDiffOnlyRealGit:
    """Exercise Scanner._get_diff_files against a real (temp) git repo."""

    def test_detects_untracked_file(self, tmp_path: Path):
        _git(tmp_path, "init", "-q")
        (tmp_path / "new.py").write_text(_SECRET_LINE)
        scanner = Scanner(llm_enabled=False, diff_only=True)
        result = scanner.scan(tmp_path)
        assert any(f.rule_id == "AI-SEC-001" for f in result.findings), \
            "Untracked secret file should be in diff"

    def test_detects_staged_file(self, tmp_path: Path):
        _git(tmp_path, "init", "-q")
        # Commit an empty baseline so HEAD exists
        (tmp_path / "README.md").write_text("ok\n")
        _git(tmp_path, "add", "README.md")
        _git(tmp_path, "commit", "-q", "-m", "init")
        # Now add + stage a secret file
        (tmp_path / "staged.py").write_text(_SECRET_LINE)
        _git(tmp_path, "add", "staged.py")
        scanner = Scanner(llm_enabled=False, diff_only=True)
        result = scanner.scan(tmp_path)
        assert any(f.rule_id == "AI-SEC-001" for f in result.findings), \
            "Staged secret file should be in diff"

    def test_detects_modified_file(self, tmp_path: Path):
        _git(tmp_path, "init", "-q")
        (tmp_path / "app.py").write_text("x = 1\n")
        _git(tmp_path, "add", "app.py")
        _git(tmp_path, "commit", "-q", "-m", "baseline")
        # Modify with a secret (unstaged change)
        (tmp_path / "app.py").write_text(_SECRET_LINE)
        scanner = Scanner(llm_enabled=False, diff_only=True)
        result = scanner.scan(tmp_path)
        assert any(f.rule_id == "AI-SEC-001" for f in result.findings), \
            "Modified file with new secret should be in diff"

    def test_skips_unchanged_file(self, tmp_path: Path):
        _git(tmp_path, "init", "-q")
        # Commit a file containing a secret — it's in HEAD and unchanged
        (tmp_path / "committed.py").write_text(_SECRET_LINE)
        _git(tmp_path, "add", "committed.py")
        _git(tmp_path, "commit", "-q", "-m", "pre-existing secret")
        scanner = Scanner(llm_enabled=False, diff_only=True)
        result = scanner.scan(tmp_path)
        assert result.total_files_scanned == 0, \
            "No files should be scanned — nothing changed"
        assert all(f.rule_id != "AI-SEC-001" for f in result.findings)


class TestLLMScanAll:
    """Verify the --llm-scan-all gate switches between file-filtered and all-files modes."""

    def _prep_scanner_with_mock_llm(self, tmp_path: Path, scan_all: bool) -> tuple[Scanner, MagicMock]:
        scanner = Scanner(
            llm_enabled=True,
            llm_provider="anthropic",
            llm_api_key="dummy",
            llm_scan_all=scan_all,
            cache_dir=str(tmp_path / "cache"),
        )
        mock_llm = MagicMock()
        mock_llm.analyze.return_value = []
        scanner._llm_engine = mock_llm
        return scanner, mock_llm

    def test_scan_all_off_skips_clean_files(self, tmp_path: Path):
        """Without --llm-scan-all, LLM is not called on files that have no AST findings."""
        (tmp_path / "clean.py").write_text("x = 1\n")  # no secrets, no AST findings
        scanner, mock_llm = self._prep_scanner_with_mock_llm(tmp_path, scan_all=False)
        scanner.scan(tmp_path)
        assert mock_llm.analyze.call_count == 0

    def test_scan_all_on_runs_llm_on_clean_files(self, tmp_path: Path):
        """With --llm-scan-all, LLM IS called even on files with no AST findings."""
        (tmp_path / "clean.py").write_text("x = 1\n")
        scanner, mock_llm = self._prep_scanner_with_mock_llm(tmp_path, scan_all=True)
        scanner.scan(tmp_path)
        assert mock_llm.analyze.call_count == 1

    def test_scan_all_passes_empty_context_on_clean_file(self, tmp_path: Path):
        """When scan_all triggers analysis of a clean file, context_findings must be empty."""
        (tmp_path / "clean.py").write_text("x = 1\n")
        scanner, mock_llm = self._prep_scanner_with_mock_llm(tmp_path, scan_all=True)
        scanner.scan(tmp_path)
        _, kwargs = mock_llm.analyze.call_args
        assert kwargs["context_findings"] == []

    def test_scan_all_still_passes_ast_context_on_flagged_files(self, tmp_path: Path):
        """When file has AST findings, LLM still gets them as context regardless of scan_all."""
        (tmp_path / "secret.py").write_text(_SECRET_LINE)
        scanner, mock_llm = self._prep_scanner_with_mock_llm(tmp_path, scan_all=True)
        scanner.scan(tmp_path)
        # Last call should be for secret.py with findings
        calls_with_context = [
            c for c in mock_llm.analyze.call_args_list
            if c.kwargs.get("context_findings")
        ]
        assert len(calls_with_context) >= 1


class TestLLMMaxLines:
    def test_max_lines_passed_to_engine(self, tmp_path: Path):
        (tmp_path / "secret.py").write_text(_SECRET_LINE)
        scanner = Scanner(
            llm_enabled=True,
            llm_provider="anthropic",
            llm_api_key="dummy",
            llm_max_lines=42,
            cache_dir=str(tmp_path / "cache"),
        )
        mock_llm = MagicMock()
        mock_llm.analyze.return_value = []
        scanner._llm_engine = mock_llm
        scanner.scan(tmp_path)
        _, kwargs = mock_llm.analyze.call_args
        assert kwargs["max_lines"] == 42


class TestCacheDirDefault:
    def test_default_cache_dir_is_platform_user_cache(self):
        """Without explicit cache_dir the Scanner uses platformdirs.user_cache_dir('aiscan')."""
        from aiscan.scanner import default_cache_dir
        from platformdirs import user_cache_dir
        assert default_cache_dir() == user_cache_dir("aiscan")

    def test_explicit_cache_dir_overrides_default(self, tmp_path: Path):
        custom = tmp_path / "custom_cache"
        Scanner(
            llm_enabled=True,
            llm_provider="anthropic",
            llm_api_key="dummy",
            cache_dir=str(custom),
        )
        # The engine's cache is constructed with the custom dir; verify the
        # DiskCache was pointed at our custom path (diskcache makes the dir).
        assert custom.exists()
