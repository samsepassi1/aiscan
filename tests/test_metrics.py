"""Tests for `aiscan metrics` — AI-vs-human finding attribution."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from aiscan.attribution import AI_AGENTS, CommitInfo, Origin, classify
from aiscan.blame import BlameError, Blamer, _parse_trailers
from aiscan.cli import main
from aiscan.metrics import compute_metrics


_VULN_LINE = "password = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'\n"


def _git(cwd: Path, *args: str, extra_env: dict[str, str] | None = None) -> None:
    """Run a git command in cwd with isolated config — mirrors test_scanner._git."""
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "HOME": str(cwd),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    })
    if extra_env:
        env.update(extra_env)
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        env=env,
    )


def _init_repo(root: Path) -> None:
    _git(root, "init", "-q", "-b", "main")


def _commit_file(
    root: Path,
    relpath: str,
    content: str,
    message: str,
    *,
    author_email: str = "test@example.com",
    author_name: str = "test",
) -> None:
    (root / relpath).parent.mkdir(parents=True, exist_ok=True)
    (root / relpath).write_text(content)
    _git(root, "add", relpath)
    _git(
        root,
        "commit",
        "-q",
        "-m",
        message,
        extra_env={"GIT_AUTHOR_EMAIL": author_email, "GIT_AUTHOR_NAME": author_name},
    )


# ---------- pure classification tests (no git) ----------


class TestClassify:
    def _base(self, **overrides):
        defaults = dict(
            sha="abc123",
            author_name="Human",
            author_email="human@example.com",
            message="refactor: cleanup",
            trailers=[],
        )
        defaults.update(overrides)
        return CommitInfo(**defaults)

    def test_trailer_claude(self):
        c = self._base(
            message="fix\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
            trailers=[("Co-Authored-By", "Claude <noreply@anthropic.com>")],
        )
        a = classify(c)
        assert a.origin == Origin.AI
        assert a.reason == "trailer:claude"
        assert a.matched_agent == "claude"

    @pytest.mark.parametrize("agent", list(AI_AGENTS.keys()))
    def test_trailer_each_agent(self, agent):
        c = self._base(trailers=[("Co-Authored-By", f"{agent} <bot@example.com>")])
        a = classify(c)
        assert a.origin == Origin.AI
        assert a.matched_agent == agent

    def test_body_claude_code(self):
        c = self._base(message="feat: x\n\n\U0001F916 Generated with [Claude Code]")
        a = classify(c)
        assert a.origin == Origin.AI
        assert a.reason == "body:claude"

    def test_email_copilot(self):
        c = self._base(author_email="bot@copilot.github.com")
        a = classify(c)
        assert a.origin == Origin.AI
        assert a.reason == "email:copilot"

    def test_human_no_signal(self):
        c = self._base(trailers=[("Signed-off-by", "Sam <sam@example.com>")])
        a = classify(c)
        assert a.origin == Origin.HUMAN
        assert a.reason == "no-signal"

    def test_uncommitted_sentinel(self):
        c = self._base(sha="")
        a = classify(c)
        assert a.origin == Origin.UNKNOWN
        assert a.reason == "uncommitted"

    def test_non_coauthor_trailer_is_not_ai(self):
        # Signed-off-by containing "claude" should not trip — trailer-name gate
        # restricts to Co-Authored-By.
        c = self._base(trailers=[("Signed-off-by", "Claude Tester <c@example.com>")])
        a = classify(c)
        assert a.origin == Origin.HUMAN

    def test_gemini_email_not_matched(self):
        # Gemini has no email signature — a Google employee commit must not
        # be classified as AI.
        c = self._base(author_email="engineer@google.com")
        a = classify(c)
        assert a.origin == Origin.HUMAN


class TestTrailerParser:
    def test_multiple_trailers(self):
        msg = "fix: x\n\nbody\n\nCo-Authored-By: Claude <c@a.com>\nSigned-off-by: Sam <s@e.com>"
        t = _parse_trailers(msg)
        assert ("Co-Authored-By", "Claude <c@a.com>") in t
        assert ("Signed-off-by", "Sam <s@e.com>") in t

    def test_no_trailers(self):
        assert _parse_trailers("fix: just a subject") == []


# ---------- end-to-end with real git repos ----------


class TestComputeMetrics:
    def test_mixed_origin_repo(self, tmp_path: Path):
        _init_repo(tmp_path)
        # AI commit via trailer
        _commit_file(
            tmp_path,
            "a.py",
            _VULN_LINE,
            "feat: a\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        )
        # Human commit
        _commit_file(tmp_path, "b.py", _VULN_LINE, "feat: b")
        # AI via body pattern
        _commit_file(
            tmp_path,
            "c.py",
            _VULN_LINE,
            "feat: c\n\n\U0001F916 Generated with [Claude Code]",
        )
        result = compute_metrics(tmp_path, min_severity="LOW")
        assert result.buckets["ai"].count == 2
        assert result.buckets["human"].count == 1
        assert result.buckets["unknown"].count == 0

    def test_severity_and_rule_breakdown(self, tmp_path: Path):
        _init_repo(tmp_path)
        _commit_file(
            tmp_path,
            "a.py",
            _VULN_LINE,
            "feat: a\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        )
        result = compute_metrics(tmp_path, min_severity="LOW")
        ai = result.buckets["ai"]
        assert ai.count >= 1
        # Hardcoded-secret rule is CRITICAL
        assert ai.by_severity.get("CRITICAL", 0) >= 1
        assert ai.by_rule.get("AI-SEC-001", 0) >= 1

    def test_metrics_from_subdir_still_attributes(self, tmp_path: Path, monkeypatch):
        # Regression: running `aiscan metrics .` from a subdirectory used
        # to drop every finding into the `unknown` bucket because the
        # Scanner recorded paths relative to the user's cwd while git
        # blame ran from the repo root. Blamer now captures the invocation
        # cwd and resolves relative finding paths against it.
        _init_repo(tmp_path)
        (tmp_path / "sub").mkdir()
        _commit_file(tmp_path, "sub/a.py", _VULN_LINE, "feat: a")

        monkeypatch.chdir(tmp_path / "sub")
        result = compute_metrics(Path("."), min_severity="LOW")

        assert result.buckets["human"].count >= 1, (
            f"expected findings attributed to human; got buckets "
            f"{ {k: v.count for k, v in result.buckets.items()} }"
        )
        # And the inverse: no finding should land in unknown/uncommitted
        # just because we ran from a subdir.
        uncommitted = [
            af for af in result.annotated
            if af.attribution.origin == Origin.UNKNOWN
            and af.attribution.reason == "uncommitted"
        ]
        assert not uncommitted, f"subdir invocation leaked findings into uncommitted: {uncommitted}"

    def test_uncommitted_line_is_unknown(self, tmp_path: Path):
        _init_repo(tmp_path)
        # Seed the repo with a baseline so HEAD exists.
        _commit_file(tmp_path, "README.md", "baseline\n", "chore: init")
        # Write a vulnerable file but do NOT commit it.
        (tmp_path / "a.py").write_text(_VULN_LINE)
        result = compute_metrics(tmp_path, min_severity="LOW")
        assert result.buckets["unknown"].count >= 1
        unknown_reasons = {af.attribution.reason for af in result.annotated if af.attribution.origin == Origin.UNKNOWN}
        assert "uncommitted" in unknown_reasons

    def test_blame_cache_avoids_duplicate_subprocess(self, tmp_path: Path):
        _init_repo(tmp_path)
        _commit_file(tmp_path, "a.py", _VULN_LINE, "feat: a")
        blamer = Blamer.for_target(tmp_path)
        with patch("aiscan.blame.subprocess.run", wraps=subprocess.run) as spy:
            sha1 = blamer.blame_sha(tmp_path / "a.py", 1)
            sha2 = blamer.blame_sha(tmp_path / "a.py", 1)
        assert sha1 == sha2 and sha1 is not None
        # Only one blame invocation should reach subprocess
        blame_calls = [c for c in spy.call_args_list if "blame" in c.args[0]]
        assert len(blame_calls) == 1

    def test_commit_info_cache(self, tmp_path: Path):
        _init_repo(tmp_path)
        _commit_file(tmp_path, "a.py", _VULN_LINE, "feat: a")
        blamer = Blamer.for_target(tmp_path)
        sha = blamer.blame_sha(tmp_path / "a.py", 1)
        assert sha is not None
        with patch("aiscan.blame.subprocess.run", wraps=subprocess.run) as spy:
            info1 = blamer.commit_info(sha)
            info2 = blamer.commit_info(sha)
        assert info1 is not None and info2 is not None
        log_calls = [c for c in spy.call_args_list if "log" in c.args[0]]
        assert len(log_calls) == 1


# ---------- CLI integration ----------


class TestMetricsCLI:
    def test_non_git_dir_errors_clearly(self, tmp_path: Path):
        runner = CliRunner()
        # tmp_path has no .git; HOME override blocks climbing to user's home.
        env = {"HOME": str(tmp_path), "GIT_CEILING_DIRECTORIES": str(tmp_path)}
        result = runner.invoke(main, ["metrics", str(tmp_path)], env=env)
        assert result.exit_code != 0
        # CliRunner merges stderr into output by default (mix_stderr=True).
        assert "not inside a git repository" in result.output

    def test_terminal_format_runs(self, tmp_path: Path):
        _init_repo(tmp_path)
        _commit_file(
            tmp_path,
            "a.py",
            _VULN_LINE,
            "feat: a\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["metrics", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert "Findings by origin" in result.output
        assert "AI" in result.output

    def test_json_format(self, tmp_path: Path):
        _init_repo(tmp_path)
        _commit_file(tmp_path, "a.py", _VULN_LINE, "feat: a")
        runner = CliRunner()
        result = runner.invoke(main, ["metrics", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0, result.output
        import json
        data = json.loads(result.output)
        assert "buckets" in data
        assert set(data["buckets"].keys()) == {"ai", "human", "unknown"}

    def test_output_flag_writes_file_without_explicit_format(self, tmp_path: Path):
        # Regression: `--output X` with the default terminal format used to
        # print to screen while claiming "Metrics written to X" without
        # actually writing anything. It must now produce JSON at X.
        _init_repo(tmp_path)
        _commit_file(tmp_path, "a.py", _VULN_LINE, "feat: a")
        out_path = tmp_path / "m.json"
        runner = CliRunner()
        result = runner.invoke(main, ["metrics", str(tmp_path), "--output", str(out_path)])
        assert result.exit_code == 0, result.output
        assert out_path.exists(), "expected --output path to be written"
        import json
        data = json.loads(out_path.read_text())
        assert "buckets" in data


class TestBlamerBoundaries:
    def test_for_target_raises_on_non_git(self, tmp_path: Path):
        # Use GIT_CEILING_DIRECTORIES to prevent git from climbing into the
        # user's real repo chain when run under pytest.
        with patch.dict(
            os.environ,
            {"GIT_CEILING_DIRECTORIES": str(tmp_path), "HOME": str(tmp_path)},
        ):
            with pytest.raises(BlameError):
                Blamer.for_target(tmp_path)
