"""Scanner orchestrator: coordinates AST layer, rule engine, LLM engine, and aggregator."""

from __future__ import annotations

import time
import uuid
import warnings
from datetime import datetime, UTC
from pathlib import Path

from platformdirs import user_cache_dir

from aiscan.ast_layer import ASTLayer, ParsedFile
from aiscan.models import Finding, ScanResult
from aiscan.rule_engine import RuleEngine


def default_cache_dir() -> str:
    """Platform-appropriate cache directory for aiscan (user-level)."""
    return user_cache_dir("aiscan")


class Scanner:
    """
    Top-level scan orchestrator.

    Usage:
        scanner = Scanner(llm_enabled=True, llm_provider="anthropic", llm_model="claude-sonnet-4-6")
        result = scanner.scan(Path("."))
    """

    def __init__(
        self,
        llm_enabled: bool = False,
        llm_provider: str = "anthropic",
        llm_model: str = "claude-sonnet-4-6",
        llm_api_key: str | None = None,
        llm_base_url: str | None = None,
        diff_only: bool = False,
        exclude: tuple[str, ...] = (),
        llm_scan_all: bool = False,
        llm_max_lines: int = 500,
        llm_timeout: float = 60.0,
        cache_dir: str | None = None,
    ) -> None:
        self.llm_enabled = llm_enabled
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.diff_only = diff_only
        self.exclude = exclude
        self.llm_scan_all = llm_scan_all
        self.llm_max_lines = llm_max_lines

        self._ast_layer = ASTLayer()
        self._rule_engine = RuleEngine()
        self._llm_engine = None

        if llm_enabled:
            from aiscan.llm_engine import LLMEngine
            self._llm_engine = LLMEngine(
                provider=llm_provider,
                model=llm_model,
                api_key=llm_api_key,
                base_url=llm_base_url,
                cache_dir=cache_dir or default_cache_dir(),
                timeout=llm_timeout,
            )

    def _get_diff_files(self, target: Path) -> list[Path]:
        """Return only files changed in the current git diff (staged + unstaged)."""
        try:
            import git
        except ImportError as exc:
            # Distinguish a packaging problem (gitpython missing despite being
            # in install_requires) from real git-state failures so the message
            # points at the actual cause.
            warnings.warn(
                f"aiscan: --diff-only requires the 'gitpython' package which "
                f"failed to import ({exc}); falling back to full scan.",
                stacklevel=2,
            )
            return self._ast_layer.collect_files(target)
        try:
            repo = git.Repo(target, search_parent_directories=True)
            if repo.working_tree_dir is None:
                raise RuntimeError("bare repository has no working tree")
            repo_root = Path(repo.working_tree_dir)
            changed: set[Path] = set()
            # Staged changes — skipped cleanly if repo has no HEAD yet (fresh init)
            try:
                has_head = repo.head.is_valid()
            except Exception:
                has_head = False
            if has_head:
                for diff_item in repo.index.diff("HEAD"):
                    if diff_item.a_path:
                        changed.add(repo_root / diff_item.a_path)
            # Unstaged changes
            for diff_item in repo.index.diff(None):
                if diff_item.a_path:
                    changed.add(repo_root / diff_item.a_path)
            # Untracked files
            for untracked in repo.untracked_files:
                changed.add(repo_root / untracked)
            return [p for p in changed if p.exists()]
        except Exception as exc:
            warnings.warn(
                f"aiscan: --diff-only failed to read git state ({exc}); falling back to full scan.",
                stacklevel=2,
            )
            return self._ast_layer.collect_files(target)

    def scan(self, target: Path) -> ScanResult:
        """Run a full scan on target (file or directory)."""
        start = time.monotonic()
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now(UTC).isoformat()
        scan_errors = 0

        # Collect files
        if self.diff_only:
            files = self._get_diff_files(target)
        else:
            files = self._ast_layer.collect_files(target)

        # Apply exclude prefixes
        if self.exclude:
            target_abs = target.resolve()
            # Warn upfront for any --exclude path that doesn't exist under the
            # target. A typo otherwise excludes nothing and the user never
            # finds out. Use the same .resolve() shape as _is_excluded so
            # symlinks and "../sibling" forms behave consistently.
            for ex in self.exclude:
                if not (target_abs / ex).resolve().exists():
                    warnings.warn(
                        f"aiscan: --exclude {ex!r} does not exist under "
                        f"{target}; nothing to exclude.",
                        stacklevel=2,
                    )

            def _is_excluded(p: Path) -> bool:
                p_abs = p.resolve()
                for ex in self.exclude:
                    ex_abs = (target_abs / ex).resolve()
                    try:
                        p_abs.relative_to(ex_abs)
                        return True
                    except ValueError:
                        pass
                return False
            files = [f for f in files if not _is_excluded(f)]

        # Parse all files. Read errors are counted into scan_errors so
        # SARIF executionSuccessful reflects an incomplete scan instead of
        # silently dropping unreadable files.
        parsed_files: list[ParsedFile] = []
        for f in files:
            try:
                parsed = self._ast_layer.parse_file(f)
            except OSError as exc:
                scan_errors += 1
                warnings.warn(
                    f"aiscan: failed to read {f} ({exc}); skipping file.",
                    stacklevel=2,
                )
                continue
            if parsed:
                parsed_files.append(parsed)

        # AST rule pass
        ast_findings: list[Finding] = []
        for pf in parsed_files:
            new_findings, rule_errors = self._rule_engine.run_with_errors(pf)
            ast_findings.extend(new_findings)
            scan_errors += rule_errors

        # LLM pass (optional) — only on files that AST already flagged
        llm_findings: list[Finding] = []
        if self.llm_enabled and self._llm_engine:
            ast_by_file: dict[str, list[Finding]] = {}
            for af in ast_findings:
                ast_by_file.setdefault(af.file_path, []).append(af)
            for pf in parsed_files:
                file_ast = ast_by_file.get(str(pf.path))
                if not file_ast and not self.llm_scan_all:
                    continue
                try:
                    llm_findings.extend(
                        self._llm_engine.analyze(
                            pf,
                            max_lines=self.llm_max_lines,
                            context_findings=file_ast or [],
                        )
                    )
                except Exception as exc:
                    scan_errors += 1
                    warnings.warn(
                        f"aiscan: LLM analysis failed for {pf.path} ({exc}); skipping file.",
                        stacklevel=2,
                    )

        # Merge and deduplicate
        from aiscan import aggregator
        all_findings = aggregator.merge(ast_findings, llm_findings, parsed_files)

        duration = time.monotonic() - start

        return ScanResult(
            scan_id=scan_id,
            target_path=str(target),
            timestamp=timestamp,
            total_files_scanned=len(parsed_files),
            findings=all_findings,
            duration_seconds=round(duration, 3),
            llm_enabled=self.llm_enabled,
            llm_provider=self.llm_provider if self.llm_enabled else None,
            llm_model=self.llm_model if self.llm_enabled else None,
            scan_errors=scan_errors,
        )
