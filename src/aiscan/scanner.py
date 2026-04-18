"""Scanner orchestrator: coordinates AST layer, rule engine, LLM engine, and aggregator."""

from __future__ import annotations

import time
import uuid
import warnings
from datetime import datetime, timezone
from pathlib import Path

from aiscan.ast_layer import ASTLayer, ParsedFile
from aiscan.models import Finding, ScanResult
from aiscan.rule_engine import RuleEngine


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
        cache_dir: str = ".aiscan_cache",
    ) -> None:
        self.llm_enabled = llm_enabled
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.diff_only = diff_only

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
                cache_dir=cache_dir,
            )

    def _get_diff_files(self, target: Path) -> list[Path]:
        """Return only files changed in the current git diff (staged + unstaged)."""
        try:
            import git
            repo = git.Repo(target, search_parent_directories=True)
            repo_root = Path(repo.working_tree_dir)
            changed: set[Path] = set()
            # Staged changes
            for item in repo.index.diff("HEAD"):
                changed.add(repo_root / item.a_path)
            # Unstaged changes
            for item in repo.index.diff(None):
                changed.add(repo_root / item.a_path)
            # Untracked files
            for item in repo.untracked_files:
                changed.add(repo_root / item)
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
        timestamp = datetime.now(timezone.utc).isoformat()

        # Collect files
        if self.diff_only:
            files = self._get_diff_files(target)
        else:
            files = self._ast_layer.collect_files(target)

        # Parse all files
        parsed_files: list[ParsedFile] = []
        for f in files:
            parsed = self._ast_layer.parse_file(f)
            if parsed:
                parsed_files.append(parsed)

        # AST rule pass
        ast_findings: list[Finding] = []
        for pf in parsed_files:
            ast_findings.extend(self._rule_engine.run(pf))

        # LLM pass (optional)
        llm_findings: list[Finding] = []
        if self.llm_enabled and self._llm_engine:
            for pf in parsed_files:
                try:
                    llm_findings.extend(self._llm_engine.analyze(pf))
                except Exception as exc:
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
        )
