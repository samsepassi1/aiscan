"""Compute AI-vs-human attribution metrics for scan findings."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, UTC
from pathlib import Path

from pydantic import BaseModel, Field

from aiscan.attribution import Attribution, Origin, classify
from aiscan.blame import Blamer
from aiscan.models import Finding, SEVERITY_ORDER, Severity


class BucketStats(BaseModel):
    count: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_rule: dict[str, int] = Field(default_factory=dict)


class AnnotatedFinding(BaseModel):
    finding: Finding
    commit_sha: str | None = None
    attribution: Attribution


class MetricsResult(BaseModel):
    scan_id: str
    target_path: str
    timestamp: str
    total_findings: int
    buckets: dict[str, BucketStats]
    annotated: list[AnnotatedFinding]
    scan_duration_seconds: float
    blame_duration_seconds: float


def _empty_bucket() -> BucketStats:
    return BucketStats(
        count=0,
        by_severity={s.value: 0 for s in Severity},
        by_rule={},
    )


def _attribute_finding(finding: Finding, blamer: Blamer) -> AnnotatedFinding:
    sha = blamer.blame_sha(Path(finding.file_path), finding.line_start)
    if sha is None:
        return AnnotatedFinding(
            finding=finding,
            commit_sha=None,
            attribution=Attribution(origin=Origin.UNKNOWN, reason="uncommitted"),
        )
    info = blamer.commit_info(sha)
    if info is None:
        return AnnotatedFinding(
            finding=finding,
            commit_sha=sha,
            attribution=Attribution(origin=Origin.UNKNOWN, reason="blame-failed"),
        )
    return AnnotatedFinding(
        finding=finding,
        commit_sha=sha,
        attribution=classify(info),
    )


def compute_metrics(
    target: Path,
    *,
    diff_only: bool = False,
    exclude: tuple[str, ...] = (),
    min_severity: str = "LOW",
) -> MetricsResult:
    """Run a scan, attribute each finding to a commit, aggregate by origin."""
    # Import Scanner lazily so metrics users don't pay tree-sitter load
    # cost just to import the module.
    from aiscan.scanner import Scanner

    blamer = Blamer.for_target(target)

    scanner = Scanner(llm_enabled=False, diff_only=diff_only, exclude=exclude)
    scan_start = time.monotonic()
    scan_result = scanner.scan(target)
    scan_duration = time.monotonic() - scan_start

    min_level = SEVERITY_ORDER[min_severity]
    findings = [
        f for f in scan_result.findings
        if not f.suppressed and SEVERITY_ORDER[f.severity.value] >= min_level
    ]

    blame_start = time.monotonic()
    annotated = [_attribute_finding(f, blamer) for f in findings]
    blame_duration = time.monotonic() - blame_start

    buckets: dict[str, BucketStats] = {
        Origin.AI.value: _empty_bucket(),
        Origin.HUMAN.value: _empty_bucket(),
        Origin.UNKNOWN.value: _empty_bucket(),
    }
    for af in annotated:
        bucket = buckets[af.attribution.origin.value]
        bucket.count += 1
        bucket.by_severity[af.finding.severity.value] = (
            bucket.by_severity.get(af.finding.severity.value, 0) + 1
        )
        bucket.by_rule[af.finding.rule_id] = (
            bucket.by_rule.get(af.finding.rule_id, 0) + 1
        )

    return MetricsResult(
        scan_id=str(uuid.uuid4()),
        target_path=str(target),
        timestamp=datetime.now(UTC).isoformat(),
        total_findings=len(annotated),
        buckets=buckets,
        annotated=annotated,
        scan_duration_seconds=scan_duration,
        blame_duration_seconds=blame_duration,
    )
