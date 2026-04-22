"""Aggregator: merges AST and LLM findings, deduplicates, and applies suppressions."""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.models import DetectionMethod, Finding, SEVERITY_ORDER


# Per-language suppression comment patterns. Using a Python-style `#` in a JS
# file (or `//` in a Python file) should NOT suppress findings — `#` is not a
# comment in JS and `//` is integer division in Python.
_SUPPRESS_PY = re.compile(r"#\s*aiscan:\s*suppress(?:\s+(.*))?$", re.IGNORECASE)
# Two branches: `//` line-comment (any reason) and `/* */` block-comment
# (reason must not contain `*` so it doesn't eat into the terminator).
_SUPPRESS_CLIKE = re.compile(
    r"(?:"
    r"//\s*aiscan:\s*suppress(?:\s+(?P<line_reason>.*))?"
    r"|"
    r"/\*\s*aiscan:\s*suppress(?:\s+(?P<block_reason>[^*]*?))?\s*\*/"
    r")\s*$",
    re.IGNORECASE,
)
_SUPPRESS_BY_LANG: dict[str, re.Pattern[str]] = {
    "python": _SUPPRESS_PY,
    "javascript": _SUPPRESS_CLIKE,
    "typescript": _SUPPRESS_CLIKE,
    "go": _SUPPRESS_CLIKE,
    "java": _SUPPRESS_CLIKE,
}


def _dedup_key(finding: Finding) -> tuple:
    """Canonical key for deduplication: (rule_id, file_path, line_start)."""
    return (finding.rule_id, finding.file_path, finding.line_start)


def _extract_reason(m: re.Match[str]) -> str:
    """Extract the optional reason from a suppression-comment match.

    Handles both the Python pattern (unnamed group 1) and the C-like pattern
    (named `line_reason` and `block_reason` groups — exactly one populated).
    """
    groups = m.groupdict()
    if groups:
        reason = groups.get("line_reason") or groups.get("block_reason")
    else:
        reason = m.group(1) if m.lastindex else None
    return (reason or "").strip()


def merge(
    ast_findings: list[Finding],
    llm_findings: list[Finding],
    parsed_files: list[ParsedFile] | None = None,
) -> list[Finding]:
    """
    Merge AST and LLM findings:
    1. For duplicate (rule_id, file, line), keep the higher-severity finding
       and mark detection_method as HYBRID.
    2. Apply # aiscan: suppress inline suppression comments.
    3. Return deduplicated, suppression-aware findings sorted by severity desc.
    """
    # Build suppression index: file_path -> set of suppressed line numbers
    suppression_index: dict[str, set[int]] = {}
    suppression_reasons: dict[tuple[str, int], str] = {}
    if parsed_files:
        for pf in parsed_files:
            pattern = _SUPPRESS_BY_LANG.get(pf.language)
            if pattern is None:
                continue  # language without known comment syntax — skip
            key = str(pf.path)
            suppression_index[key] = set()
            for line_no, line in enumerate(pf.lines, start=1):
                m = pattern.search(line)
                if m:
                    suppression_index[key].add(line_no)
                    # Python pattern: group 1. CLIKE pattern: named groups.
                    reason = _extract_reason(m)
                    suppression_reasons[(key, line_no)] = reason

    merged: dict[tuple, Finding] = {}

    for finding in ast_findings + llm_findings:
        dedup_key = _dedup_key(finding)
        if dedup_key not in merged:
            merged[dedup_key] = finding
            continue
        existing = merged[dedup_key]
        winner = (
            finding
            if SEVERITY_ORDER[finding.severity.value] > SEVERITY_ORDER[existing.severity.value]
            else existing
        )
        # Only mark HYBRID when the two findings came from different detection tiers
        if existing.detection_method != finding.detection_method:
            merged[dedup_key] = winner.model_copy(update={"detection_method": DetectionMethod.HYBRID})
        else:
            merged[dedup_key] = winner

    # Apply suppressions
    result: list[Finding] = []
    for finding in merged.values():
        file_suppressions = suppression_index.get(finding.file_path, set())
        if finding.line_start in file_suppressions or finding.line_end in file_suppressions:
            reason = suppression_reasons.get(
                (finding.file_path, finding.line_start),
                suppression_reasons.get((finding.file_path, finding.line_end), "inline suppression"),
            )
            result.append(finding.model_copy(update={
                "suppressed": True,
                "suppression_reason": reason,
            }))
        else:
            result.append(finding)

    # Sort: unsuppressed first, then by severity desc, then by file/line
    result.sort(key=lambda f: (
        f.suppressed,
        -SEVERITY_ORDER[f.severity.value],
        f.file_path,
        f.line_start,
    ))
    return result
