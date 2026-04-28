"""Reporter: SARIF 2.1.0, JSON, and Rich terminal table output."""

from __future__ import annotations

import json
from importlib.metadata import version as pkg_version, PackageNotFoundError
from pathlib import Path
from typing import Any, TextIO

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from aiscan.metrics import MetricsResult
from aiscan.models import Finding, ScanResult, Severity


# SARIF severity mapping
SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

# Rich terminal color mapping
SEVERITY_TO_RICH_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def _tool_version() -> str:
    try:
        return pkg_version("aiscan")
    except PackageNotFoundError:
        return "unknown"


def generate_sarif(result: ScanResult) -> dict:
    """Generate a SARIF 2.1.0 document from a ScanResult."""
    # Collect unique rules referenced by findings
    rules_seen: dict[str, Finding] = {}
    for f in result.findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = f

    sarif_rules = []
    for rule_id, finding in rules_seen.items():
        sarif_rules.append({
            "id": rule_id,
            "name": finding.rule_name,
            "shortDescription": {"text": finding.rule_name},
            "fullDescription": {"text": finding.message},
            "properties": {
                "cwe": finding.cwe_ids,
                "severity": finding.severity.value,
            },
        })

    sarif_results = []
    for f in result.findings:
        sarif_result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": SEVERITY_TO_SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line_start,
                            "endLine": f.line_end,
                            "startColumn": f.column_start + 1 if f.column_start else 1,
                            "endColumn": f.column_end + 1 if f.column_end else 1,
                        },
                    }
                }
            ],
            "properties": {
                "confidence": f.confidence,
                "cwe": f.cwe_ids,
                "detectionMethod": f.detection_method.value,
                "remediation": f.remediation,
                "suppressed": f.suppressed,
            },
        }
        if f.code_snippet:
            sarif_result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.code_snippet
            }
        sarif_results.append(sarif_result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aiscan",
                        "version": _tool_version(),
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": result.scan_errors == 0,
                        "commandLine": f"aiscan scan {result.target_path}",
                        "startTimeUtc": result.timestamp,
                    }
                ],
            }
        ],
    }


def write_sarif(result: ScanResult, output: TextIO | None = None, path: Path | None = None) -> str:
    """Serialize a ScanResult to a SARIF 2.1.0 JSON string and optionally write to file."""
    sarif_doc = generate_sarif(result)
    sarif_json = json.dumps(sarif_doc, indent=2)
    if path:
        path.write_text(sarif_json)
    elif output:
        output.write(sarif_json)
    return sarif_json


def write_json(result: ScanResult, output: TextIO | None = None, path: Path | None = None) -> str:
    """Serialize a ScanResult to JSON using Pydantic's serializer."""
    json_str = result.model_dump_json(indent=2)
    if path:
        path.write_text(json_str)
    elif output:
        output.write(json_str)
    return json_str


def write_terminal(result: ScanResult, console: Console | None = None) -> None:
    """Print a Rich formatted table of findings to the terminal."""
    con = console or Console()

    # Summary header
    active = [f for f in result.findings if not f.suppressed]
    suppressed = [f for f in result.findings if f.suppressed]

    con.print()
    con.rule("[bold]aiscan[/bold] — scan complete")
    con.print(
        f"  Target: [bold]{result.target_path}[/bold]  |  "
        f"Files: {result.total_files_scanned}  |  "
        f"Duration: {result.duration_seconds:.2f}s  |  "
        f"LLM: {'[green]enabled[/green]' if result.llm_enabled else '[dim]disabled[/dim]'}"
    )
    con.print()

    # An empty file count is almost always a misconfiguration, not a clean
    # bill of health (target path wrong, every file ignored by .aiscanignore,
    # or no files in supported extensions). Distinguish loudly.
    if result.total_files_scanned == 0:
        con.print(
            "[bold yellow]No scannable files found under target.[/bold yellow]"
        )
        con.print(
            "[dim]Supported extensions: .py, .js, .jsx, .ts, .tsx, .go, .java. "
            "Check the target path, .aiscanignore, and --exclude flags.[/dim]"
        )
        con.print()
        return

    if not active:
        con.print("[bold green]No findings — clean scan.[/bold green]")
        if suppressed:
            con.print(f"[dim]{len(suppressed)} finding(s) suppressed by inline comments.[/dim]")
        con.print()
        return

    # Findings table
    table = Table(
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        expand=False,
        title=f"{len(active)} Finding(s)",
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule ID", width=14)
    table.add_column("File", overflow="fold")
    table.add_column("Line", width=6, justify="right")
    table.add_column("Message", overflow="fold")
    table.add_column("CWE", width=14)

    for f in active:
        style = SEVERITY_TO_RICH_STYLE[f.severity]
        table.add_row(
            Text(f.severity.value, style=style),
            f.rule_id,
            f.file_path,
            str(f.line_start),
            f.message[:120] + ("…" if len(f.message) > 120 else ""),
            ", ".join(f.cwe_ids[:2]),
        )

    con.print(table)

    # Severity summary
    by_sev = result.findings_by_severity
    parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = len(by_sev[sev.value])
        if count:
            style = SEVERITY_TO_RICH_STYLE[sev]
            parts.append(f"[{style}]{count} {sev.value}[/{style}]")
    con.print("  " + "  ".join(parts))

    if suppressed:
        con.print(f"  [dim]{len(suppressed)} finding(s) suppressed[/dim]")
    con.print()


# Display style for each attribution origin.
_ORIGIN_STYLE = {
    "ai": "magenta",
    "human": "cyan",
    "unknown": "dim",
}


def write_metrics_terminal(result: MetricsResult, console: Console | None = None) -> None:
    """Print an AI-vs-human finding-attribution report to the terminal."""
    con = console or Console()

    con.print()
    con.rule("[bold]aiscan[/bold] — metrics")
    con.print(
        f"  Target: [bold]{result.target_path}[/bold]  |  "
        f"Findings: {result.total_findings}  |  "
        f"Scan: {result.scan_duration_seconds:.2f}s  |  "
        f"Blame: {result.blame_duration_seconds:.2f}s"
    )
    con.print()

    if result.total_findings == 0:
        con.print("[bold green]No findings — nothing to attribute.[/bold green]")
        con.print()
        return

    # Bucket totals table
    totals = Table(
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        title="Findings by origin",
    )
    totals.add_column("Origin", style="bold", width=10)
    totals.add_column("Count", justify="right", width=6)
    totals.add_column("%", justify="right", width=6)
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        totals.add_column(sev.value.title()[:4], justify="right", width=5)

    total = max(result.total_findings, 1)
    for origin in ("ai", "human", "unknown"):
        bucket = result.buckets[origin]
        pct = 100.0 * bucket.count / total
        style = _ORIGIN_STYLE[origin]
        totals.add_row(
            Text(origin.upper(), style=style),
            str(bucket.count),
            f"{pct:.0f}%",
            *[
                str(bucket.by_severity.get(sev.value, 0))
                for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            ],
        )
    con.print(totals)

    # Rule breakdown per non-empty bucket
    for origin in ("ai", "human", "unknown"):
        bucket = result.buckets[origin]
        if not bucket.by_rule:
            continue
        rule_table = Table(
            show_header=True,
            header_style="bold",
            box=box.SIMPLE,
            title=f"{origin.upper()} findings by rule",
        )
        rule_table.add_column("Rule ID", width=14)
        rule_table.add_column("Count", justify="right", width=6)
        for rule_id, count in sorted(bucket.by_rule.items(), key=lambda kv: -kv[1]):
            rule_table.add_row(rule_id, str(count))
        con.print(rule_table)

    # Unknown sub-reason breakdown
    if result.buckets["unknown"].count:
        reasons: dict[str, int] = {}
        for af in result.annotated:
            if af.attribution.origin.value == "unknown":
                reasons[af.attribution.reason] = reasons.get(af.attribution.reason, 0) + 1
        summary = "  ".join(f"{k}={v}" for k, v in sorted(reasons.items()))
        con.print(f"  [dim]Unknown reasons: {summary}[/dim]")
    con.print()


def write_metrics_json(result: MetricsResult, path: Path | None = None) -> str:
    """Serialize a MetricsResult to JSON using Pydantic's serializer."""
    json_str = result.model_dump_json(indent=2)
    if path:
        path.write_text(json_str)
    return json_str
