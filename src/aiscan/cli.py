"""Click CLI for aiscan."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from rich.console import Console

from aiscan.models import SEVERITY_ORDER


console = Console()


@click.group()
@click.version_option(package_name="aiscan")
def main() -> None:
    """aiscan — AI-native security scanner for AI-generated code.

    Combines deterministic AST rules with optional LLM analysis to catch
    the vulnerability patterns that AI coding assistants (Copilot, Cursor,
    ChatGPT) are statistically known to introduce.
    """
    pass


@main.command()
@click.argument("target", default=".", type=click.Path(exists=True, path_type=Path))
@click.option("--llm", is_flag=True, default=False, help="Enable LLM analysis tier.")
@click.option(
    "--llm-provider",
    default="anthropic",
    type=click.Choice(["anthropic", "openai", "local"]),
    show_default=True,
    help="LLM provider to use for the analysis tier.",
)
@click.option("--llm-model", default="claude-sonnet-4-6", show_default=True, help="LLM model name.")
@click.option(
    "--llm-api-key",
    default=None,
    envvar="AISCAN_LLM_API_KEY",
    help="API key for the LLM provider. Defaults to AISCAN_LLM_API_KEY env var, "
         "or ANTHROPIC_API_KEY / OPENAI_API_KEY depending on provider.",
)
@click.option(
    "--llm-base-url",
    default=None,
    envvar="AISCAN_LLM_BASE_URL",
    help="Custom LLM endpoint URL. For Ollama: http://localhost:11434/v1. "
         "For LM Studio: http://localhost:1234/v1.",
)
@click.option(
    "--severity",
    default="LOW",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    show_default=True,
    help="Minimum severity of findings to include in output.",
)
@click.option(
    "--format",
    "output_format",
    default="terminal",
    type=click.Choice(["terminal", "sarif", "json"]),
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", default=None, type=click.Path(path_type=Path), help="Write output to file.")
@click.option(
    "--exit-code",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any non-suppressed findings are at or above --severity threshold.",
)
@click.option(
    "--diff-only",
    is_flag=True,
    default=False,
    help="Only scan files changed in the current git diff (useful in pre-commit hooks).",
)
@click.option(
    "--exclude",
    multiple=True,
    metavar="PATH",
    help="Exclude a path (relative to TARGET) from scanning. Can be repeated.",
)
@click.option(
    "--llm-scan-all",
    is_flag=True,
    default=False,
    help="Run LLM analysis on every file, not just those with AST findings. "
         "Higher coverage, higher cost.",
)
@click.option(
    "--llm-max-lines",
    default=500,
    type=int,
    show_default=True,
    metavar="N",
    help="Maximum number of lines of a file to send to the LLM. "
         "Larger files are truncated and a warning is emitted.",
)
@click.option(
    "--llm-timeout",
    default=60.0,
    type=float,
    show_default=True,
    metavar="SECONDS",
    help="Timeout for each LLM API call.",
)
@click.option(
    "--cache-dir",
    default=None,
    type=click.Path(path_type=Path),
    metavar="PATH",
    help="Directory for the LLM response cache. Defaults to a platform-"
         "appropriate user cache dir (e.g. ~/Library/Caches/aiscan on macOS, "
         "~/.cache/aiscan on Linux).",
)
def scan(
    target: Path,
    llm: bool,
    llm_provider: str,
    llm_model: str,
    llm_api_key: str | None,
    llm_base_url: str | None,
    severity: str,
    output_format: str,
    output: Path | None,
    exit_code: bool,
    diff_only: bool,
    exclude: tuple[str, ...],
    llm_scan_all: bool,
    llm_max_lines: int,
    llm_timeout: float,
    cache_dir: Path | None,
) -> None:
    """Scan TARGET path for AI-generated code vulnerabilities.

    TARGET defaults to the current directory.
    """
    # Resolve API key from environment if not provided
    if llm and not llm_api_key:
        if llm_provider == "anthropic":
            llm_api_key = os.environ.get("ANTHROPIC_API_KEY")
        elif llm_provider == "openai":
            llm_api_key = os.environ.get("OPENAI_API_KEY")
        # local provider needs no key

    from aiscan.scanner import Scanner

    scanner = Scanner(
        llm_enabled=llm,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_api_key=llm_api_key,
        llm_base_url=llm_base_url,
        diff_only=diff_only,
        exclude=exclude,
        llm_scan_all=llm_scan_all,
        llm_max_lines=llm_max_lines,
        llm_timeout=llm_timeout,
        cache_dir=str(cache_dir) if cache_dir else None,
    )

    if output_format == "terminal":
        console.print(f"[dim]Scanning [bold]{target}[/bold]...[/dim]")

    result = scanner.scan(target)

    # Filter findings by minimum severity without mutating the result model
    min_severity_order = SEVERITY_ORDER[severity]
    filtered = result.model_copy(update={
        "findings": [
            f for f in result.findings
            if SEVERITY_ORDER[f.severity.value] >= min_severity_order
        ]
    })

    # Output
    from aiscan import reporter

    if output_format == "terminal":
        reporter.write_terminal(filtered, console=console)
    elif output_format == "sarif":
        sarif_str = reporter.write_sarif(filtered, path=output)
        if not output:
            click.echo(sarif_str)
    elif output_format == "json":
        json_str = reporter.write_json(filtered, path=output)
        if not output:
            click.echo(json_str)

    if output:
        console.print(f"[green]Results written to {output}[/green]")

    # Exit code logic
    if exit_code and any(not f.suppressed for f in filtered.findings):
        sys.exit(1)


@main.command()
def rules() -> None:
    """List all built-in detection rules."""
    from rich.table import Table
    from rich import box
    from aiscan.rule_engine import RuleEngine

    engine = RuleEngine()
    table = Table(
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        title="Built-in Detection Rules",
    )
    table.add_column("Rule ID", width=14)
    table.add_column("Name")
    table.add_column("Severity", width=10)
    table.add_column("Languages")
    table.add_column("CWE IDs")

    for rule in engine.list_rules():
        table.add_row(
            rule["rule_id"],
            rule["rule_name"],
            rule["severity"],
            ", ".join(rule["languages"]),
            ", ".join(rule["cwe_ids"]),
        )

    console.print(table)
