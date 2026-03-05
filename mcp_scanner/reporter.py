from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import ScanResult, Severity

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def report_terminal(result: ScanResult) -> None:
    console = Console()

    console.print()
    console.rule("[bold]MCP Security Scanner Results[/bold]")
    console.print(
        f"  Target: [bold]{result.target_path}[/bold]  |  "
        f"Files scanned: {result.files_scanned}  |  "
        f"Findings: {len(result.findings)}  |  "
        f"Duration: {result.duration_seconds}s"
    )
    console.print()

    if not result.findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("#", width=3, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Rule", width=26)
    table.add_column("Title", ratio=2)
    table.add_column("File", ratio=2)
    table.add_column("Line", width=5, justify="right")

    for idx, finding in enumerate(result.findings, 1):
        style = _SEVERITY_STYLE.get(finding.severity, "")
        table.add_row(
            str(idx),
            f"[{style}]{finding.severity.value.upper()}[/{style}]",
            finding.rule_id.value,
            finding.title,
            finding.file_path,
            str(finding.line_number),
        )

    console.print(table)

    console.print()
    for idx, finding in enumerate(result.findings, 1):
        style = _SEVERITY_STYLE.get(finding.severity, "")
        console.print(f"[{style}]--- Finding {idx}: {finding.title} ---[/{style}]")
        console.print(f"  Rule:     {finding.rule_id.value}")
        console.print(f"  Severity: {finding.severity.value.upper()}")
        console.print(f"  File:     {finding.file_path}:{finding.line_number}")
        console.print(f"  {finding.description}")
        if finding.snippet:
            console.print(f"  [dim]{finding.snippet.rstrip()}[/dim]")
        console.print()


def report_json(result: ScanResult, output_path: str) -> None:
    data = asdict(result)
    Path(output_path).write_text(
        json.dumps(data, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
