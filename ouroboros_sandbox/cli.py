"""CLI for ouroboros_sandbox."""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


@click.group("sandbox")
def cli():
    """Ouroboros Sandbox - containerized dynamic auditing for MCP servers."""
    pass


@cli.command("audit")
@click.argument("target")
@click.option(
    "--start",
    "-s",
    help="Command to start the MCP server (e.g., 'python -m server').",
)
@click.option(
    "--image",
    "-i",
    default="python:3.12-slim",
    help="Docker base image to use.",
)
@click.option(
    "--timeout",
    "-t",
    default=300,
    type=int,
    help="Maximum audit duration in seconds.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output report to file (JSON or Markdown based on extension).",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "markdown", "md"]),
    default="markdown",
    help="Output format.",
)
@click.option(
    "--max-iterations",
    default=30,
    type=int,
    help="Maximum agent iterations.",
)
@click.option(
    "--region",
    default="us-east-1",
    help="AWS region for Bedrock.",
)
@click.option(
    "--skip-static",
    is_flag=True,
    help="Skip static analysis.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose logging.",
)
def audit_cmd(
    target: str,
    start: str | None,
    image: str,
    timeout: int,
    output: str | None,
    output_format: str,
    max_iterations: int,
    region: str,
    skip_static: bool,
    verbose: bool,
):
    """Audit an MCP server in a sandboxed Docker container.

    TARGET can be a local path to the server code.

    Examples:

        ouroboros sandbox audit ./my-mcp-server

        ouroboros sandbox audit ./server --start "python -m server"

        ouroboros sandbox audit ./server -o report.md
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    target_path = Path(target).resolve()
    if not target_path.exists():
        console.print(f"[red]Error:[/red] Target path not found: {target_path}")
        sys.exit(1)

    console.print(Panel.fit(
        f"[bold]Ouroboros Sandbox Audit[/bold]\n\n"
        f"Target: [cyan]{target_path}[/cyan]\n"
        f"Image: [cyan]{image}[/cyan]\n"
        f"Timeout: [cyan]{timeout}s[/cyan]",
        title="Configuration",
    ))

    from .agent.auditor import audit
    from .report.unified import create_unified_report, format_markdown_report, format_json_report

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running audit...", total=None)

            report = asyncio.run(audit(
                target_path=str(target_path),
                start_command=start,
                base_image=image,
                max_iterations=max_iterations,
                region=region,
                run_static_scan=not skip_static,
            ))

            progress.update(task, description="Audit complete!")

    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Audit failed:[/red] {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    _display_results(report)

    if output:
        output_path = Path(output)
        report_dict = report.to_dict()

        if output_format in ("markdown", "md") or output_path.suffix == ".md":
            unified = create_unified_report(
                target=report.target,
                static_result=None,
                dynamic_findings=report.dynamic_findings,
                network_events=report.network_events,
                tools_probed=report.tools_probed,
                narrative=report.narrative,
                duration_seconds=report.duration_seconds,
                overall_verdict=report.overall_verdict,
            )
            unified["static_findings"] = report_dict["static_findings"]
            content = format_markdown_report(unified)
        else:
            content = json.dumps(report_dict, indent=2, default=str)

        output_path.write_text(content)
        console.print(f"\n[green]Report saved to:[/green] {output_path}")


def _display_results(report):
    """Display audit results in the console."""
    from mcp_scanner.models import Verdict

    verdict_colors = {
        Verdict.SAFE: "green",
        Verdict.CAUTION: "yellow",
        Verdict.BLOCK: "red",
    }
    verdict_color = verdict_colors.get(report.overall_verdict, "white")

    console.print()
    console.print(Panel.fit(
        f"[bold {verdict_color}]{report.overall_verdict.value.upper()}[/bold {verdict_color}]",
        title="Overall Verdict",
    ))

    summary_table = Table(title="Summary", show_header=False)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Duration", f"{report.duration_seconds:.1f}s")
    summary_table.add_row("Static Findings", str(len(report.static_findings)))
    summary_table.add_row("Dynamic Findings", str(len(report.dynamic_findings)))
    summary_table.add_row("Network Events", str(len(report.network_events)))
    summary_table.add_row("Tools Probed", str(len(report.tools_probed)))

    console.print(summary_table)

    if report.static_findings:
        console.print()
        static_table = Table(title="Static Findings")
        static_table.add_column("Severity", style="bold")
        static_table.add_column("Title")
        static_table.add_column("Location")

        for f in report.static_findings[:10]:
            sev_color = _severity_color(f.severity.value)
            static_table.add_row(
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                f.title[:50],
                f"{Path(f.file_path).name}:{f.line_number}",
            )

        if len(report.static_findings) > 10:
            static_table.add_row("...", f"({len(report.static_findings) - 10} more)", "")

        console.print(static_table)

    if report.dynamic_findings:
        console.print()
        dynamic_table = Table(title="Dynamic Findings")
        dynamic_table.add_column("Severity", style="bold")
        dynamic_table.add_column("Title")
        dynamic_table.add_column("Target")

        for f in report.dynamic_findings[:10]:
            sev_color = _severity_color(f.severity.value)
            dynamic_table.add_row(
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                f.title[:50],
                f.target[:30],
            )

        if len(report.dynamic_findings) > 10:
            dynamic_table.add_row("...", f"({len(report.dynamic_findings) - 10} more)", "")

        console.print(dynamic_table)

    if report.network_events:
        console.print()
        suspicious = [e for e in report.network_events if e.port > 10000 or e.port in {22, 23, 3306, 5432}]
        if suspicious:
            console.print(f"[yellow]Warning:[/yellow] {len(suspicious)} suspicious network connections detected")


def _severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    return colors.get(severity.lower(), "white")


@cli.command("check-docker")
def check_docker_cmd():
    """Check if Docker is available and working."""
    try:
        import docker
        client = docker.from_env()
        info = client.info()
        console.print("[green]Docker is available![/green]")
        console.print(f"  Version: {info.get('ServerVersion', 'unknown')}")
        console.print(f"  Containers: {info.get('Containers', 0)}")
        console.print(f"  Images: {info.get('Images', 0)}")
    except ImportError:
        console.print("[red]Error:[/red] docker package not installed")
        console.print("  Run: pip install docker")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] Docker not available: {e}")
        console.print("  Make sure Docker Desktop is running")
        sys.exit(1)


if __name__ == "__main__":
    cli()
