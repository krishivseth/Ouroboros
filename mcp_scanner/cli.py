from __future__ import annotations

import logging

import click

from .engine import scan
from .models import Severity
from .reporter import report_json, report_terminal


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
def cli(verbose: bool) -> None:
    """MCP Security Scanner -- static analysis for MCP server vulnerabilities."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


# Register runtime subcommand group
try:
    from ouroboros_runtime.cli import cli as runtime_cli
    cli.add_command(runtime_cli, name="runtime")
except ImportError:
    pass

# Register sandbox subcommand group
try:
    from ouroboros_sandbox.cli import cli as sandbox_cli
    cli.add_command(sandbox_cli, name="sandbox")
except ImportError:
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format", "fmt",
    type=click.Choice(["terminal", "json"], case_sensitive=False),
    default="terminal",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--severity",
    type=click.Choice([s.value for s in Severity], case_sensitive=False),
    default=Severity.LOW.value,
    show_default=True,
    help="Minimum severity threshold.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output file path (required for JSON format).",
)
def scan_cmd(path: str, fmt: str, severity: str, output: str | None) -> None:
    """Scan an MCP server codebase for vulnerabilities."""
    min_severity = Severity(severity.lower())
    result = scan(path, min_severity=min_severity)

    if fmt == "json":
        out = output or "mcp_scan_report.json"
        report_json(result, out)
        click.echo(f"Report written to {out}")
    else:
        report_terminal(result)
        if output:
            report_json(result, output)
            click.echo(f"JSON report also written to {output}")


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--severity",
    type=click.Choice([s.value for s in Severity], case_sensitive=False),
    default=Severity.HIGH.value,
    show_default=True,
    help="Minimum severity fed to the agent.",
)
@click.option(
    "--max-iterations",
    type=int,
    default=15,
    show_default=True,
    help="Maximum agent tool-call iterations.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write narrative to a markdown file.",
)
@click.option(
    "--model",
    type=str,
    default=None,
    help="Override Bedrock model ID.",
)
@click.option(
    "--region",
    type=str,
    default="us-east-1",
    show_default=True,
    help="AWS region for Bedrock.",
)
def investigate(
    path: str,
    severity: str,
    max_iterations: int,
    output: str | None,
    model: str | None,
    region: str,
) -> None:
    """Investigate scan findings with an AI agent via Bedrock."""
    from .engine import scan_with_registry
    from .investigator.agent import investigate as run_investigation
    from .investigator.narrative import render_narrative_terminal, write_narrative_file

    min_severity = Severity(severity.lower())

    click.echo("Running static scan...")
    scan_result, registry = scan_with_registry(path, min_severity=min_severity)

    if not scan_result.findings:
        click.echo("No findings at the selected severity level. Nothing to investigate.")
        return

    click.echo(
        f"Found {len(scan_result.findings)} finding(s). "
        f"Starting agent investigation (max {max_iterations} iterations)..."
    )

    kwargs: dict = {"max_iterations": max_iterations, "region": region}
    if model:
        kwargs["model_id"] = model

    narrative = run_investigation(
        target_path=path,
        scan_result=scan_result,
        registry=registry,
        **kwargs,
    )

    render_narrative_terminal(narrative)

    if output:
        write_narrative_file(narrative, output)
        click.echo(f"Narrative written to {output}")
