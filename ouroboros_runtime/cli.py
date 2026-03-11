"""CLI for Ouroboros Runtime."""
from __future__ import annotations

import asyncio
import json
import logging
import sys

import click
from rich.console import Console
from rich.table import Table

from mcp_scanner.models import Verdict

from .core.engine import create_default_engine
from .core.probes.base import ProbeInput
from .mcp.proxy_stdio import run_proxy
from .policy.enforcer import PolicyEnforcer
from .policy.loader import load_policy

console = Console()


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def cli(verbose: bool) -> None:
    """Ouroboros Runtime - Pre-execution security for AI agent workflows."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


@cli.command("scan")
@click.argument("url")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option("--policy", "-p", type=click.Path(exists=True), help="Path to policy YAML file")
def scan_cmd(url: str, output_format: str, policy: str | None) -> None:
    """Scan a URL endpoint for security issues."""
    engine = create_default_engine()
    policy_config = load_policy(policy)
    enforcer = PolicyEnforcer(policy_config)

    console.print(f"[bold]Scanning:[/bold] {url}")
    console.print()

    input_data = ProbeInput(url=url)
    verdict = engine.scan(input_data)

    enforcement = enforcer.enforce(verdict)

    if output_format == "json":
        output = {
            "url": url,
            "verdict": verdict.verdict.value,
            "probe_duration_ms": verdict.probe_duration_ms,
            "findings": [
                {
                    "rule_id": f.rule_id.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in verdict.findings
            ],
            "enforcement_action": enforcement.action.value,
        }
        console.print_json(json.dumps(output, indent=2))
    else:
        _print_verdict_table(verdict, enforcement)


def _print_verdict_table(verdict, enforcement) -> None:
    """Print verdict results as a rich table."""
    verdict_colors = {
        Verdict.SAFE: "green",
        Verdict.CAUTION: "yellow",
        Verdict.BLOCK: "red",
    }

    color = verdict_colors.get(verdict.verdict, "white")
    console.print(f"[bold {color}]Verdict: {verdict.verdict.value.upper()}[/bold {color}]")
    console.print(f"Duration: {verdict.probe_duration_ms:.1f}ms")
    console.print(f"Enforcement: {enforcement.action.value}")
    console.print()

    if verdict.findings:
        table = Table(title="Findings")
        table.add_column("Rule", style="cyan")
        table.add_column("Severity", style="magenta")
        table.add_column("Title")
        table.add_column("Evidence", max_width=50)

        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for finding in verdict.findings:
            sev_color = severity_colors.get(finding.severity.value, "white")
            table.add_row(
                finding.rule_id.value,
                f"[{sev_color}]{finding.severity.value}[/{sev_color}]",
                finding.title,
                finding.evidence[:100] + "..." if len(finding.evidence) > 100 else finding.evidence,
            )

        console.print(table)
    else:
        console.print("[green]No security issues detected.[/green]")

    console.print()
    console.print("[dim]Reasoning chain:[/dim]")
    for step in verdict.reasoning_chain:
        console.print(f"  {step}")


@cli.command("proxy")
@click.option("--stdio", is_flag=True, help="Use stdio transport")
@click.option("--policy", "-p", type=click.Path(exists=True), help="Path to policy YAML file")
@click.argument("server_command", nargs=-1, required=True)
def proxy_cmd(stdio: bool, policy: str | None, server_command: tuple[str, ...]) -> None:
    """Launch the MCP proxy.

    Example:
        ouroboros runtime proxy --stdio -- node my-server/index.js
    """
    if not stdio:
        console.print("[red]Error: Only --stdio transport is currently supported[/red]")
        sys.exit(1)

    if not server_command:
        console.print("[red]Error: Server command is required[/red]")
        sys.exit(1)

    console.print(f"[bold]Starting proxy for:[/bold] {' '.join(server_command)}")

    try:
        asyncio.run(run_proxy(list(server_command), policy))
    except KeyboardInterrupt:
        console.print("\n[yellow]Proxy stopped.[/yellow]")
    except Exception as e:
        console.print(f"[red]Proxy error: {e}[/red]")
        sys.exit(1)


@cli.command("check-policy")
@click.argument("policy_path", type=click.Path(exists=True))
def check_policy_cmd(policy_path: str) -> None:
    """Validate a policy YAML file."""
    try:
        config = load_policy(policy_path)
        console.print("[green]Policy file is valid.[/green]")
        console.print()
        console.print(f"[bold]Rules configured:[/bold] {len(config.policies)}")
        console.print(f"[bold]Domain overrides:[/bold] {len(config.allowlist)}")
        console.print()
        console.print("[bold]Settings:[/bold]")
        console.print(f"  Escalation: {config.settings.escalation}")
        console.print(f"  Cache TTL: {config.settings.cache_ttl_seconds}s")
        console.print(f"  Max escalation time: {config.settings.max_escalation_time_ms}ms")
        console.print(f"  Max cache size: {config.settings.max_cache_size}")
    except Exception as e:
        console.print(f"[red]Policy validation failed: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    cli()
