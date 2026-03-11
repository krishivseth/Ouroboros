"""Unified report generation combining static and dynamic findings."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from mcp_scanner.models import Finding, RuntimeFinding, ScanResult, Verdict
from ..container.network import NetworkEvent


def create_unified_report(
    target: str,
    static_result: ScanResult | None,
    dynamic_findings: list[RuntimeFinding],
    network_events: list[NetworkEvent],
    tools_probed: list[dict[str, Any]],
    narrative: str,
    duration_seconds: float,
    overall_verdict: Verdict,
) -> dict[str, Any]:
    """Create a unified report combining all audit data.

    Args:
        target: Path to the audited server.
        static_result: Results from static analysis.
        dynamic_findings: Findings from dynamic probing.
        network_events: Network activity during audit.
        tools_probed: List of MCP tools that were probed.
        narrative: Agent's narrative report.
        duration_seconds: Total audit duration.
        overall_verdict: Final verdict.

    Returns:
        Unified report as a dictionary.
    """
    static_findings = static_result.findings if static_result else []

    return {
        "metadata": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration_seconds,
            "overall_verdict": overall_verdict.value,
        },
        "summary": {
            "static_findings_count": len(static_findings),
            "dynamic_findings_count": len(dynamic_findings),
            "network_events_count": len(network_events),
            "tools_probed_count": len(tools_probed),
            "verdict": overall_verdict.value,
        },
        "static_findings": [
            _serialize_static_finding(f) for f in static_findings
        ],
        "dynamic_findings": [
            _serialize_dynamic_finding(f) for f in dynamic_findings
        ],
        "network_activity": {
            "total_events": len(network_events),
            "events": [e.to_dict() for e in network_events],
        },
        "tools_probed": tools_probed,
        "narrative": narrative,
    }


def format_markdown_report(report: dict[str, Any]) -> str:
    """Format a unified report as markdown.

    Args:
        report: Unified report dictionary.

    Returns:
        Markdown-formatted report.
    """
    lines = []

    lines.append("# Ouroboros Security Audit Report")
    lines.append("")

    meta = report.get("metadata", {})
    lines.append(f"**Target:** `{meta.get('target', 'Unknown')}`")
    lines.append(f"**Timestamp:** {meta.get('timestamp', 'Unknown')}")
    lines.append(f"**Duration:** {meta.get('duration_seconds', 0):.1f} seconds")
    lines.append(f"**Verdict:** **{meta.get('overall_verdict', 'unknown').upper()}**")
    lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    summary = report.get("summary", {})
    lines.append(f"- Static findings: {summary.get('static_findings_count', 0)}")
    lines.append(f"- Dynamic findings: {summary.get('dynamic_findings_count', 0)}")
    lines.append(f"- Network events: {summary.get('network_events_count', 0)}")
    lines.append(f"- Tools probed: {summary.get('tools_probed_count', 0)}")
    lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Static Analysis Findings")
    lines.append("")
    static_findings = report.get("static_findings", [])
    if static_findings:
        for f in static_findings:
            severity = f.get("severity", "unknown").upper()
            lines.append(f"### [{severity}] {f.get('title', 'Unknown')}")
            lines.append("")
            lines.append(f"**Rule:** `{f.get('rule_id', 'unknown')}`")
            lines.append(f"**Location:** `{f.get('file_path', 'unknown')}` line {f.get('line_number', 0)}")
            lines.append("")
            lines.append(f.get("description", "No description"))
            lines.append("")
            if f.get("snippet"):
                lines.append("```")
                lines.append(f.get("snippet", ""))
                lines.append("```")
                lines.append("")
    else:
        lines.append("*No static findings.*")
        lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Dynamic Analysis Findings")
    lines.append("")
    dynamic_findings = report.get("dynamic_findings", [])
    if dynamic_findings:
        for f in dynamic_findings:
            severity = f.get("severity", "unknown").upper()
            lines.append(f"### [{severity}] {f.get('title', 'Unknown')}")
            lines.append("")
            lines.append(f"**Rule:** `{f.get('rule_id', 'unknown')}`")
            lines.append(f"**Target:** `{f.get('target', 'unknown')}`")
            lines.append("")
            lines.append(f.get("description", "No description"))
            lines.append("")
            if f.get("evidence"):
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(f.get("evidence", "")[:500])
                lines.append("```")
                lines.append("")
    else:
        lines.append("*No dynamic findings.*")
        lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Network Activity")
    lines.append("")
    network = report.get("network_activity", {})
    events = network.get("events", [])
    if events:
        lines.append(f"Total connections: {network.get('total_events', 0)}")
        lines.append("")
        lines.append("| Timestamp | Destination | Port | Protocol |")
        lines.append("|-----------|-------------|------|----------|")
        for e in events[:20]:
            lines.append(
                f"| {e.get('timestamp', '')} | {e.get('destination', '')} | "
                f"{e.get('port', '')} | {e.get('protocol', '')} |"
            )
        if len(events) > 20:
            lines.append(f"| ... | *{len(events) - 20} more events* | ... | ... |")
        lines.append("")
    else:
        lines.append("*No network activity detected.*")
        lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Tools Probed")
    lines.append("")
    tools = report.get("tools_probed", [])
    if tools:
        for t in tools:
            tool_name = t.get("tool_name", "unknown")
            lines.append(f"- **{tool_name}**")
            if t.get("description"):
                lines.append(f"  - {t.get('description')}")
        lines.append("")
    else:
        lines.append("*No tools were probed.*")
        lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Agent Narrative")
    lines.append("")
    narrative = report.get("narrative", "")
    if narrative:
        lines.append(narrative)
    else:
        lines.append("*No narrative generated.*")

    return "\n".join(lines)


def format_json_report(report: dict[str, Any], indent: int = 2) -> str:
    """Format a unified report as JSON.

    Args:
        report: Unified report dictionary.
        indent: JSON indentation level.

    Returns:
        JSON-formatted report.
    """
    return json.dumps(report, indent=indent, default=str)


def _serialize_static_finding(finding: Finding) -> dict[str, Any]:
    """Serialize a static Finding to a dictionary."""
    return {
        "rule_id": finding.rule_id.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "snippet": finding.snippet,
        "metadata": finding.metadata,
    }


def _serialize_dynamic_finding(finding: RuntimeFinding) -> dict[str, Any]:
    """Serialize a RuntimeFinding to a dictionary."""
    return {
        "rule_id": finding.rule_id.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "target": finding.target,
        "evidence": finding.evidence,
        "metadata": finding.metadata,
    }
