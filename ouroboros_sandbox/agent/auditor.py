"""Main auditor agent for sandbox dynamic analysis."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import boto3

from mcp_scanner.models import Finding, RuntimeFinding, Severity, Verdict
from mcp_scanner.engine import scan as scan_directory
from ..container.manager import ContainerManager, ContainerConfig
from ..container.network import NetworkMonitor, NetworkEvent
from ..probes import SchemaDriftProbe, BehavioralProbe, ResponseInjectionProbe, score_tool_schemas
from .tools import SANDBOX_TOOL_CONFIG, SandboxToolContext, dispatch_sandbox_tool
from .prompts import SANDBOX_SYSTEM_PROMPT, build_investigation_prompt

logger = logging.getLogger(__name__)

# Dynamic iteration budget constants
DEFAULT_BASE_ITERATIONS = 5
ITERATIONS_PER_TOOL = 3

# Type alias for event callback
EventCallback = Any  # Callable[[str, dict], Awaitable[None]] but avoiding import issues


@dataclass
class AuditContext:
    """Context for an audit session."""
    target_path: str
    container: ContainerManager
    network_monitor: NetworkMonitor
    tool_context: SandboxToolContext
    static_findings: list[Finding] = field(default_factory=list)
    dynamic_findings: list[RuntimeFinding] = field(default_factory=list)
    network_events: list[NetworkEvent] = field(default_factory=list)
    tools_probed: list[dict[str, Any]] = field(default_factory=list)
    narrative: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    event_callback: EventCallback | None = None

    @property
    def duration_seconds(self) -> float:
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return 0.0

    async def emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit an event if callback is configured."""
        if self.event_callback:
            try:
                await self.event_callback(event_type, data)
            except Exception as e:
                logger.warning("Event callback failed: %s", e)


@dataclass
class AuditReport:
    """Complete audit report combining static and dynamic analysis."""
    target: str
    duration_seconds: float
    overall_verdict: Verdict
    static_findings: list[Finding]
    dynamic_findings: list[RuntimeFinding]
    network_events: list[NetworkEvent]
    tools_probed: list[dict[str, Any]]
    narrative: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "duration_seconds": self.duration_seconds,
            "overall_verdict": self.overall_verdict.value,
            "static_findings": [
                {
                    "rule_id": f.rule_id.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                }
                for f in self.static_findings
            ],
            "dynamic_findings": [
                {
                    "rule_id": f.rule_id.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "target": f.target,
                    "evidence": f.evidence,
                }
                for f in self.dynamic_findings
            ],
            "network_events": [e.to_dict() for e in self.network_events],
            "tools_probed": self.tools_probed,
            "narrative": self.narrative,
        }


async def audit(
    target_path: str,
    start_command: str | None = None,
    base_image: str = "python:3.12-slim",
    max_iterations: int = 30,
    region: str = "us-east-1",
    model_id: str = "us.anthropic.claude-sonnet-4-20250514-v1:0",
    run_static_scan: bool = True,
    event_callback: EventCallback | None = None,
) -> AuditReport:
    """Run a full sandbox audit on an MCP server.

    Args:
        target_path: Path to the MCP server code.
        start_command: Optional command to start the server.
        base_image: Docker image to use for the container.
        max_iterations: Maximum agent iterations.
        region: AWS region for Bedrock.
        model_id: Bedrock model ID.
        run_static_scan: Whether to run static analysis first.
        event_callback: Optional async callback for streaming events.
            Signature: async def callback(event_type: str, data: dict) -> None

    Returns:
        AuditReport with all findings.
    """
    target_path = str(Path(target_path).resolve())
    logger.info("Starting audit of %s", target_path)

    # Helper to emit events
    async def emit(event_type: str, data: dict[str, Any]) -> None:
        if event_callback:
            try:
                await event_callback(event_type, data)
            except Exception as e:
                logger.warning("Event callback failed: %s", e)

    await emit("phase", {"phase": "initializing", "status": "running"})

    static_findings: list[Finding] = []
    if run_static_scan:
        logger.info("Running static scan...")
        await emit("phase", {"phase": "static_scan", "status": "running"})
        try:
            scan_result = scan_directory(target_path)
            static_findings = scan_result.findings
            logger.info("Static scan found %d findings", len(static_findings))
            
            for f in static_findings:
                await emit("finding", {
                    "severity": f.severity.value,
                    "title": f.title,
                    "rule_id": f.rule_id.value,
                    "target": f.file_path,
                    "source": "static",
                })
            
            await emit("phase", {"phase": "static_scan", "status": "completed"})
        except Exception as e:
            logger.warning("Static scan failed: %s", e)
            await emit("phase", {"phase": "static_scan", "status": "failed", "error": str(e)})

    await emit("phase", {"phase": "container_setup", "status": "running"})

    config = ContainerConfig(
        image=base_image,
        network_mode="bridge",
        memory_limit="1g",
        timeout_seconds=300,
    )

    container = ContainerManager(config)
    network_monitor = NetworkMonitor(container)

    try:
        container.create(target_path)
        container.start()
        network_monitor.start()
        
        await emit("phase", {"phase": "container_setup", "status": "completed"})

        tool_context = SandboxToolContext(container, network_monitor)

        ctx = AuditContext(
            target_path=target_path,
            container=container,
            network_monitor=network_monitor,
            tool_context=tool_context,
            static_findings=static_findings,
            start_time=time.time(),
            event_callback=event_callback,
        )

        await emit("phase", {"phase": "agent_probing", "status": "running"})

        await _run_agent_loop(
            ctx=ctx,
            start_command=start_command,
            max_iterations=max_iterations,
            region=region,
            model_id=model_id,
        )

        ctx.end_time = time.time()
        ctx.network_events = network_monitor.get_events()

        overall_verdict = _compute_verdict(ctx)
        
        await emit("phase", {"phase": "agent_probing", "status": "completed"})
        await emit("complete", {
            "verdict": overall_verdict.value,
            "findings_count": len(ctx.static_findings) + len(ctx.dynamic_findings),
            "duration_seconds": ctx.duration_seconds,
        })

        return AuditReport(
            target=target_path,
            duration_seconds=ctx.duration_seconds,
            overall_verdict=overall_verdict,
            static_findings=ctx.static_findings,
            dynamic_findings=ctx.dynamic_findings,
            network_events=ctx.network_events,
            tools_probed=ctx.tools_probed,
            narrative=ctx.narrative,
        )

    except Exception as e:
        await emit("error", {"message": str(e)})
        raise

    finally:
        network_monitor.stop()
        container.stop()


async def _run_agent_loop(
    ctx: AuditContext,
    start_command: str | None,
    max_iterations: int,
    region: str,
    model_id: str,
) -> None:
    """Run the agent conversation loop.
    
    The loop is split into two phases:
    1. Setup phase (scripted, doesn't count against budget): file exploration, dependency install, server start
    2. Probing phase (agentic, counts against budget): adversarial testing of discovered tools
    """
    # Check for Bedrock API Key (ANTHROPIC_API_KEY starting with ABSK)
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    
    if api_key.startswith("ABSK"):
        # Set the bearer token for boto3 to use
        os.environ["AWS_BEARER_TOKEN_BEDROCK"] = api_key
        logger.info("Using Bedrock API Key authentication")
    
    client = boto3.client("bedrock-runtime", region_name=region)

    system_prompt = SANDBOX_SYSTEM_PROMPT
    if ctx.static_findings:
        investigation_prompt = build_investigation_prompt([
            {
                "rule_id": f.rule_id.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "file_path": f.file_path,
                "line_number": f.line_number,
            }
            for f in ctx.static_findings
        ])
        system_prompt = f"{system_prompt}\n\n{investigation_prompt}"

    messages: list[dict[str, Any]] = []

    initial_message = "Begin the security audit. Start by exploring the codebase."
    if start_command:
        initial_message += f" The server can be started with: `{start_command}`"

    messages.append({
        "role": "user",
        "content": [{"text": initial_message}],
    })

    schema_probe = SchemaDriftProbe()
    behavioral_probe = BehavioralProbe()
    injection_probe = ResponseInjectionProbe()
    
    # Track effective iteration budget (may expand when tools are discovered)
    effective_max_iterations = max_iterations
    tools_discovered = False
    iteration = 0
    
    # Track iteration usage for diagnostics
    setup_iterations = 0
    probing_iterations = 0
    iteration_log: list[dict[str, Any]] = []
    
    # Setup phase tools (don't count against probing budget)
    SETUP_TOOLS = {"list_files", "read_file", "run_command", "get_tool_schemas"}

    while iteration < effective_max_iterations:
        iteration += 1
        logger.debug("Agent iteration %d/%d", iteration, effective_max_iterations)

        try:
            response = client.converse(
                modelId=model_id,
                system=[{"text": system_prompt}],
                messages=messages,
                toolConfig=SANDBOX_TOOL_CONFIG,
            )
            output = response.get("output", {})
            message = output.get("message", {})
            stop_reason = response.get("stopReason")
        except Exception as e:
            logger.error("Bedrock API error: %s", e)
            break

        messages.append({"role": "assistant", "content": message.get("content", [])})

        for block in message.get("content", []):
            if "text" in block:
                text = block["text"]
                logger.debug("Agent: %s", text[:200])
                
                # Emit agent thought event (truncated for streaming)
                await ctx.emit_event("agent_thought", {
                    "text": text[:500] if len(text) > 500 else text,
                    "iteration": iteration,
                })

                if any(marker in text.lower() for marker in [
                    "## executive summary",
                    "# security report",
                    "overall verdict:",
                    "## overall verdict",
                ]):
                    ctx.narrative = text
                    logger.info("Agent produced final report")

        if stop_reason == "end_turn":
            logger.info("Agent completed (end_turn)")
            break

        if stop_reason == "tool_use":
            tool_results = []
            iteration_tools: list[str] = []

            for block in message.get("content", []):
                if "toolUse" in block:
                    tool_use = block["toolUse"]
                    tool_name = tool_use["name"]
                    tool_input = tool_use.get("input", {})
                    iteration_tools.append(tool_name)

                    logger.info("Tool call: %s", tool_name)
                    
                    # Emit tool call event
                    await ctx.emit_event("tool_call", {
                        "tool": tool_name,
                        "input": tool_input,
                        "iteration": iteration,
                    })

                    result = dispatch_sandbox_tool(tool_use, ctx.tool_context)
                    tool_results.append({"toolResult": result})

                    findings_before = len(ctx.dynamic_findings)
                    
                    _process_tool_result(
                        ctx=ctx,
                        tool_name=tool_name,
                        tool_input=tool_input,
                        result=result,
                        schema_probe=schema_probe,
                        behavioral_probe=behavioral_probe,
                        injection_probe=injection_probe,
                    )
                    
                    # Emit any new findings
                    for f in ctx.dynamic_findings[findings_before:]:
                        await ctx.emit_event("finding", {
                            "severity": f.severity.value,
                            "title": f.title,
                            "rule_id": f.rule_id.value,
                            "target": f.target,
                            "source": "dynamic",
                        })
                    
                    # Expand iteration budget when tools are discovered
                    if tool_name == "get_tool_schemas" and not tools_discovered:
                        result_content = result.get("content", [{}])[0].get("json", {})
                        discovered_tools = result_content.get("tools", [])
                        if discovered_tools:
                            tools_discovered = True
                            new_budget = DEFAULT_BASE_ITERATIONS + (len(discovered_tools) * ITERATIONS_PER_TOOL)
                            if new_budget > effective_max_iterations:
                                logger.info(
                                    "Expanding iteration budget from %d to %d for %d tools",
                                    effective_max_iterations, new_budget, len(discovered_tools)
                                )
                                effective_max_iterations = new_budget
                            
                            # Emit tool discovery events
                            for tool in discovered_tools:
                                await ctx.emit_event("tool_discovered", {
                                    "tool_name": tool.get("name"),
                                    "description": tool.get("description"),
                                })

            # Categorize iteration as setup or probing
            is_setup_iteration = all(t in SETUP_TOOLS for t in iteration_tools)
            if is_setup_iteration:
                setup_iterations += 1
            else:
                probing_iterations += 1
            
            # Log iteration details
            iteration_log.append({
                "iteration": iteration,
                "tools": iteration_tools,
                "is_setup": is_setup_iteration,
                "findings_added": len(ctx.dynamic_findings) - findings_before if iteration_tools else 0,
            })
            
            if tool_results:
                messages.append({"role": "user", "content": tool_results})

    # Log iteration budget usage summary
    logger.info(
        "Iteration budget usage: %d total (%d setup, %d probing) out of %d max",
        iteration, setup_iterations, probing_iterations, effective_max_iterations
    )
    
    # Emit iteration summary for diagnostics
    await ctx.emit_event("iteration_summary", {
        "total_iterations": iteration,
        "setup_iterations": setup_iterations,
        "probing_iterations": probing_iterations,
        "max_iterations": effective_max_iterations,
        "iteration_log": iteration_log[-10:],  # Last 10 iterations
    })
    
    # Warn if setup consumed most of the budget
    if iteration > 0 and setup_iterations / iteration > 0.6:
        logger.warning(
            "Setup consumed %.0f%% of iterations (%d/%d). Consider increasing max_iterations or optimizing setup.",
            (setup_iterations / iteration) * 100, setup_iterations, iteration
        )

    if not ctx.narrative:
        ctx.narrative = _generate_fallback_narrative(ctx)


def _process_tool_result(
    ctx: AuditContext,
    tool_name: str,
    tool_input: dict[str, Any],
    result: dict[str, Any],
    schema_probe: SchemaDriftProbe,
    behavioral_probe: BehavioralProbe,
    injection_probe: ResponseInjectionProbe,
) -> None:
    """Process a tool result and run probes."""
    result_content = result.get("content", [{}])[0].get("json", {})

    if tool_name == "call_mcp_tool":
        mcp_tool_name = tool_input.get("tool_name", "unknown")
        mcp_result = result_content.get("result", {})

        ctx.tools_probed.append({
            "tool_name": mcp_tool_name,
            "arguments": tool_input.get("arguments", {}),
            "result_summary": str(mcp_result)[:500],
        })

        injection_findings = injection_probe.check(mcp_result, mcp_tool_name)
        ctx.dynamic_findings.extend(injection_findings)

        behavioral_probe.record_response(
            mcp_tool_name,
            tool_input.get("arguments", {}),
            mcp_result,
        )

        consistency_finding = behavioral_probe.check_consistency(
            mcp_tool_name,
            tool_input.get("arguments", {}),
        )
        if consistency_finding:
            ctx.dynamic_findings.append(consistency_finding)

        suspicious_finding = schema_probe.check_for_suspicious_fields(
            mcp_result, mcp_tool_name
        )
        if suspicious_finding:
            ctx.dynamic_findings.append(suspicious_finding)

    elif tool_name == "get_tool_schemas":
        tools = result_content.get("tools", [])
        for tool in tools:
            ctx.tools_probed.append({
                "tool_name": tool.get("name"),
                "description": tool.get("description"),
                "schema": tool.get("input_schema"),
            })
        
        # Run tool risk scoring on discovered tools
        risk_findings = score_tool_schemas(tools)
        if risk_findings:
            logger.info("Tool risk scorer found %d dangerous capabilities", len(risk_findings))
            ctx.dynamic_findings.extend(risk_findings)


def _compute_verdict(ctx: AuditContext) -> Verdict:
    """Compute overall verdict from findings."""
    all_severities = []

    for f in ctx.static_findings:
        all_severities.append(f.severity)

    for f in ctx.dynamic_findings:
        all_severities.append(f.severity)

    suspicious_network = ctx.network_monitor.get_suspicious_events()
    if suspicious_network:
        all_severities.append(Severity.HIGH)

    if not all_severities:
        return Verdict.SAFE

    max_severity = max(all_severities, key=lambda s: s.rank)

    if max_severity >= Severity.HIGH:
        return Verdict.BLOCK
    elif max_severity >= Severity.MEDIUM:
        return Verdict.CAUTION
    else:
        return Verdict.SAFE


def _generate_fallback_narrative(ctx: AuditContext) -> str:
    """Generate a fallback narrative if agent didn't produce one."""
    lines = [
        "# Security Audit Report",
        "",
        "## Executive Summary",
        "",
        f"Audit completed in {ctx.duration_seconds:.1f} seconds.",
        f"Found {len(ctx.static_findings)} static findings and {len(ctx.dynamic_findings)} dynamic findings.",
        "",
        "## Static Findings",
        "",
    ]

    if ctx.static_findings:
        for f in ctx.static_findings[:10]:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title}")
    else:
        lines.append("No static findings.")

    lines.extend([
        "",
        "## Dynamic Findings",
        "",
    ])

    if ctx.dynamic_findings:
        for f in ctx.dynamic_findings[:10]:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title}")
    else:
        lines.append("No dynamic findings.")

    lines.extend([
        "",
        "## Network Activity",
        "",
        f"Total connections: {len(ctx.network_events)}",
        f"Suspicious connections: {len(ctx.network_monitor.get_suspicious_events())}",
    ])

    verdict = _compute_verdict(ctx)
    lines.extend([
        "",
        "## Overall Verdict",
        "",
        f"**{verdict.value.upper()}**",
    ])

    return "\n".join(lines)
