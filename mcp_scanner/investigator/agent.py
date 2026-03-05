from __future__ import annotations

import json
import logging
from dataclasses import asdict
from typing import Any

import boto3
from botocore.exceptions import ClientError

from ..models import Finding, ScanResult, Severity
from ..registry import ServerRegistry
from .tools import TOOL_CONFIG, dispatch_tool

logger = logging.getLogger(__name__)

MODEL_ID = "us.anthropic.claude-sonnet-4-20250514-v1:0"
MAX_ITERATIONS = 15
BEDROCK_REGION = "us-east-1"

SYSTEM_PROMPT = """\
You are an expert MCP security researcher. You have been given the results of a \
static analysis scan of an MCP server codebase. Your job is to investigate the \
highest-severity findings, understand the attack chains, and produce a prioritized \
attack narrative.

## Tool Usage Rules

1. Before calling check_endpoint_reachability, you must first call get_function_body \
for the same file_path and function_name to discover the function's parameter names. \
Use one of the returned params values as the param_name argument.

2. If a tool returns an error field, note it and move on to the next investigation \
step rather than retrying the same call. Do not waste iterations on repeated failures.

3. After investigating the highest-priority findings, produce a final attack narrative. \
Do not continue exploring indefinitely.

## Investigation Strategy

- Investigate only the top 2 CRITICAL findings. Ignore the rest.
- For each: call get_function_body once, then immediately move on.
- Make no more than 4 tool calls total across all findings.
- Do not call check_endpoint_reachability or find_related_patterns unless critical.
- After 4 tool calls, stop and write your narrative immediately.

## Output Format

When you are done investigating, produce your final response as a markdown attack \
narrative with these sections:

1. **Executive Summary** -- 2-3 sentence overview of the most critical risks.
2. **Attack Chains** -- Numbered list of exploitable attack paths, each with:
   - Severity rating
   - Affected files and functions
   - Step-by-step exploitation description
   - Evidence (code snippets, taint paths)
3. **Prioritized Recommendations** -- Ordered list of fixes, most urgent first.
"""


def _build_user_prompt(scan_result: ScanResult) -> str:
    """Serialize scan findings into the initial user message."""
    lines = [
        f"## MCP Security Scan Results for `{scan_result.target_path}`\n",
        f"Files scanned: {scan_result.files_scanned}",
        f"Total findings: {len(scan_result.findings)}",
        f"Scan duration: {scan_result.duration_seconds}s\n",
        "### Findings\n",
    ]
    for i, f in enumerate(scan_result.findings, 1):
        lines.append(
            f"{i}. **[{f.severity.value.upper()}] {f.title}**\n"
            f"   - Rule: {f.rule_id.value}\n"
            f"   - File: `{f.file_path}` line {f.line_number}\n"
            f"   - {f.description}\n"
            f"   - Snippet: `{f.snippet.strip()}`\n"
        )

    lines.append(
        "\nInvestigate these findings using the available tools. "
        "Focus on CRITICAL and HIGH severity issues. "
        "Determine which are truly exploitable and how they can be chained. "
        "Then produce your attack narrative."
    )
    return "\n".join(lines)


def _extract_final_text(messages: list[dict[str, Any]]) -> str:
    """Pull the final assistant text from the message history."""
    for msg in reversed(messages):
        if msg.get("role") != "assistant":
            continue
        for block in msg.get("content", []):
            if "text" in block:
                return block["text"]
    return ""


def investigate(
    target_path: str,
    scan_result: ScanResult,
    registry: ServerRegistry,
    *,
    max_iterations: int = MAX_ITERATIONS,
    model_id: str = MODEL_ID,
    region: str = BEDROCK_REGION,
) -> str:
    """Run the agentic investigation loop.

    Returns the final markdown attack narrative.
    """
    client = boto3.client("bedrock-runtime", region_name=region)

    messages: list[dict[str, Any]] = [
        {"role": "user", "content": [{"text": _build_user_prompt(scan_result)}]},
    ]

    iteration = 0
    stop_reason = "end_turn"  # default if loop never runs
    for iteration in range(max_iterations):
        logger.debug("Agent iteration %d/%d", iteration + 1, max_iterations)

        try:
            response = client.converse(
                modelId=model_id,
                system=[{"text": SYSTEM_PROMPT}],
                messages=messages,
                toolConfig=TOOL_CONFIG,
            )
        except ClientError as exc:
            logger.error("Bedrock API error: %s", exc)
            return f"**Error**: Bedrock API call failed: {exc}"

        output_msg = response["output"]["message"]
        messages.append(output_msg)
        stop_reason = response.get("stopReason", "end_turn")

        logger.debug("Stop reason: %s", stop_reason)

        if stop_reason != "tool_use":
            break

        # Collect all tool results into a single user message
        tool_results: list[dict[str, Any]] = []
        for block in output_msg["content"]:
            if "toolUse" in block:
                tool_use = block["toolUse"]
                logger.debug(
                    "Tool call: %s(%s)",
                    tool_use["name"],
                    json.dumps(tool_use.get("input", {}), default=str)[:200],
                )
                result = dispatch_tool(tool_use, registry, target_path)
                tool_results.append({"toolResult": result})

        if tool_results:
            messages.append({"role": "user", "content": tool_results})

    logger.info(
        "Investigation complete after %d iteration(s)", iteration + 1
    )

    # If we exhausted iterations without end_turn, force a final narrative
    if stop_reason == "tool_use":
        messages.append({
            "role": "user",
            "content": [{"text": "You have reached the investigation limit. Stop using tools now and immediately write your final attack narrative based on what you have found so far."}]
        })
        try:
            response = client.converse(
                modelId=model_id,
                system=[{"text": SYSTEM_PROMPT}],
                messages=messages,
                toolConfig={"tools": TOOL_CONFIG["tools"], "toolChoice": {"type": "none"}},
            )
            messages.append(response["output"]["message"])
        except ClientError as exc:
            logger.error("Forced final call failed: %s", exc)

    return _extract_final_text(messages)
