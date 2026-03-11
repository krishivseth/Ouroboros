"""Bidirectional MCP message interceptor."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_scanner.models import RuntimeFinding, RuntimeVerdict, Verdict

from ..core.engine import RuntimeEngine
from ..core.probes.base import ProbeInput
from ..policy.enforcer import EnforcementAction, EnforcementResult, PolicyEnforcer
from .canary import CanaryTracker

logger = logging.getLogger(__name__)


class InterceptAction(str, Enum):
    """Action to take after interception."""
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class InterceptResult:
    """Result of intercepting a request or response."""
    action: InterceptAction
    findings: list[RuntimeFinding] = field(default_factory=list)
    modified_message: dict[str, Any] | None = None
    error_response: dict[str, Any] | None = None
    verdict: RuntimeVerdict | None = None
    enforcement: EnforcementResult | None = None


class Interceptor:
    """Bidirectional interceptor for MCP JSON-RPC messages.

    Provides on_request and on_response hooks for inspecting and
    potentially blocking MCP tool calls.
    """

    def __init__(
        self,
        engine: RuntimeEngine,
        enforcer: PolicyEnforcer,
        canary: CanaryTracker | None = None,
    ):
        self._engine = engine
        self._enforcer = enforcer
        self._canary = canary or CanaryTracker()

    @property
    def engine(self) -> RuntimeEngine:
        return self._engine

    @property
    def enforcer(self) -> PolicyEnforcer:
        return self._enforcer

    @property
    def canary(self) -> CanaryTracker:
        return self._canary

    def on_request(
        self,
        method: str,
        params: dict[str, Any],
        request_id: Any = None,
    ) -> InterceptResult:
        """Process an outgoing request before it reaches the server.

        Currently:
        - Injects canary token into params._meta.ouroboros_canary
        - Phase 2 will add exfiltration scanning

        Only processes 'tools/call' method; others pass through.
        """
        if method != "tools/call":
            return InterceptResult(action=InterceptAction.PASS)

        request_id_str = str(request_id) if request_id else "unknown"

        modified_params = self._canary.inject(params.copy(), request_id_str)

        logger.debug(
            "Injected canary into request %s for tool %s",
            request_id_str,
            params.get("name", "unknown"),
        )

        return InterceptResult(
            action=InterceptAction.PASS,
            modified_message={"method": method, "params": modified_params},
        )

    def on_response(
        self,
        method: str,
        params: dict[str, Any],
        result: dict[str, Any],
        request_id: Any = None,
    ) -> InterceptResult:
        """Process a response before it reaches the client.

        - Runs Core probes on response content
        - Checks for canary leakage
        - Applies policy enforcement

        Only processes 'tools/call' method; others pass through.
        """
        if method != "tools/call":
            return InterceptResult(action=InterceptAction.PASS)

        tool_name = params.get("name", "unknown")
        request_id_str = str(request_id) if request_id else "unknown"

        response_body = self._extract_response_text(result)

        probe_input = ProbeInput(
            tool_name=tool_name,
            tool_params=params.get("arguments", {}),
            response_body=response_body,
            mcp_result=result,
        )

        verdict = self._engine.scan(probe_input)

        canary_finding = self._canary.check_leakage(
            response_body, tool_name, request_id_str
        )
        if canary_finding:
            verdict.findings.append(canary_finding)
            if canary_finding.severity >= verdict.findings[0].severity if verdict.findings else True:
                verdict = RuntimeVerdict(
                    verdict=Verdict.BLOCK,
                    target=verdict.target,
                    findings=verdict.findings,
                    probe_duration_ms=verdict.probe_duration_ms,
                    reasoning_chain=verdict.reasoning_chain + ["Canary leakage detected"],
                )

        enforcement = self._enforcer.enforce(verdict)

        if enforcement.action == EnforcementAction.BLOCK:
            error_response = enforcement.error_response
            if error_response:
                error_response["id"] = request_id

            logger.warning(
                "BLOCKED response from tool %s: %d finding(s)",
                tool_name,
                len(enforcement.blocked_findings),
            )

            return InterceptResult(
                action=InterceptAction.BLOCK,
                findings=verdict.findings,
                error_response=error_response,
                verdict=verdict,
                enforcement=enforcement,
            )

        if enforcement.action == EnforcementAction.WARN:
            logger.info(
                "WARNING for tool %s: %d finding(s)",
                tool_name,
                len(enforcement.warned_findings),
            )

            return InterceptResult(
                action=InterceptAction.WARN,
                findings=verdict.findings,
                modified_message=result,
                verdict=verdict,
                enforcement=enforcement,
            )

        return InterceptResult(
            action=InterceptAction.PASS,
            findings=verdict.findings,
            verdict=verdict,
            enforcement=enforcement,
        )

    def _extract_response_text(self, result: dict[str, Any]) -> str:
        """Extract text content from MCP tool result.

        MCP tool results typically have structure:
        {"content": [{"type": "text", "text": "..."}]}
        """
        if not result:
            return ""

        content = result.get("content", [])
        if not isinstance(content, list):
            return json.dumps(result)

        text_parts = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    text_parts.append(item.get("text", ""))
                elif "text" in item:
                    text_parts.append(item["text"])

        if text_parts:
            return "\n".join(text_parts)

        return json.dumps(result)

    def should_intercept(self, method: str) -> bool:
        """Check if a method should be intercepted."""
        return method == "tools/call"
