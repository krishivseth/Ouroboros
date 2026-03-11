"""SSE streaming utilities."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)


def format_sse_event(event_type: str, data: dict[str, Any]) -> str:
    """Format data as an SSE event string."""
    json_data = json.dumps(data, default=str)
    return f"event: {event_type}\ndata: {json_data}\n\n"


async def heartbeat_generator(
    interval_seconds: float = 15.0,
) -> AsyncIterator[str]:
    """Generate periodic heartbeat events."""
    import asyncio
    while True:
        await asyncio.sleep(interval_seconds)
        yield format_sse_event("heartbeat", {"timestamp": datetime.utcnow().isoformat()})


class EventEmitter:
    """Helper class for emitting events during audit."""

    def __init__(self, job):
        self.job = job
        self._phase = "initializing"

    async def phase(self, phase_name: str, status: str = "running") -> None:
        """Emit a phase change event."""
        self._phase = phase_name
        await self.job.emit_event("phase", {
            "phase": phase_name,
            "status": status,
        })

    async def finding(
        self,
        severity: str,
        title: str,
        rule_id: str,
        target: str | None = None,
        description: str | None = None,
    ) -> None:
        """Emit a finding event."""
        await self.job.emit_event("finding", {
            "severity": severity,
            "title": title,
            "rule_id": rule_id,
            "target": target,
            "description": description,
        })

    async def tool_call(
        self,
        tool_name: str,
        tool_input: dict[str, Any] | None = None,
        is_adversarial: bool = False,
    ) -> None:
        """Emit a tool call event."""
        await self.job.emit_event("tool_call", {
            "tool": tool_name,
            "input": tool_input,
            "adversarial": is_adversarial,
            "phase": self._phase,
        })

    async def agent_thought(self, text: str) -> None:
        """Emit an agent thought/reasoning event."""
        await self.job.emit_event("agent_thought", {
            "text": text,
            "phase": self._phase,
        })

    async def tool_discovered(
        self,
        tool_name: str,
        description: str | None = None,
        risk_level: str | None = None,
    ) -> None:
        """Emit a tool discovery event."""
        await self.job.emit_event("tool_discovered", {
            "tool_name": tool_name,
            "description": description,
            "risk_level": risk_level,
        })

    async def network_event(
        self,
        destination: str,
        port: int,
        protocol: str = "tcp",
    ) -> None:
        """Emit a network activity event."""
        await self.job.emit_event("network_event", {
            "destination": destination,
            "port": port,
            "protocol": protocol,
        })

    async def complete(
        self,
        verdict: str,
        findings_count: int,
        duration_seconds: float,
    ) -> None:
        """Emit completion event."""
        await self.job.emit_event("complete", {
            "verdict": verdict,
            "findings_count": findings_count,
            "duration_seconds": duration_seconds,
        })

    async def error(self, message: str) -> None:
        """Emit error event."""
        await self.job.emit_event("error", {
            "message": message,
            "phase": self._phase,
        })
