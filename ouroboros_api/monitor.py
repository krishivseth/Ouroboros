"""WebSocket-based monitor for real-time MCP traffic."""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)


@dataclass
class MonitorEvent:
    """An event from the MCP proxy."""
    type: str
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)


class MonitorEventBus:
    """Global event bus for MCP traffic monitoring.
    
    The proxy publishes events here, and WebSocket clients subscribe.
    """
    
    def __init__(self, max_history: int = 100):
        self._subscribers: list[asyncio.Queue[MonitorEvent]] = []
        self._history: list[MonitorEvent] = []
        self._max_history = max_history
        self._lock = asyncio.Lock()
    
    async def publish(self, event: MonitorEvent) -> None:
        """Publish an event to all subscribers."""
        async with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
            
            for queue in self._subscribers:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning("Subscriber queue full, dropping event")
    
    async def subscribe(self) -> AsyncIterator[MonitorEvent]:
        """Subscribe to events. Yields events as they arrive."""
        queue: asyncio.Queue[MonitorEvent] = asyncio.Queue(maxsize=100)
        
        async with self._lock:
            self._subscribers.append(queue)
        
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield event
                except asyncio.TimeoutError:
                    yield MonitorEvent(type="heartbeat", data={"status": "connected"})
        finally:
            async with self._lock:
                if queue in self._subscribers:
                    self._subscribers.remove(queue)
    
    def get_history(self) -> list[MonitorEvent]:
        """Get recent event history."""
        return list(self._history)
    
    @property
    def subscriber_count(self) -> int:
        """Number of active subscribers."""
        return len(self._subscribers)


# Global event bus instance
monitor_bus = MonitorEventBus()


async def emit_call_start(
    call_id: str,
    target: str,
    target_type: str,
    tool_name: str | None = None,
) -> None:
    """Emit a call_start event."""
    await monitor_bus.publish(MonitorEvent(
        type="call_start",
        data={
            "id": call_id,
            "target": target,
            "targetType": target_type,
            "toolName": tool_name,
            "timestamp": datetime.utcnow().isoformat(),
        },
    ))


async def emit_probe_result(
    call_id: str,
    probe_name: str,
    duration_ms: float,
    findings: list[dict[str, Any]],
    detail: list[str],
) -> None:
    """Emit a probe_result event."""
    await monitor_bus.publish(MonitorEvent(
        type="probe_result",
        data={
            "id": call_id,
            "probe": probe_name,
            "duration_ms": duration_ms,
            "findings": findings,
            "detail": detail,
        },
    ))


async def emit_verdict(
    call_id: str,
    verdict: dict[str, Any],
) -> None:
    """Emit a verdict event."""
    await monitor_bus.publish(MonitorEvent(
        type="verdict",
        data={
            "id": call_id,
            "verdict": verdict,
        },
    ))
