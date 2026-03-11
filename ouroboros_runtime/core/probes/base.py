"""Base probe interface and input dataclass."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from mcp_scanner.models import RuntimeFinding


@dataclass
class ProbeInput:
    """Input data for security probes.

    Carries both request and response fields. Probes use whichever fields
    are relevant to their analysis.
    """

    # Request fields
    url: str | None = None
    method: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None

    # Response fields
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str | None = None

    # MCP-specific fields
    tool_name: str | None = None
    tool_params: dict[str, Any] = field(default_factory=dict)
    mcp_result: dict[str, Any] | None = None


class BaseProbe(ABC):
    """Abstract base class for all security probes.

    Probes are synchronous. The proxy wraps them with asyncio.to_thread
    for async execution.
    """

    probe_id: str

    @abstractmethod
    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        """Execute the probe and return any findings.

        Args:
            input: The probe input containing request/response data.

        Returns:
            List of RuntimeFinding objects, empty if no issues detected.
        """
        ...
