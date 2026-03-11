"""Canary token generation and tracking for cross-tool exfiltration detection."""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any

from mcp_scanner.models import RuleID, RuntimeFinding, Severity


@dataclass
class CanaryTracker:
    """Tracks canary tokens for detecting cross-tool data leakage.

    Generates a unique session canary and tracks which requests it was
    injected into. If the canary appears in a response from a different
    tool/server, it indicates data leakage.
    """

    _session_canary: str = field(default_factory=lambda: secrets.token_hex(16))
    _injected_requests: dict[str, str] = field(default_factory=dict)

    @property
    def session_canary(self) -> str:
        """The unique canary token for this session."""
        return self._session_canary

    def inject(self, params: dict[str, Any], request_id: str) -> dict[str, Any]:
        """Inject canary token into MCP request params.

        Adds the canary to params._meta.ouroboros_canary without modifying
        the tool's actual input parameters.

        Returns the modified params dict.
        """
        if "_meta" not in params:
            params["_meta"] = {}

        params["_meta"]["ouroboros_canary"] = self._session_canary
        self._injected_requests[request_id] = self._session_canary

        return params

    def check_leakage(
        self,
        response_body: str,
        tool_name: str,
        request_id: str | None = None,
    ) -> RuntimeFinding | None:
        """Check if the session canary appears in a response body.

        If the canary is found in a response from a different request than
        where it was injected, this indicates cross-tool data leakage.

        Args:
            response_body: The response content to check.
            tool_name: Name of the tool that produced this response.
            request_id: ID of the current request (to exclude self-detection).

        Returns:
            A RuntimeFinding if leakage is detected, None otherwise.
        """
        if not response_body:
            return None

        if self._session_canary not in response_body:
            return None

        return RuntimeFinding(
            rule_id=RuleID.CROSS_TOOL_EXFILTRATION,
            severity=Severity.CRITICAL,
            title="Cross-tool data exfiltration detected",
            description=(
                f"Canary token injected into request metadata was found in "
                f"response from tool '{tool_name}'. This indicates data is "
                f"leaking between tool calls or servers."
            ),
            target=tool_name,
            evidence=f"Canary '{self._session_canary[:8]}...' found in response",
            metadata={
                "canary_prefix": self._session_canary[:8],
                "tool_name": tool_name,
                "request_id": request_id,
            },
        )

    def reset(self) -> None:
        """Generate a new session canary and clear tracking state."""
        self._session_canary = secrets.token_hex(16)
        self._injected_requests.clear()

    def get_injected_count(self) -> int:
        """Return the number of requests that have been injected with canary."""
        return len(self._injected_requests)
