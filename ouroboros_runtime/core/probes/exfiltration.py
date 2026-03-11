"""Exfiltration detection probe (Phase 2 stub)."""
from __future__ import annotations

from mcp_scanner.models import RuntimeFinding

from .base import BaseProbe, ProbeInput


class ExfiltrationProbe(BaseProbe):
    """Detects potential data exfiltration in request payloads.

    Phase 2 implementation will scan outgoing requests for sensitive
    data being sent to untrusted destinations.
    """

    probe_id = "exfiltration"

    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        # Phase 2 implementation: request payload analysis
        return []
