"""Schema drift detection probe (Phase 3 stub)."""
from __future__ import annotations

from mcp_scanner.models import RuntimeFinding

from ..core.probes.base import BaseProbe, ProbeInput


class SchemaDriftProbe(BaseProbe):
    """Detects when MCP tool responses diverge from declared JSON schema."""

    probe_id = "schema-drift"

    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        # Phase 3 implementation
        return []
