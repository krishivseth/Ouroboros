"""Behavioral consistency probe (Phase 3 stub)."""
from __future__ import annotations

from mcp_scanner.models import RuntimeFinding

from ..core.probes.base import BaseProbe, ProbeInput


class BehavioralProbe(BaseProbe):
    """Detects inconsistent responses for identical inputs across calls."""

    probe_id = "behavioral"

    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        # Phase 3 implementation: historical comparison mode
        return []
