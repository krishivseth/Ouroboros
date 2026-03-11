"""Runtime engine that orchestrates probe execution."""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from mcp_scanner.models import RuntimeFinding, RuntimeVerdict, Verdict

from .cache import VerdictCache
from .probes.base import BaseProbe, ProbeInput
from .verdict import compute_verdict

if TYPE_CHECKING:
    from ..policy.enforcer import PolicyEnforcer

logger = logging.getLogger(__name__)


class RuntimeEngine:
    """Orchestrates security probe execution and verdict computation.

    The engine runs all registered probes against input data, caches
    results, and computes an overall verdict.
    """

    def __init__(
        self,
        probes: list[BaseProbe] | None = None,
        cache: VerdictCache | None = None,
        enforcer: "PolicyEnforcer | None" = None,
    ):
        self._probes = probes or []
        self._cache = cache or VerdictCache()
        self._enforcer = enforcer

    @property
    def probes(self) -> list[BaseProbe]:
        return self._probes

    @property
    def cache(self) -> VerdictCache:
        return self._cache

    def add_probe(self, probe: BaseProbe) -> None:
        """Register a probe with the engine."""
        self._probes.append(probe)

    def scan(self, input: ProbeInput) -> RuntimeVerdict:
        """Run all probes against the input and return a verdict.

        Checks cache first. If cache miss, runs probes and caches result.
        """
        target = input.tool_name or input.url or "unknown"

        # Check cache
        cache_key = self._cache.compute_key(
            input.tool_name,
            input.tool_params,
            input.response_body,
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            logger.debug("Cache hit for %s", target)
            return cached

        # Run probes
        start_time = time.perf_counter()
        findings: list[RuntimeFinding] = []
        reasoning: list[str] = []

        for probe in self._probes:
            probe_start = time.perf_counter()
            reasoning.append(f"Running {probe.probe_id} probe...")

            try:
                probe_findings = probe.run(input)
                probe_duration = (time.perf_counter() - probe_start) * 1000

                if probe_findings:
                    findings.extend(probe_findings)
                    reasoning.append(
                        f"  -> {len(probe_findings)} finding(s) in {probe_duration:.1f}ms"
                    )
                else:
                    reasoning.append(f"  -> clean in {probe_duration:.1f}ms")

            except Exception as e:
                logger.exception("Probe %s failed: %s", probe.probe_id, e)
                reasoning.append(f"  -> ERROR: {e}")

        total_duration = (time.perf_counter() - start_time) * 1000

        # Compute verdict
        verdict = compute_verdict(
            findings=findings,
            target=target,
            probe_duration_ms=total_duration,
            reasoning_chain=reasoning,
        )

        # Cache result
        self._cache.put(cache_key, verdict)

        logger.debug(
            "Scan complete for %s: %s (%d findings, %.1fms)",
            target,
            verdict.verdict.value,
            len(findings),
            total_duration,
        )

        return verdict

    def scan_url(self, url: str) -> RuntimeVerdict:
        """Convenience method to scan a URL endpoint."""
        input = ProbeInput(url=url)
        return self.scan(input)

    def scan_mcp_response(
        self,
        tool_name: str,
        tool_params: dict,
        response_body: str,
    ) -> RuntimeVerdict:
        """Convenience method to scan an MCP tool response."""
        input = ProbeInput(
            tool_name=tool_name,
            tool_params=tool_params,
            response_body=response_body,
        )
        return self.scan(input)


def create_default_engine() -> RuntimeEngine:
    """Create an engine with all default probes registered."""
    from .probes import ALL_PROBES

    engine = RuntimeEngine()
    for probe_cls in ALL_PROBES:
        engine.add_probe(probe_cls())

    return engine
