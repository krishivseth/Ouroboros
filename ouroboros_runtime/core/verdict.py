"""Verdict computation from findings."""
from __future__ import annotations

from mcp_scanner.models import RuntimeFinding, RuntimeVerdict, Severity, Verdict


def compute_verdict(
    findings: list[RuntimeFinding],
    target: str,
    probe_duration_ms: float,
    reasoning_chain: list[str] | None = None,
) -> RuntimeVerdict:
    """Compute overall verdict from a list of findings.

    Verdict logic:
    - No findings -> SAFE
    - Max severity HIGH or CRITICAL -> BLOCK
    - Max severity MEDIUM -> CAUTION
    - Otherwise -> SAFE
    """
    if not findings:
        return RuntimeVerdict(
            verdict=Verdict.SAFE,
            target=target,
            findings=[],
            probe_duration_ms=probe_duration_ms,
            reasoning_chain=reasoning_chain or ["No findings detected"],
        )

    max_severity = max(f.severity for f in findings)

    if max_severity >= Severity.HIGH:
        verdict = Verdict.BLOCK
    elif max_severity >= Severity.MEDIUM:
        verdict = Verdict.CAUTION
    else:
        verdict = Verdict.SAFE

    return RuntimeVerdict(
        verdict=verdict,
        target=target,
        findings=findings,
        probe_duration_ms=probe_duration_ms,
        reasoning_chain=reasoning_chain or [
            f"Found {len(findings)} issue(s)",
            f"Max severity: {max_severity.value}",
            f"Verdict: {verdict.value}",
        ],
    )


def merge_verdicts(verdicts: list[RuntimeVerdict]) -> RuntimeVerdict:
    """Merge multiple verdicts into a single verdict.

    Takes the strictest verdict and combines all findings.
    """
    if not verdicts:
        return RuntimeVerdict(
            verdict=Verdict.SAFE,
            target="unknown",
            findings=[],
            probe_duration_ms=0.0,
            reasoning_chain=["No verdicts to merge"],
        )

    all_findings: list[RuntimeFinding] = []
    all_reasoning: list[str] = []
    total_duration = 0.0

    for v in verdicts:
        all_findings.extend(v.findings)
        all_reasoning.extend(v.reasoning_chain)
        total_duration += v.probe_duration_ms

    # Determine strictest verdict
    verdict_order = {Verdict.SAFE: 0, Verdict.CAUTION: 1, Verdict.BLOCK: 2}
    strictest = max(verdicts, key=lambda v: verdict_order[v.verdict])

    return RuntimeVerdict(
        verdict=strictest.verdict,
        target=verdicts[0].target,
        findings=all_findings,
        probe_duration_ms=total_duration,
        reasoning_chain=all_reasoning,
    )
