from __future__ import annotations

import logging
import time

from .loader import load
from .models import Finding, ScanResult, Severity
from .registry import ServerRegistry, extract
from .rules import ALL_RULES
from .rules.multi_vector import MultiVectorRule

logger = logging.getLogger(__name__)


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan(
    target_path: str,
    *,
    min_severity: Severity = Severity.LOW,
) -> ScanResult:
    """Run the full scan pipeline against *target_path*."""
    result, _ = scan_with_registry(target_path, min_severity=min_severity)
    return result


def scan_with_registry(
    target_path: str,
    *,
    min_severity: Severity = Severity.LOW,
) -> tuple[ScanResult, ServerRegistry]:
    """Run the full scan pipeline and also return the ServerRegistry."""
    t0 = time.monotonic()

    parsed_files = load(target_path)
    registry = extract(parsed_files)

    # Pass 1: standard rules
    findings: list[Finding] = []
    for rule_cls in ALL_RULES:
        rule = rule_cls()
        logger.debug("Running rule: %s", rule.name)
        findings.extend(rule.analyze(registry))

    # Pass 2: meta-rule (needs prior findings)
    meta = MultiVectorRule()
    findings.extend(meta.analyze(registry, findings))

    findings = _deduplicate(findings)
    findings = [f for f in findings if f.severity >= min_severity]
    findings.sort(key=lambda f: f.severity.rank, reverse=True)

    elapsed = time.monotonic() - t0
    result = ScanResult(
        target_path=target_path,
        findings=findings,
        files_scanned=len(parsed_files),
        duration_seconds=round(elapsed, 3),
    )
    return result, registry
