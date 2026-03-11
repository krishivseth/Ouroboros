"""Tests for verdict computation and caching."""
from __future__ import annotations

import time

import pytest

from mcp_scanner.models import RuleID, RuntimeFinding, RuntimeVerdict, Severity, Verdict
from ouroboros_runtime.core.cache import VerdictCache
from ouroboros_runtime.core.verdict import compute_verdict, merge_verdicts


class TestVerdictComputation:
    """Tests for verdict computation logic."""

    def test_no_findings_safe(self):
        """No findings should result in SAFE verdict."""
        verdict = compute_verdict([], "test", 10.0)
        assert verdict.verdict == Verdict.SAFE
        assert len(verdict.findings) == 0

    def test_low_severity_safe(self):
        """Low severity findings should result in SAFE verdict."""
        findings = [
            RuntimeFinding(
                rule_id=RuleID.HEADER_MISCONFIGURATION,
                severity=Severity.LOW,
                title="Test",
                description="Test",
                target="test",
                evidence="Test",
            )
        ]
        verdict = compute_verdict(findings, "test", 10.0)
        assert verdict.verdict == Verdict.SAFE

    def test_medium_severity_caution(self):
        """Medium severity findings should result in CAUTION verdict."""
        findings = [
            RuntimeFinding(
                rule_id=RuleID.MALICIOUS_CONTENT,
                severity=Severity.MEDIUM,
                title="Test",
                description="Test",
                target="test",
                evidence="Test",
            )
        ]
        verdict = compute_verdict(findings, "test", 10.0)
        assert verdict.verdict == Verdict.CAUTION

    def test_high_severity_block(self):
        """High severity findings should result in BLOCK verdict."""
        findings = [
            RuntimeFinding(
                rule_id=RuleID.RESPONSE_INJECTION,
                severity=Severity.HIGH,
                title="Test",
                description="Test",
                target="test",
                evidence="Test",
            )
        ]
        verdict = compute_verdict(findings, "test", 10.0)
        assert verdict.verdict == Verdict.BLOCK

    def test_critical_severity_block(self):
        """Critical severity findings should result in BLOCK verdict."""
        findings = [
            RuntimeFinding(
                rule_id=RuleID.CROSS_TOOL_EXFILTRATION,
                severity=Severity.CRITICAL,
                title="Test",
                description="Test",
                target="test",
                evidence="Test",
            )
        ]
        verdict = compute_verdict(findings, "test", 10.0)
        assert verdict.verdict == Verdict.BLOCK

    def test_max_severity_wins(self):
        """Verdict should be based on max severity."""
        findings = [
            RuntimeFinding(
                rule_id=RuleID.HEADER_MISCONFIGURATION,
                severity=Severity.LOW,
                title="Low",
                description="Test",
                target="test",
                evidence="Test",
            ),
            RuntimeFinding(
                rule_id=RuleID.RESPONSE_INJECTION,
                severity=Severity.HIGH,
                title="High",
                description="Test",
                target="test",
                evidence="Test",
            ),
        ]
        verdict = compute_verdict(findings, "test", 10.0)
        assert verdict.verdict == Verdict.BLOCK


class TestMergeVerdicts:
    """Tests for merging multiple verdicts."""

    def test_merge_empty(self):
        """Merging empty list should return SAFE verdict."""
        verdict = merge_verdicts([])
        assert verdict.verdict == Verdict.SAFE

    def test_merge_single(self):
        """Merging single verdict should return that verdict."""
        v = RuntimeVerdict(
            verdict=Verdict.CAUTION,
            target="test",
            findings=[],
            probe_duration_ms=10.0,
        )
        merged = merge_verdicts([v])
        assert merged.verdict == Verdict.CAUTION

    def test_merge_strictest_wins(self):
        """Merged verdict should be the strictest."""
        v1 = RuntimeVerdict(
            verdict=Verdict.SAFE,
            target="test",
            findings=[],
            probe_duration_ms=10.0,
        )
        v2 = RuntimeVerdict(
            verdict=Verdict.BLOCK,
            target="test",
            findings=[],
            probe_duration_ms=10.0,
        )
        merged = merge_verdicts([v1, v2])
        assert merged.verdict == Verdict.BLOCK

    def test_merge_combines_findings(self):
        """Merged verdict should combine all findings."""
        f1 = RuntimeFinding(
            rule_id=RuleID.HEADER_MISCONFIGURATION,
            severity=Severity.LOW,
            title="F1",
            description="Test",
            target="test",
            evidence="Test",
        )
        f2 = RuntimeFinding(
            rule_id=RuleID.RESPONSE_INJECTION,
            severity=Severity.HIGH,
            title="F2",
            description="Test",
            target="test",
            evidence="Test",
        )
        v1 = RuntimeVerdict(
            verdict=Verdict.SAFE,
            target="test",
            findings=[f1],
            probe_duration_ms=10.0,
        )
        v2 = RuntimeVerdict(
            verdict=Verdict.BLOCK,
            target="test",
            findings=[f2],
            probe_duration_ms=20.0,
        )
        merged = merge_verdicts([v1, v2])
        assert len(merged.findings) == 2
        assert merged.probe_duration_ms == 30.0


class TestVerdictCache:
    """Tests for verdict caching."""

    @pytest.fixture
    def cache(self):
        return VerdictCache(max_size=10, ttl_seconds=1.0)

    @pytest.fixture
    def sample_verdict(self):
        return RuntimeVerdict(
            verdict=Verdict.SAFE,
            target="test",
            findings=[],
            probe_duration_ms=10.0,
        )

    def test_compute_key(self, cache):
        """Cache key should be deterministic."""
        key1 = cache.compute_key("tool", {"a": 1}, "response")
        key2 = cache.compute_key("tool", {"a": 1}, "response")
        assert key1 == key2

    def test_compute_key_different_inputs(self, cache):
        """Different inputs should produce different keys."""
        key1 = cache.compute_key("tool1", {}, "response")
        key2 = cache.compute_key("tool2", {}, "response")
        assert key1 != key2

    def test_put_and_get(self, cache, sample_verdict):
        """Put and get should work correctly."""
        key = cache.compute_key("tool", {}, "response")
        cache.put(key, sample_verdict)
        retrieved = cache.get(key)
        assert retrieved is not None
        assert retrieved.verdict == sample_verdict.verdict

    def test_get_missing(self, cache):
        """Get on missing key should return None."""
        result = cache.get("nonexistent")
        assert result is None

    def test_ttl_expiration(self, cache, sample_verdict):
        """Entries should expire after TTL."""
        key = cache.compute_key("tool", {}, "response")
        cache.put(key, sample_verdict)

        time.sleep(1.5)

        result = cache.get(key)
        assert result is None

    def test_lru_eviction(self, sample_verdict):
        """Oldest entries should be evicted when max size reached."""
        cache = VerdictCache(max_size=3, ttl_seconds=60.0)

        for i in range(5):
            key = cache.compute_key(f"tool{i}", {}, "response")
            cache.put(key, sample_verdict)

        assert cache.size() == 3

        key0 = cache.compute_key("tool0", {}, "response")
        assert cache.get(key0) is None

        key4 = cache.compute_key("tool4", {}, "response")
        assert cache.get(key4) is not None

    def test_clear(self, cache, sample_verdict):
        """Clear should remove all entries."""
        key = cache.compute_key("tool", {}, "response")
        cache.put(key, sample_verdict)
        cache.clear()
        assert cache.size() == 0

    def test_invalidate(self, cache, sample_verdict):
        """Invalidate should remove specific entry."""
        key = cache.compute_key("tool", {}, "response")
        cache.put(key, sample_verdict)
        cache.invalidate(key)
        assert cache.get(key) is None
