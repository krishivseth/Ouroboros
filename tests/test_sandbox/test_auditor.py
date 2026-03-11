"""Tests for sandbox auditor."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch, AsyncMock

from mcp_scanner.models import Finding, RuntimeFinding, RuleID, Severity, Verdict
from ouroboros_sandbox.agent.auditor import (
    AuditContext,
    AuditReport,
    _compute_verdict,
    _generate_fallback_narrative,
)
from ouroboros_sandbox.container.manager import ContainerManager
from ouroboros_sandbox.container.network import NetworkMonitor


class TestAuditContext:
    """Tests for AuditContext."""

    def test_duration_calculation(self):
        mock_container = MagicMock(spec=ContainerManager)
        mock_network = MagicMock(spec=NetworkMonitor)
        mock_tool_ctx = MagicMock()

        ctx = AuditContext(
            target_path="/test",
            container=mock_container,
            network_monitor=mock_network,
            tool_context=mock_tool_ctx,
            start_time=100.0,
            end_time=150.0,
        )

        assert ctx.duration_seconds == 50.0

    def test_duration_zero_when_not_set(self):
        mock_container = MagicMock(spec=ContainerManager)
        mock_network = MagicMock(spec=NetworkMonitor)
        mock_tool_ctx = MagicMock()

        ctx = AuditContext(
            target_path="/test",
            container=mock_container,
            network_monitor=mock_network,
            tool_context=mock_tool_ctx,
        )

        assert ctx.duration_seconds == 0.0


class TestAuditReport:
    """Tests for AuditReport."""

    def test_to_dict(self):
        static_finding = Finding(
            rule_id=RuleID.TOOL_POISONING,
            severity=Severity.HIGH,
            title="Test Finding",
            description="Test description",
            file_path="/test/file.py",
            line_number=10,
            snippet="code",
        )

        dynamic_finding = RuntimeFinding(
            rule_id=RuleID.SANDBOX_RESPONSE_INJECTION,
            severity=Severity.CRITICAL,
            title="Injection Found",
            description="Found injection",
            target="test_tool",
            evidence="evidence",
        )

        report = AuditReport(
            target="/test",
            duration_seconds=60.0,
            overall_verdict=Verdict.BLOCK,
            static_findings=[static_finding],
            dynamic_findings=[dynamic_finding],
            network_events=[],
            tools_probed=[{"tool_name": "test"}],
            narrative="# Report",
        )

        result = report.to_dict()

        assert result["target"] == "/test"
        assert result["duration_seconds"] == 60.0
        assert result["overall_verdict"] == "block"
        assert len(result["static_findings"]) == 1
        assert len(result["dynamic_findings"]) == 1
        assert result["static_findings"][0]["rule_id"] == "tool-poisoning"
        assert result["dynamic_findings"][0]["rule_id"] == "sandbox-response-injection"


class TestComputeVerdict:
    """Tests for _compute_verdict function."""

    def test_safe_with_no_findings(self):
        mock_container = MagicMock(spec=ContainerManager)
        mock_network = MagicMock(spec=NetworkMonitor)
        mock_network.get_suspicious_events.return_value = []
        mock_tool_ctx = MagicMock()

        ctx = AuditContext(
            target_path="/test",
            container=mock_container,
            network_monitor=mock_network,
            tool_context=mock_tool_ctx,
        )

        verdict = _compute_verdict(ctx)
        assert verdict == Verdict.SAFE

    def test_block_with_critical_finding(self):
        mock_container = MagicMock(spec=ContainerManager)
        mock_network = MagicMock(spec=NetworkMonitor)
        mock_network.get_suspicious_events.return_value = []
        mock_tool_ctx = MagicMock()

        ctx = AuditContext(
            target_path="/test",
            container=mock_container,
            network_monitor=mock_network,
            tool_context=mock_tool_ctx,
            dynamic_findings=[
                RuntimeFinding(
                    rule_id=RuleID.SANDBOX_RESPONSE_INJECTION,
                    severity=Severity.CRITICAL,
                    title="Critical",
                    description="desc",
                    target="tool",
                    evidence="ev",
                )
            ],
        )

        verdict = _compute_verdict(ctx)
        assert verdict == Verdict.BLOCK

    def test_caution_with_medium_finding(self):
        mock_container = MagicMock(spec=ContainerManager)
        mock_network = MagicMock(spec=NetworkMonitor)
        mock_network.get_suspicious_events.return_value = []
        mock_tool_ctx = MagicMock()

        ctx = AuditContext(
            target_path="/test",
            container=mock_container,
            network_monitor=mock_network,
            tool_context=mock_tool_ctx,
            static_findings=[
                Finding(
                    rule_id=RuleID.EXCESSIVE_PERMISSIONS,
                    severity=Severity.MEDIUM,
                    title="Medium",
                    description="desc",
                    file_path="/test.py",
                    line_number=1,
                    snippet="code",
                )
            ],
        )

        verdict = _compute_verdict(ctx)
        assert verdict == Verdict.CAUTION

    def test_block_with_suspicious_network(self):
        mock_container = MagicMock(spec=ContainerManager)
        mock_network = MagicMock(spec=NetworkMonitor)
        mock_network.get_suspicious_events.return_value = [MagicMock()]
        mock_tool_ctx = MagicMock()

        ctx = AuditContext(
            target_path="/test",
            container=mock_container,
            network_monitor=mock_network,
            tool_context=mock_tool_ctx,
        )

        verdict = _compute_verdict(ctx)
        assert verdict == Verdict.BLOCK


class TestGenerateFallbackNarrative:
    """Tests for _generate_fallback_narrative function."""

    def test_generates_markdown(self):
        mock_container = MagicMock(spec=ContainerManager)
        mock_network = MagicMock(spec=NetworkMonitor)
        mock_network.get_suspicious_events.return_value = []
        mock_tool_ctx = MagicMock()

        ctx = AuditContext(
            target_path="/test",
            container=mock_container,
            network_monitor=mock_network,
            tool_context=mock_tool_ctx,
            start_time=100.0,
            end_time=150.0,
        )

        narrative = _generate_fallback_narrative(ctx)

        assert "# Security Audit Report" in narrative
        assert "Executive Summary" in narrative
        assert "50.0 seconds" in narrative

    def test_includes_findings(self):
        mock_container = MagicMock(spec=ContainerManager)
        mock_network = MagicMock(spec=NetworkMonitor)
        mock_network.get_suspicious_events.return_value = []
        mock_tool_ctx = MagicMock()

        ctx = AuditContext(
            target_path="/test",
            container=mock_container,
            network_monitor=mock_network,
            tool_context=mock_tool_ctx,
            static_findings=[
                Finding(
                    rule_id=RuleID.TOOL_POISONING,
                    severity=Severity.HIGH,
                    title="Test Finding",
                    description="desc",
                    file_path="/test.py",
                    line_number=1,
                    snippet="code",
                )
            ],
        )

        narrative = _generate_fallback_narrative(ctx)

        assert "Test Finding" in narrative
        assert "HIGH" in narrative
