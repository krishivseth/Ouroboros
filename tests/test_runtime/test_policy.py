"""Tests for policy loading and enforcement."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from mcp_scanner.models import RuleID, RuntimeFinding, RuntimeVerdict, Severity, Verdict
from ouroboros_runtime.policy.loader import (
    EnforcementAction,
    PolicyConfig,
    RulePolicy,
    load_policy,
)
from ouroboros_runtime.policy.enforcer import PolicyEnforcer


class TestPolicyLoader:
    """Tests for policy YAML loading."""

    def test_load_defaults(self):
        """Default policy should load successfully."""
        config = load_policy()
        assert isinstance(config, PolicyConfig)
        assert len(config.policies) > 0
        assert config.settings.cache_ttl_seconds == 300

    def test_load_custom_policy(self):
        """Custom policy file should load correctly."""
        yaml_content = """
policies:
  RESPONSE_INJECTION:
    action: warn
    severity_threshold: medium
  TLS_FAILURE:
    action: log

settings:
  cache_ttl_seconds: 600
  escalation: false
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config = load_policy(f.name)

        assert config.policies[RuleID.RESPONSE_INJECTION].action == EnforcementAction.WARN
        assert config.policies[RuleID.RESPONSE_INJECTION].severity_threshold == Severity.MEDIUM
        assert config.policies[RuleID.TLS_FAILURE].action == EnforcementAction.LOG
        assert config.settings.cache_ttl_seconds == 600
        assert config.settings.escalation is False

    def test_load_with_allowlist(self):
        """Policy with domain allowlist should load correctly."""
        yaml_content = """
policies:
  RESPONSE_INJECTION:
    action: block

allowlist:
  - domain: "api.github.com"
    rules:
      response-injection: skip
  - domain: "*.internal.com"
    rules:
      tls-failure: log
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config = load_policy(f.name)

        assert len(config.allowlist) == 2
        assert config.allowlist[0].domain == "api.github.com"
        assert config.allowlist[1].domain == "*.internal.com"

    def test_load_missing_file(self):
        """Missing file should return default policy."""
        config = load_policy("/nonexistent/path/policy.yaml")
        assert isinstance(config, PolicyConfig)
        assert len(config.policies) > 0

    def test_load_invalid_yaml(self):
        """Invalid YAML should return default policy."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: [")
            f.flush()
            config = load_policy(f.name)

        assert isinstance(config, PolicyConfig)


class TestPolicyEnforcer:
    """Tests for policy enforcement."""

    @pytest.fixture
    def enforcer(self):
        return PolicyEnforcer()

    @pytest.fixture
    def safe_verdict(self):
        return RuntimeVerdict(
            verdict=Verdict.SAFE,
            target="test",
            findings=[],
            probe_duration_ms=10.0,
        )

    @pytest.fixture
    def block_verdict(self):
        return RuntimeVerdict(
            verdict=Verdict.BLOCK,
            target="test",
            findings=[
                RuntimeFinding(
                    rule_id=RuleID.RESPONSE_INJECTION,
                    severity=Severity.HIGH,
                    title="Test finding",
                    description="Test description",
                    target="test",
                    evidence="Test evidence",
                )
            ],
            probe_duration_ms=10.0,
        )

    def test_enforce_safe_verdict(self, enforcer, safe_verdict):
        """Safe verdict should result in LOG action."""
        result = enforcer.enforce(safe_verdict)
        assert result.action == EnforcementAction.LOG
        assert len(result.blocked_findings) == 0

    def test_enforce_block_verdict(self, enforcer, block_verdict):
        """High severity injection should result in BLOCK action."""
        result = enforcer.enforce(block_verdict)
        assert result.action == EnforcementAction.BLOCK
        assert len(result.blocked_findings) == 1
        assert result.error_response is not None

    def test_enforce_with_domain_override(self):
        """Domain override should change enforcement action."""
        yaml_content = """
policies:
  RESPONSE_INJECTION:
    action: block

allowlist:
  - domain: "safe.example.com"
    rules:
      response-injection: skip
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config = load_policy(f.name)

        enforcer = PolicyEnforcer(config)

        verdict = RuntimeVerdict(
            verdict=Verdict.BLOCK,
            target="test",
            findings=[
                RuntimeFinding(
                    rule_id=RuleID.RESPONSE_INJECTION,
                    severity=Severity.HIGH,
                    title="Test",
                    description="Test",
                    target="test",
                    evidence="Test",
                )
            ],
            probe_duration_ms=10.0,
        )

        result = enforcer.enforce(verdict, domain="safe.example.com")
        # When all findings are skipped, the action should be LOG (no actionable findings)
        assert result.action in (EnforcementAction.SKIP, EnforcementAction.LOG)
        assert len(result.skipped_findings) == 1

    def test_severity_threshold(self):
        """Findings below severity threshold should be downgraded."""
        yaml_content = """
policies:
  RESPONSE_INJECTION:
    action: block
    severity_threshold: high
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config = load_policy(f.name)

        enforcer = PolicyEnforcer(config)

        verdict = RuntimeVerdict(
            verdict=Verdict.CAUTION,
            target="test",
            findings=[
                RuntimeFinding(
                    rule_id=RuleID.RESPONSE_INJECTION,
                    severity=Severity.MEDIUM,
                    title="Test",
                    description="Test",
                    target="test",
                    evidence="Test",
                )
            ],
            probe_duration_ms=10.0,
        )

        result = enforcer.enforce(verdict)
        assert result.action == EnforcementAction.WARN

    def test_error_response_format(self, enforcer, block_verdict):
        """Error response should have correct JSON-RPC format."""
        result = enforcer.enforce(block_verdict)
        assert result.error_response is not None
        assert result.error_response["jsonrpc"] == "2.0"
        assert result.error_response["error"]["code"] == -32001
        assert "Ouroboros" in result.error_response["error"]["message"]

    def test_should_block(self, enforcer, safe_verdict, block_verdict):
        """should_block should return correct boolean."""
        assert enforcer.should_block(safe_verdict) is False
        assert enforcer.should_block(block_verdict) is True
