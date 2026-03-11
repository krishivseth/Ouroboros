"""Policy enforcement engine."""
from __future__ import annotations

import fnmatch
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from mcp_scanner.models import RuleID, RuntimeFinding, RuntimeVerdict, Severity, Verdict

from .loader import EnforcementAction, PolicyConfig, RulePolicy, load_policy

logger = logging.getLogger(__name__)


@dataclass
class EnforcementResult:
    """Result of policy enforcement on a verdict."""
    action: EnforcementAction
    blocked_findings: list[RuntimeFinding] = field(default_factory=list)
    warned_findings: list[RuntimeFinding] = field(default_factory=list)
    logged_findings: list[RuntimeFinding] = field(default_factory=list)
    skipped_findings: list[RuntimeFinding] = field(default_factory=list)
    error_response: dict[str, Any] | None = None


class PolicyEnforcer:
    """Enforces policy rules on runtime verdicts.

    Maps findings to enforcement actions based on rule policies,
    severity thresholds, and domain overrides.
    """

    def __init__(self, config: PolicyConfig | None = None):
        self._config = config or load_policy()

    @property
    def config(self) -> PolicyConfig:
        return self._config

    def reload(self, path: str | None = None) -> None:
        """Reload policy configuration from file."""
        self._config = load_policy(path)

    def enforce(
        self,
        verdict: RuntimeVerdict,
        domain: str | None = None,
    ) -> EnforcementResult:
        """Apply policy enforcement to a verdict.

        Returns the strictest action across all findings, along with
        categorized findings and an error response if blocking.
        """
        result = EnforcementResult(action=EnforcementAction.LOG)

        if not verdict.findings:
            result.action = EnforcementAction.LOG
            return result

        action_priority = {
            EnforcementAction.SKIP: 0,
            EnforcementAction.LOG: 1,
            EnforcementAction.WARN: 2,
            EnforcementAction.BLOCK: 3,
        }

        for finding in verdict.findings:
            action = self._get_action_for_finding(finding, domain)

            if action == EnforcementAction.BLOCK:
                result.blocked_findings.append(finding)
            elif action == EnforcementAction.WARN:
                result.warned_findings.append(finding)
            elif action == EnforcementAction.LOG:
                result.logged_findings.append(finding)
            else:
                result.skipped_findings.append(finding)

            if action_priority[action] > action_priority[result.action]:
                result.action = action

        if result.action == EnforcementAction.BLOCK and result.blocked_findings:
            result.error_response = self._build_error_response(
                verdict, result.blocked_findings
            )

        return result

    def _get_action_for_finding(
        self,
        finding: RuntimeFinding,
        domain: str | None,
    ) -> EnforcementAction:
        """Determine the enforcement action for a single finding."""
        rule_id = finding.rule_id

        # Check domain overrides first
        if domain:
            for override in self._config.allowlist:
                if self._domain_matches(domain, override.domain):
                    rule_key = rule_id.value
                    if rule_key in override.rules:
                        return override.rules[rule_key]

        # Get rule policy
        policy = self._config.policies.get(rule_id)
        if policy is None:
            return EnforcementAction.WARN

        # Check severity threshold
        if policy.severity_threshold is not None:
            if finding.severity < policy.severity_threshold:
                return self._downgrade_action(policy.action)

        return policy.action

    def _downgrade_action(self, action: EnforcementAction) -> EnforcementAction:
        """Downgrade an action when severity threshold is not met."""
        if action == EnforcementAction.BLOCK:
            return EnforcementAction.WARN
        if action == EnforcementAction.WARN:
            return EnforcementAction.LOG
        return action

    def _domain_matches(self, domain: str, pattern: str) -> bool:
        """Check if domain matches a pattern (supports wildcards)."""
        return fnmatch.fnmatch(domain.lower(), pattern.lower())

    def _build_error_response(
        self,
        verdict: RuntimeVerdict,
        blocked_findings: list[RuntimeFinding],
    ) -> dict[str, Any]:
        """Build a JSON-RPC error response for blocked requests."""
        primary = blocked_findings[0]

        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32001,
                "message": "Ouroboros: request blocked",
                "data": {
                    "rule": primary.rule_id.value,
                    "severity": primary.severity.value,
                    "verdict": "BLOCK",
                    "explanation": primary.description,
                    "findings": [
                        {
                            "rule": f.rule_id.value,
                            "severity": f.severity.value,
                            "title": f.title,
                            "description": f.description,
                            "evidence": f.evidence[:500] if f.evidence else "",
                        }
                        for f in blocked_findings
                    ],
                },
            },
        }

    def should_block(self, verdict: RuntimeVerdict, domain: str | None = None) -> bool:
        """Quick check if a verdict should result in blocking."""
        result = self.enforce(verdict, domain)
        return result.action == EnforcementAction.BLOCK

    def get_error_response_json(
        self,
        verdict: RuntimeVerdict,
        request_id: Any = None,
    ) -> str:
        """Get JSON-formatted error response for a blocked verdict."""
        result = self.enforce(verdict)
        if result.error_response:
            result.error_response["id"] = request_id
            return json.dumps(result.error_response)
        return json.dumps({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32001,
                "message": "Ouroboros: request blocked",
                "data": {"verdict": "BLOCK"},
            },
        })
