"""Tool capability risk scoring based on tool names and descriptions.

This probe scores tools by their inherent risk based on name and description
patterns, BEFORE any actual tool calls. A tool called `execute_code` is
dangerous by definition regardless of implementation.

The risk score represents attack surface, not exploitability. A tool flagged
as CRITICAL here may still be properly sandboxed - adversarial probing
determines whether the surface is defended.
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from typing import Any

from mcp_scanner.models import RuntimeFinding, RuleID, Severity

logger = logging.getLogger(__name__)


@dataclass
class ToolRiskResult:
    """Result of tool risk scoring."""
    tool_name: str
    severity: Severity
    category: str
    reason: str
    requires_adversarial_probing: bool = True


# Patterns for dangerous tool capabilities
# Format: (regex_pattern, category, reason)
CRITICAL_PATTERNS = [
    (r"\b(execute|eval|exec|run)[-_]?(code|command|script|shell|python|js|javascript)?\b",
     "code_execution", "Tool can execute arbitrary code"),
    (r"\b(shell|bash|sh|cmd|powershell|terminal)\b",
     "shell_access", "Tool provides shell access"),
    (r"\bsystem[-_]?(call|exec|command)?\b",
     "system_call", "Tool can make system calls"),
    (r"\b(spawn|fork|subprocess|popen)\b",
     "process_spawn", "Tool can spawn processes"),
    (r"\b(os[-_]?command|run[-_]?process)\b",
     "os_command", "Tool can run OS commands"),
]

HIGH_PATTERNS = [
    (r"\b(write|create|save|overwrite)[-_]?(file|data|content)?\b",
     "file_write", "Tool can write files"),
    (r"\b(delete|remove|unlink|rm)[-_]?(file|dir|directory)?\b",
     "file_delete", "Tool can delete files"),
    (r"\b(fetch|request|http|curl|wget|download|upload)\b",
     "network_request", "Tool can make network requests"),
    (r"\b(send|post|put)[-_]?(data|request|message)?\b",
     "network_send", "Tool can send data over network"),
    (r"\b(database|sql|query|db[-_]?exec)\b",
     "database_access", "Tool has database access"),
    (r"\b(modify|update|patch)[-_]?(file|config|settings)?\b",
     "file_modify", "Tool can modify files"),
]

MEDIUM_PATTERNS = [
    (r"\b(read|get|load|open)[-_]?(file|data|content)?\b",
     "file_read", "Tool can read files"),
    (r"\b(list|ls|dir|browse)[-_]?(dir|directory|files|folder)?\b",
     "directory_listing", "Tool can list directories"),
    (r"\b(env|environment|config|settings)\b",
     "env_access", "Tool may access environment/config"),
    (r"\b(search|find|grep|locate)\b",
     "file_search", "Tool can search filesystem"),
]

# Description patterns that indicate restricted/safe implementations
MITIGATION_PATTERNS = [
    r"\bsandbox(ed)?\b",
    r"\brestricted\b",
    r"\bsafe\b",
    r"\bvalidat(e|ed|ion)\b",
    r"\bwhitelist(ed)?\b",
    r"\ballowlist(ed)?\b",
    r"\bworkspace[-_]?only\b",
    r"\bno[-_]?(shell|exec|system)\b",
]


class ToolRiskScorer:
    """Scores tools by inherent risk based on name and description."""

    def __init__(self) -> None:
        self._compiled_critical = [(re.compile(p, re.IGNORECASE), cat, reason)
                                   for p, cat, reason in CRITICAL_PATTERNS]
        self._compiled_high = [(re.compile(p, re.IGNORECASE), cat, reason)
                               for p, cat, reason in HIGH_PATTERNS]
        self._compiled_medium = [(re.compile(p, re.IGNORECASE), cat, reason)
                                 for p, cat, reason in MEDIUM_PATTERNS]
        self._compiled_mitigations = [re.compile(p, re.IGNORECASE)
                                      for p in MITIGATION_PATTERNS]

    def _check_mitigations(self, description: str) -> bool:
        """Check if description mentions mitigations that reduce risk."""
        for pattern in self._compiled_mitigations:
            if pattern.search(description):
                return True
        return False

    def _match_patterns(
        self,
        text: str,
        patterns: list[tuple[re.Pattern, str, str]],
    ) -> tuple[str, str] | None:
        """Match text against patterns, return (category, reason) if found."""
        for pattern, category, reason in patterns:
            if pattern.search(text):
                return (category, reason)
        return None

    def score_tool(
        self,
        tool_name: str,
        description: str,
    ) -> ToolRiskResult | None:
        """Score a single tool's inherent risk.

        Args:
            tool_name: The tool's name.
            description: The tool's description.

        Returns:
            ToolRiskResult if the tool has notable risk, None otherwise.
        """
        combined_text = f"{tool_name} {description}"
        has_mitigations = self._check_mitigations(description)

        # Check CRITICAL patterns
        match = self._match_patterns(combined_text, self._compiled_critical)
        if match:
            category, reason = match
            # Mitigations downgrade CRITICAL to HIGH
            severity = Severity.HIGH if has_mitigations else Severity.CRITICAL
            return ToolRiskResult(
                tool_name=tool_name,
                severity=severity,
                category=category,
                reason=reason,
                requires_adversarial_probing=True,
            )

        # Check HIGH patterns
        match = self._match_patterns(combined_text, self._compiled_high)
        if match:
            category, reason = match
            # Mitigations downgrade HIGH to MEDIUM
            severity = Severity.MEDIUM if has_mitigations else Severity.HIGH
            return ToolRiskResult(
                tool_name=tool_name,
                severity=severity,
                category=category,
                reason=reason,
                requires_adversarial_probing=True,
            )

        # Check MEDIUM patterns
        match = self._match_patterns(combined_text, self._compiled_medium)
        if match:
            category, reason = match
            # Mitigations downgrade MEDIUM to LOW (not reported)
            if has_mitigations:
                return None
            return ToolRiskResult(
                tool_name=tool_name,
                severity=Severity.MEDIUM,
                category=category,
                reason=reason,
                requires_adversarial_probing=True,
            )

        return None

    def score_tools(
        self,
        tools: list[dict[str, Any]],
    ) -> list[ToolRiskResult]:
        """Score multiple tools.

        Args:
            tools: List of tool dicts with 'name' and 'description' keys.

        Returns:
            List of ToolRiskResult for tools with notable risk.
        """
        results = []
        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "")
            result = self.score_tool(name, description)
            if result:
                results.append(result)
                logger.info(
                    "Tool '%s' scored as %s risk: %s",
                    name, result.severity.value, result.reason
                )
        return results

    def to_findings(
        self,
        results: list[ToolRiskResult],
    ) -> list[RuntimeFinding]:
        """Convert risk results to RuntimeFinding objects.

        Args:
            results: List of ToolRiskResult from score_tools().

        Returns:
            List of RuntimeFinding objects for the audit report.
        """
        findings = []
        for result in results:
            findings.append(RuntimeFinding(
                rule_id=RuleID.DANGEROUS_TOOL_CAPABILITY,
                severity=result.severity,
                title=f"Dangerous capability: {result.category.replace('_', ' ')}",
                description=(
                    f"Tool '{result.tool_name}' has {result.reason.lower()}. "
                    f"This represents attack surface that requires adversarial "
                    f"probing to determine if properly defended."
                ),
                target=result.tool_name,
                evidence=f"Tool name/description matched {result.category} pattern",
                metadata={
                    "category": result.category,
                    "requires_probing": result.requires_adversarial_probing,
                },
            ))
        return findings


def score_tool_schemas(tools: list[dict[str, Any]]) -> list[RuntimeFinding]:
    """Convenience function to score tools and return findings.

    Args:
        tools: List of tool dicts from tools/list response.

    Returns:
        List of RuntimeFinding for dangerous tool capabilities.
    """
    scorer = ToolRiskScorer()
    results = scorer.score_tools(tools)
    return scorer.to_findings(results)
