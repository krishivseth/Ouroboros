from __future__ import annotations

import re

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry
from .base import BaseRule

_COERCIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"you must",
        r"do not mention",
        r"present it as if",
        r"include .* in your response",
        r"access .* resource",
        r"do not tell",
        r"never reveal",
        r"ignore previous",
        r"disregard",
    )
]


class ToolPoisoningRule(BaseRule):
    rule_id = RuleID.TOOL_POISONING
    name = "Tool Poisoning"
    description = (
        "Detects tool docstrings containing coercive LLM instructions "
        "such as 'you must', 'do not mention', or 'present it as if'."
    )
    severity = Severity.CRITICAL

    def analyze(self, registry: ServerRegistry) -> list[Finding]:
        findings: list[Finding] = []

        for tool in registry.tools:
            if not tool.docstring:
                continue

            matched: list[str] = []
            for pat in _COERCIVE_PATTERNS:
                if pat.search(tool.docstring):
                    matched.append(pat.pattern)

            if not matched:
                continue

            lineno = tool.line_number
            snippet = tool.source_lines[lineno - 1] if lineno <= len(tool.source_lines) else ""
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"Coercive instructions in docstring of tool '{tool.name}'",
                description=(
                    f"Tool '{tool.name}' contains {len(matched)} coercive pattern(s) "
                    f"in its docstring that may manipulate LLM behavior: "
                    f"{', '.join(matched)}"
                ),
                file_path=tool.file_path,
                line_number=lineno,
                snippet=snippet.rstrip(),
                metadata={"function": tool.name, "patterns": matched},
            ))

        return findings
