from __future__ import annotations

import ast

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry
from .base import BaseRule


def _fstring_contains_param(node: ast.JoinedStr, param_names: set[str]) -> str | None:
    """Return the first param name found inside an f-string, or None."""
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            if isinstance(value.value, ast.Name) and value.value.id in param_names:
                return value.value.id
    return None


class PromptInjectionRule(BaseRule):
    rule_id = RuleID.PROMPT_INJECTION
    name = "Prompt Injection"
    description = (
        "Detects resources/tools that reflect unsanitized user input "
        "back into LLM context via f-string interpolation."
    )
    severity = Severity.HIGH

    def analyze(self, registry: ServerRegistry) -> list[Finding]:
        findings: list[Finding] = []

        for entry in [*registry.resources, *registry.tools]:
            params = set(entry.param_names)
            if not params:
                continue

            for node in ast.walk(entry.node):
                if not isinstance(node, ast.Return):
                    continue
                if not isinstance(node.value, ast.JoinedStr):
                    continue

                param_hit = _fstring_contains_param(node.value, params)
                if param_hit is None:
                    continue

                lineno = node.lineno
                snippet = entry.source_lines[lineno - 1] if lineno <= len(entry.source_lines) else ""
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=f"Unsanitized parameter '{param_hit}' reflected via f-string return",
                    description=(
                        f"Function '{entry.name}' returns an f-string that directly "
                        f"interpolates the user-controlled parameter '{param_hit}'. "
                        f"An attacker can inject arbitrary instructions via this parameter."
                    ),
                    file_path=entry.file_path,
                    line_number=lineno,
                    snippet=snippet.rstrip(),
                    metadata={"function": entry.name, "parameter": param_hit},
                ))

        return findings
