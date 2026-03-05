from __future__ import annotations

import ast

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry
from .base import BaseRule

_SECRET_KEYWORDS = {"token", "key", "secret", "password", "credential", "api_key", "auth", "bearer"}


class TokenLeakageRule(BaseRule):
    rule_id = RuleID.TOKEN_LEAKAGE
    name = "Token Leakage"
    description = (
        "Detects tool return values that interpolate variables named "
        "token, key, secret, password, or credential."
    )
    severity = Severity.CRITICAL

    def analyze(self, registry: ServerRegistry) -> list[Finding]:
        findings: list[Finding] = []

        for tool in registry.tools:
            for node in ast.walk(tool.node):
                if not isinstance(node, ast.Return):
                    continue
                if not isinstance(node.value, ast.JoinedStr):
                    continue

                leaked: list[str] = []
                for val in node.value.values:
                    if not isinstance(val, ast.FormattedValue):
                        continue
                    names = [
                        n.id for n in ast.walk(val.value)
                        if isinstance(n, ast.Name)
                    ]
                    for name in names:
                        name_lower = name.lower()
                        if any(kw in name_lower for kw in _SECRET_KEYWORDS):
                            leaked.append(name)

                if not leaked:
                    continue

                lineno = node.lineno
                snippet = tool.source_lines[lineno - 1] if lineno <= len(tool.source_lines) else ""
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=f"Potential secret leaked in return of '{tool.name}'",
                    description=(
                        f"Tool '{tool.name}' returns an f-string interpolating "
                        f"variable(s) with secret-like names: {', '.join(leaked)}. "
                        f"These values may be exposed to the LLM and ultimately "
                        f"to the user."
                    ),
                    file_path=tool.file_path,
                    line_number=lineno,
                    snippet=snippet.rstrip(),
                    metadata={"function": tool.name, "leaked_names": leaked},
                ))

        return findings
