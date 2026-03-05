from __future__ import annotations

import ast

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry
from .base import BaseRule

_DANGEROUS_FUNCS = {"open", "os.path.exists", "os.path.isfile", "os.listdir"}


def _unparse_func(node: ast.expr) -> str:
    """Best-effort unparse of a Call.func node."""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _contains_param_name(node: ast.expr, param_names: set[str]) -> str | None:
    """Walk an expression tree looking for an ast.Name matching a param."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in param_names:
            return child.id
    return None


class ExcessivePermissionsRule(BaseRule):
    rule_id = RuleID.EXCESSIVE_PERMISSIONS
    name = "Excessive Permissions"
    description = (
        "Detects tools that pass user-controlled input to open() or "
        "os.path.exists() without path prefix validation."
    )
    severity = Severity.HIGH

    def analyze(self, registry: ServerRegistry) -> list[Finding]:
        findings: list[Finding] = []

        for entry in [*registry.tools, *registry.resources]:
            params = set(entry.param_names)
            if not params:
                continue

            for node in ast.walk(entry.node):
                if not isinstance(node, ast.Call):
                    continue

                func_name = _unparse_func(node.func)
                if func_name not in _DANGEROUS_FUNCS:
                    continue

                for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                    tainted = _contains_param_name(arg, params)
                    if tainted is None:
                        continue

                    lineno = node.lineno
                    snippet = entry.source_lines[lineno - 1] if lineno <= len(entry.source_lines) else ""
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=f"User parameter '{tainted}' passed to {func_name}()",
                        description=(
                            f"Function '{entry.name}' passes user-controlled parameter "
                            f"'{tainted}' to '{func_name}()' without path validation, "
                            f"allowing path traversal or unauthorized file access."
                        ),
                        file_path=entry.file_path,
                        line_number=lineno,
                        snippet=snippet.rstrip(),
                        metadata={
                            "function": entry.name,
                            "parameter": tainted,
                            "dangerous_call": func_name,
                        },
                    ))
                    break

        return findings
