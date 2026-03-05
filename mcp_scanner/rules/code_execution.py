from __future__ import annotations

import ast

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry
from .base import BaseRule

_DANGEROUS_SINKS = {
    "eval", "exec",
    "subprocess.check_output", "subprocess.run", "subprocess.call",
    "subprocess.Popen",
    "os.system", "os.popen",
}


def _unparse_func(node: ast.expr) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _arg_contains_param(args: list[ast.expr], param_names: set[str]) -> str | None:
    for arg in args:
        for child in ast.walk(arg):
            if isinstance(child, ast.Name) and child.id in param_names:
                return child.id
    return None


class CodeExecutionRule(BaseRule):
    rule_id = RuleID.CODE_EXECUTION
    name = "Malicious Code Execution"
    description = (
        "Detects tools passing user input to subprocess, eval(), exec(), "
        "os.system(), or writing user content to temp files and executing them."
    )
    severity = Severity.CRITICAL

    def analyze(self, registry: ServerRegistry) -> list[Finding]:
        findings: list[Finding] = []

        for tool in registry.tools:
            params = set(tool.param_names)
            if not params:
                continue

            for node in ast.walk(tool.node):
                if not isinstance(node, ast.Call):
                    continue

                func_name = _unparse_func(node.func)
                if func_name not in _DANGEROUS_SINKS:
                    continue

                all_args = [*node.args, *(kw.value for kw in node.keywords)]
                tainted = _arg_contains_param(all_args, params)
                if tainted is None:
                    continue

                lineno = node.lineno
                snippet = tool.source_lines[lineno - 1] if lineno <= len(tool.source_lines) else ""
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=f"User input '{tainted}' flows to {func_name}() in '{tool.name}'",
                    description=(
                        f"Tool '{tool.name}' passes user-controlled parameter "
                        f"'{tainted}' to '{func_name}()', enabling arbitrary code "
                        f"or command execution."
                    ),
                    file_path=tool.file_path,
                    line_number=lineno,
                    snippet=snippet.rstrip(),
                    metadata={
                        "function": tool.name,
                        "parameter": tainted,
                        "sink": func_name,
                    },
                ))

        return findings
