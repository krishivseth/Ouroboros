from __future__ import annotations

import ast

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry
from .base import BaseRule


def _get_module_level_var_names(tree: ast.Module) -> set[str]:
    """Collect variable names assigned at module level."""
    names: set[str] = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


class RugPullRule(BaseRule):
    rule_id = RuleID.RUG_PULL
    name = "Rug Pull Attack"
    description = (
        "Detects runtime mutation of __doc__ on tool functions, "
        "enabling behaviour changes after installation."
    )
    severity = Severity.CRITICAL

    def analyze(self, registry: ServerRegistry) -> list[Finding]:
        findings: list[Finding] = []
        tool_names = {t.name for t in registry.tools}

        seen_files: dict[str, ast.Module] = {}
        for tool in registry.tools:
            if tool.file_path not in seen_files:
                source = "\n".join(tool.source_lines)
                try:
                    seen_files[tool.file_path] = ast.parse(source, filename=tool.file_path)
                except SyntaxError:
                    continue

        for tool in registry.tools:
            tree = seen_files.get(tool.file_path)
            if tree is None:
                continue

            # Detection path 1: assignment to <tool_name>.__doc__
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if not isinstance(target, ast.Attribute):
                        continue
                    if target.attr != "__doc__":
                        continue
                    if isinstance(target.value, ast.Name) and target.value.id in tool_names:
                        lineno = node.lineno
                        snippet = tool.source_lines[lineno - 1] if lineno <= len(tool.source_lines) else ""
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=f"Runtime __doc__ mutation on tool '{target.value.id}'",
                            description=(
                                f"The docstring of tool '{target.value.id}' is reassigned "
                                f"at runtime (line {lineno}), enabling a rug-pull attack "
                                f"where the tool's advertised behaviour changes after "
                                f"installation."
                            ),
                            file_path=tool.file_path,
                            line_number=lineno,
                            snippet=snippet.rstrip(),
                            metadata={"function": target.value.id},
                        ))

            # Detection path 2: state-dependent branching inside the tool body
            module_vars = _get_module_level_var_names(tree)
            if not module_vars:
                continue

            for node in ast.walk(tool.node):
                if not isinstance(node, ast.If):
                    continue
                for child in ast.walk(node.test):
                    if isinstance(child, ast.Name) and child.id in module_vars:
                        lineno = node.lineno
                        snippet = tool.source_lines[lineno - 1] if lineno <= len(tool.source_lines) else ""
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            title=f"State-dependent branching in tool '{tool.name}'",
                            description=(
                                f"Tool '{tool.name}' contains an if-condition referencing "
                                f"module-level variable '{child.id}' (line {lineno}), "
                                f"which may enable state-dependent behaviour changes."
                            ),
                            file_path=tool.file_path,
                            line_number=lineno,
                            snippet=snippet.rstrip(),
                            metadata={"function": tool.name, "variable": child.id},
                        ))
                        break

        return findings
