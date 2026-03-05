from __future__ import annotations

import ast

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry
from .base import BaseRule

_WRITE_FUNCS = {"write"}
_OPEN_FUNC = "open"


def _is_open_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name) and node.func.id == _OPEN_FUNC:
        return True
    return False


def _has_write_mode(node: ast.Call) -> bool:
    """Check if an open() call uses a write mode ('w', 'a', etc.)."""
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        return "w" in str(node.args[1].value) or "a" in str(node.args[1].value)
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            return "w" in str(kw.value.value) or "a" in str(kw.value.value)
    return False


def _has_read_mode(node: ast.Call) -> bool:
    """Check if an open() call uses read mode (default or explicit 'r')."""
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        return "r" in str(node.args[1].value)
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            return "r" in str(kw.value.value)
    # Default mode for open() is 'r'
    return len(node.args) < 2 and not any(kw.arg == "mode" for kw in node.keywords)


def _arg_contains_param(node: ast.Call, param_names: set[str]) -> str | None:
    for arg in node.args:
        for child in ast.walk(arg):
            if isinstance(child, ast.Name) and child.id in param_names:
                return child.id
    return None


def _contains_write_call(node: ast.expr) -> bool:
    """Check if any sub-expression is a .write() method call."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            if child.func.attr in _WRITE_FUNCS:
                return True
    return False


class IndirectPromptInjectionRule(BaseRule):
    rule_id = RuleID.INDIRECT_PROMPT_INJECTION
    name = "Indirect Prompt Injection"
    description = (
        "Detects tools that write user-controlled content to a file "
        "and then read it back, allowing injection through stored data."
    )
    severity = Severity.HIGH

    def analyze(self, registry: ServerRegistry) -> list[Finding]:
        findings: list[Finding] = []

        for tool in registry.tools:
            params = set(tool.param_names)
            if not params:
                continue

            write_sites: list[tuple[int, str]] = []
            read_sites: list[int] = []

            for node in ast.walk(tool.node):
                if not isinstance(node, ast.Call):
                    continue

                if _is_open_call(node):
                    tainted = _arg_contains_param(node, params)
                    if _has_write_mode(node) and tainted:
                        write_sites.append((node.lineno, tainted))
                    elif _has_read_mode(node):
                        read_sites.append(node.lineno)
                    continue

                if isinstance(node.func, ast.Attribute) and node.func.attr == "write":
                    for arg in node.args:
                        for child in ast.walk(arg):
                            if isinstance(child, ast.Name) and child.id in params:
                                write_sites.append((node.lineno, child.id))
                                break

            if not write_sites or not read_sites:
                # Fall-through: look for param directly in an f-string return
                # (user content flows straight back into LLM context)
                for node in ast.walk(tool.node):
                    if not isinstance(node, ast.Return):
                        continue
                    if not isinstance(node.value, ast.JoinedStr):
                        continue
                    for val in node.value.values:
                        if isinstance(val, ast.FormattedValue) and isinstance(val.value, ast.Name):
                            if val.value.id in params:
                                lineno = node.lineno
                                snippet = tool.source_lines[lineno - 1] if lineno <= len(tool.source_lines) else ""
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=self.severity,
                                    title=f"User content '{val.value.id}' flows into LLM context in '{tool.name}'",
                                    description=(
                                        f"Tool '{tool.name}' accepts free-form user input "
                                        f"via parameter '{val.value.id}' and returns it "
                                        f"directly in an f-string, allowing indirect "
                                        f"prompt injection."
                                    ),
                                    file_path=tool.file_path,
                                    line_number=lineno,
                                    snippet=snippet.rstrip(),
                                    metadata={"function": tool.name, "parameter": val.value.id},
                                ))
                continue

            for write_line, tainted in write_sites:
                for read_line in read_sites:
                    if read_line > write_line:
                        lineno = write_line
                        snippet = tool.source_lines[lineno - 1] if lineno <= len(tool.source_lines) else ""
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=f"Write-then-read pattern with user input '{tainted}' in '{tool.name}'",
                            description=(
                                f"Tool '{tool.name}' writes user-controlled parameter "
                                f"'{tainted}' to a file (line {write_line}) then reads a "
                                f"file back (line {read_line}), enabling indirect prompt "
                                f"injection through stored content."
                            ),
                            file_path=tool.file_path,
                            line_number=lineno,
                            snippet=snippet.rstrip(),
                            metadata={
                                "function": tool.name,
                                "parameter": tainted,
                                "write_line": write_line,
                                "read_line": read_line,
                            },
                        ))
                        break
                break

        return findings
