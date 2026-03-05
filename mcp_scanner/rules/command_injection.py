from __future__ import annotations

import ast

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry
from .base import BaseRule

_SHELL_SINKS = {
    "subprocess.check_output", "subprocess.run", "subprocess.call",
    "subprocess.Popen",
    "os.system", "os.popen",
}


def _unparse_func(node: ast.expr) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _fstring_contains_param(node: ast.JoinedStr, param_names: set[str]) -> str | None:
    for val in node.values:
        if isinstance(val, ast.FormattedValue):
            for child in ast.walk(val.value):
                if isinstance(child, ast.Name) and child.id in param_names:
                    return child.id
    return None


def _arg_is_fstring_with_param(
    args: list[ast.expr], param_names: set[str]
) -> tuple[str | None, bool]:
    """Check if any argument is an f-string containing a param name.

    Also checks for plain param names (for non-f-string injection).
    Returns (param_name, is_fstring).
    """
    for arg in args:
        if isinstance(arg, ast.JoinedStr):
            hit = _fstring_contains_param(arg, param_names)
            if hit:
                return hit, True
        for child in ast.walk(arg):
            if isinstance(child, ast.JoinedStr):
                hit = _fstring_contains_param(child, param_names)
                if hit:
                    return hit, True
    return None, False


class CommandInjectionRule(BaseRule):
    rule_id = RuleID.COMMAND_INJECTION
    name = "Command Injection"
    description = (
        "Detects shell command strings built via f-string interpolation "
        "of tool parameters passed to subprocess with shell=True."
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
                if func_name not in _SHELL_SINKS:
                    continue

                if not _has_shell_true(node):
                    continue

                all_args = [*node.args, *(kw.value for kw in node.keywords if kw.arg != "shell")]
                tainted, is_fstring = _arg_is_fstring_with_param(all_args, params)

                # Also catch the case where the command was built in a
                # preceding assignment (e.g. `command = f"ping {host}"`)
                # and passed as a variable to the subprocess call.
                if tainted is None:
                    tainted = self._check_variable_fstring(tool.node, node, params)
                    is_fstring = tainted is not None

                if tainted is None:
                    continue

                lineno = node.lineno
                snippet = tool.source_lines[lineno - 1] if lineno <= len(tool.source_lines) else ""
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=f"Command injection via f-string with '{tainted}' in '{tool.name}'",
                    description=(
                        f"Tool '{tool.name}' builds a shell command using f-string "
                        f"interpolation of parameter '{tainted}' and passes it to "
                        f"'{func_name}()' with shell=True, enabling command injection."
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

    @staticmethod
    def _check_variable_fstring(
        func_node: ast.FunctionDef,
        call_node: ast.Call,
        param_names: set[str],
    ) -> str | None:
        """If the subprocess call uses a variable, trace it back to see if
        it was assigned an f-string containing a param name."""
        var_names: set[str] = set()
        for arg in call_node.args:
            if isinstance(arg, ast.Name):
                var_names.add(arg.id)

        if not var_names:
            return None

        for node in ast.walk(func_node):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if target.id not in var_names:
                    continue
                if isinstance(node.value, ast.JoinedStr):
                    hit = _fstring_contains_param(node.value, param_names)
                    if hit:
                        return hit
        return None
