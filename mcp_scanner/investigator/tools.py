from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from ..loader import load
from ..models import ParsedFile
from ..registry import ServerRegistry, ToolEntry, ResourceEntry


# ---------------------------------------------------------------------------
# Bedrock toolSpec definitions (Converse API format)
# ---------------------------------------------------------------------------

TOOL_CONFIG: dict[str, Any] = {
    "tools": [
        {
            "toolSpec": {
                "name": "get_function_body",
                "description": (
                    "Retrieve the full source code of a Python function by file path "
                    "and function name. Returns source, line range, parameter names, "
                    "and docstring. Use this before check_endpoint_reachability to "
                    "discover parameter names."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the Python file containing the function.",
                            },
                            "function_name": {
                                "type": "string",
                                "description": "Name of the function to retrieve.",
                            },
                        },
                        "required": ["file_path", "function_name"],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "check_endpoint_reachability",
                "description": (
                    "Trace a specific parameter through a function body to determine "
                    "if it reaches a dangerous sink (subprocess, eval, exec, open, "
                    "os.system, os.popen). You MUST call get_function_body first to "
                    "discover the function's parameter names, then pass one of those "
                    "names as param_name."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the Python file.",
                            },
                            "function_name": {
                                "type": "string",
                                "description": "Name of the function to analyze.",
                            },
                            "param_name": {
                                "type": "string",
                                "description": (
                                    "Parameter name to trace (must be one of the "
                                    "values from get_function_body's params list)."
                                ),
                            },
                        },
                        "required": ["file_path", "function_name", "param_name"],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "find_related_patterns",
                "description": (
                    "Search across all scanned files for occurrences of a pattern "
                    "string or regex. Useful for checking if a poisoned docstring "
                    "references other tools, or if a credential pattern appears elsewhere."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "pattern": {
                                "type": "string",
                                "description": "The literal string or regex pattern to search for.",
                            },
                            "is_regex": {
                                "type": "boolean",
                                "description": "If true, treat pattern as a regex. Defaults to false.",
                            },
                        },
                        "required": ["pattern"],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "get_file_imports",
                "description": (
                    "Return all import statements from a given Python file. Helps "
                    "understand what modules are available (subprocess, os, sys) and "
                    "whether dangerous capabilities are imported."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the Python file.",
                            },
                        },
                        "required": ["file_path"],
                    }
                },
            }
        },
    ]
}


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

_DANGEROUS_SINKS = {
    "eval", "exec", "compile",
    "os.system", "os.popen", "os.execvp",
    "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.run", "subprocess.Popen",
    "open",
}

_DANGEROUS_NAMES = {s.split(".")[-1] for s in _DANGEROUS_SINKS}
_DANGEROUS_ATTRS = {s for s in _DANGEROUS_SINKS if "." in s}


def _find_function_node(
    file_path: str,
    function_name: str,
    registry: ServerRegistry,
) -> tuple[ast.FunctionDef | None, list[str]]:
    """Locate a FunctionDef and its file's source_lines."""
    for entry in (*registry.tools, *registry.resources):
        if entry.file_path == file_path and entry.name == function_name:
            return entry.node, entry.source_lines

    # Fallback: parse the file directly
    path = Path(file_path)
    if not path.is_file():
        return None, []
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None, []
    source_lines = source.split("\n")
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return None, []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            return node, source_lines
    return None, source_lines


def _get_func_params(node: ast.FunctionDef) -> list[str]:
    skip = {"self", "cls", "ctx", "context"}
    return [a.arg for a in node.args.args if a.arg.lower() not in skip]


def _extract_source(
    node: ast.FunctionDef, source_lines: list[str],
) -> tuple[str, int, int]:
    start = node.lineno
    end = node.end_lineno or node.lineno
    lines = source_lines[start - 1 : end]
    return "\n".join(lines), start, end


def get_function_body(
    file_path: str,
    function_name: str,
    registry: ServerRegistry,
) -> dict[str, Any]:
    func_node, source_lines = _find_function_node(file_path, function_name, registry)
    if func_node is None:
        return {"error": f"Function '{function_name}' not found in {file_path}"}

    source, line_start, line_end = _extract_source(func_node, source_lines)
    return {
        "source": source,
        "line_start": line_start,
        "line_end": line_end,
        "params": _get_func_params(func_node),
        "docstring": ast.get_docstring(func_node),
    }


def _collect_names_in_node(node: ast.expr) -> set[str]:
    """Collect all ast.Name ids referenced within an expression."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names


def _resolve_sink_name(node: ast.expr) -> str | None:
    """Turn a call target into a dotted string like 'subprocess.check_output'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value_name = _resolve_sink_name(node.value)
        if value_name:
            return f"{value_name}.{node.attr}"
        return node.attr
    return None


def check_endpoint_reachability(
    file_path: str,
    function_name: str,
    param_name: str,
    registry: ServerRegistry,
) -> dict[str, Any]:
    func_node, source_lines = _find_function_node(file_path, function_name, registry)
    if func_node is None:
        return {"error": f"Function '{function_name}' not found in {file_path}"}

    params = _get_func_params(func_node)
    if param_name not in params:
        return {
            "error": (
                f"Parameter '{param_name}' not found in {function_name}. "
                f"Available params: {params}"
            )
        }

    # Lightweight taint tracking: track names that carry the tainted value
    tainted: set[str] = {param_name}
    taint_path: list[str] = [f"param:{param_name}"]
    reachable_sinks: list[dict[str, Any]] = []

    for node in ast.walk(func_node):
        # Track assignments: if RHS references a tainted name, LHS becomes tainted
        if isinstance(node, ast.Assign):
            rhs_names = _collect_names_in_node(node.value)
            if rhs_names & tainted:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        tainted.add(target.id)
                        taint_path.append(f"assign:{target.id} (line {node.lineno})")

        # Track f-strings containing tainted names
        if isinstance(node, ast.JoinedStr):
            fstring_names = _collect_names_in_node(node)
            if fstring_names & tainted:
                for parent in ast.walk(func_node):
                    if isinstance(parent, ast.Assign):
                        if parent.value is node or (
                            hasattr(parent, 'value') and any(
                                child is node for child in ast.walk(parent.value)
                            )
                        ):
                            for t in parent.targets:
                                if isinstance(t, ast.Name):
                                    tainted.add(t.id)
                                    taint_path.append(
                                        f"fstring:{t.id} (line {parent.lineno})"
                                    )

        # Check calls to dangerous sinks
        if isinstance(node, ast.Call):
            sink_name = _resolve_sink_name(node.func)
            if sink_name is None:
                continue

            is_dangerous = (
                sink_name in _DANGEROUS_NAMES
                or sink_name in _DANGEROUS_ATTRS
            )
            if not is_dangerous:
                continue

            # Check if any argument references a tainted name
            all_arg_names: set[str] = set()
            for arg in node.args:
                all_arg_names |= _collect_names_in_node(arg)
            for kw in node.keywords:
                if kw.value:
                    all_arg_names |= _collect_names_in_node(kw.value)

            if all_arg_names & tainted:
                line = node.lineno
                snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                reachable_sinks.append({
                    "sink": sink_name,
                    "line": line,
                    "snippet": snippet,
                })
                taint_path.append(f"sink:{sink_name} (line {line})")

    return {
        "reachable_sinks": reachable_sinks,
        "taint_path": taint_path,
    }


def find_related_patterns(
    pattern: str,
    target_path: str,
    is_regex: bool = False,
) -> dict[str, Any]:
    if is_regex:
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            return {"error": f"invalid regex: {exc}"}
    else:
        compiled = None

    parsed_files = load(target_path)
    matches: list[dict[str, Any]] = []
    max_matches = 50

    for pf in parsed_files:
        for i, line in enumerate(pf.source_lines):
            if compiled is not None:
                if compiled.search(line):
                    matches.append({
                        "file_path": pf.file_path,
                        "line_number": i + 1,
                        "line_content": line.rstrip(),
                    })
            else:
                if pattern in line:
                    matches.append({
                        "file_path": pf.file_path,
                        "line_number": i + 1,
                        "line_content": line.rstrip(),
                    })
            if len(matches) >= max_matches:
                break
        if len(matches) >= max_matches:
            break

    return {"matches": matches}


def get_file_imports(
    file_path: str,
) -> dict[str, Any]:
    path = Path(file_path)
    if not path.is_file():
        return {"error": f"File not found: {file_path}"}

    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {"error": f"Could not read {file_path}: {exc}"}

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as exc:
        return {"error": f"Syntax error in {file_path}: {exc}"}

    imports: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append({
                    "module": alias.name,
                    "names": None,
                    "line_number": node.lineno,
                })
        elif isinstance(node, ast.ImportFrom):
            imports.append({
                "module": node.module or "",
                "names": [alias.name for alias in node.names],
                "line_number": node.lineno,
            })

    return {"imports": imports}


# ---------------------------------------------------------------------------
# Dispatcher -- routes tool name to implementation
# ---------------------------------------------------------------------------

def dispatch_tool(
    tool_use: dict[str, Any],
    registry: ServerRegistry,
    target_path: str,
) -> dict[str, Any]:
    """Route a Bedrock tool_use block to the matching implementation.

    Returns a toolResult dict ready to be embedded in a Converse message.
    """
    name = tool_use["name"]
    tool_input = tool_use.get("input", {})
    tool_use_id = tool_use["toolUseId"]

    try:
        if name == "get_function_body":
            result = get_function_body(
                file_path=tool_input["file_path"],
                function_name=tool_input["function_name"],
                registry=registry,
            )
        elif name == "check_endpoint_reachability":
            result = check_endpoint_reachability(
                file_path=tool_input["file_path"],
                function_name=tool_input["function_name"],
                param_name=tool_input["param_name"],
                registry=registry,
            )
        elif name == "find_related_patterns":
            result = find_related_patterns(
                pattern=tool_input["pattern"],
                target_path=target_path,
                is_regex=tool_input.get("is_regex", False),
            )
        elif name == "get_file_imports":
            result = get_file_imports(
                file_path=tool_input["file_path"],
            )
        else:
            result = {"error": f"Unknown tool: {name}"}
    except Exception as exc:
        result = {"error": f"Tool '{name}' failed: {exc}"}

    return {
        "toolUseId": tool_use_id,
        "content": [{"json": result}],
    }
