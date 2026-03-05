from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field

from .models import ParsedFile

logger = logging.getLogger(__name__)


@dataclass
class ToolEntry:
    name: str
    docstring: str | None
    param_names: list[str]
    node: ast.FunctionDef
    file_path: str
    line_number: int
    source_lines: list[str]
    server_var: str | None = None


@dataclass
class ResourceEntry:
    name: str
    uri_template: str | None
    docstring: str | None
    param_names: list[str]
    node: ast.FunctionDef
    file_path: str
    line_number: int
    source_lines: list[str]
    server_var: str | None = None


@dataclass
class ServerInstance:
    server_name: str | None
    variable_name: str
    file_path: str
    line_number: int


@dataclass
class ServerRegistry:
    tools: list[ToolEntry] = field(default_factory=list)
    resources: list[ResourceEntry] = field(default_factory=list)
    servers: list[ServerInstance] = field(default_factory=list)


def _get_mcp_variable_names(tree: ast.Module) -> set[str]:
    """Find variable names assigned to FastMCP(...) calls."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        func = node.value.func
        is_fastmcp = (
            (isinstance(func, ast.Name) and func.id == "FastMCP")
            or (isinstance(func, ast.Attribute) and func.attr == "FastMCP")
        )
        if is_fastmcp:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def _extract_server_instances(tree: ast.Module, file_path: str) -> list[ServerInstance]:
    """Extract FastMCP('name') constructor calls."""
    instances: list[ServerInstance] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        func = node.value.func
        is_fastmcp = (
            (isinstance(func, ast.Name) and func.id == "FastMCP")
            or (isinstance(func, ast.Attribute) and func.attr == "FastMCP")
        )
        if not is_fastmcp:
            continue

        server_name: str | None = None
        if node.value.args and isinstance(node.value.args[0], ast.Constant):
            server_name = str(node.value.args[0].value)

        for target in node.targets:
            if isinstance(target, ast.Name):
                instances.append(ServerInstance(
                    server_name=server_name,
                    variable_name=target.id,
                    file_path=file_path,
                    line_number=node.lineno,
                ))
    return instances


def _is_mcp_decorator(decorator: ast.expr, mcp_vars: set[str], kind: str) -> bool:
    """Check if *decorator* matches @mcp_var.tool() / @mcp_var.resource(...)."""
    # @mcp.tool() or @mcp.resource(...)  (Call wrapping Attribute)
    if isinstance(decorator, ast.Call):
        return _is_mcp_decorator(decorator.func, mcp_vars, kind)

    # @mcp.tool  (bare Attribute, no parentheses)
    if isinstance(decorator, ast.Attribute):
        if decorator.attr != kind:
            return False
        if isinstance(decorator.value, ast.Name) and decorator.value.id in mcp_vars:
            return True

    return False


def _extract_resource_uri(decorator: ast.expr) -> str | None:
    """Pull the URI template string from @mcp.resource('notes://{user_id}')."""
    if isinstance(decorator, ast.Call) and decorator.args:
        first = decorator.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def _get_func_param_names(node: ast.FunctionDef) -> list[str]:
    """Return parameter names excluding 'self' and 'ctx'/'context'."""
    skip = {"self", "cls", "ctx", "context"}
    names: list[str] = []
    for arg in node.args.args:
        if arg.arg.lower() not in skip:
            names.add(arg.arg) if False else names.append(arg.arg)
    return names


def extract(parsed_files: list[ParsedFile]) -> ServerRegistry:
    """Build a ServerRegistry from a list of parsed files."""
    registry = ServerRegistry()

    for pf in parsed_files:
        mcp_vars = _get_mcp_variable_names(pf.tree)
        if not mcp_vars:
            continue

        registry.servers.extend(_extract_server_instances(pf.tree, pf.file_path))

        for node in ast.walk(pf.tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            for decorator in node.decorator_list:
                matched_server_var = None
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if isinstance(decorator.func.value, ast.Name):
                        matched_server_var = decorator.func.value.id
                elif isinstance(decorator, ast.Attribute) and isinstance(decorator.value, ast.Name):
                    matched_server_var = decorator.value.id

                if _is_mcp_decorator(decorator, mcp_vars, "tool"):
                    registry.tools.append(ToolEntry(
                        name=node.name,
                        docstring=ast.get_docstring(node),
                        param_names=_get_func_param_names(node),
                        node=node,
                        file_path=pf.file_path,
                        line_number=node.lineno,
                        source_lines=pf.source_lines,
                        server_var=matched_server_var,
                    ))
                    break

                if _is_mcp_decorator(decorator, mcp_vars, "resource"):
                    uri = _extract_resource_uri(decorator)
                    registry.resources.append(ResourceEntry(
                        name=node.name,
                        uri_template=uri,
                        docstring=ast.get_docstring(node),
                        param_names=_get_func_param_names(node),
                        node=node,
                        file_path=pf.file_path,
                        line_number=node.lineno,
                        source_lines=pf.source_lines,
                        server_var=matched_server_var,
                    ))
                    break

    return registry
