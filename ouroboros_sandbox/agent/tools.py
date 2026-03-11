"""Tool definitions and dispatch for sandbox agent."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from ..container.manager import ContainerManager
from ..container.mcp_client import MCPClient
from ..container.network import NetworkMonitor

logger = logging.getLogger(__name__)


SANDBOX_TOOL_CONFIG: dict[str, Any] = {
    "tools": [
        {
            "toolSpec": {
                "name": "run_in_container",
                "description": (
                    "Execute a shell command inside the sandboxed container. "
                    "Use this to install dependencies, inspect files, or run scripts. "
                    "Returns stdout, stderr, and exit code."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The shell command to execute.",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds (default: 30).",
                            },
                        },
                        "required": ["command"],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "read_container_file",
                "description": (
                    "Read the contents of a file from the container filesystem. "
                    "Use this to inspect source code, configuration files, or logs."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Absolute path to the file in the container.",
                            },
                        },
                        "required": ["path"],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "list_container_dir",
                "description": (
                    "List the contents of a directory in the container. "
                    "Use this to explore the codebase structure."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Absolute path to the directory.",
                            },
                        },
                        "required": ["path"],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "start_mcp_server",
                "description": (
                    "Start the MCP server with the specified command. "
                    "Call this after installing dependencies. "
                    "The server will be initialized and ready for tool calls."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Command to start the server (e.g., 'python -m server' or 'node index.js').",
                            },
                        },
                        "required": ["command"],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "get_tool_schemas",
                "description": (
                    "Get the list of available MCP tools and their schemas. "
                    "Call this after starting the server to discover what tools are available."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {},
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "call_mcp_tool",
                "description": (
                    "Call an MCP tool with the specified arguments. "
                    "Use this to probe tools for security issues. "
                    "Returns the tool's response."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "tool_name": {
                                "type": "string",
                                "description": "Name of the tool to call.",
                            },
                            "arguments": {
                                "type": "object",
                                "description": "Arguments to pass to the tool.",
                            },
                        },
                        "required": ["tool_name"],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "get_network_log",
                "description": (
                    "Get all outbound network connections made by the container. "
                    "Use this to detect data exfiltration attempts."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {},
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "get_container_logs",
                "description": (
                    "Get the stdout/stderr logs from the container. "
                    "Useful for debugging server startup issues."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "tail": {
                                "type": "integer",
                                "description": "Number of lines to return (default: 100).",
                            },
                        },
                    }
                },
            }
        },
    ]
}


class SandboxToolContext:
    """Context for sandbox tool execution."""

    def __init__(
        self,
        container: ContainerManager,
        network_monitor: NetworkMonitor,
    ):
        self.container = container
        self.network_monitor = network_monitor
        self.mcp_client: MCPClient | None = None
        self._server_started: bool = False

    @property
    def server_started(self) -> bool:
        return self._server_started


def run_in_container(
    ctx: SandboxToolContext,
    command: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """Execute a command in the container."""
    try:
        result = ctx.container.exec(command, timeout=timeout)
        return {
            "exit_code": result.exit_code,
            "stdout": result.stdout[:10000],
            "stderr": result.stderr[:5000],
            "duration_ms": result.duration_ms,
            "success": result.success,
        }
    except Exception as e:
        return {"error": str(e)}


def read_container_file(ctx: SandboxToolContext, path: str) -> dict[str, Any]:
    """Read a file from the container."""
    try:
        content = ctx.container.read_file(path)
        return {
            "path": path,
            "content": content[:50000],
            "truncated": len(content) > 50000,
        }
    except FileNotFoundError:
        return {"error": f"File not found: {path}"}
    except Exception as e:
        return {"error": str(e)}


def list_container_dir(ctx: SandboxToolContext, path: str) -> dict[str, Any]:
    """List directory contents in the container."""
    try:
        files = ctx.container.list_dir(path)
        return {
            "path": path,
            "files": files,
            "count": len(files),
        }
    except FileNotFoundError:
        return {"error": f"Directory not found: {path}"}
    except Exception as e:
        return {"error": str(e)}


async def start_mcp_server(ctx: SandboxToolContext, command: str) -> dict[str, Any]:
    """Start the MCP server and initialize it."""
    try:
        ctx.mcp_client = MCPClient(ctx.container, command)

        start_result = await ctx.mcp_client.start_server()
        if not start_result.success:
            return {
                "error": f"Failed to start server: {start_result.stderr}",
                "stdout": start_result.stdout,
            }

        try:
            server_info = await ctx.mcp_client.initialize()
            ctx._server_started = True
            return {
                "success": True,
                "server_info": server_info,
                "message": "Server started and initialized successfully",
            }
        except Exception as e:
            return {
                "error": f"Server started but initialization failed: {e}",
                "hint": "The server may not be an MCP server or may have crashed",
            }

    except Exception as e:
        return {"error": str(e)}


async def get_tool_schemas(ctx: SandboxToolContext) -> dict[str, Any]:
    """Get available tool schemas from the MCP server."""
    if not ctx.mcp_client or not ctx._server_started:
        return {"error": "Server not started. Call start_mcp_server first."}

    try:
        tools = await ctx.mcp_client.list_tools()
        return {
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                }
                for t in tools
            ],
            "count": len(tools),
        }
    except Exception as e:
        return {"error": str(e)}


async def call_mcp_tool(
    ctx: SandboxToolContext,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call an MCP tool."""
    if not ctx.mcp_client or not ctx._server_started:
        return {"error": "Server not started. Call start_mcp_server first."}

    try:
        result = await ctx.mcp_client.call_tool(tool_name, arguments or {})
        return {
            "tool_name": tool_name,
            "arguments": arguments,
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


def get_network_log(ctx: SandboxToolContext) -> dict[str, Any]:
    """Get network activity log."""
    events = ctx.network_monitor.get_events()
    suspicious = ctx.network_monitor.get_suspicious_events()

    return {
        "total_connections": len(events),
        "suspicious_connections": len(suspicious),
        "events": [e.to_dict() for e in events],
        "suspicious": [e.to_dict() for e in suspicious],
    }


def get_container_logs(ctx: SandboxToolContext, tail: int = 100) -> dict[str, Any]:
    """Get container logs."""
    try:
        logs = ctx.container.get_logs(tail=tail)
        return {
            "logs": logs,
            "lines": len(logs.split("\n")),
        }
    except Exception as e:
        return {"error": str(e)}


def _run_async_in_thread(coro):
    """Run an async coroutine in a new thread with its own event loop.
    
    This is needed because uvloop (used by uvicorn) doesn't support nest_asyncio.
    """
    import concurrent.futures
    import threading
    
    result = None
    exception = None
    
    def run():
        nonlocal result, exception
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(coro)
        except Exception as e:
            exception = e
        finally:
            loop.close()
    
    thread = threading.Thread(target=run)
    thread.start()
    thread.join(timeout=120)  # 2 minute timeout
    
    if thread.is_alive():
        raise TimeoutError("Async operation timed out")
    
    if exception:
        raise exception
    
    return result


def dispatch_sandbox_tool(
    tool_use: dict[str, Any],
    ctx: SandboxToolContext,
) -> dict[str, Any]:
    """Route tool calls to implementations.

    Args:
        tool_use: Bedrock tool_use block with name, input, toolUseId.
        ctx: Sandbox tool context with container and network monitor.

    Returns:
        toolResult dict for Bedrock Converse API.
    """
    name = tool_use["name"]
    tool_input = tool_use.get("input", {})
    tool_use_id = tool_use["toolUseId"]

    logger.debug("Dispatching tool: %s", name)

    try:
        if name == "run_in_container":
            result = run_in_container(
                ctx,
                command=tool_input["command"],
                timeout=tool_input.get("timeout", 30),
            )
        elif name == "read_container_file":
            result = read_container_file(ctx, path=tool_input["path"])
        elif name == "list_container_dir":
            result = list_container_dir(ctx, path=tool_input["path"])
        elif name == "start_mcp_server":
            result = _run_async_in_thread(
                start_mcp_server(ctx, command=tool_input["command"])
            )
        elif name == "get_tool_schemas":
            result = _run_async_in_thread(
                get_tool_schemas(ctx)
            )
        elif name == "call_mcp_tool":
            result = _run_async_in_thread(
                call_mcp_tool(
                    ctx,
                    tool_name=tool_input["tool_name"],
                    arguments=tool_input.get("arguments", {}),
                )
            )
        elif name == "get_network_log":
            result = get_network_log(ctx)
        elif name == "get_container_logs":
            result = get_container_logs(ctx, tail=tool_input.get("tail", 100))
        else:
            result = {"error": f"Unknown tool: {name}"}

    except Exception as e:
        logger.exception("Tool %s failed", name)
        result = {"error": f"Tool '{name}' failed: {e}"}

    return {
        "toolUseId": tool_use_id,
        "content": [{"json": result}],
    }
