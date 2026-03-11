"""MCP JSON-RPC client for communicating with servers in containers."""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from .manager import ContainerManager, ExecResult

logger = logging.getLogger(__name__)


@dataclass
class ToolSchema:
    """Schema for an MCP tool."""
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class MCPResponse:
    """Response from an MCP server."""
    id: str | int | None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None

    @property
    def success(self) -> bool:
        return self.error is None


class MCPClient:
    """JSON-RPC client for MCP servers running in containers.

    Communicates with the server via stdin/stdout using docker exec.
    """

    def __init__(
        self,
        container: ContainerManager,
        server_command: str,
        workdir: str | None = None,
    ):
        self.container = container
        self.server_command = server_command
        self.workdir = workdir or container.config.workdir
        self._server_pid: int | None = None
        self._initialized: bool = False
        self._server_info: dict[str, Any] = {}
        self._tools: list[ToolSchema] = []

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def server_info(self) -> dict[str, Any]:
        return self._server_info

    @property
    def tools(self) -> list[ToolSchema]:
        return self._tools

    async def start_server(self) -> ExecResult:
        """Start the MCP server process in the container.

        The server is started in the background and we verify it's running.
        """
        logger.info("Starting MCP server: %s", self.server_command)

        result = self.container.exec(
            f"nohup {self.server_command} > /tmp/mcp_server.log 2>&1 & echo $!",
            workdir=self.workdir,
        )

        if result.success and result.stdout.strip():
            try:
                self._server_pid = int(result.stdout.strip())
                logger.info("Server started with PID %d", self._server_pid)
            except ValueError:
                logger.warning("Could not parse server PID: %s", result.stdout)

        await asyncio.sleep(1.0)

        return result

    async def initialize(self) -> dict[str, Any]:
        """Send initialize request to the MCP server.

        Returns:
            Server capabilities and info.
        """
        request = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "ouroboros-sandbox",
                    "version": "0.1.0",
                },
            },
        }

        response = await self._send_request(request)

        if response.success and response.result:
            self._server_info = response.result
            self._initialized = True

            await self._send_notification("notifications/initialized", {})

            logger.info("Server initialized: %s", self._server_info.get("serverInfo", {}))
            return self._server_info

        error_msg = response.error.get("message", "Unknown error") if response.error else "No response"
        raise RuntimeError(f"Failed to initialize MCP server: {error_msg}")

    async def list_tools(self) -> list[ToolSchema]:
        """Get list of available tools from the server.

        Returns:
            List of tool schemas.
        """
        if not self._initialized:
            raise RuntimeError("Server not initialized. Call initialize() first.")

        request = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/list",
            "params": {},
        }

        response = await self._send_request(request)

        if response.success and response.result:
            tools_data = response.result.get("tools", [])
            self._tools = [
                ToolSchema(
                    name=t.get("name", ""),
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                )
                for t in tools_data
            ]
            logger.info("Discovered %d tools", len(self._tools))
            return self._tools

        error_msg = response.error.get("message", "Unknown error") if response.error else "No response"
        raise RuntimeError(f"Failed to list tools: {error_msg}")

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Call an MCP tool and return the result.

        Args:
            name: Tool name.
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        if not self._initialized:
            raise RuntimeError("Server not initialized. Call initialize() first.")

        request = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments or {},
            },
        }

        logger.debug("Calling tool %s with args: %s", name, arguments)
        response = await self._send_request(request)

        if response.success and response.result:
            return response.result

        error_msg = response.error.get("message", "Unknown error") if response.error else "No response"
        return {"error": error_msg}

    async def stop_server(self) -> None:
        """Stop the MCP server process."""
        if self._server_pid:
            logger.info("Stopping server PID %d", self._server_pid)
            self.container.exec(f"kill {self._server_pid} 2>/dev/null || true")
            self._server_pid = None

        self._initialized = False

    async def _send_request(self, request: dict[str, Any]) -> MCPResponse:
        """Send a JSON-RPC request to the server via stdin/stdout.

        Uses a helper script to pipe the request to the server.
        """
        request_json = json.dumps(request)

        script = f'''
python3 << 'PYEOF'
import sys
import json
import subprocess

request = {repr(request_json)}

proc = subprocess.Popen(
    {repr(self.server_command.split())},
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    cwd={repr(self.workdir)},
)

try:
    stdout, stderr = proc.communicate(input=request.encode() + b"\\n", timeout=30)
    for line in stdout.decode().strip().split("\\n"):
        if line.strip():
            print(line)
            break
except subprocess.TimeoutExpired:
    proc.kill()
    print(json.dumps({{"error": {{"code": -32000, "message": "Timeout"}}}}))
except Exception as e:
    print(json.dumps({{"error": {{"code": -32000, "message": str(e)}}}}))
PYEOF
'''

        result = self.container.exec(script, timeout=60)

        if not result.success:
            return MCPResponse(
                id=request.get("id"),
                error={"code": -32000, "message": result.stderr or "Execution failed"},
            )

        try:
            response_line = result.stdout.strip().split("\n")[-1]
            response_data = json.loads(response_line)
            return MCPResponse(
                id=response_data.get("id"),
                result=response_data.get("result"),
                error=response_data.get("error"),
            )
        except json.JSONDecodeError as e:
            return MCPResponse(
                id=request.get("id"),
                error={"code": -32700, "message": f"Invalid JSON response: {e}"},
            )

    async def _send_notification(self, method: str, params: dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        notification_json = json.dumps(notification)

        self.container.exec(
            f"echo '{notification_json}' | timeout 5 {self.server_command} || true",
            timeout=10,
        )

    def get_tool_schema(self, tool_name: str) -> ToolSchema | None:
        """Get schema for a specific tool by name."""
        for tool in self._tools:
            if tool.name == tool_name:
                return tool
        return None
