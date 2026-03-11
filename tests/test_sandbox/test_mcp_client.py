"""Tests for MCP client."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass

from ouroboros_sandbox.container.mcp_client import (
    MCPClient,
    MCPResponse,
    ToolSchema,
)
from ouroboros_sandbox.container.manager import ContainerManager, ContainerConfig, ExecResult


class TestToolSchema:
    """Tests for ToolSchema dataclass."""

    def test_creation(self):
        schema = ToolSchema(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object"},
        )
        assert schema.name == "test_tool"
        assert schema.description == "A test tool"
        assert schema.input_schema == {"type": "object"}


class TestMCPResponse:
    """Tests for MCPResponse dataclass."""

    def test_success_with_result(self):
        response = MCPResponse(
            id="123",
            result={"data": "test"},
            error=None,
        )
        assert response.success is True

    def test_failure_with_error(self):
        response = MCPResponse(
            id="123",
            result=None,
            error={"code": -32000, "message": "Error"},
        )
        assert response.success is False


class TestMCPClient:
    """Tests for MCPClient."""

    def _make_mock_container(self, workdir: str = "/workspace") -> MagicMock:
        """Create a properly configured mock container."""
        mock_container = MagicMock()
        mock_container.config = ContainerConfig(workdir=workdir)
        return mock_container

    def test_init(self):
        mock_container = self._make_mock_container()

        client = MCPClient(mock_container, "python -m server")

        assert client.server_command == "python -m server"
        assert client.workdir == "/workspace"
        assert client.is_initialized is False

    def test_custom_workdir(self):
        mock_container = self._make_mock_container()

        client = MCPClient(mock_container, "python -m server", workdir="/app")

        assert client.workdir == "/app"

    def test_get_tool_schema_not_found(self):
        mock_container = self._make_mock_container()

        client = MCPClient(mock_container, "python -m server")
        client._tools = [
            ToolSchema("tool1", "desc1", {}),
            ToolSchema("tool2", "desc2", {}),
        ]

        assert client.get_tool_schema("tool1") is not None
        assert client.get_tool_schema("tool3") is None

    def test_call_tool_not_initialized(self):
        mock_container = self._make_mock_container()
        client = MCPClient(mock_container, "python -m server")

        import asyncio
        with pytest.raises(RuntimeError):
            asyncio.get_event_loop().run_until_complete(client.call_tool("test", {}))

    def test_list_tools_not_initialized(self):
        mock_container = self._make_mock_container()
        client = MCPClient(mock_container, "python -m server")

        import asyncio
        with pytest.raises(RuntimeError):
            asyncio.get_event_loop().run_until_complete(client.list_tools())
