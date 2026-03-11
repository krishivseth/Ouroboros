"""Async stdio proxy for MCP servers."""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import uuid
from datetime import datetime
from typing import Any

import aiohttp

from ..core.engine import RuntimeEngine, create_default_engine
from ..policy.enforcer import PolicyEnforcer
from ..policy.loader import load_policy
from .canary import CanaryTracker
from .interceptor import InterceptAction, Interceptor

logger = logging.getLogger(__name__)


class MonitorEmitter:
    """Emits events to the Ouroboros API monitor endpoint."""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self._api_url = api_url
        self._session: aiohttp.ClientSession | None = None
    
    async def start(self) -> None:
        self._session = aiohttp.ClientSession()
    
    async def stop(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None
    
    async def emit(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit an event to the monitor API."""
        if not self._session:
            return
        
        try:
            async with self._session.post(
                f"{self._api_url}/api/monitor/emit",
                json={"type": event_type, "data": data},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status != 200:
                    logger.warning("Failed to emit event: %s", await resp.text())
        except Exception as e:
            logger.debug("Failed to emit event: %s", e)


class StdioProxy:
    """Async proxy that wraps an MCP server process.

    Reads JSON-RPC messages from stdin (from client), forwards to child
    server process, intercepts responses, and writes back to stdout.
    """

    def __init__(
        self,
        server_command: list[str],
        engine: RuntimeEngine | None = None,
        enforcer: PolicyEnforcer | None = None,
        canary: CanaryTracker | None = None,
        emitter: MonitorEmitter | None = None,
    ):
        self._server_command = server_command
        self._engine = engine or create_default_engine()
        self._enforcer = enforcer or PolicyEnforcer(load_policy())
        self._canary = canary or CanaryTracker()
        self._interceptor = Interceptor(self._engine, self._enforcer, self._canary)
        self._emitter = emitter
        self._process: asyncio.subprocess.Process | None = None
        self._running = False

    async def start(self) -> None:
        """Start the proxy and child server process."""
        logger.info("Starting proxy with command: %s", " ".join(self._server_command))

        if self._emitter:
            await self._emitter.start()

        self._process = await asyncio.create_subprocess_exec(
            *self._server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        self._running = True

        await asyncio.gather(
            self._read_client_stdin(),
            self._read_server_stderr(),
        )

    async def stop(self) -> None:
        """Stop the proxy and terminate the child process."""
        self._running = False
        if self._emitter:
            await self._emitter.stop()
        if self._process:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
            self._process = None

    async def _read_client_stdin(self) -> None:
        """Read JSON-RPC messages from client stdin and process them."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        buffer = b""

        while self._running:
            try:
                chunk = await reader.read(4096)
                if not chunk:
                    break

                buffer += chunk

                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if line.strip():
                        await self._handle_client_message(line.decode("utf-8"))

            except Exception as e:
                logger.exception("Error reading from client stdin: %s", e)
                break

        await self.stop()

    async def _handle_client_message(self, message: str) -> None:
        """Process a JSON-RPC message from the client."""
        try:
            data = json.loads(message)
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON from client: %s", e)
            return

        method = data.get("method", "")
        params = data.get("params", {})
        request_id = data.get("id")
        
        call_id = str(uuid.uuid4())
        tool_name = params.get("name", "unknown") if method == "tools/call" else None
        
        # Emit call_start event for tool calls
        if method == "tools/call" and self._emitter:
            await self._emitter.emit("call_start", {
                "id": call_id,
                "target": tool_name,
                "targetType": "mcp",
                "toolName": tool_name,
                "timestamp": datetime.utcnow().isoformat(),
            })

        intercept_result = self._interceptor.on_request(method, params, request_id)

        if intercept_result.modified_message:
            data["params"] = intercept_result.modified_message.get("params", params)

        await self._send_to_server(data)

        if self._interceptor.should_intercept(method):
            response = await self._read_server_response(request_id)
            if response:
                await self._handle_server_response(method, params, response, request_id, call_id)
        else:
            response = await self._read_server_response(request_id)
            if response:
                await self._send_to_client(response)

    async def _handle_server_response(
        self,
        method: str,
        params: dict[str, Any],
        response: dict[str, Any],
        request_id: Any,
        call_id: str,
    ) -> None:
        """Process a response from the server before forwarding to client."""
        result = response.get("result", {})
        tool_name = params.get("name", "unknown")
        start_time = datetime.utcnow()

        intercept_result = await asyncio.to_thread(
            self._interceptor.on_response,
            method,
            params,
            result,
            request_id,
        )
        
        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        # Emit probe results
        if self._emitter and intercept_result.verdict:
            for probe_name in ["injection", "ssl", "headers", "redirect", "content"]:
                findings = [
                    {
                        "id": str(uuid.uuid4()),
                        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        "rule": f.rule_id.value if hasattr(f.rule_id, 'value') else str(f.rule_id),
                        "evidence": f.evidence,
                    }
                    for f in intercept_result.findings
                ]
                await self._emitter.emit("probe_result", {
                    "id": call_id,
                    "probe": f"PROBE: {probe_name}",
                    "duration_ms": duration_ms / 5,
                    "findings": findings if probe_name == "injection" else [],
                    "detail": [f"Scanned {tool_name} response"],
                })

        if intercept_result.action == InterceptAction.BLOCK:
            # Emit verdict event
            if self._emitter:
                await self._emitter.emit("verdict", {
                    "id": call_id,
                    "verdict": {
                        "id": call_id,
                        "target": tool_name,
                        "targetType": "mcp",
                        "toolName": tool_name,
                        "timestamp": datetime.utcnow().isoformat(),
                        "verdict": "BLOCK",
                        "action": "blocked",
                        "totalDuration_ms": duration_ms,
                        "findings": [
                            {
                                "id": str(uuid.uuid4()),
                                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                                "rule": f.rule_id.value if hasattr(f.rule_id, 'value') else str(f.rule_id),
                                "evidence": f.evidence,
                            }
                            for f in intercept_result.findings
                        ],
                    },
                })
            
            if intercept_result.error_response:
                await self._send_to_client(intercept_result.error_response)
            else:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32001,
                        "message": "Ouroboros: request blocked",
                    },
                }
                await self._send_to_client(error_response)

            logger.warning(
                "Blocked response for request %s: %d findings",
                request_id,
                len(intercept_result.findings),
            )
        else:
            # Emit verdict event for PASS/WARN
            if self._emitter:
                verdict_str = "CAUTION" if intercept_result.action == InterceptAction.WARN else "SAFE"
                action_str = "warned" if intercept_result.action == InterceptAction.WARN else "passed"
                await self._emitter.emit("verdict", {
                    "id": call_id,
                    "verdict": {
                        "id": call_id,
                        "target": tool_name,
                        "targetType": "mcp",
                        "toolName": tool_name,
                        "timestamp": datetime.utcnow().isoformat(),
                        "verdict": verdict_str,
                        "action": action_str,
                        "totalDuration_ms": duration_ms,
                        "findings": [
                            {
                                "id": str(uuid.uuid4()),
                                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                                "rule": f.rule_id.value if hasattr(f.rule_id, 'value') else str(f.rule_id),
                                "evidence": f.evidence,
                            }
                            for f in intercept_result.findings
                        ],
                    },
                })
            
            if intercept_result.action == InterceptAction.WARN:
                logger.info(
                    "Warning for request %s: %d findings",
                    request_id,
                    len(intercept_result.findings),
                )

            await self._send_to_client(response)

    async def _send_to_server(self, message: dict[str, Any]) -> None:
        """Send a JSON-RPC message to the child server."""
        if not self._process or not self._process.stdin:
            return

        data = json.dumps(message) + "\n"
        self._process.stdin.write(data.encode("utf-8"))
        await self._process.stdin.drain()

    async def _read_server_response(self, expected_id: Any) -> dict[str, Any] | None:
        """Read a response from the server stdout."""
        if not self._process or not self._process.stdout:
            return None

        try:
            line = await asyncio.wait_for(
                self._process.stdout.readline(),
                timeout=30.0,
            )
            if not line:
                return None

            response = json.loads(line.decode("utf-8"))
            return response

        except asyncio.TimeoutError:
            logger.error("Timeout waiting for server response")
            return None
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON from server: %s", e)
            return None

    async def _send_to_client(self, message: dict[str, Any]) -> None:
        """Send a JSON-RPC message to the client via stdout."""
        data = json.dumps(message) + "\n"
        sys.stdout.write(data)
        sys.stdout.flush()

    async def _read_server_stderr(self) -> None:
        """Read and log stderr from the child server."""
        if not self._process or not self._process.stderr:
            return

        while self._running:
            try:
                line = await self._process.stderr.readline()
                if not line:
                    break
                logger.debug("Server stderr: %s", line.decode("utf-8").strip())
            except Exception:
                break


async def run_proxy(
    server_command: list[str],
    policy_path: str | None = None,
    api_url: str = "http://localhost:8000",
    emit_events: bool = True,
) -> None:
    """Run the stdio proxy with the given server command."""
    engine = create_default_engine()
    policy = load_policy(policy_path)
    enforcer = PolicyEnforcer(policy)
    emitter = MonitorEmitter(api_url) if emit_events else None

    proxy = StdioProxy(
        server_command=server_command,
        engine=engine,
        enforcer=enforcer,
        emitter=emitter,
    )

    try:
        await proxy.start()
    except KeyboardInterrupt:
        await proxy.stop()
    except Exception as e:
        logger.exception("Proxy error: %s", e)
        await proxy.stop()
        raise
