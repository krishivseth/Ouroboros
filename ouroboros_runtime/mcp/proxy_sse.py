"""SSE/Streamable HTTP proxy for remote MCP servers.

NOT IMPLEMENTED: This module is a stub for future SSE transport support.
Currently only stdio transport is supported via proxy_stdio.py.

The SSE proxy would enable interception of remote MCP servers that use
Server-Sent Events or Streamable HTTP transport instead of stdio.

See: https://spec.modelcontextprotocol.io/specification/basic/transports/
"""
from __future__ import annotations


class SSEProxy:
    """Proxy for MCP servers using SSE/Streamable HTTP transport.
    
    NOT IMPLEMENTED: This is a placeholder for future development.
    
    The SSE proxy would:
    1. Accept incoming SSE connections from MCP clients
    2. Forward requests to the remote MCP server
    3. Intercept responses using the same RuntimeEngine as stdio proxy
    4. Stream responses back to the client with verdicts applied
    
    Challenges to address:
    - Bidirectional SSE streaming
    - Connection lifecycle management
    - Reconnection handling
    - Multiple concurrent clients
    """
    
    def __init__(
        self,
        server_url: str,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
    ):
        raise NotImplementedError(
            "SSE proxy is not yet implemented. "
            "Use proxy_stdio.py for local MCP servers. "
            "See README.md Known Limitations for details."
        )


async def run_sse_proxy(
    server_url: str,
    listen_host: str = "127.0.0.1",
    listen_port: int = 8080,
    policy_path: str | None = None,
) -> None:
    """Run the SSE proxy server.
    
    NOT IMPLEMENTED: This is a placeholder for future development.
    
    Args:
        server_url: URL of the remote MCP server (e.g., https://mcp.example.com/sse)
        listen_host: Host to bind the proxy server to
        listen_port: Port to bind the proxy server to
        policy_path: Optional path to policy.yaml
    
    Raises:
        NotImplementedError: Always, as this feature is not yet implemented.
    """
    raise NotImplementedError(
        "SSE proxy is not yet implemented. "
        "Use proxy_stdio.py for local MCP servers. "
        "See README.md Known Limitations for details."
    )
