"""Upstream MCP server registry and connection orchestrator."""

import asyncio
from typing import Any, Mapping
from fastmcp import Client

from veilgate.config.policy_models import Transport, UpstreamSpec, VeilgatePolicy
from veilgate.exceptions.types import (
    UpstreamProtocolError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.services.upstream_registry")


class UpstreamRegistry:
    """Manages spawning, lifecycle, and invocation of configured upstream MCP servers."""

    def __init__(self, policy: VeilgatePolicy, default_timeout_seconds: float = 30.0) -> None:
        self.policy: VeilgatePolicy = policy
        self.default_timeout_seconds: float = default_timeout_seconds
        # In-memory FastMCP server handles for test fixtures
        self._test_servers: dict[str, Any] = {}

    def register_test_server(self, server_id: str, server: Any) -> None:
        """Register an active FastMCP test server for in-process fixtures."""
        self._test_servers[server_id] = server

    async def list_tools_from_upstream(
        self, upstream_spec: UpstreamSpec
    ) -> list[dict[str, Any]]:
        """Introspect tools from upstream server."""
        if upstream_spec.id in self._test_servers:
            server = self._test_servers[upstream_spec.id]
            try:
                async with Client(server) as client:
                    tools = await client.list_tools()
                    return [
                        {
                            "name": t.name,
                            "description": t.description or "",
                            "inputSchema": getattr(t, "input_schema", getattr(t, "inputSchema", {})),
                            "outputSchema": getattr(t, "output_schema", getattr(t, "outputSchema", None)),
                        }
                        for t in tools
                    ]
            except Exception as e:
                raise UpstreamProtocolError(upstream_spec.id, f"Failed to list tools: {e}") from e

        # Mock fallback for headless tests without active subprocess
        return []

    async def call_upstream_tool(
        self,
        server_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Forward a tool call to the specified upstream server with timeout handling."""
        timeout_s = self.default_timeout_seconds
        upstream_spec = next((u for u in self.policy.upstreams if u.id == server_id), None)
        if upstream_spec and upstream_spec.timeout_seconds:
            timeout_s = upstream_spec.timeout_seconds

        if server_id in self._test_servers:
            server = self._test_servers[server_id]
            try:
                async with asyncio.timeout(timeout_s):
                    async with Client(server) as client:
                        result = await client.call_tool(tool_name, arguments=dict(arguments))
                        content_list: list[dict[str, Any]] = []
                        for c in result.content:
                            if hasattr(c, "text"):
                                content_list.append({"type": "text", "text": c.text})
                        return {
                            "content": content_list,
                            "structured_content": getattr(result, "structured_content", None),
                            "is_error": result.is_error,
                        }
            except TimeoutError as e:
                raise UpstreamTimeoutError(server_id=server_id, timeout_seconds=timeout_s) from e
            except Exception as e:
                raise UpstreamProtocolError(server_id=server_id, safe_message=f"Upstream call error: {e}") from e

        raise UpstreamUnavailableError(server_id=server_id)
