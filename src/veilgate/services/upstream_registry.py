"""Upstream MCP server registry and connection orchestrator."""

import asyncio
import json
import os
import shutil
import sys
from collections.abc import Mapping
from typing import Any

from fastmcp import Client
from fastmcp.client.transports import (
    SSETransport,
    StdioTransport,
    StreamableHttpTransport,
)

from veilgate.config.policy_models import Transport, UpstreamSpec, VeilgatePolicy
from veilgate.exceptions.types import (
    UpstreamProtocolError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.services.upstream_registry")

# Safe baseline OS environment variables forwarded to child stdio MCP servers (never includes VEILGATE_MASTER_KEY)
SAFE_OS_ENV_KEYS: tuple[str, ...] = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "COMSPEC",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMFILES",
    "COMMONPROGRAMFILES",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "NODE_PATH",
    "NPM_CONFIG_CACHE",
)

INTERPRETER_COMMANDS_REQUIRING_ARGS: set[str] = {
    "python",
    "python3",
    "node",
    "npx",
    "uv",
    "uvx",
}


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

    def _build_safe_env(self, upstream_spec: UpstreamSpec) -> dict[str, str]:
        """Construct sanitized environment dictionary for child stdio subprocesses."""
        safe_env: dict[str, str] = {
            k: os.environ[k] for k in SAFE_OS_ENV_KEYS if k in os.environ
        }
        if upstream_spec.env:
            for k, v in upstream_spec.env.items():
                if k != "VEILGATE_MASTER_KEY":
                    safe_env[k] = v
        safe_env.pop("VEILGATE_MASTER_KEY", None)
        return safe_env

    def _build_client_target(self, upstream_spec: UpstreamSpec) -> Any | None:
        """Resolve FastMCP Client transport or in-memory server handle for an upstream spec."""
        if upstream_spec.id in self._test_servers:
            return self._test_servers[upstream_spec.id]

        if upstream_spec.transport == Transport.STDIO:
            cmd = (upstream_spec.command or "").strip()
            if not cmd:
                return None
            # Do not launch bare interactive REPLs when headless placeholder specs omit script args
            if cmd.lower() in INTERPRETER_COMMANDS_REQUIRING_ARGS and not upstream_spec.args:
                return None

            if cmd.lower() in ("python", "python3"):
                resolved_cmd = sys.executable
            else:
                resolved_cmd = shutil.which(cmd) or cmd

            return StdioTransport(
                command=resolved_cmd,
                args=list(upstream_spec.args),
                env=self._build_safe_env(upstream_spec),
            )

        if upstream_spec.transport == Transport.HTTP and upstream_spec.url:
            return StreamableHttpTransport(upstream_spec.url)

        if upstream_spec.transport == Transport.SSE and upstream_spec.url:
            return SSETransport(upstream_spec.url)

        return None

    async def list_tools_from_upstream(
        self, upstream_spec: UpstreamSpec
    ) -> list[dict[str, Any]]:
        """Introspect tools from upstream server over configured transport."""
        target = self._build_client_target(upstream_spec)
        if target is None:
            return []

        timeout_s = upstream_spec.timeout_seconds or self.default_timeout_seconds
        try:
            async with asyncio.timeout(timeout_s):
                async with Client(target) as client:
                    tools = await client.list_tools()
                    return [
                        {
                            "name": t.name,
                            "description": t.description or "",
                            "inputSchema": t.input_schema if hasattr(t, "input_schema") else getattr(t, "inputSchema", {}),
                            "outputSchema": t.output_schema if hasattr(t, "output_schema") else getattr(t, "outputSchema", None),
                        }
                        for t in tools
                    ]
        except TimeoutError as e:
            logger.exception(f"ERROR | {type(e).__name__}: {e}")
            raise UpstreamTimeoutError(server_id=upstream_spec.id, timeout_seconds=timeout_s) from e
        except Exception as e:
            logger.exception(f"ERROR | {type(e).__name__}: {e}")
            raise UpstreamProtocolError(upstream_spec.id, f"Failed to list tools: {e}") from e

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

        target: Any | None = None
        if server_id in self._test_servers:
            target = self._test_servers[server_id]
        elif upstream_spec is not None:
            target = self._build_client_target(upstream_spec)

        if target is None:
            raise UpstreamUnavailableError(server_id=server_id)

        logger.info(f"STARTED | step=call_upstream_tool | server={server_id} | tool={tool_name}")
        logger.info(
            f"INPUT | step=call_upstream_tool | {json.dumps({'server': server_id, 'tool': tool_name, 'keys': list(arguments.keys())}, ensure_ascii=False)}"
        )
        try:
            async with asyncio.timeout(timeout_s):
                async with Client(target) as client:
                    result = await client.call_tool(tool_name, arguments=dict(arguments))
                    content_list: list[dict[str, Any]] = []
                    for c in result.content:
                        if hasattr(c, "text"):
                            content_list.append({"type": "text", "text": c.text})

                    structured = getattr(result, "structured_content", None)
                    # If upstream returned a JSON string in TextContent without structured_content, parse it
                    if structured is None and len(content_list) == 1:
                        raw_text = content_list[0].get("text", "").strip()
                        if (raw_text.startswith("{") and raw_text.endswith("}")) or (
                            raw_text.startswith("[") and raw_text.endswith("]")
                        ):
                            try:
                                parsed = json.loads(raw_text)
                                if isinstance(parsed, (dict, list)):
                                    structured = parsed
                            except json.JSONDecodeError:
                                pass

                    output_data = {
                        "content": content_list,
                        "structured_content": structured,
                        "is_error": result.is_error,
                    }
        except TimeoutError as e:
            logger.exception(f"ERROR | {type(e).__name__}: {e}")
            raise UpstreamTimeoutError(server_id=server_id, timeout_seconds=timeout_s) from e
        except Exception as e:
            logger.exception(f"ERROR | {type(e).__name__}: {e}")
            raise UpstreamProtocolError(server_id=server_id, safe_message=f"Upstream call error: {e}") from e

        logger.info(
            f"OUTPUT | step=call_upstream_tool | {json.dumps({'server': server_id, 'tool': tool_name, 'is_error': output_data['is_error'], 'has_structured': output_data['structured_content'] is not None}, ensure_ascii=False)}"
        )
        logger.info(f"SUCCESS | step=call_upstream_tool | server={server_id} | tool={tool_name}")
        return output_data
