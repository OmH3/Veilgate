"""FastMCP Middleware adapter connecting the MCP transport to FirewallPipeline."""

from typing import Any
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import Tool, ToolResult
from mcp.types import TextContent
from ulid import ULID

from veilgate.config.constants import ReasonCode
from veilgate.config.policy_models import Transport
from veilgate.exceptions.types import PolicyViolation, UpstreamError, VeilgateError
from veilgate.pipeline import FirewallPipeline
from veilgate.services.models import SessionContext
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.middleware.context_middleware")


class VeilgateContextMiddleware(Middleware):
    """FastMCP middleware intercepting tools/list and tools/call requests."""

    def __init__(self, pipeline: FirewallPipeline, default_session_id: str | None = None) -> None:
        self.pipeline: FirewallPipeline = pipeline
        self.session_id: str = default_session_id or f"ses_{ULID()}"
        self._session_ctx: SessionContext = SessionContext(
            session_id=self.session_id,
            correlation_id=str(ULID()),
            integrity="HIGH",
            transport=Transport.STDIO,
        )

    async def on_list_tools(
        self,
        context: MiddlewareContext,
        call_next: CallNext,
    ) -> list[Tool]:
        """Intercept tools/list, prune schemas, and inject search meta-tools."""
        compacted_tools = await self.pipeline.on_list_tools(self._session_ctx)
        result_tools: list[Tool] = []

        for item in compacted_tools:
            result_tools.append(
                Tool(
                    name=item["name"],
                    description=item.get("description", ""),
                    parameters=item.get("inputSchema", {"type": "object", "properties": {}}),
                )
            )

        return result_tools

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: CallNext,
    ) -> ToolResult:
        """Intercept tools/call, verify taint, authorize, and minimize output."""
        tool_name = context.message.name
        arguments = context.message.arguments or {}
        correlation_id = str(ULID())
        self._session_ctx.correlation_id = correlation_id

        try:
            minimized = await self.pipeline.on_call_tool(
                tool_name=tool_name,
                arguments=arguments,
                session=self._session_ctx,
            )

            # Format text content block
            text = minimized.content[0]["text"] if minimized.content else ""
            content_blocks = [TextContent(type="text", text=text)]

            return ToolResult(
                content=content_blocks,
                structured_content=minimized.structured_content if isinstance(minimized.structured_content, dict) else None,
                is_error=minimized.is_error,
            )

        except (PolicyViolation, UpstreamError) as e:
            # Expected security boundaries: format safe, non-leaking agent message
            agent_msg = e.to_agent_message(correlation_id=correlation_id)
            logger.warning(f"BLOCKED | {agent_msg}")
            return ToolResult(
                content=[TextContent(type="text", text=agent_msg)],
                is_error=True,
            )

        except Exception as e:
            # Internal crash guard: fail-closed with generic safe message, log exception to stderr
            logger.exception(f"FAIL_CLOSED | Unexpected pipeline exception on {tool_name}: {e}")
            fail_safe_msg = f"[VEILGATE BLOCKED] code={ReasonCode.INTERNAL_FAIL_CLOSED.value} | An internal error occurred. correlation_id={correlation_id}"
            return ToolResult(
                content=[TextContent(type="text", text=fail_safe_msg)],
                is_error=True,
            )
