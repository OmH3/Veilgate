"""Firewall call middleware intercepting tools/call for taint checking and response minimization."""

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult
from mcp.types import TextContent
from ulid import ULID

from veilgate.config.constants import ReasonCode
from veilgate.exceptions.types import PolicyViolation, UpstreamError
from veilgate.pipeline import FirewallPipeline
from veilgate.services.models import SessionContext
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.middleware.firewall_call_mw")


class FirewallCallMiddleware(Middleware):
    """Intercepts tools/call to enforce taint policies, ACLs, and egress minimization."""

    def __init__(self, pipeline: FirewallPipeline, session_ctx: SessionContext) -> None:
        self.pipeline: FirewallPipeline = pipeline
        self.session_ctx: SessionContext = session_ctx

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: CallNext,
    ) -> ToolResult:
        """Intercept tools/call, verify taint, authorize, and minimize output."""
        tool_name = context.message.name
        arguments = context.message.arguments or {}
        correlation_id = str(ULID())
        self.session_ctx.correlation_id = correlation_id

        try:
            minimized = await self.pipeline.on_call_tool(
                tool_name=tool_name,
                arguments=arguments,
                session=self.session_ctx,
            )

            text = minimized.content[0]["text"] if minimized.content else ""
            content_blocks = [TextContent(type="text", text=text)]

            return ToolResult(
                content=content_blocks,
                structured_content=minimized.structured_content if isinstance(minimized.structured_content, dict) else None,
                is_error=minimized.is_error,
            )

        except (PolicyViolation, UpstreamError) as e:
            agent_msg = e.to_agent_message(correlation_id=correlation_id)
            logger.warning(f"BLOCKED | {agent_msg}")
            return ToolResult(
                content=[TextContent(type="text", text=agent_msg)],
                is_error=True,
            )

        except Exception as e:
            logger.exception(f"FAIL_CLOSED | Unexpected pipeline exception on {tool_name}: {e}")
            fail_safe_msg = f"[VEILGATE BLOCKED] code={ReasonCode.INTERNAL_FAIL_CLOSED.value} | An internal error occurred. correlation_id={correlation_id}"
            return ToolResult(
                content=[TextContent(type="text", text=fail_safe_msg)],
                is_error=True,
            )
