"""Discovery middleware intercepting tools/list for catalog pruning and diet compaction."""

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import Tool

from veilgate.pipeline import FirewallPipeline
from veilgate.services.models import SessionContext


class DiscoveryMiddleware(Middleware):
    """Prunes denied tools and applies context diet compaction during tools/list."""

    def __init__(self, pipeline: FirewallPipeline, session_ctx: SessionContext) -> None:
        self.pipeline: FirewallPipeline = pipeline
        self.session_ctx: SessionContext = session_ctx

    async def on_list_tools(
        self,
        context: MiddlewareContext,
        call_next: CallNext,
    ) -> list[Tool]:
        """Intercept tools/list, prune schemas, and inject search meta-tools."""
        compacted_tools = await self.pipeline.on_list_tools(self.session_ctx)
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
