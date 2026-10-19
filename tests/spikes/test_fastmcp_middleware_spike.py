"""Phase 0 Spike: Verifying FastMCP 4.1.1 Middleware capability to:

1. Intercept and rewrite incoming tool call arguments before upstream execution.
2. Intercept and rewrite outgoing tool call results (content + structured_content).
3. Intercept and prune tools/list response schemas.
"""

import anyio
import pytest
from fastmcp import Client, FastMCP
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult
from mcp import types as mt
from mcp.types import TextContent, Tool


class VeilgateSpikeMiddleware(Middleware):
    """Spike middleware verifying argument re-hydration and result minimization hooks."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        # Step 1: Ingress argument interception and re-hydration
        original_args = context.message.arguments or {}
        rehydrated_args = dict(original_args)

        # Simulate vault re-hydration: swap placeholder '<vg:TEST_NUM:100>' with 100
        for k, v in original_args.items():
            if v == "<vg:TEST_NUM:100>":
                rehydrated_args[k] = 100

        # Replace message arguments in context
        new_params = mt.CallToolRequestParams(
            name=context.message.name,
            arguments=rehydrated_args,
        )
        mutated_context = context.copy(message=new_params)

        # Step 2: Invoke upstream tool
        upstream_result = await call_next(mutated_context)

        # Step 3: Egress result interception and minimization
        # Both content and structured_content are minimized so MCP client outputSchema validation passes
        minimized_structured: dict[str, object] | None = None
        if upstream_result.structured_content is not None:
            minimized_structured = {
                "total": upstream_result.structured_content.get("total"),
                "ssn": "<vg:SSN:999AAA>",
                # 'internal_bloat' is dropped on egress
            }

        minimized_content = [
            TextContent(
                type="text",
                text=f"[MINIMIZED] total={upstream_result.structured_content['total'] if upstream_result.structured_content else 'N/A'} ssn=<vg:SSN:999AAA>",
            )
        ]

        return ToolResult(
            content=minimized_content,
            structured_content=minimized_structured,
            meta=upstream_result.meta,
            is_error=upstream_result.is_error,
        )

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, list[Tool]],
    ) -> list[Tool]:
        # Intercept catalog, prune denied tools, and rewrite output_schema for minimized fields
        full_catalog = await call_next(context)
        pruned_catalog: list[Tool] = []
        for tool in full_catalog:
            if "secret" in tool.name:
                continue
            if tool.output_schema is not None and "properties" in tool.output_schema:
                rewritten_schema = dict(tool.output_schema)
                props = dict(rewritten_schema.get("properties", {}))
                props.pop("internal_bloat", None)
                rewritten_schema["properties"] = props
                if "required" in rewritten_schema:
                    rewritten_schema["required"] = [
                        r for r in rewritten_schema["required"] if r != "internal_bloat"
                    ]
                tool = tool.model_copy(update={"output_schema": rewritten_schema})
            pruned_catalog.append(tool)
        return pruned_catalog


@pytest.mark.anyio
async def test_fastmcp_middleware_rewrite_args_and_results() -> None:
    """Spike test proving FastMCP 4 middleware can rewrite arguments, results, and output_schema."""
    server = FastMCP("spike-server")
    server.add_middleware(VeilgateSpikeMiddleware())

    @server.tool
    def add_numbers(x: int, y: int) -> dict[str, object]:
        return {
            "total": x + y,
            "ssn": "000-12-3456",
            "internal_bloat": "drop-me",
        }

    @server.tool
    def secret_tool() -> str:
        return "classified"

    async with Client(server) as client:
        # 1. Verify tools/list pruning
        tools = await client.list_tools()
        tool_names = [t.name for t in tools]
        assert "add_numbers" in tool_names
        assert "secret_tool" not in tool_names, "secret_tool was not pruned by on_list_tools!"

        # 2. Verify argument re-hydration and result minimization in tools/call
        # We pass a synthetic token string '<vg:TEST_NUM:100>' as x
        result = await client.call_tool(
            "add_numbers",
            arguments={"x": "<vg:TEST_NUM:100>", "y": 50},
        )

        assert not result.is_error
        assert len(result.content) == 1
        assert isinstance(result.content[0], TextContent)
        # Upstream received 100 + 50 = 150 without error, and middleware minimized the result
        assert "total=150" in result.content[0].text
        assert "<vg:SSN:999AAA>" in result.content[0].text
        assert result.structured_content == {
            "total": 150,
            "ssn": "<vg:SSN:999AAA>",
        }


if __name__ == "__main__":
    anyio.run(test_fastmcp_middleware_rewrite_args_and_results)
    print("ALL SPIKE CHECKS PASSED: FastMCP 4 middleware cleanly rewrites arguments, results, and catalogs!")
