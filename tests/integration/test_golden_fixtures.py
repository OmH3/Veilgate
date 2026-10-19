"""Integration tests evaluating Veilgate against captured golden upstream shapes.

Tests verify:
1. False-block resilience: harmless tools (time) pass with zero redaction.
2. Sensitive protection: sensitive bank account, deal margin, salary band, and SSN are tokenized.
3. Bloat minimization: etags, internal row IDs, and navigation links are dropped into stash.
"""

import json
from pathlib import Path
import pytest

from veilgate.config.constants import ReasonCode
from veilgate.config.policy_models import (
    Capability,
    FieldAction,
    FieldRuleSpec,
    SinkMacro,
    TokenizeSpec,
    ToolPolicySpec,
    Transport,
    UpstreamSpec,
    VeilgatePolicy,
)
from ulid import ULID

from veilgate.config.settings import VeilgateSettings
from veilgate.gateway import create_gateway_pipeline
from veilgate.services.models import SessionContext, ToolRef


GOLDEN_DIR = Path(__file__).parent.parent / "golden"


@pytest.fixture
def golden_policy() -> VeilgatePolicy:
    """Policy configuring golden upstreams and protection rules."""
    return VeilgatePolicy(
        version="1",
        extends="recommended",
        default_tool_allow=True,
        upstreams=[
            UpstreamSpec(id="time", transport=Transport.STDIO, command="python"),
            UpstreamSpec(id="invoicedb", transport=Transport.STDIO, command="python"),
            UpstreamSpec(id="fetch", transport=Transport.STDIO, command="python"),
        ],
        protect=["deal_margin", "salary_band"],
        drop=["internal_row_id", "audit_metadata"],
        tools=[
            ToolPolicySpec(
                match="invoicedb.delete_*",
                allow=False,
            ),
            ToolPolicySpec(
                match="fetch.fetch",
                capabilities=[Capability.EXTERNAL_EGRESS],
                open_world_hint=True,
                untrusted_tool=True,
            ),
        ],
    )


@pytest.mark.anyio
async def test_golden_time_server_zero_false_blocks(
    tmp_path: Path,
    golden_policy: VeilgatePolicy,
) -> None:
    """Verify that harmless time server tools and outputs pass through with zero false blocks."""
    time_fixture = json.loads((GOLDEN_DIR / "time_server.json").read_text(encoding="utf-8"))
    settings = VeilgateSettings(db_path=tmp_path / "golden_test.db")
    pipeline, _ = await create_gateway_pipeline(settings, policy=golden_policy)

    session = SessionContext(session_id="ses_golden_time")
    await pipeline.sessions.create_or_touch(session.session_id, transport=session.transport.value)

    # Ingest catalog entry
    for t in time_fixture["tools"]:
        await pipeline.catalog_svc.ingest_tool(
            server_id=time_fixture["server_id"],
            tool_name=t["name"],
            description=t.get("description", ""),
            input_schema=t.get("inputSchema"),
        )

    # Verify discovery
    tools = await pipeline.on_list_tools(session)
    tool_names = [t["name"] for t in tools]
    assert "time_get_current_time" in tool_names
    assert "time_convert_time" in tool_names

    # Test sample call minimization
    sample = time_fixture["sample_calls"]["get_current_time"]
    minimized = await pipeline.minimizer.minimize(
        raw_payload=sample["output"],
        ref=ToolRef(server="time", tool="get_current_time"),
        session=session,
        event_id=str(ULID()),
    )

    # Invariant: 0 transforms applied, pristine pass-through
    assert len(minimized.transforms) == 0
    assert json.loads(minimized.content[0]["text"]) == sample["output"]


@pytest.mark.anyio
async def test_golden_invoicedb_protection_and_bloat_stripping(
    tmp_path: Path,
    golden_policy: VeilgatePolicy,
) -> None:
    """Verify that invoicedb sensitive metrics are tokenized and bloat is dropped into stash."""
    inv_fixture = json.loads((GOLDEN_DIR / "invoicedb_server.json").read_text(encoding="utf-8"))
    settings = VeilgateSettings(db_path=tmp_path / "golden_inv.db")
    pipeline, _ = await create_gateway_pipeline(settings, policy=golden_policy)

    session = SessionContext(session_id="ses_golden_inv")
    await pipeline.sessions.create_or_touch(session.session_id, transport=session.transport.value)

    # Ingest catalog
    for t in inv_fixture["tools"]:
        await pipeline.catalog_svc.ingest_tool(
            server_id=inv_fixture["server_id"],
            tool_name=t["name"],
            description=t.get("description", ""),
            input_schema=t.get("inputSchema"),
        )

    # 1. Pruning assertion: delete_invoice must be blocked and pruned from tools/list
    tools = await pipeline.on_list_tools(session)
    tool_names = [t["name"] for t in tools]
    assert "invoicedb_delete_invoice" not in tool_names
    assert "invoicedb_get_vendor_details" in tool_names

    # 2. Minimization and tokenization of sensitive payload
    sample = inv_fixture["sample_calls"]["get_vendor_details"]
    minimized = await pipeline.minimizer.minimize(
        raw_payload=sample["output"],
        ref=ToolRef(server="invoicedb", tool="get_vendor_details"),
        session=session,
        event_id=str(ULID()),
    )

    # Asserts
    min_data = json.loads(minimized.content[0]["text"])
    assert min_data["vendor_name"] == "Apex Cloud Systems"
    assert min_data["contact_email"].endswith("@vault.veilgate.invalid")
    assert min_data["contact_email"].startswith("vg-")
    assert "<vg:BANK_ACCOUNT:" in min_data["bank_account"]
    assert "<vg:BANK_ROUTING:" in min_data["routing_number"]
    assert "<vg:DEAL_MARGIN:" in min_data["deal_margin"]
    assert "<vg:SALARY_BAND:" in min_data["salary_band"]

    # Bloat keys must be dropped
    assert "internal_row_id" not in min_data
    assert "_links" not in min_data

    # Stash assertion
    assert minimized.stash_id is not None
    stashed = await pipeline.stash_repo.get_stash(minimized.stash_id, session.session_id)
    assert stashed is not None
    stashed_fields = json.loads(stashed.payload_json)
    assert "$.internal_row_id" in stashed_fields
    assert "$._links" in stashed_fields
