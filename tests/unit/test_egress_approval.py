"""Unit tests for interactive egress tool approval and dev mode removal."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from veilgate.config.constants import ReasonCode
from veilgate.config.policy_loader import PolicyLoader
from veilgate.config.policy_models import (
    Capability,
    LearnedGrant,
    ToolPolicySpec,
    VeilgatePolicy,
)
from veilgate.repositories.approval_repo import ApprovalRepository
from veilgate.repositories.models import ApprovalRecord, CatalogEntryRecord
from veilgate.services.acl_service import AclService
from veilgate.services.approval_service import ApprovalService, compute_args_hash
from veilgate.services.models import SessionContext, ToolRef


def test_acl_egress_tool_not_allowed_requires_approval() -> None:
    """Verify that an egress tool matching allow: false requires human approval instead of silent deny."""
    policy = VeilgatePolicy(
        tools=[
            ToolPolicySpec(match="mailer.*", allow=False),
            ToolPolicySpec(match="fs.read", allow=False),
        ]
    )
    acl = AclService(policy)
    session = SessionContext(session_id="test_ses")

    # 1. Egress tool -> REQUIRE_APPROVAL
    mailer_ref = ToolRef.parse("mailer_send_email")
    catalog_entry = CatalogEntryRecord(
        qualified_ref="mailer.send_email",
        server_id="mailer",
        fingerprint="fp1",
        capabilities=[Capability.EXTERNAL_EGRESS.value],
        first_seen_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )
    decision = acl.decide(mailer_ref, session, catalog_entry)
    assert decision.decision == "REQUIRE_APPROVAL"
    assert decision.reason == ReasonCode.EGRESS_APPROVAL_REQUIRED

    # 2. Non-egress tool -> DENY
    fs_ref = ToolRef.parse("fs_read")
    fs_catalog = CatalogEntryRecord(
        qualified_ref="fs.read",
        server_id="fs",
        fingerprint="fp2",
        capabilities=[Capability.READ.value],
        first_seen_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )
    fs_decision = acl.decide(fs_ref, session, fs_catalog)
    assert fs_decision.decision == "DENY"
    assert fs_decision.reason == ReasonCode.TOOL_NOT_ALLOWED


def test_acl_learned_grant_allows_previously_approved_egress() -> None:
    """Verify that once a tool is approved-and-saved, subsequent calls are automatically ALLOWed."""
    policy = VeilgatePolicy(
        tools=[ToolPolicySpec(match="mailer.*", allow=False)],
        learned_grants=[
            LearnedGrant(
                grant_id="grnt_001",
                pattern="mailer.send_email",
                token_type="APPROVED_GRANT",
                created_at="2026-01-01T00:00:00Z",
            )
        ],
    )
    acl = AclService(policy)
    session = SessionContext(session_id="test_ses")
    mailer_ref = ToolRef.parse("mailer.send_email")

    decision = acl.decide(mailer_ref, session)
    assert decision.decision == "ALLOW"
    assert decision.reason == ReasonCode.APPROVAL_APPROVED_AND_SAVED


@pytest.mark.anyio
async def test_approval_service_allow_always_persists_grant() -> None:
    """Verify that approving with APPROVED_AND_SAVED persists a learned grant without requiring --dev."""
    repo = MagicMock(spec=ApprovalRepository)
    repo.create_request = AsyncMock()

    # Simulate pending record updated to APPROVED_AND_SAVED
    actual_hash = compute_args_hash({})
    pending_record = ApprovalRecord(
        approval_id="appr_123",
        session_id="s1",
        qualified_ref="mailer.send_email",
        summary_json=f'{{"args_hash": "{actual_hash}"}}',
        reason="EGRESS_APPROVAL_REQUIRED",
        status="APPROVED_AND_SAVED",
        learned_grant="mailer.send_email",
        requested_at="2026-01-01T00:00:00Z",
    )
    repo.get = AsyncMock(return_value=pending_record)

    loader = MagicMock(spec=PolicyLoader)
    loader.append_learned_grant = MagicMock()

    service = ApprovalService(
        approval_repo=repo,
        policy_loader=loader,
        timeout_seconds=5,
    )

    decision = await service.request_approval(
        ref=ToolRef.parse("mailer.send_email"),
        args={},
        session=SessionContext(session_id="s1"),
        reason="EGRESS_APPROVAL_REQUIRED",
    )

    assert decision.status == "APPROVED_AND_SAVED"
    loader.append_learned_grant.assert_called_once()
    saved_grant = loader.append_learned_grant.call_args[0][0]
    assert saved_grant.pattern == "mailer.send_email"
