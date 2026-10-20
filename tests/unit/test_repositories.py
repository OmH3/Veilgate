"""Comprehensive unit tests for Veilgate repositories."""

import os
from pathlib import Path

import pytest

from veilgate.repositories.approval_repo import ApprovalRepository
from veilgate.repositories.audit_repo import AuditRepository
from veilgate.repositories.catalog_repo import CatalogRepository
from veilgate.repositories.db import DatabaseManager
from veilgate.repositories.models import CatalogEntryRecord, TokenRecordCreate
from veilgate.repositories.session_repo import SessionRepository
from veilgate.repositories.stash_repo import StashRepository
from veilgate.repositories.vault_repo import VaultRepository
from veilgate.security.crypto import VaultCrypto


@pytest.fixture
async def initialized_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing initialized SQLite database."""
    db_file = tmp_path / "repo_test.db"
    mgr = DatabaseManager(db_file)
    await mgr.initialize()
    return mgr


@pytest.fixture
def crypto() -> VaultCrypto:
    """Fixture providing VaultCrypto instance."""
    return VaultCrypto(os.urandom(32))


@pytest.mark.anyio
async def test_session_repository(initialized_db: DatabaseManager) -> None:
    """Verify session repository lifecycle and integrity updates."""
    repo = SessionRepository(initialized_db)
    session = await repo.create_or_touch("ses_test_1", transport="stdio", label="Test Client")
    assert session.session_id == "ses_test_1"
    assert session.integrity == "HIGH"
    assert session.label == "Test Client"

    # Touch session
    touched = await repo.create_or_touch("ses_test_1", transport="stdio")
    assert touched.session_id == "ses_test_1"

    # Lower integrity
    await repo.update_integrity("ses_test_1", "LOW")
    updated = await repo.get("ses_test_1")
    assert updated is not None
    assert updated.integrity == "LOW"

    active = await repo.list_active()
    assert len(active) >= 1


@pytest.mark.anyio
async def test_vault_repository_idempotent_stability(
    initialized_db: DatabaseManager, crypto: VaultCrypto
) -> None:
    """Verify VaultRepository stores, encrypts, reveals, and reuses tokens (ADR-4)."""
    session_repo = SessionRepository(initialized_db)
    await session_repo.create_or_touch("ses_vault_1", transport="stdio")

    vault = VaultRepository(initialized_db, crypto)

    spec1 = TokenRecordCreate(
        token_id="7K3QF2",
        session_id="ses_vault_1",
        rendered="<vg:BANK_ROUTING:7K3QF2>",
        token_type="BANK_ROUTING",
        sensitivity="PII_HIGH",
        value_kind="string",
        raw_value="021000021",
        origin_ref="invoicedb.get_invoice",
        origin_path="$.bank_routing_number",
        origin_event_id="evt_01",
        allowed_sinks=["invoicedb.compare_*:account"],
        allow_external_egress=False,
    )
    rec1 = await vault.get_or_create(spec1)
    assert rec1.token_id == "7K3QF2"
    assert rec1.rendered == "<vg:BANK_ROUTING:7K3QF2>"

    # Decrypt and verify plaintext
    plaintext = await vault.reveal(rec1)
    assert plaintext == "021000021"

    # Test ADR-4 deterministic reuse: same value, same session, same type -> reuses 7K3QF2
    spec2 = TokenRecordCreate(
        token_id="DIFFERENT_ID",
        session_id="ses_vault_1",
        rendered="<vg:BANK_ROUTING:DIFFERENT_ID>",
        token_type="BANK_ROUTING",
        sensitivity="PII_HIGH",
        value_kind="string",
        raw_value="021000021",
        origin_ref="invoicedb.other_tool",
        origin_path="$.routing",
        origin_event_id="evt_02",
        allowed_sinks=["invoicedb.*"],
        allow_external_egress=False,
    )
    rec2 = await vault.get_or_create(spec2)
    assert rec2.token_id == "7K3QF2", "Did not reuse stable token ID for same value in session!"


@pytest.mark.anyio
async def test_catalog_repository(initialized_db: DatabaseManager) -> None:
    """Verify tool catalog registration, status changes, and schema cache."""
    repo = CatalogRepository(initialized_db)

    entry = CatalogEntryRecord(
        qualified_ref="invoicedb.get_invoice",
        server_id="invoicedb",
        fingerprint="sha256_fp_123",
        status="active",
        capabilities=["read"],
        risk_level="LOW",
        schema_tokens=42,
        first_seen_at="2026-10-19T10:00:00Z",
        updated_at="2026-10-19T10:00:00Z",
    )
    await repo.upsert_tool(entry)

    tool = await repo.get_tool("invoicedb.get_invoice")
    assert tool is not None
    assert tool.capabilities == ["read"]
    assert tool.status == "active"

    # Pin fingerprint
    await repo.pin_fingerprint("invoicedb.get_invoice", "sha256_fp_123")
    pinned = await repo.get_tool("invoicedb.get_invoice")
    assert pinned is not None
    assert pinned.pinned_fp == "sha256_fp_123"

    # Test schema cache
    await repo.set_schema_classifications(
        "invoicedb.get_invoice",
        "shape_abc",
        '[{"path": "$.ssn", "action": "TOKENIZE"}]',
        source="deterministic",
    )
    cached = await repo.get_schema_classifications("invoicedb.get_invoice", "shape_abc")
    assert cached is not None
    assert "TOKENIZE" in cached


@pytest.mark.anyio
async def test_audit_repository_hash_chain(initialized_db: DatabaseManager) -> None:
    """Verify cryptographic hash chaining and tamper detection in audit logs."""
    audit = AuditRepository(initialized_db)

    # Record 3 sequential events
    await audit.record("evt_1", "ses_1", "cor_1", "LIST", "{}", "srv.tool1", "OK")
    await audit.record("evt_2", "ses_1", "cor_1", "CALL", "{}", "srv.tool2", "OK")
    await audit.record("evt_3", "ses_1", "cor_1", "TRANSFORM", "{}", "srv.tool2", "OK")

    is_valid, err = await audit.verify_chain()
    assert is_valid is True
    assert err is None

    events = await audit.list_events(session_id="ses_1")
    assert len(events) == 3


@pytest.mark.anyio
async def test_approval_repository(initialized_db: DatabaseManager) -> None:
    """Verify approval creation, listing pending, and recording decision."""
    repo = ApprovalRepository(initialized_db)

    await repo.create_request(
        approval_id="appr_01",
        session_id="ses_1",
        qualified_ref="mailer.send_email",
        summary_json='{"to": "user@example.com"}',
        reason="EXTERNAL_EGRESS_REQUIRES_APPROVAL",
    )

    pending = await repo.list_pending()
    assert len(pending) == 1
    assert pending[0].approval_id == "appr_01"

    await repo.decide("appr_01", status="APPROVED", decided_by="dev_user")
    updated = await repo.get("appr_01")
    assert updated is not None
    assert updated.status == "APPROVED"
    assert updated.decided_by == "dev_user"


@pytest.mark.anyio
async def test_stash_repository(initialized_db: DatabaseManager) -> None:
    """Verify response stash caching and retrieval."""
    repo = StashRepository(initialized_db)

    await repo.stash_result(
        stash_id="stash_123",
        session_id="ses_1",
        qualified_ref="invoicedb.get_invoice",
        payload_json='{"dropped_debug_info": "data"}',
    )

    stashed = await repo.get_stash("stash_123", "ses_1")
    assert stashed is not None
    assert "dropped_debug_info" in stashed.payload_json

    # Wrong session returns None
    assert await repo.get_stash("stash_123", "other_session") is None
