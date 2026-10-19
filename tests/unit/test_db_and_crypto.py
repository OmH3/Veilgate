"""Unit tests for SQLite database manager and Vault cryptography."""

import base64
import os
from pathlib import Path
import pytest

from veilgate.config.constants import CROCKFORD_BASE32_ALPHABET
from veilgate.exceptions.types import VaultCryptoError
from veilgate.repositories.db import DatabaseManager
from veilgate.security.crypto import (
    VaultCrypto,
    generate_crockford_token_id,
    resolve_master_key,
)


@pytest.mark.anyio
async def test_database_manager_initialization_and_tables(tmp_path: Path) -> None:
    """Verify DatabaseManager connects, sets PRAGMAs, and creates schema."""
    db_file = tmp_path / "test_veilgate.db"
    db_manager = DatabaseManager(db_file)
    await db_manager.initialize()

    async with db_manager.connection() as conn:
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        )
        rows = await cursor.fetchall()
        tables = [row["name"] for row in rows]

        assert "sessions" in tables
        assert "tokens" in tables
        assert "tool_catalog" in tables
        assert "schema_cache" in tables
        assert "audit_events" in tables
        assert "approvals" in tables
        assert "result_stash" in tables
        assert "telemetry" in tables


@pytest.mark.anyio
async def test_audit_append_only_triggers(tmp_path: Path) -> None:
    """Verify triggers prevent UPDATE and DELETE on audit_events."""
    db_file = tmp_path / "audit_test.db"
    db_manager = DatabaseManager(db_file)
    await db_manager.initialize()

    async with db_manager.connection() as conn:
        await conn.execute(
            """
            INSERT INTO audit_events (
                event_id, ts, session_id, correlation_id, kind, qualified_ref, details_json, prev_hash, row_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("evt_1", "2026-10-19T10:00:00Z", "ses_1", "cor_1", "CALL", "srv.tool", "{}", "000", "aaa"),
        )
        await conn.commit()

        # Attempt UPDATE should abort
        with pytest.raises(Exception, match="audit is append-only"):
            await conn.execute("UPDATE audit_events SET kind = 'MODIFIED' WHERE event_id = 'evt_1';")

        # Attempt DELETE should abort
        with pytest.raises(Exception, match="audit is append-only"):
            await conn.execute("DELETE FROM audit_events WHERE event_id = 'evt_1';")


def test_resolve_master_key_from_base64() -> None:
    """Verify resolving explicitly configured 32-byte key."""
    raw_key = os.urandom(32)
    b64_key = base64.b64encode(raw_key).decode("utf-8")
    resolved = resolve_master_key(b64_key)
    assert resolved == raw_key


def test_vault_crypto_roundtrip() -> None:
    """Verify AES-256-GCM encryption and decryption roundtrip."""
    key = os.urandom(32)
    crypto = VaultCrypto(key)
    secret = "987-65-4321"

    ciphertext, nonce = crypto.encrypt(secret)
    assert ciphertext != secret.encode("utf-8")
    assert len(nonce) == 12

    decrypted = crypto.decrypt(ciphertext, nonce)
    assert decrypted == secret


def test_vault_crypto_tampered_ciphertext_fails() -> None:
    """Verify GCM tag authentication failure on modified ciphertext."""
    key = os.urandom(32)
    crypto = VaultCrypto(key)
    secret = "SuperSecretAPIKey"

    ciphertext, nonce = crypto.encrypt(secret)
    # Tamper with byte
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF

    with pytest.raises(VaultCryptoError):
        crypto.decrypt(bytes(tampered), nonce)


def test_vault_crypto_hmac_deterministic() -> None:
    """Verify HMAC-SHA256 produces same hash for normalized values."""
    key = os.urandom(32)
    crypto = VaultCrypto(key)

    h1 = crypto.compute_hmac("  123-45-6789  ")
    h2 = crypto.compute_hmac("123-45-6789")
    h3 = crypto.compute_hmac("987-65-4321")

    assert h1 == h2
    assert h1 != h3


def test_generate_crockford_token_id() -> None:
    """Verify Crockford Base32 token ID format and character alphabet."""
    for _ in range(50):
        token_id = generate_crockford_token_id()
        assert len(token_id) == 6
        for char in token_id:
            assert char in CROCKFORD_BASE32_ALPHABET
