"""Vault repository managing encrypted token storage and deterministic resolution."""

from datetime import datetime, timedelta, timezone
import json
from typing import Mapping

from veilgate.config.constants import TABLE_TOKENS
from veilgate.exceptions.types import TokenNotFoundError, VaultCryptoError
from veilgate.repositories.db import DatabaseManager
from veilgate.repositories.models import TokenRecord, TokenRecordCreate
from veilgate.security.crypto import VaultCrypto


class VaultRepository:
    """Manages token persistence, AES-256-GCM encryption, and HMAC-based indexing."""

    def __init__(self, db_manager: DatabaseManager, crypto: VaultCrypto) -> None:
        self.db: DatabaseManager = db_manager
        self.crypto: VaultCrypto = crypto

    async def get_or_create(self, spec: TokenRecordCreate) -> TokenRecord:
        """Retrieve existing token or mint and encrypt a new one idempotently.

        Enforces ADR-4 (session-scoped deterministic stability): if the same
        sensitive value is observed multiple times for the same session and type,
        the previously minted token is reused.
        """
        value_hmac = self.crypto.compute_hmac(spec.raw_value)
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(seconds=spec.ttl_seconds)).isoformat()
        now_iso = now.isoformat()

        # Serialize allowed_sinks to JSON string if it's a list or macro string
        sinks_json = (
            json.dumps(spec.allowed_sinks)
            if isinstance(spec.allowed_sinks, list)
            else str(spec.allowed_sinks)
        )

        async with self.db.connection() as conn:
            # 1. Check for existing stable token within this session
            cursor = await conn.execute(
                f"""
                SELECT * FROM {TABLE_TOKENS}
                WHERE session_id = ? AND token_type = ? AND value_hmac = ?;
                """,
                (spec.session_id, spec.token_type, value_hmac),
            )
            row = await cursor.fetchone()
            if row is not None:
                return TokenRecord.model_validate(dict(row))

            # 2. Encrypt value
            ciphertext, nonce = self.crypto.encrypt(spec.raw_value)

            # 3. Insert new token record
            await conn.execute(
                f"""
                INSERT INTO {TABLE_TOKENS} (
                    token_id, session_id, rendered, token_type, sensitivity,
                    value_kind, value_hmac, ciphertext, nonce, origin_ref,
                    origin_path, origin_event_id, allowed_sinks_json,
                    allow_external_egress, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    spec.token_id,
                    spec.session_id,
                    spec.rendered,
                    spec.token_type,
                    spec.sensitivity,
                    spec.value_kind,
                    value_hmac,
                    ciphertext,
                    nonce,
                    spec.origin_ref,
                    spec.origin_path,
                    spec.origin_event_id,
                    sinks_json,
                    1 if spec.allow_external_egress else 0,
                    now_iso,
                    expires_at,
                ),
            )
            await conn.commit()

        created = await self.get_by_token(spec.token_id, spec.session_id)
        if created is None:
            raise VaultCryptoError(f"Failed to persist token {spec.token_id}")
        return created

    async def get_by_token(self, token_id: str, session_id: str) -> TokenRecord | None:
        """Find a token by token_id scoped strictly to session_id."""
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"SELECT * FROM {TABLE_TOKENS} WHERE session_id = ? AND token_id = ?;",
                (session_id, token_id),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return TokenRecord.model_validate(dict(row))

    async def get_by_rendered(self, rendered: str, session_id: str) -> TokenRecord | None:
        """Find a token by its rendered representation scoped to session_id."""
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"SELECT * FROM {TABLE_TOKENS} WHERE session_id = ? AND rendered = ?;",
                (session_id, rendered),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return TokenRecord.model_validate(dict(row))

    async def reveal(self, record: TokenRecord) -> str:
        """Decrypt token ciphertext from vault in memory only."""
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"SELECT ciphertext, nonce FROM {TABLE_TOKENS} WHERE session_id = ? AND token_id = ?;",
                (record.session_id, record.token_id),
            )
            row = await cursor.fetchone()
            if row is None:
                raise TokenNotFoundError(token_id=record.token_id)
            ciphertext: bytes = row["ciphertext"]
            nonce: bytes = row["nonce"]

        return self.crypto.decrypt(ciphertext, nonce)

    async def purge_expired(self) -> int:
        """Delete tokens where expires_at has elapsed."""
        now = datetime.now(timezone.utc).isoformat()
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"DELETE FROM {TABLE_TOKENS} WHERE expires_at < ?;",
                (now,),
            )
            await conn.commit()
            return cursor.rowcount
