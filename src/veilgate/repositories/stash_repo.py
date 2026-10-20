"""Repository for caching dropped non-sensitive response payload fragments."""

from datetime import UTC, datetime, timedelta

from veilgate.config.constants import TABLE_RESULT_STASH
from veilgate.repositories.db import DatabaseManager
from veilgate.repositories.models import StashRecord


class StashRepository:
    """Manages temporary caching of dropped non-sensitive fields for veilgate_expand."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db: DatabaseManager = db_manager
        self._cache: dict[tuple[str, str], StashRecord] = {}
        self._payload_cache: dict[tuple[str, str, str], StashRecord] = {}

    async def stash_result(
        self,
        stash_id: str,
        session_id: str,
        qualified_ref: str,
        payload_json: str,
        ttl_seconds: int = 1_800,
    ) -> StashRecord:
        """Cache dropped non-sensitive payload fields."""
        payload_key = (session_id, qualified_ref, payload_json)
        if payload_key in self._payload_cache:
            return self._payload_cache[payload_key]

        now = datetime.now(UTC)
        expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()

        async with self.db.connection() as conn:
            await conn.execute(
                f"""
                INSERT INTO {TABLE_RESULT_STASH} (
                    stash_id, session_id, qualified_ref, payload_json, expires_at
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (stash_id, session_id, qualified_ref, payload_json, expires_at),
            )
            await conn.commit()

        record = StashRecord(
            stash_id=stash_id,
            session_id=session_id,
            qualified_ref=qualified_ref,
            payload_json=payload_json,
            expires_at=expires_at,
        )
        self._cache[(stash_id, session_id)] = record
        self._payload_cache[payload_key] = record
        return record

    async def get_stash(self, stash_id: str, session_id: str) -> StashRecord | None:
        """Fetch unexpired stashed payload scoped strictly to session_id."""
        cache_key = (stash_id, session_id)
        if cache_key in self._cache:
            return self._cache[cache_key]

        now = datetime.now(UTC).isoformat()
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"""
                SELECT * FROM {TABLE_RESULT_STASH}
                WHERE stash_id = ? AND session_id = ? AND expires_at > ?;
                """,
                (stash_id, session_id, now),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            record = StashRecord.model_validate(dict(row))
            self._cache[cache_key] = record
            return record

    async def purge_expired(self) -> int:
        """Purge all expired stash rows."""
        now = datetime.now(UTC).isoformat()
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"DELETE FROM {TABLE_RESULT_STASH} WHERE expires_at < ?;",
                (now,),
            )
            await conn.commit()
            return cursor.rowcount
