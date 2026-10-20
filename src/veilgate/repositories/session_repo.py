"""Repository for managing client session lifecycles and integrity states."""

from datetime import UTC, datetime

from veilgate.config.constants import TABLE_SESSIONS
from veilgate.repositories.db import DatabaseManager
from veilgate.repositories.models import SessionRecord


class SessionRepository:
    """Manages SQLite queries for the sessions table."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db: DatabaseManager = db_manager

    async def create_or_touch(
        self,
        session_id: str,
        transport: str,
        label: str | None = None,
    ) -> SessionRecord:
        """Insert a new session or update last_seen_at for an existing session."""
        now = datetime.now(UTC).isoformat()
        async with self.db.connection() as conn:
            await conn.execute(
                f"""
                INSERT INTO {TABLE_SESSIONS} (session_id, label, transport, integrity, created_at, last_seen_at)
                VALUES (?, ?, ?, 'HIGH', ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    last_seen_at = excluded.last_seen_at,
                    label = COALESCE(excluded.label, {TABLE_SESSIONS}.label);
                """,
                (session_id, label, transport, now, now),
            )
            await conn.commit()
            cursor = await conn.execute(
                f"SELECT * FROM {TABLE_SESSIONS} WHERE session_id = ?;",
                (session_id,),
            )
            row = await cursor.fetchone()

        if row is None:
            raise RuntimeError(f"Failed to retrieve or create session {session_id}")
        return SessionRecord.model_validate(dict(row))

    async def get(self, session_id: str) -> SessionRecord | None:
        """Fetch session by ID."""
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"SELECT * FROM {TABLE_SESSIONS} WHERE session_id = ?;",
                (session_id,),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return SessionRecord.model_validate(dict(row))

    async def update_integrity(self, session_id: str, integrity: str) -> None:
        """Update session integrity level ('HIGH' or 'LOW')."""
        if integrity not in ("HIGH", "LOW"):
            raise ValueError(f"Invalid integrity state: {integrity}")

        now = datetime.now(UTC).isoformat()
        async with self.db.connection() as conn:
            await conn.execute(
                f"""
                UPDATE {TABLE_SESSIONS}
                SET integrity = ?, last_seen_at = ?
                WHERE session_id = ?;
                """,
                (integrity, now, session_id),
            )
            await conn.commit()

    async def list_active(self) -> list[SessionRecord]:
        """List all tracked sessions."""
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"SELECT * FROM {TABLE_SESSIONS} ORDER BY last_seen_at DESC;"
            )
            rows = await cursor.fetchall()
            return [SessionRecord.model_validate(dict(r)) for r in rows]
