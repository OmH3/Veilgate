"""Tamper-evident append-only audit trail repository with cryptographic hash chaining."""

import hashlib
from datetime import UTC, datetime

from veilgate.config.constants import TABLE_AUDIT_EVENTS
from veilgate.repositories.db import DatabaseManager
from veilgate.repositories.models import AuditEventRecord


def compute_row_hash(
    prev_hash: str,
    event_id: str,
    ts: str,
    session_id: str,
    correlation_id: str,
    kind: str,
    qualified_ref: str | None,
    reason: str | None,
    details_json: str,
) -> str:
    """Compute deterministic SHA-256 hash chaining previous row hash with current row payload."""
    payload = "|".join(
        [
            prev_hash,
            event_id,
            ts,
            session_id,
            correlation_id,
            kind,
            qualified_ref or "",
            reason or "",
            details_json,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditRepository:
    """Manages append-only audit logs with SHA-256 tamper-evident hash chaining."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db: DatabaseManager = db_manager
        self._last_row_hash: str | None = None

    async def record(
        self,
        event_id: str,
        session_id: str,
        correlation_id: str,
        kind: str,
        details_json: str,
        qualified_ref: str | None = None,
        reason: str | None = None,
        ts: str | None = None,
    ) -> AuditEventRecord:
        """Insert an immutable audit event with computed cryptographic hash link."""
        event_ts = ts or datetime.now(UTC).isoformat()

        async with self.db.connection() as conn:
            # 1. Fetch hash of latest committed row if not cached
            if self._last_row_hash is None:
                cursor = await conn.execute(
                    f"SELECT row_hash FROM {TABLE_AUDIT_EVENTS} ORDER BY seq DESC LIMIT 1;"
                )
                row = await cursor.fetchone()
                prev_hash = row["row_hash"] if row is not None else ("0" * 64)
            else:
                prev_hash = self._last_row_hash

            # 2. Compute current row hash
            row_hash = compute_row_hash(
                prev_hash=prev_hash,
                event_id=event_id,
                ts=event_ts,
                session_id=session_id,
                correlation_id=correlation_id,
                kind=kind,
                qualified_ref=qualified_ref,
                reason=reason,
                details_json=details_json,
            )

            # 3. Insert row
            ins_cur = await conn.execute(
                f"""
                INSERT INTO {TABLE_AUDIT_EVENTS} (
                    event_id, ts, session_id, correlation_id, kind,
                    qualified_ref, reason, details_json, prev_hash, row_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event_id,
                    event_ts,
                    session_id,
                    correlation_id,
                    kind,
                    qualified_ref,
                    reason,
                    details_json,
                    prev_hash,
                    row_hash,
                ),
            )
            await conn.commit()
            self._last_row_hash = row_hash
            seq_id = int(ins_cur.lastrowid or 1)

            return AuditEventRecord(
                seq=seq_id,
                event_id=event_id,
                ts=event_ts,
                session_id=session_id,
                correlation_id=correlation_id,
                kind=kind,
                qualified_ref=qualified_ref,
                reason=reason,
                details_json=details_json,
                prev_hash=prev_hash,
                row_hash=row_hash,
            )

    async def list_events(
        self,
        session_id: str | None = None,
        kind: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEventRecord]:
        """Query audit log with pagination and filters."""
        query = f"SELECT * FROM {TABLE_AUDIT_EVENTS}"
        clauses: list[str] = []
        params: list[str | int] = []

        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if kind:
            clauses.append("kind = ?")
            params.append(kind)

        if clauses:
            query += " WHERE " + " AND ".join(clauses)

        query += " ORDER BY seq DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        async with self.db.connection() as conn:
            cursor = await conn.execute(query, tuple(params))
            rows = await cursor.fetchall()
            return [AuditEventRecord.model_validate(dict(r)) for r in rows]

    async def verify_chain(self) -> tuple[bool, str | None]:
        """Verify the cryptographic integrity of the entire audit chain.

        Returns:
            Tuple of (is_valid: bool, error_message: str | None).
        """
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"SELECT * FROM {TABLE_AUDIT_EVENTS} ORDER BY seq ASC;"
            )
            rows = await cursor.fetchall()

        expected_prev_hash = "0" * 64
        for row in rows:
            data = dict(row)
            if data["prev_hash"] != expected_prev_hash:
                return (
                    False,
                    f"Hash break at seq={data['seq']}: expected prev_hash={expected_prev_hash}, got {data['prev_hash']}",
                )

            computed = compute_row_hash(
                prev_hash=data["prev_hash"],
                event_id=data["event_id"],
                ts=data["ts"],
                session_id=data["session_id"],
                correlation_id=data["correlation_id"],
                kind=data["kind"],
                qualified_ref=data["qualified_ref"],
                reason=data["reason"],
                details_json=data["details_json"],
            )

            if computed != data["row_hash"]:
                return (
                    False,
                    f"Tampered row at seq={data['seq']}: computed row_hash={computed}, stored {data['row_hash']}",
                )

            expected_prev_hash = computed

        return True, None
