"""Repository for human-in-the-loop approval workflows."""

from datetime import UTC, datetime

from veilgate.config.constants import TABLE_APPROVALS
from veilgate.repositories.db import DatabaseManager
from veilgate.repositories.models import ApprovalRecord


class ApprovalRepository:
    """Manages human approval requests, decisions, and learned policy grants."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db: DatabaseManager = db_manager

    async def create_request(
        self,
        approval_id: str,
        session_id: str,
        qualified_ref: str,
        summary_json: str,
        reason: str,
    ) -> ApprovalRecord:
        """Create a new pending approval record."""
        now = datetime.now(UTC).isoformat()
        async with self.db.connection() as conn:
            await conn.execute(
                f"""
                INSERT INTO {TABLE_APPROVALS} (
                    approval_id, session_id, qualified_ref, summary_json,
                    reason, status, requested_at
                ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?);
                """,
                (approval_id, session_id, qualified_ref, summary_json, reason, now),
            )
            await conn.commit()

        record = await self.get(approval_id)
        if record is None:
            raise RuntimeError(f"Failed to create approval request {approval_id}")
        return record

    async def get(self, approval_id: str) -> ApprovalRecord | None:
        """Retrieve approval record by ID."""
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"SELECT * FROM {TABLE_APPROVALS} WHERE approval_id = ?;",
                (approval_id,),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return ApprovalRecord.model_validate(dict(row))

    async def decide(
        self,
        approval_id: str,
        status: str,
        decided_by: str,
        learned_grant: str | None = None,
    ) -> None:
        """Record decision ('APPROVED', 'APPROVED_AND_SAVED', 'DENIED', 'EXPIRED')."""
        now = datetime.now(UTC).isoformat()
        async with self.db.connection() as conn:
            await conn.execute(
                f"""
                UPDATE {TABLE_APPROVALS}
                SET status = ?, decided_at = ?, decided_by = ?, learned_grant = ?
                WHERE approval_id = ?;
                """,
                (status, now, decided_by, learned_grant, approval_id),
            )
            await conn.commit()

    async def list_pending(self) -> list[ApprovalRecord]:
        """List all requests currently awaiting review."""
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"SELECT * FROM {TABLE_APPROVALS} WHERE status = 'PENDING' ORDER BY requested_at ASC;"
            )
            rows = await cursor.fetchall()
            return [ApprovalRecord.model_validate(dict(r)) for r in rows]
