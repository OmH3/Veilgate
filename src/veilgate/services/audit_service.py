"""Audit service for logging structured, non-leaking security events."""

import json
from typing import Any
from ulid import ULID

from veilgate.config.constants import ReasonCode
from veilgate.repositories.audit_repo import AuditRepository
from veilgate.repositories.models import AuditEventRecord
from veilgate.services.models import SessionContext
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.services.audit_service")


class AuditService:
    """Records immutable audit trail entries with cryptographic hash chaining."""

    def __init__(self, audit_repo: AuditRepository) -> None:
        self.audit_repo: AuditRepository = audit_repo

    async def record(
        self,
        kind: str,
        session: SessionContext,
        qualified_ref: str | None = None,
        reason: ReasonCode | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEventRecord:
        """Record an immutable, sanitized audit event."""
        event_id = str(ULID())
        sanitized_details = details or {}
        details_json = json.dumps(sanitized_details, sort_keys=True)

        record = await self.audit_repo.record(
            event_id=event_id,
            session_id=session.session_id,
            correlation_id=session.correlation_id,
            kind=kind,
            qualified_ref=qualified_ref,
            reason=reason.value if reason else None,
            details_json=details_json,
        )

        logger.info(
            f"AUDIT | seq={record.seq} kind={kind} tool={qualified_ref} "
            f"reason={reason.value if reason else 'NONE'} event_id={event_id}"
        )
        return record
