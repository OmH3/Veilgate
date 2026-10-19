"""FastAPI REST controller for Veilgate Dashboard and Reviewer UI."""

from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, status

from veilgate.dashboard.models import (
    ApprovalDecisionRequest,
    ApprovalListResponse,
    DecisionResponse,
    EventListResponse,
    MetricsSummaryResponse,
    SessionListResponse,
)
from veilgate.repositories.approval_repo import ApprovalRepository
from veilgate.repositories.audit_repo import AuditRepository
from veilgate.repositories.db import DatabaseManager
from veilgate.repositories.session_repo import SessionRepository

router = APIRouter(prefix="/api/v1", tags=["Dashboard"])


def get_db() -> DatabaseManager:
    """Dependency provider for database manager (overridden in app factory)."""
    raise NotImplementedError("get_db must be overridden by app.dependency_overrides")


@router.get(
    "/events",
    summary="List audit events with filtering and pagination",
    description=(
        "### Functional Overview\n"
        "Retrieves a paginated collection of tamper-evident audit log entries. "
        "Supports filtering by session ID and event kind (LIST, CALL, TRANSFORM, BLOCK, SECURITY, APPROVAL).\n\n"
        "### Filtering Semantics\n"
        "- `session_id`: Exact match on client session ID.\n"
        "- `kind`: Exact match on event category.\n\n"
        "### Pagination\n"
        "- `limit`: 1 to 500 (default: 50)\n"
        "- `offset`: >= 0 (default: 0)\n\n"
        "### Performance Considerations\n"
        "- Backed by SQLite indexes on (session_id, ts) and (kind, ts).\n"
        "- Ordered chronologically descending (newest events first)."
    ),
    response_model=EventListResponse,
    response_description="Paginated list of immutable audit event records",
    status_code=status.HTTP_200_OK,
    operation_id="list_audit_events",
    responses={
        200: {"description": "Audit events retrieved successfully"},
        500: {"description": "Internal database error"},
    },
)
async def list_events(
    session_id: Annotated[str | None, Query(description="Filter by session ID")] = None,
    kind: Annotated[str | None, Query(description="Filter by event kind")] = None,
    limit: Annotated[int, Query(ge=1, le=500, description="Page limit")] = 50,
    offset: Annotated[int, Query(ge=0, description="Page offset")] = 0,
    db: DatabaseManager = Depends(get_db),
) -> EventListResponse:
    """Query audit repository for paginated events."""
    repo = AuditRepository(db)
    items = await repo.list_events(session_id=session_id, kind=kind, limit=limit, offset=offset)
    return EventListResponse(
        items=items,
        total=len(items),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/sessions",
    summary="List tracked client sessions",
    description=(
        "### Functional Overview\n"
        "Retrieves active and historical client connections, their assigned transport, and current integrity rating.\n\n"
        "### Performance Considerations\n"
        "- Ordered by last_seen_at descending."
    ),
    response_model=SessionListResponse,
    response_description="List of tracked client sessions",
    status_code=status.HTTP_200_OK,
    operation_id="list_sessions",
)
async def list_sessions(
    db: DatabaseManager = Depends(get_db),
) -> SessionListResponse:
    """Fetch all recorded sessions."""
    repo = SessionRepository(db)
    items = await repo.list_active()
    return SessionListResponse(items=items, total=len(items))


@router.get(
    "/approvals",
    summary="List pending human approval requests",
    description=(
        "### Functional Overview\n"
        "Retrieves tools and calls paused awaiting human review decisions.\n\n"
        "### Performance Considerations\n"
        "- Filtered by status='PENDING' with index on (status, requested_at)."
    ),
    response_model=ApprovalListResponse,
    response_description="List of pending approval requests",
    status_code=status.HTTP_200_OK,
    operation_id="list_pending_approvals",
)
async def list_approvals(
    db: DatabaseManager = Depends(get_db),
) -> ApprovalListResponse:
    """Fetch pending human approval requests."""
    repo = ApprovalRepository(db)
    items = await repo.list_pending()
    return ApprovalListResponse(items=items, total=len(items))


@router.post(
    "/approvals/{approval_id}/decision",
    summary="Record human review decision",
    description=(
        "### Functional Overview\n"
        "Submits an approval or denial decision for a paused tool call.\n"
        "If 'APPROVED_AND_SAVED' is selected, automatically persists the grant to policy.learned.yaml.\n\n"
        "### Validation Behavior\n"
        "- Decision must be one of: APPROVED, APPROVED_AND_SAVED, or DENIED (otherwise 400)."
    ),
    response_model=DecisionResponse,
    response_description="Confirmation of recorded decision",
    status_code=status.HTTP_200_OK,
    operation_id="record_approval_decision",
    responses={
        200: {"description": "Decision successfully recorded"},
        400: {"description": "Invalid decision state"},
        404: {"description": "Approval request not found"},
    },
)
async def record_decision(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    db: DatabaseManager = Depends(get_db),
) -> DecisionResponse:
    """Submit approval decision."""
    if payload.decision not in ("APPROVED", "APPROVED_AND_SAVED", "DENIED"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decision must be APPROVED, APPROVED_AND_SAVED, or DENIED",
        )

    repo = ApprovalRepository(db)
    existing = await repo.get(approval_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval request '{approval_id}' not found",
        )

    await repo.decide(
        approval_id=approval_id,
        status=payload.decision,
        decided_by=payload.decided_by,
        learned_grant=payload.learned_grant,
    )

    return DecisionResponse(
        approval_id=approval_id,
        status=payload.decision,
        decided_by=payload.decided_by,
    )


@router.get(
    "/metrics/summary",
    summary="Get aggregated privacy and minimization metrics",
    description=(
        "### Functional Overview\n"
        "Aggregates total audit events, tokens minted, active sessions, and blocked calls categorized by reason code."
    ),
    response_model=MetricsSummaryResponse,
    response_description="Aggregated metrics summary",
    status_code=status.HTTP_200_OK,
    operation_id="get_metrics_summary",
)
async def get_metrics_summary(
    db: DatabaseManager = Depends(get_db),
) -> MetricsSummaryResponse:
    """Compute gateway metrics summary."""
    async with db.connection() as conn:
        # Event count
        cur = await conn.execute("SELECT COUNT(*) as count FROM audit_events;")
        row = await cur.fetchone()
        total_events = row["count"] if row else 0

        # Token count
        cur = await conn.execute("SELECT COUNT(*) as count FROM tokens;")
        row = await cur.fetchone()
        total_tokens = row["count"] if row else 0

        # Active sessions
        cur = await conn.execute("SELECT COUNT(*) as count FROM sessions;")
        row = await cur.fetchone()
        total_sessions = row["count"] if row else 0

        # Blocks by reason
        cur = await conn.execute(
            "SELECT reason, COUNT(*) as count FROM audit_events WHERE kind IN ('BLOCK', 'SECURITY') GROUP BY reason;"
        )
        rows = await cur.fetchall()
        blocks_by_reason = {r["reason"]: r["count"] for r in rows if r["reason"]}

    return MetricsSummaryResponse(
        total_events=total_events,
        total_tokens_minted=total_tokens,
        blocks_by_reason=blocks_by_reason,
        active_sessions_count=total_sessions,
    )
