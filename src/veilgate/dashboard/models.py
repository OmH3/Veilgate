"""Pydantic V2 response and request envelope models for Dashboard API."""

from pydantic import BaseModel, Field

from veilgate.repositories.models import ApprovalRecord, AuditEventRecord, SessionRecord


class EventListResponse(BaseModel):
    """Paginated collection of audit events."""

    items: list[AuditEventRecord]
    total: int
    limit: int
    offset: int


class SessionListResponse(BaseModel):
    """Collection of active client sessions."""

    items: list[SessionRecord]
    total: int


class ApprovalListResponse(BaseModel):
    """Collection of pending human approval requests."""

    items: list[ApprovalRecord]
    total: int


class ApprovalDecisionRequest(BaseModel):
    """Payload to record human reviewer decision."""

    decision: str = Field(
        ...,
        description="Reviewer decision: APPROVED, APPROVED_AND_SAVED, or DENIED.",
        examples=["APPROVED"],
    )
    decided_by: str = Field(
        default="human_operator",
        description="Identity of reviewing operator.",
        examples=["alice@example.com"],
    )
    learned_grant: str | None = Field(
        default=None,
        description="Optional grant pattern when APPROVED_AND_SAVED is chosen.",
        examples=["invoicedb.compare_*:account"],
    )


class DecisionResponse(BaseModel):
    """Confirmation of recorded approval decision."""

    approval_id: str
    status: str
    decided_by: str


class MetricsSummaryResponse(BaseModel):
    """Aggregated gateway privacy and token minimization statistics."""

    total_events: int
    total_tokens_minted: int
    blocks_by_reason: dict[str, int]
    active_sessions_count: int
