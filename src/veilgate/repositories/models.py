"""Internal persistence records and schema models for SQLite repositories."""

from pydantic import BaseModel, ConfigDict, Field


class SessionRecord(BaseModel):
    """Database record representation of an active client session."""

    model_config = ConfigDict(extra="ignore")

    session_id: str
    label: str | None = None
    transport: str
    integrity: str = "HIGH"
    created_at: str
    last_seen_at: str


class TokenRecord(BaseModel):
    """Token representation retrieved from vault (without raw plaintext)."""

    model_config = ConfigDict(extra="ignore")

    token_id: str
    session_id: str
    rendered: str
    token_type: str
    sensitivity: str
    value_kind: str
    origin_ref: str
    origin_path: str
    origin_event_id: str
    allowed_sinks_json: str
    allow_external_egress: bool
    created_at: str
    expires_at: str


class TokenRecordCreate(BaseModel):
    """Input payload to vault for token minting and encryption."""

    model_config = ConfigDict(extra="ignore")

    token_id: str
    session_id: str
    rendered: str
    token_type: str
    sensitivity: str
    value_kind: str
    raw_value: str
    origin_ref: str
    origin_path: str
    origin_event_id: str
    allowed_sinks: list[str] | str
    allow_external_egress: bool = False
    ttl_seconds: int = 86_400


class CatalogEntryRecord(BaseModel):
    """Database record for introspected and classified upstream tools."""

    model_config = ConfigDict(extra="ignore")

    qualified_ref: str
    server_id: str
    fingerprint: str
    pinned_fp: str | None = None
    status: str = "active"
    capabilities: list[str] = Field(default_factory=list)
    is_open_world: bool = False
    untrusted_tool: bool = False
    risk_level: str = "LOW"
    schema_tokens: int = 0
    raw_json: str = "{}"
    first_seen_at: str
    updated_at: str


class AuditEventRecord(BaseModel):
    """Immutable audit trail row model."""

    model_config = ConfigDict(extra="ignore")

    seq: int | None = None
    event_id: str
    ts: str
    session_id: str
    correlation_id: str
    kind: str
    qualified_ref: str | None = None
    reason: str | None = None
    details_json: str
    prev_hash: str
    row_hash: str


class ApprovalRecord(BaseModel):
    """Human-in-the-loop approval request record."""

    model_config = ConfigDict(extra="ignore")

    approval_id: str
    session_id: str
    qualified_ref: str
    summary_json: str
    reason: str
    status: str = "PENDING"
    learned_grant: str | None = None
    requested_at: str
    decided_at: str | None = None
    decided_by: str | None = None


class StashRecord(BaseModel):
    """Dropped non-sensitive response payload stash record."""

    model_config = ConfigDict(extra="ignore")

    stash_id: str
    session_id: str
    qualified_ref: str
    payload_json: str
    expires_at: str
