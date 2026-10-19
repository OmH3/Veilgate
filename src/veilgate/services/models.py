"""Domain and data transfer models for Veilgate gateway pipeline services."""

from typing import Any
from pydantic import BaseModel, ConfigDict, Field
from ulid import ULID

from veilgate.config.constants import ReasonCode
from veilgate.config.policy_models import (
    FieldAction,
    PolicyLayer,
    SensitivityClass,
    SinkMacro,
    Transport,
)
from veilgate.repositories.models import TokenRecord


class ToolRef(BaseModel):
    """Normalized dual-identifier reference for MCP tools."""

    model_config = ConfigDict(frozen=True)

    server: str
    tool: str

    @property
    def qualified(self) -> str:
        """Internal dotted representation (e.g., 'invoicedb.get_invoice')."""
        return f"{self.server}.{self.tool}"

    @property
    def exposed(self) -> str:
        """Client wire-level underscored representation (e.g., 'invoicedb_get_invoice')."""
        return f"{self.server}_{self.tool}"

    @classmethod
    def parse(cls, identifier: str) -> "ToolRef":
        """Parse qualified ('server.tool') or exposed ('server_tool') names."""
        if "." in identifier:
            parts = identifier.split(".", 1)
            return cls(server=parts[0], tool=parts[1])
        if "_" in identifier:
            parts = identifier.split("_", 1)
            return cls(server=parts[0], tool=parts[1])
        return cls(server="default", tool=identifier)


class SessionContext(BaseModel):
    """Runtime context for an active client connection."""

    model_config = ConfigDict(extra="ignore")

    session_id: str
    correlation_id: str = Field(default_factory=lambda: str(ULID()))
    integrity: str = "HIGH"
    transport: Transport = Transport.STDIO
    client_supports_elicitation: bool = False
    client_supports_list_changed: bool = False
    promoted_tools: set[str] = Field(default_factory=set)
    task_intent: str | None = None


class TokenOrigin(BaseModel):
    """Lineage tracker for minted token."""

    model_config = ConfigDict(extra="ignore")

    ref: ToolRef
    json_path: str
    event_id: str


class TokenFinding(BaseModel):
    """Detected token within an input argument payload."""

    model_config = ConfigDict(extra="ignore")

    rendered: str
    token_id: str
    token_type: str
    arg_path: str
    is_standalone_scalar: bool
    record: TokenRecord | None = None


class TaintVerdict(BaseModel):
    """Disposition for a specific token detected in input arguments."""

    model_config = ConfigDict(extra="ignore")

    finding: TokenFinding
    decision: str  # "REHYDRATE", "FORWARD_OPAQUE", "BLOCK"
    reason: ReasonCode
    matched_layer: PolicyLayer | None = None


class TaintPlan(BaseModel):
    """Aggregated taint verdicts for an invocation."""

    model_config = ConfigDict(extra="ignore")

    verdicts: list[TaintVerdict] = Field(default_factory=list)

    @property
    def blocked(self) -> bool:
        """Returns True if any verdict requires blocking the invocation."""
        return any(v.decision == "BLOCK" for v in self.verdicts)

    @property
    def blocking_verdict(self) -> TaintVerdict | None:
        """Returns the first blocking verdict if present."""
        return next((v for v in self.verdicts if v.decision == "BLOCK"), None)


class AclDecision(BaseModel):
    """Outcome of tool discovery or invocation access control check."""

    model_config = ConfigDict(extra="ignore")

    decision: str  # "ALLOW", "DENY", "REQUIRE_APPROVAL"
    reason: ReasonCode
    matched_rule: str | None = None
    matched_layer: PolicyLayer | None = None


class ApprovalDecision(BaseModel):
    """Human-in-the-loop decision outcome."""

    model_config = ConfigDict(extra="ignore")

    approval_id: str
    status: str  # "APPROVED", "APPROVED_AND_SAVED", "DENIED", "EXPIRED"
    decided_by: str
    learned_grant: str | None = None


class FieldClassification(BaseModel):
    """Data sensitivity and minimization classification for a payload field."""

    model_config = ConfigDict(extra="ignore")

    json_path: str
    sensitivity: SensitivityClass = SensitivityClass.PUBLIC
    action: FieldAction = FieldAction.ALLOW
    source: str = "deterministic"
    matched_layer: PolicyLayer = PolicyLayer.PACK
    token_type: str | None = None
    allowed_sinks: list[str] | SinkMacro = SinkMacro.TRUSTED_READ
    allow_external_egress: bool = False
    confidence: float | None = None


class TransformRecord(BaseModel):
    """Record of a specific transformation applied to a field during egress."""

    model_config = ConfigDict(extra="ignore")

    json_path: str
    action: FieldAction
    token_type: str | None = None
    reason: str


class MinimizedResult(BaseModel):
    """Processed, tokenized, and diet-minimized tool result."""

    model_config = ConfigDict(extra="ignore")

    content: list[dict[str, Any]]
    structured_content: dict[str, Any] | list[Any] | None = None
    is_error: bool = False
    transforms: list[TransformRecord] = Field(default_factory=list)
    stash_id: str | None = None
    tokens_before: int = 0
    tokens_after: int = 0
    integrity_lowered: bool = False
