"""Declarative policy schema models for Veilgate Gateway.

Defines Pydantic V2 models for user policies (policy.yaml), interactive grants
(policy.learned.yaml), and modular rule packs (packs/*.yaml).
"""

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class Transport(StrEnum):
    """MCP transport protocols."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


class Capability(StrEnum):
    """Inferred or declared tool capability markers."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXTERNAL_EGRESS = "external_egress"
    EXEC = "exec"


class RiskLevel(StrEnum):
    """Categorized risk rating for tools."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FieldAction(StrEnum):
    """Transform action applied to sensitive or bloated response fields."""

    ALLOW = "ALLOW"
    DROP = "DROP"
    TOKENIZE = "TOKENIZE"
    MASK = "MASK"
    HASH = "HASH"


class SensitivityClass(StrEnum):
    """Data classification categories."""

    SECRET = "SECRET"
    PII_HIGH = "PII_HIGH"
    PII_MEDIUM = "PII_MEDIUM"
    PII_LOW = "PII_LOW"
    PUBLIC = "PUBLIC"
    TASK_REQUIRED = "TASK_REQUIRED"
    UNNECESSARY_BLOAT = "UNNECESSARY_BLOAT"


class DietMode(StrEnum):
    """Context diet tool catalog presentation modes."""

    AUTO = "auto"
    FULL = "full"
    PROFILE = "profile"
    SEARCH = "search"
    INTENT = "intent"


class SinkMacro(StrEnum):
    """High-level capability macros for allowed token destinations."""

    NONE = "none"
    SAME_SERVER_READ = "same_server_read"
    TRUSTED_READ = "trusted_read"
    SAME_SERVER_WRITE = "same_server_write"


class UnlistedSinkPolicy(StrEnum):
    """Fallback action when a token reaches a tool sink without explicit rule."""

    BLOCK = "block"
    FORWARD_OPAQUE = "forward_opaque"
    PROMPT_AND_LEARN = "prompt_and_learn"


class TrustLevel(StrEnum):
    """Trust rating assigned to upstream servers and tools."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    AUTO = "auto"


class PolicyLayer(StrEnum):
    """Policy hierarchy layers for origin tracking and debugging."""

    USER = "policy.yaml"
    LEARNED = "policy.learned.yaml"
    PACK = "packs/*.yaml"


class UpstreamSpec(BaseModel):
    """Configuration specification for an upstream MCP server."""

    model_config = ConfigDict(extra="ignore")

    id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9]{1,23}$")] = Field(
        ...,
        description="Unique namespace identifier for upstream server. Lowercase alphanumeric only (no underscores).",
    )
    transport: Transport = Field(
        default=Transport.STDIO,
        description="Transport protocol (stdio, http, sse).",
    )
    command: str | None = Field(
        default=None,
        description="Executable command for stdio transport.",
    )
    args: list[str] = Field(
        default_factory=list,
        description="Arguments passed to command.",
    )
    url: str | None = Field(
        default=None,
        description="Endpoint URL for http/sse transports.",
    )
    env: dict[str, str] = Field(
        default_factory=dict,
        description="Environment variables injected into upstream process.",
    )
    trust: TrustLevel = Field(
        default=TrustLevel.AUTO,
        description="Trust level (auto-inferred from server-profiles pack if auto).",
    )
    pinned_fingerprints: dict[str, str] = Field(
        default_factory=dict,
        description="Pinned tool schema fingerprints to protect against rug-pulls.",
    )
    timeout_seconds: float | None = Field(
        default=None,
        description="Per-upstream timeout override in seconds.",
    )


class TokenizeSpec(BaseModel):
    """Tokenization options for a sensitive field rule."""

    model_config = ConfigDict(extra="ignore")

    token_type: str = Field(
        default="GENERIC",
        description="Token category label (e.g., SSN, BANK_ROUTING, EMAIL, API_KEY).",
    )
    allowed_sinks: list[str] | SinkMacro = Field(
        default=SinkMacro.TRUSTED_READ,
        description="Allowed destination tool glob patterns or sink capability macro.",
    )
    allow_external_egress: bool = Field(
        default=False,
        description="Whether this token may ever leave the gateway to external APIs.",
    )


class FieldRuleSpec(BaseModel):
    """Field-level transformation rule matching JSONPath or key globs."""

    model_config = ConfigDict(extra="ignore")

    path: str = Field(
        ...,
        description="JSONPath selector (e.g. $.customer.ssn or $..routing_number).",
    )
    action: FieldAction = Field(
        default=FieldAction.TOKENIZE,
        description="Action to execute: TOKENIZE, DROP, MASK, HASH, or ALLOW.",
    )
    tokenize: TokenizeSpec | None = Field(
        default=None,
        description="Tokenization details if action is TOKENIZE.",
    )
    mask_char: str = Field(
        default="*",
        description="Masking character if action is MASK.",
    )
    mask_keep_last: int = Field(
        default=4,
        description="Number of unmasked characters to retain at string end.",
    )


class ToolPolicySpec(BaseModel):
    """Access control and field rules matching a tool pattern."""

    model_config = ConfigDict(extra="ignore")

    match: str = Field(
        ...,
        description="Glob pattern for qualified tool names (e.g., invoicedb.* or mailer.send_email).",
    )
    allow: bool = Field(
        default=True,
        description="Whether matched tools are permitted for agent discovery and execution.",
    )
    capabilities: list[Capability] | None = Field(
        default=None,
        description="Explicit capability overrides (read, write, delete, external_egress, exec).",
    )
    risk_level: RiskLevel | None = Field(
        default=None,
        description="Explicit risk level override.",
    )
    trust: TrustLevel | None = Field(
        default=None,
        description="Explicit trust override for this specific tool.",
    )
    blocked_token_types: list[str] = Field(
        default_factory=list,
        description="Token types strictly forbidden from entering any parameter of this tool.",
    )
    field_rules: list[FieldRuleSpec] = Field(
        default_factory=list,
        description="Field transformation rules for results returned by this tool.",
    )
    arg_guards: list[str] = Field(
        default_factory=list,
        description="Argument names that must not receive raw tokens or untrusted tainted data.",
    )
    require_approval: bool = Field(
        default=False,
        description="Forces human approval before invocation regardless of risk level.",
    )


class DietSpec(BaseModel):
    """Catalog pruning and token minimization configuration."""

    model_config = ConfigDict(extra="ignore")

    mode: DietMode = Field(
        default=DietMode.AUTO,
        description="Catalog diet mode (auto, full, profile, search, intent).",
    )
    search_threshold: int = Field(
        default=20,
        description="Catalog size triggering meta-tool search mode.",
    )
    top_k: int = Field(
        default=8,
        description="Number of ranked tools returned by search queries.",
    )
    max_description_chars: int = Field(
        default=300,
        description="Character threshold for schema description compaction.",
    )
    pinned_tools: list[str] = Field(
        default_factory=list,
        description="Tool glob patterns always included in catalog regardless of search mode.",
    )


class CompactionSpec(BaseModel):
    """Response payload compaction thresholds."""

    model_config = ConfigDict(extra="ignore")

    table_threshold: int = Field(
        default=10,
        description="Array length triggering markdown table rendering in text content.",
    )
    max_array_items: int = Field(
        default=50,
        description="Maximum array items included before truncation with stash reference.",
    )
    max_string_chars: int = Field(
        default=2_000,
        description="Maximum string character length before truncation.",
    )
    drop_bloat: bool = Field(
        default=True,
        description="Automatically drop standard HTTP bloat keys defined in bloat-http pack.",
    )
    stash_dropped_fields: bool = Field(
        default=True,
        description="Stash dropped non-sensitive fields in result_stash for optional veilgate_expand.",
    )


class LearnedGrant(BaseModel):
    """Interactive grant persisted from --dev approval decisions."""

    model_config = ConfigDict(extra="ignore")

    grant_id: str = Field(..., description="Unique grant identifier.")
    pattern: str = Field(..., description="Target tool pattern (e.g. invoicedb.compare_*:account).")
    token_type: str = Field(..., description="Permitted token type.")
    created_at: str = Field(..., description="ISO 8601 timestamp of grant creation.")


class VeilgatePolicy(BaseModel):
    """Complete 3-layer resolved policy document."""

    model_config = ConfigDict(extra="ignore")

    version: str = Field(default="1", description="Policy schema version.")
    extends: str = Field(default="recommended", description="Base rule pack to inherit.")
    default_tool_allow: bool = Field(
        default=True,
        description="Default allow/deny decision for tools not matching explicit rules.",
    )
    unlisted_sink_policy: UnlistedSinkPolicy = Field(
        default=UnlistedSinkPolicy.BLOCK,
        description="Policy for token transmission to tools not listed in allowed_sinks.",
    )
    upstreams: list[UpstreamSpec] = Field(
        default_factory=list,
        description="List of configured upstream MCP servers.",
    )
    protect: list[str] = Field(
        default_factory=list,
        description="Flat list of sensitive keyword names auto-compiled to deep tokenization matchers.",
    )
    drop: list[str] = Field(
        default_factory=list,
        description="Flat list of bloat keyword names auto-compiled to deep drop matchers.",
    )
    tools: list[ToolPolicySpec] = Field(
        default_factory=list,
        description="Explicit per-tool policies and overrides.",
    )
    diet: DietSpec = Field(
        default_factory=DietSpec,
        description="Tool catalog context diet specifications.",
    )
    compaction: CompactionSpec = Field(
        default_factory=CompactionSpec,
        description="Response payload compaction parameters.",
    )
    learned_grants: list[LearnedGrant] = Field(
        default_factory=list,
        description="Interactive grants merged from policy.learned.yaml.",
    )
