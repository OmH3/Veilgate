import re
from enum import StrEnum

# Token formatting and parsing specifications
TOKEN_PREFIX: str = "<vg:"
TOKEN_SUFFIX: str = ">"
TOKEN_REGEX_PATTERN: str = r"<vg:([A-Z_]{2,32}):([0-9A-HJKMNP-TV-Z]{6})>"
TOKEN_REGEX: re.Pattern[str] = re.compile(TOKEN_REGEX_PATTERN)

# Crockford Base32 alphabet (excludes I, L, O, U to prevent visual ambiguity)
CROCKFORD_BASE32_ALPHABET: str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# Format-preserving email and URL tokens (.invalid RFC 2606 guarantees non-deliverability)
EMAIL_TOKEN_REGEX_PATTERN: str = r"vg-([0-9a-hjkmnp-tv-z]{6})@vault\.veilgate\.invalid"
EMAIL_TOKEN_REGEX: re.Pattern[str] = re.compile(EMAIL_TOKEN_REGEX_PATTERN, re.IGNORECASE)
EMAIL_TOKEN_DOMAIN: str = "vault.veilgate.invalid"

URL_TOKEN_PREFIX: str = "https://vault.veilgate.invalid/t/"
URL_TOKEN_REGEX_PATTERN: str = r"https://vault\.veilgate\.invalid/t/([0-9a-hjkmnp-tv-z]{6})"
URL_TOKEN_REGEX: re.Pattern[str] = re.compile(URL_TOKEN_REGEX_PATTERN, re.IGNORECASE)

# Synthetic integer base for type-preserving integer tokenization
SYNTHETIC_INT_BASE: int = 900_000_000_000

# SQLite table names
TABLE_SESSIONS: str = "sessions"
TABLE_TOKENS: str = "tokens"
TABLE_TOOL_CATALOG: str = "tool_catalog"
TABLE_SCHEMA_CACHE: str = "schema_cache"
TABLE_AUDIT_EVENTS: str = "audit_events"
TABLE_APPROVALS: str = "approvals"
TABLE_RESULT_STASH: str = "result_stash"
TABLE_TELEMETRY: str = "telemetry"

# Default operational constants
DEFAULT_TOKEN_TTL_SECONDS: int = 86_400  # 24 hours
DEFAULT_STASH_TTL_SECONDS: int = 1_800   # 30 minutes
DEFAULT_UPSTREAM_TIMEOUT_SECONDS: float = 30.0
DEFAULT_APPROVAL_TIMEOUT_SECONDS: int = 120
DEFAULT_SEARCH_THRESHOLD: int = 20
DEFAULT_TOP_K: int = 8
DEFAULT_MAX_DESCRIPTION_CHARS: int = 300
DEFAULT_TABLE_THRESHOLD: int = 10
DEFAULT_MAX_ARRAY_ITEMS: int = 50
DEFAULT_MAX_STRING_CHARS: int = 2_000


class ReasonCode(StrEnum):
    """Normalized gateway decision and diagnostic reason codes."""

    OK = "OK"
    OK_SINK_ALLOWED = "OK_SINK_ALLOWED"
    OK_FORWARD_OPAQUE = "OK_FORWARD_OPAQUE"

    # ACL & Tool Catalog
    TOOL_UNKNOWN = "TOOL_UNKNOWN"
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    TOOL_QUARANTINED = "TOOL_QUARANTINED"

    # Human-in-the-Loop Approvals
    APPROVAL_APPROVED = "APPROVAL_APPROVED"
    APPROVAL_APPROVED_AND_SAVED = "APPROVAL_APPROVED_AND_SAVED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    APPROVAL_TIMEOUT = "APPROVAL_TIMEOUT"
    EGRESS_APPROVAL_REQUIRED = "EGRESS_APPROVAL_REQUIRED"

    # Token Capability & Taint Tracking
    TOKEN_UNKNOWN = "TOKEN_UNKNOWN"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_SCOPE_MISMATCH = "TOKEN_SCOPE_MISMATCH"
    TAINT_EGRESS_FORBIDDEN = "TAINT_EGRESS_FORBIDDEN"
    TAINT_SINK_NOT_ALLOWED = "TAINT_SINK_NOT_ALLOWED"
    TAINT_ARG_GUARD_BLOCKED = "TAINT_ARG_GUARD_BLOCKED"
    TOKEN_TYPE_BLOCKED = "TOKEN_TYPE_BLOCKED"
    TOKEN_ENCODED_SMUGGLING = "TOKEN_ENCODED_SMUGGLING"

    # Session Integrity
    LOW_INTEGRITY_APPROVAL_REQUIRED = "LOW_INTEGRITY_APPROVAL_REQUIRED"

    # Upstream Fleet Communication
    UPSTREAM_UNAVAILABLE = "UPSTREAM_UNAVAILABLE"
    UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"

    # Internal Guardrails
    INTERNAL_FAIL_CLOSED = "INTERNAL_FAIL_CLOSED"
