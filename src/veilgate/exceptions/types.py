"""Semantic exception hierarchy for Veilgate Gateway.

Mirrors enterprise API Gateway exception architectures with structured reason
codes, safe client error messages, and granular policy violation hierarchies.
"""

from collections.abc import Mapping

from veilgate.config.constants import ReasonCode


class VeilgateError(Exception):
    """Base exception for all Veilgate runtime and configuration errors.

    Attributes:
        safe_message: Sanitized message safe to return to clients or LLMs.
        reason: Normalized ReasonCode indicating root cause.
        details: Optional non-sensitive contextual metadata.
    """

    def __init__(
        self,
        safe_message: str,
        reason: ReasonCode = ReasonCode.INTERNAL_FAIL_CLOSED,
        details: Mapping[str, str | int | float | bool] | None = None,
    ) -> None:
        super().__init__(safe_message)
        self.safe_message: str = safe_message
        self.reason: ReasonCode = reason
        self.details: Mapping[str, str | int | float | bool] = details or {}

    def to_agent_message(self, correlation_id: str | None = None) -> str:
        """Format a structured, actionable error message for the LLM agent.

        Args:
            correlation_id: Optional correlation tracking ULID.

        Returns:
            Structured block string informing the agent of the policy block
            without leaking raw vault data or internal network topologies.
        """
        parts: list[str] = [
            f"[VEILGATE BLOCKED] code={self.reason.value}",
            f"message={self.safe_message}",
        ]
        if self.details:
            details_str = " ".join(f"{k}={v}" for k, v in sorted(self.details.items()))
            parts.append(details_str)
        if correlation_id:
            parts.append(f"correlation_id={correlation_id}")
        return " | ".join(parts)


class ConfigError(VeilgateError):
    """Raised when policy.yaml, packs, or environment configuration is invalid."""

    def __init__(
        self,
        safe_message: str,
        details: Mapping[str, str | int | float | bool] | None = None,
    ) -> None:
        super().__init__(
            safe_message=safe_message,
            reason=ReasonCode.INTERNAL_FAIL_CLOSED,
            details=details,
        )


class UpstreamError(VeilgateError):
    """Base class for communication faults with upstream MCP servers."""

    def __init__(
        self,
        safe_message: str,
        reason: ReasonCode = ReasonCode.UPSTREAM_ERROR,
        details: Mapping[str, str | int | float | bool] | None = None,
    ) -> None:
        super().__init__(safe_message=safe_message, reason=reason, details=details)


class UpstreamUnavailableError(UpstreamError):
    """Raised when an upstream MCP server cannot be spawned or contacted."""

    def __init__(
        self,
        server_id: str,
        safe_message: str | None = None,
    ) -> None:
        msg = safe_message or f"Upstream server '{server_id}' is unreachable or failed to start."
        super().__init__(
            safe_message=msg,
            reason=ReasonCode.UPSTREAM_UNAVAILABLE,
            details={"server_id": server_id},
        )


class UpstreamTimeoutError(UpstreamError):
    """Raised when an upstream MCP server exceeds the operational timeout."""

    def __init__(
        self,
        server_id: str,
        timeout_seconds: float,
    ) -> None:
        super().__init__(
            safe_message=f"Upstream server '{server_id}' timed out after {timeout_seconds}s.",
            reason=ReasonCode.UPSTREAM_TIMEOUT,
            details={"server_id": server_id, "timeout_seconds": timeout_seconds},
        )


class UpstreamProtocolError(UpstreamError):
    """Raised when an upstream MCP server returns malformed JSON-RPC or schema violations."""

    def __init__(
        self,
        server_id: str,
        safe_message: str,
    ) -> None:
        super().__init__(
            safe_message=safe_message,
            reason=ReasonCode.UPSTREAM_ERROR,
            details={"server_id": server_id},
        )


class PolicyViolation(VeilgateError):
    """Base class for deterministic policy violations (expected business/security rules)."""


class ToolNotAllowedError(PolicyViolation):
    """Raised when an agent attempts to invoke a tool denied by ACL policy."""

    def __init__(
        self,
        tool_name: str,
        safe_message: str | None = None,
    ) -> None:
        msg = safe_message or f"Tool '{tool_name}' is not permitted by current ACL policy."
        super().__init__(
            safe_message=msg,
            reason=ReasonCode.TOOL_NOT_ALLOWED,
            details={"tool": tool_name},
        )


class ToolQuarantinedError(PolicyViolation):
    """Raised when a tool schema changed unexpectedly without explicit admin re-approval."""

    def __init__(
        self,
        tool_name: str,
        expected_fingerprint: str,
        observed_fingerprint: str,
    ) -> None:
        super().__init__(
            safe_message=f"Tool '{tool_name}' schema fingerprint mismatch (quarantined). Admin approval required.",
            reason=ReasonCode.TOOL_QUARANTINED,
            details={
                "tool": tool_name,
                "expected_fp": expected_fingerprint[:12],
                "observed_fp": observed_fingerprint[:12],
            },
        )


class TaintViolationError(PolicyViolation):
    """Raised when data taint rules, arg guards, or egress restrictions are violated."""

    def __init__(
        self,
        safe_message: str,
        reason: ReasonCode = ReasonCode.TAINT_EGRESS_FORBIDDEN,
        token_id: str | None = None,
        arg_path: str | None = None,
        tool_name: str | None = None,
    ) -> None:
        details: dict[str, str | int | float | bool] = {}
        if token_id:
            details["token_id"] = token_id
        if arg_path:
            details["arg_path"] = arg_path
        if tool_name:
            details["tool"] = tool_name
        super().__init__(safe_message=safe_message, reason=reason, details=details)


class ApprovalDeniedError(PolicyViolation):
    """Raised when a human reviewer explicitly denies a tool invocation."""

    def __init__(
        self,
        tool_name: str,
        safe_message: str | None = None,
    ) -> None:
        msg = safe_message or f"Invocation of '{tool_name}' was denied by human reviewer."
        super().__init__(
            safe_message=msg,
            reason=ReasonCode.APPROVAL_DENIED,
            details={"tool": tool_name},
        )


class ApprovalTimeoutError(PolicyViolation):
    """Raised when an approval request times out waiting for reviewer response."""

    def __init__(
        self,
        tool_name: str,
        timeout_seconds: int,
    ) -> None:
        super().__init__(
            safe_message=f"Approval request for '{tool_name}' timed out after {timeout_seconds}s.",
            reason=ReasonCode.APPROVAL_TIMEOUT,
            details={"tool": tool_name, "timeout_seconds": timeout_seconds},
        )


class LowIntegrityApprovalRequiredError(PolicyViolation):
    """Raised when a low-integrity session attempts a state-modifying action without approval."""

    def __init__(
        self,
        tool_name: str,
        capability: str,
    ) -> None:
        super().__init__(
            safe_message=f"Tool '{tool_name}' requires approval because session integrity is LOW (capability={capability}).",
            reason=ReasonCode.LOW_INTEGRITY_APPROVAL_REQUIRED,
            details={"tool": tool_name, "capability": capability},
        )


class VaultError(VeilgateError):
    """Base class for token vault encryption and persistence errors."""


class TokenNotFoundError(VaultError):
    """Raised when a token identifier is missing, expired, or scoped to another session."""

    def __init__(
        self,
        token_id: str,
        reason: ReasonCode = ReasonCode.TOKEN_UNKNOWN,
    ) -> None:
        super().__init__(
            safe_message=f"Token '{token_id}' not found, expired, or invalid for active session.",
            reason=reason,
            details={"token_id": token_id},
        )


class VaultCryptoError(VaultError):
    """Raised when cryptographic key retrieval, encryption, or decryption fails."""

    def __init__(
        self,
        safe_message: str = "Cryptographic operation failed in token vault.",
    ) -> None:
        super().__init__(
            safe_message=safe_message,
            reason=ReasonCode.INTERNAL_FAIL_CLOSED,
        )


class ClassifierError(VeilgateError):
    """Base class for heuristic or model-based payload classifier errors."""


class JevUnavailableError(ClassifierError):
    """Raised when the Jev shape classification API is unreachable or times out."""

    def __init__(
        self,
        safe_message: str = "Jev classifier service unavailable; falling back to deterministic rules.",
        details: Mapping[str, str | int | float | bool] | None = None,
    ) -> None:
        super().__init__(
            safe_message=safe_message,
            reason=ReasonCode.INTERNAL_FAIL_CLOSED,
            details=details,
        )
