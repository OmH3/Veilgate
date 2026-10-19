"""Unit tests for Veilgate semantic exception hierarchy."""

import pytest

from veilgate.config.constants import ReasonCode
from veilgate.exceptions.types import (
    ApprovalDeniedError,
    ApprovalTimeoutError,
    ConfigError,
    LowIntegrityApprovalRequiredError,
    PolicyViolation,
    TaintViolationError,
    TokenNotFoundError,
    ToolNotAllowedError,
    ToolQuarantinedError,
    UpstreamError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
    VaultCryptoError,
    VaultError,
    VeilgateError,
)


def test_base_veilgate_error_formatting() -> None:
    """Verify base error to_agent_message formatting."""
    err = VeilgateError(
        safe_message="Payload blocked by policy.",
        reason=ReasonCode.TAINT_EGRESS_FORBIDDEN,
        details={"tool": "mailer_send_email", "arg": "body"},
    )
    formatted = err.to_agent_message(correlation_id="01JAB12345")
    assert "[VEILGATE BLOCKED]" in formatted
    assert "code=TAINT_EGRESS_FORBIDDEN" in formatted
    assert "message=Payload blocked by policy." in formatted
    assert "arg=body" in formatted
    assert "tool=mailer_send_email" in formatted
    assert "correlation_id=01JAB12345" in formatted


def test_tool_not_allowed_error_inheritance() -> None:
    """Verify ToolNotAllowedError is a PolicyViolation with TOOL_NOT_ALLOWED reason."""
    err = ToolNotAllowedError(tool_name="invoicedb_delete_all")
    assert isinstance(err, PolicyViolation)
    assert isinstance(err, VeilgateError)
    assert err.reason == ReasonCode.TOOL_NOT_ALLOWED
    assert err.details["tool"] == "invoicedb_delete_all"


def test_tool_quarantined_error_details() -> None:
    """Verify ToolQuarantinedError truncates fingerprints safely."""
    err = ToolQuarantinedError(
        tool_name="github_create_issue",
        expected_fingerprint="abcdef1234567890abcdef",
        observed_fingerprint="123456abcdef7890123456",
    )
    assert err.reason == ReasonCode.TOOL_QUARANTINED
    assert err.details["expected_fp"] == "abcdef123456"
    assert err.details["observed_fp"] == "123456abcdef"


def test_taint_violation_error() -> None:
    """Verify TaintViolationError captures token and argument paths."""
    err = TaintViolationError(
        safe_message="Routing number cannot leave local boundary.",
        reason=ReasonCode.TAINT_EGRESS_FORBIDDEN,
        token_id="7K3QF2",
        arg_path="$.body",
        tool_name="mailer_send_email",
    )
    assert err.reason == ReasonCode.TAINT_EGRESS_FORBIDDEN
    assert err.details["token_id"] == "7K3QF2"
    assert err.details["arg_path"] == "$.body"
    assert err.details["tool"] == "mailer_send_email"


def test_upstream_error_hierarchy() -> None:
    """Verify UpstreamError hierarchy attributes."""
    err = UpstreamUnavailableError(server_id="invoicedb")
    assert isinstance(err, UpstreamError)
    assert err.reason == ReasonCode.UPSTREAM_UNAVAILABLE
    assert err.details["server_id"] == "invoicedb"

    timeout_err = UpstreamTimeoutError(server_id="mailer", timeout_seconds=30.0)
    assert timeout_err.reason == ReasonCode.UPSTREAM_TIMEOUT
    assert timeout_err.details["timeout_seconds"] == 30.0


def test_vault_error_hierarchy() -> None:
    """Verify VaultError subclasses."""
    not_found = TokenNotFoundError(token_id="XYZ123")
    assert isinstance(not_found, VaultError)
    assert not_found.reason == ReasonCode.TOKEN_UNKNOWN

    crypto_err = VaultCryptoError()
    assert isinstance(crypto_err, VaultError)
    assert crypto_err.reason == ReasonCode.INTERNAL_FAIL_CLOSED
