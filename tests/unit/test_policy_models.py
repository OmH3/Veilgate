"""Unit tests for Veilgate declarative policy models."""

import pytest
from pydantic import ValidationError

from veilgate.config.policy_models import (
    Capability,
    FieldAction,
    FieldRuleSpec,
    SinkMacro,
    TokenizeSpec,
    ToolPolicySpec,
    Transport,
    TrustLevel,
    UnlistedSinkPolicy,
    UpstreamSpec,
    VeilgatePolicy,
)


def test_minimal_upstream_spec_validation() -> None:
    """Verify upstream namespace ID constraint enforces lowercase alphanumeric without underscore."""
    # Valid
    upstream = UpstreamSpec(id="invoicedb", transport=Transport.STDIO, command="python")
    assert upstream.id == "invoicedb"
    assert upstream.trust == TrustLevel.AUTO

    # Invalid with underscore
    with pytest.raises(ValidationError):
        UpstreamSpec(id="invoice_db", transport=Transport.STDIO)

    # Invalid uppercase
    with pytest.raises(ValidationError):
        UpstreamSpec(id="InvoiceDB", transport=Transport.STDIO)


def test_field_rule_spec_defaults() -> None:
    """Verify default field rule configuration."""
    rule = FieldRuleSpec(
        path="$.customer.ssn",
        action=FieldAction.TOKENIZE,
        tokenize=TokenizeSpec(token_type="SSN", allowed_sinks=SinkMacro.NONE),
    )
    assert rule.path == "$.customer.ssn"
    assert rule.action == FieldAction.TOKENIZE
    assert rule.tokenize is not None
    assert rule.tokenize.token_type == "SSN"
    assert rule.tokenize.allowed_sinks == SinkMacro.NONE


def test_full_policy_serialization_and_defaults() -> None:
    """Verify complete VeilgatePolicy deserializes with defaults."""
    raw = {
        "version": "1",
        "extends": "recommended",
        "upstreams": [
            {"id": "invoicedb", "transport": "stdio", "command": "python", "args": ["server.py"]},
            {"id": "mailer", "transport": "stdio", "command": "python", "args": ["mailer.py"]},
        ],
        "protect": ["deal_margin", "salary_band"],
        "drop": ["internal_row_id"],
        "tools": [
            {
                "match": "mailer.send_email",
                "capabilities": ["external_egress"],
                "blocked_token_types": ["SSN", "BANK_ROUTING"],
            }
        ],
    }
    policy = VeilgatePolicy.model_validate(raw)
    assert len(policy.upstreams) == 2
    assert policy.protect == ["deal_margin", "salary_band"]
    assert policy.drop == ["internal_row_id"]
    assert policy.tools[0].match == "mailer.send_email"
    assert policy.tools[0].capabilities == [Capability.EXTERNAL_EGRESS]
    assert policy.tools[0].blocked_token_types == ["SSN", "BANK_ROUTING"]
    assert policy.unlisted_sink_policy == UnlistedSinkPolicy.BLOCK
