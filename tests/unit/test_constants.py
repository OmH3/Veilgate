"""Unit tests for Veilgate constants and regex specifications."""


from veilgate.config.constants import (
    CROCKFORD_BASE32_ALPHABET,
    EMAIL_TOKEN_REGEX,
    TOKEN_REGEX,
    URL_TOKEN_REGEX,
    ReasonCode,
)


def test_crockford_base32_alphabet_length_and_omissions() -> None:
    """Verify Crockford Base32 has 32 chars and omits ambiguous I, L, O, U."""
    assert len(CROCKFORD_BASE32_ALPHABET) == 32
    assert "I" not in CROCKFORD_BASE32_ALPHABET
    assert "L" not in CROCKFORD_BASE32_ALPHABET
    assert "O" not in CROCKFORD_BASE32_ALPHABET
    assert "U" not in CROCKFORD_BASE32_ALPHABET


def test_standard_token_regex_matching() -> None:
    """Verify standard token frame regex <vg:TYPE:TOKEN_ID>."""
    match = TOKEN_REGEX.search("Sensitive: <vg:BANK_ROUTING:7K3QF2> and more text")
    assert match is not None
    assert match.group(1) == "BANK_ROUTING"
    assert match.group(2) == "7K3QF2"

    # Multiple tokens in payload
    sample = "SSN <vg:SSN:ABC123> and Phone <vg:PHONE_US:XYZ987>"
    matches = TOKEN_REGEX.findall(sample)
    assert len(matches) == 2
    assert matches[0] == ("SSN", "ABC123")
    assert matches[1] == ("PHONE_US", "XYZ987")


def test_email_token_regex_matching() -> None:
    """Verify format-preserving email token regex."""
    sample = "Contact us at vg-7k3qf2@vault.veilgate.invalid for details."
    match = EMAIL_TOKEN_REGEX.search(sample)
    assert match is not None
    assert match.group(1).lower() == "7k3qf2"


def test_url_token_regex_matching() -> None:
    """Verify format-preserving URL token regex."""
    sample = "Download file at https://vault.veilgate.invalid/t/9m2px1 now."
    match = URL_TOKEN_REGEX.search(sample)
    assert match is not None
    assert match.group(1).lower() == "9m2px1"


def test_reason_codes_comprehensive() -> None:
    """Verify standard ReasonCode values exist and are unique."""
    codes = [code.value for code in ReasonCode]
    assert len(codes) == len(set(codes))
    assert ReasonCode.OK == "OK"
    assert ReasonCode.TAINT_EGRESS_FORBIDDEN == "TAINT_EGRESS_FORBIDDEN"
    assert ReasonCode.TOOL_QUARANTINED == "TOOL_QUARANTINED"
    assert ReasonCode.UPSTREAM_TIMEOUT == "UPSTREAM_TIMEOUT"
