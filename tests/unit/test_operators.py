"""Unit tests for rule operators and checksum algorithms."""

from veilgate.engines.operators import evaluate_operator, get_operator


def test_luhn_checksum_valid_and_invalid() -> None:
    """Verify Luhn checksum operator with valid and invalid credit card numbers."""
    op = get_operator("luhn_checksum")
    assert op is not None

    # Valid test card (Visa)
    assert op.evaluate("4532-0151-1283-0366") is True
    assert op.evaluate("4532015112830366") is True

    # Invalid card
    assert op.evaluate("4532-0151-1283-0367") is False
    assert op.evaluate("12345") is False


def test_routing_checksum_valid_and_invalid() -> None:
    """Verify US ABA routing checksum (Chase Manhattan 021000021)."""
    op = get_operator("routing_checksum")
    assert op is not None

    # Valid US routing numbers
    assert op.evaluate("021000021") is True  # Chase NY
    assert op.evaluate("111000025") is True  # Dallas Fed
    assert op.evaluate("021000022") is False  # Invalid check digit
    assert op.evaluate("1234") is False


def test_verhoeff_checksum_valid_and_invalid() -> None:
    """Verify Verhoeff algorithm on valid Aadhaar / European numbers."""
    op = get_operator("verhoeff_checksum")
    assert op is not None

    # Valid 12-digit Verhoeff test number
    assert op.evaluate("216447547165") is True
    assert op.evaluate("216447547164") is False


def test_regex_and_glob_operators() -> None:
    """Verify regex and glob matching operators."""
    assert evaluate_operator("regex", "000-12-3456", {"pattern": r"^\d{3}-\d{2}-\d{4}$"}) is True
    assert evaluate_operator("regex", "abc", {"pattern": r"^\d+$"}) is False

    assert evaluate_operator("glob", "invoicedb.get_invoice", {"pattern": "invoicedb.*"}) is True
    assert evaluate_operator("glob", "mailer.send_email", {"pattern": "invoicedb.*"}) is False


def test_key_stem_operator() -> None:
    """Verify key stem matcher across delimiters and casing."""
    op = get_operator("key_stem")
    assert op is not None

    params = {"stems": ["routing", "account_number", "ssn"]}
    assert op.evaluate("bank_routing_number", params) is True
    assert op.evaluate("Routing", params) is True
    assert op.evaluate("customer_ssn_id", params) is True
    assert op.evaluate("unrelated_field", params) is False


def test_entropy_operator() -> None:
    """Verify Shannon entropy detects high-entropy strings."""
    op = get_operator("entropy")
    assert op is not None

    # Low entropy repetitive string
    assert op.evaluate("aaaaaaaaaaaaaaaa", {"threshold": 4.0, "min_length": 16}) is False

    # High entropy base64 random API key
    assert op.evaluate("dGhpc19pc19hX3JhbmRvbV9zZWNyZXRfa2V5XzEyMzQ1Ng==", {"threshold": 3.8, "min_length": 16}) is True
