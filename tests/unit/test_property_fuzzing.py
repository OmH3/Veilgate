"""Property-based fuzzing suite (veilgate_implementation_plan.md §10.3) using Hypothesis."""

import html
import os
import urllib.parse

from hypothesis import given, settings
from hypothesis import strategies as st

from veilgate.config.constants import CROCKFORD_BASE32_ALPHABET
from veilgate.security.crypto import VaultCrypto
from veilgate.services.approval_service import compute_args_hash
from veilgate.services.catalog_service import compute_tool_fingerprint
from veilgate.utils.text_scan import detect_smuggled_tokens

CROCKFORD_ID_STRATEGY = st.text(alphabet=CROCKFORD_BASE32_ALPHABET, min_size=6, max_size=6)
TOKEN_TYPE_STRATEGY = st.sampled_from(["SSN", "BANK_ROUTING", "BANK_ACCOUNT", "PAN", "API_KEY"])


@settings(max_examples=40)
@given(plaintext=st.text(min_size=0, max_size=500))
def test_property_vault_crypto_roundtrip_arbitrary_unicode(plaintext: str) -> None:
    """Property: AES-256-GCM encrypt/decrypt is lossless for all valid Unicode strings."""
    crypto = VaultCrypto(os.urandom(32))
    ciphertext, nonce = crypto.encrypt(plaintext)
    assert crypto.decrypt(ciphertext, nonce) == plaintext


@settings(max_examples=40)
@given(token_id=CROCKFORD_ID_STRATEGY, token_type=TOKEN_TYPE_STRATEGY)
def test_property_smuggled_token_detection_across_encodings(token_id: str, token_type: str) -> None:
    """Property: URL-encoded and HTML-entity-encoded Veilgate tokens are always detected as smuggled."""
    raw_token = f"<vg:{token_type}:{token_id}>"

    # Unencoded token is detected as non-smuggled standalone
    findings_raw, is_smuggled_raw = detect_smuggled_tokens(raw_token)
    assert len(findings_raw) == 1
    assert findings_raw[0][1] == token_id
    assert is_smuggled_raw is False

    # URL-encoded token is detected as smuggled
    url_encoded = urllib.parse.quote(raw_token)
    findings_url, is_smuggled_url = detect_smuggled_tokens(url_encoded)
    assert len(findings_url) >= 1
    assert findings_url[0][1] == token_id
    assert is_smuggled_url is True

    # HTML-escaped token is detected as smuggled
    html_encoded = html.escape(raw_token)
    findings_html, is_smuggled_html = detect_smuggled_tokens(html_encoded)
    assert len(findings_html) >= 1
    assert findings_html[0][1] == token_id
    assert is_smuggled_html is True


@settings(max_examples=40)
@given(
    tool_name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=3, max_size=20),
    keys=st.lists(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=10), min_size=1, max_size=6, unique=True),
)
def test_property_tool_fingerprint_key_order_invariance(tool_name: str, keys: list[str]) -> None:
    """Property: Tool schema SHA-256 fingerprint is invariant to JSON key ordering."""
    props_forward = {k: {"type": "string"} for k in keys}
    props_reverse = {k: {"type": "string"} for k in reversed(keys)}

    fp_forward = compute_tool_fingerprint(tool_name, {"type": "object", "properties": props_forward})
    fp_reverse = compute_tool_fingerprint(tool_name, {"type": "object", "properties": props_reverse})
    assert fp_forward == fp_reverse


@settings(max_examples=40)
@given(
    k1=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=8),
    v1=st.integers(min_value=1, max_value=10_000),
    v2=st.integers(min_value=10_001, max_value=99_999),
)
def test_property_args_hash_toctou_sensitivity(k1: str, v1: int, v2: int) -> None:
    """Property: Canonical args_hash changes whenever any argument value mutates."""
    h1 = compute_args_hash({k1: v1, "static": "ok"})
    h1_reordered = compute_args_hash({"static": "ok", k1: v1})
    h2 = compute_args_hash({k1: v2, "static": "ok"})

    assert h1 == h1_reordered
    assert h1 != h2
