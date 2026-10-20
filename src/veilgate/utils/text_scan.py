"""Text normalization, entity unescaping, and encoded token smuggling detection."""

import html
import json
import urllib.parse

from veilgate.config.constants import (
    EMAIL_TOKEN_REGEX,
    TOKEN_REGEX,
    URL_TOKEN_REGEX,
)


def decode_all_layers(raw_text: str) -> list[str]:
    """Produce normalized representations of text across URL, HTML, and JSON escape layers."""
    variants = [raw_text]

    # 1. HTML unescape
    html_unescaped = html.unescape(raw_text)
    if html_unescaped != raw_text:
        variants.append(html_unescaped)

    # 2. URL unquote
    try:
        url_unquoted = urllib.parse.unquote_plus(raw_text)
        if url_unquoted != raw_text and url_unquoted not in variants:
            variants.append(url_unquoted)
        # Double URL unquote
        double_unquoted = urllib.parse.unquote_plus(url_unquoted)
        if double_unquoted not in variants:
            variants.append(double_unquoted)
    except Exception:
        pass

    # 3. JSON string unescape
    if "\\" in raw_text:
        try:
            # Wrap as JSON string to unescape unicode and escapes
            json_unquoted = json.loads(f'"{raw_text}"')
            if json_unquoted not in variants:
                variants.append(json_unquoted)
        except Exception:
            pass

    return variants


def scan_text_for_tokens(text: str) -> list[tuple[str, str, str, bool]]:
    """Scan raw string for standard, email, and URL token patterns.

    Returns:
        List of (rendered, token_id, token_type, is_standalone).
    """
    findings: list[tuple[str, str, str, bool]] = []

    # Standard pattern: <vg:TYPE:ID>
    for match in TOKEN_REGEX.finditer(text):
        rendered = match.group(0)
        t_type = match.group(1)
        t_id = match.group(2)
        is_standalone = (text.strip() == rendered)
        findings.append((rendered, t_id, t_type, is_standalone))

    # Email pattern: vg-[base32]@vault.veilgate.invalid
    for match in EMAIL_TOKEN_REGEX.finditer(text):
        rendered = match.group(0)
        t_id = match.group(1).upper()
        is_standalone = (text.strip().lower() == rendered.lower())
        findings.append((rendered, t_id, "EMAIL", is_standalone))

    # URL pattern: https://vault.veilgate.invalid/t/[base32]
    for match in URL_TOKEN_REGEX.finditer(text):
        rendered = match.group(0)
        t_id = match.group(1).upper()
        is_standalone = (text.strip().lower() == rendered.lower())
        findings.append((rendered, t_id, "URL", is_standalone))

    return findings


def detect_smuggled_tokens(raw_text: str) -> tuple[list[tuple[str, str, str, bool]], bool]:
    """Detect tokens in text, identifying whether tokens were concealed via encoded smuggling.

    Returns:
        Tuple of (all_findings, is_encoded_smuggling).
        is_encoded_smuggling is True if tokens are found in decoded/unescaped layers
        but were absent in the literal raw_text (Attack A6 defense).
    """
    raw_findings = scan_text_for_tokens(raw_text)
    raw_token_ids = {f[1] for f in raw_findings}

    all_variants = decode_all_layers(raw_text)
    decoded_findings: list[tuple[str, str, str, bool]] = list(raw_findings)
    smuggled = False

    for variant in all_variants[1:]:
        variant_findings = scan_text_for_tokens(variant)
        for vf in variant_findings:
            if vf[1] not in raw_token_ids:
                smuggled = True
                if vf not in decoded_findings:
                    decoded_findings.append(vf)

    return decoded_findings, smuggled
