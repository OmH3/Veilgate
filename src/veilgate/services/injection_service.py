"""Prompt injection detection and sanitization service for tool descriptions and untrusted outputs."""

import re

from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.services.injection_service")

# Unicode Tag characters (U+E0000 to U+E007F) used for hidden payload smuggling
UNICODE_TAGS_REGEX: re.Pattern[str] = re.compile(r"[\U000e0000-\U000e007f]")

# Zero-width invisibles
ZERO_WIDTH_REGEX: re.Pattern[str] = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff]")

# Canonical prompt injection signatures (case-insensitive)
INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"<important>", re.IGNORECASE), "tag_important"),
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE), "override_ignore_previous"),
    (re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE), "override_dev_mode"),
    (re.compile(r"system\s*:\s*(you\s+are|override|disregard)", re.IGNORECASE), "system_role_spoofing"),
    (re.compile(r"disregard\s+(all\s+)?(prior|previous)\s+safety", re.IGNORECASE), "override_safety"),
]


class InjectionService:
    """Detects and mitigates prompt injections, tag characters, and covert instructions."""

    def scan_tool_description(self, description: str) -> tuple[bool, str | None]:
        """Scan tool description for covert tags, zero-width characters, or override directives.

        Returns:
            Tuple of (is_malicious, violation_reason).
        """
        if not description:
            return False, None

        # 1. Unicode tag smuggling check
        if UNICODE_TAGS_REGEX.search(description):
            return True, "covert_unicode_tags_detected"

        # 2. Zero-width character flooding
        zw_matches = ZERO_WIDTH_REGEX.findall(description)
        if len(zw_matches) >= 3:
            return True, "zero_width_character_smuggling"

        # 3. Direct injection phrases
        for pattern, sig in INJECTION_PATTERNS:
            if pattern.search(description):
                return True, f"prompt_injection_signature:{sig}"

        return False, None

    def sanitize_description(self, description: str) -> str:
        """Strip invisible characters and tag codepoints from tool description."""
        if not description:
            return ""
        cleaned = UNICODE_TAGS_REGEX.sub("", description)
        cleaned = ZERO_WIDTH_REGEX.sub("", cleaned)
        return cleaned.strip()

    def scan_untrusted_output(self, text: str) -> tuple[bool, str | None]:
        """Scan untrusted tool execution outputs for agent hijacking attempts."""
        if not text:
            return False, None

        if UNICODE_TAGS_REGEX.search(text):
            return True, "covert_unicode_tags_in_output"

        for pattern, sig in INJECTION_PATTERNS:
            if pattern.search(text):
                return True, f"prompt_injection_in_output:{sig}"

        return False, None
