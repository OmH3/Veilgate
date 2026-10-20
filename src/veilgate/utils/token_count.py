"""Token estimation utilities for context budgets and compression calculations."""

import json
from typing import Any


def estimate_token_count(text: str) -> int:
    """Fast offline estimation of token count (~4 characters per token average)."""
    if not text:
        return 0
    # Rule of thumb for English/code text: 1 token ~= 4 chars or 0.75 words
    char_estimate = len(text) / 4.0
    word_estimate = len(text.split()) / 0.75
    # Blend estimate
    return max(1, int((char_estimate + word_estimate) / 2.0))


def estimate_json_tokens(data: Any) -> int:
    """Estimate token count for a JSON-serializable structure."""
    if data is None:
        return 0
    try:
        serialized = json.dumps(data, separators=(",", ":"))
        return estimate_token_count(serialized)
    except Exception:
        return estimate_token_count(str(data))
