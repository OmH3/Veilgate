"""Text matching, globbing, key stem, and Shannon entropy operators."""

import fnmatch
import math
import re
from typing import Any

from veilgate.engines.operators.base import RuleOperator


class RegexOperator(RuleOperator):
    """Regular expression pattern matcher."""

    name: str = "regex"

    def evaluate(self, candidate: str, params: dict[str, Any] | None = None) -> bool:
        if not params or "pattern" not in params:
            return False
        pattern = params["pattern"]
        flags = re.IGNORECASE if params.get("ignore_case", False) else 0
        try:
            return bool(re.search(pattern, candidate, flags))
        except re.error:
            return False


class GlobOperator(RuleOperator):
    """Wildcard glob matcher."""

    name: str = "glob"

    def evaluate(self, candidate: str, params: dict[str, Any] | None = None) -> bool:
        if not params or "pattern" not in params:
            return False
        pattern = params["pattern"]
        return fnmatch.fnmatch(candidate.lower(), pattern.lower())


class KeyStemOperator(RuleOperator):
    """Dictionary key stem matcher ignoring separators and casing."""

    name: str = "key_stem"

    def evaluate(self, candidate: str, params: dict[str, Any] | None = None) -> bool:
        if not params or "stems" not in params:
            return False

        stems: list[str] = params["stems"]
        # Normalize candidate key: remove underscores, hyphens, and lowercase
        normalized_candidate = re.sub(r"[_\-\s.]", "", candidate).lower()

        for stem in stems:
            normalized_stem = re.sub(r"[_\-\s.]", "", stem).lower()
            if normalized_stem in normalized_candidate:
                return True
        return False


class EntropyOperator(RuleOperator):
    """Shannon entropy calculator detecting high-entropy secrets and random keys."""

    name: str = "entropy"

    def evaluate(self, candidate: str, params: dict[str, Any] | None = None) -> bool:
        threshold = float(params.get("threshold", 4.0)) if params else 4.0
        min_length = int(params.get("min_length", 16)) if params else 16

        clean = candidate.strip()
        if len(clean) < min_length:
            return False

        # Shannon entropy calculation
        prob = [float(clean.count(c)) / len(clean) for c in set(clean)]
        entropy = -sum(p * math.log2(p) for p in prob)

        return entropy >= threshold
