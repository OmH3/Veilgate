"""Algorithmic checksum validators for high-precision PII detection."""

import re
from typing import Any

from veilgate.engines.operators.base import RuleOperator

# Verhoeff multiplication, permutation, and inverse tables
_VERHOEFF_D: list[list[int]] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P: list[list[int]] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


class LuhnChecksumOperator(RuleOperator):
    """Credit card Luhn algorithm (Mod 10) validator."""

    name: str = "luhn_checksum"

    def evaluate(self, candidate: str, params: dict[str, Any] | None = None) -> bool:
        digits = re.sub(r"\D", "", candidate)
        if len(digits) < 13 or len(digits) > 19:
            return False

        checksum = 0
        reverse_digits = digits[::-1]
        for idx, char in enumerate(reverse_digits):
            d = int(char)
            if idx % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d

        return checksum % 10 == 0


class RoutingChecksumOperator(RuleOperator):
    """US Federal Reserve ABA routing transit number 9-digit checksum validator."""

    name: str = "routing_checksum"

    def evaluate(self, candidate: str, params: dict[str, Any] | None = None) -> bool:
        digits = re.sub(r"\D", "", candidate)
        if len(digits) != 9:
            return False

        d = [int(ch) for ch in digits]
        # Weighted sum: 3(d1 + d4 + d7) + 7(d2 + d5 + d8) + 1(d3 + d6 + d9) mod 10 == 0
        weighted_sum = (
            3 * (d[0] + d[3] + d[6])
            + 7 * (d[1] + d[4] + d[7])
            + 1 * (d[2] + d[5] + d[8])
        )
        return weighted_sum % 10 == 0


class VerhoeffChecksumOperator(RuleOperator):
    """Verhoeff dihedral group D5 checksum algorithm for Aadhaar and official IDs."""

    name: str = "verhoeff_checksum"

    def evaluate(self, candidate: str, params: dict[str, Any] | None = None) -> bool:
        digits = re.sub(r"\D", "", candidate)
        if len(digits) != 12:
            return False

        c = 0
        for i, digit_char in enumerate(reversed(digits)):
            c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(digit_char)]]

        return c == 0
