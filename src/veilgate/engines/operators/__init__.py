"""Rule operator registry and evaluation dispatcher."""

from typing import Any

from veilgate.engines.operators.base import RuleOperator
from veilgate.engines.operators.checksums import (
    LuhnChecksumOperator,
    RoutingChecksumOperator,
    VerhoeffChecksumOperator,
)
from veilgate.engines.operators.text import (
    EntropyOperator,
    GlobOperator,
    KeyStemOperator,
    RegexOperator,
)

OPERATORS: dict[str, RuleOperator] = {
    "regex": RegexOperator(),
    "glob": GlobOperator(),
    "key_stem": KeyStemOperator(),
    "entropy": EntropyOperator(),
    "luhn_checksum": LuhnChecksumOperator(),
    "routing_checksum": RoutingChecksumOperator(),
    "verhoeff_checksum": VerhoeffChecksumOperator(),
}


def get_operator(name: str) -> RuleOperator | None:
    """Retrieve registered operator by name."""
    return OPERATORS.get(name)


def evaluate_operator(
    name: str,
    candidate: str,
    params: dict[str, Any] | None = None,
) -> bool:
    """Evaluate a candidate string using the named operator.

    Returns False if operator is unknown.
    """
    op = get_operator(name)
    if op is None:
        return False
    return op.evaluate(candidate, params)


__all__ = [
    "EntropyOperator",
    "GlobOperator",
    "KeyStemOperator",
    "LuhnChecksumOperator",
    "OPERATORS",
    "RegexOperator",
    "RoutingChecksumOperator",
    "RuleOperator",
    "VerhoeffChecksumOperator",
    "evaluate_operator",
    "get_operator",
]
