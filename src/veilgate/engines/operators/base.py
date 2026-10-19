"""Base protocol for generic rule operators."""

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class RuleOperator(Protocol):
    """Protocol for declarative rule pack operators."""

    name: str

    def evaluate(self, candidate: str, params: dict[str, Any] | None = None) -> bool:
        """Evaluate candidate string against operator criteria."""
        ...
