"""Identifier and token generators for Veilgate sessions, tokens, stashes, and audit events."""

from ulid import ULID

from veilgate.security.crypto import generate_crockford_token_id


def generate_event_id() -> str:
    """Generate a high-precision, monotonically sortable ULID event ID."""
    return str(ULID())


def generate_token_id() -> str:
    """Generate a random 6-character Crockford Base32 token ID."""
    return generate_crockford_token_id()


def generate_session_id() -> str:
    """Generate a unique session identifier."""
    return f"ses_{ULID()}"


def generate_stash_id() -> str:
    """Generate a unique stash payload identifier."""
    return f"stsh_{ULID()}"


def generate_approval_id() -> str:
    """Generate a human-readable approval request ID."""
    return f"appr_{generate_crockford_token_id()}"
