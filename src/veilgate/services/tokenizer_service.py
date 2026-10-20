"""Tokenizer service for minting, formatting, and storing encrypted tokens."""

import hashlib

from veilgate.config.constants import (
    EMAIL_TOKEN_DOMAIN,
    SYNTHETIC_INT_BASE,
    TOKEN_PREFIX,
    TOKEN_SUFFIX,
    URL_TOKEN_PREFIX,
)
from veilgate.config.policy_models import SensitivityClass, SinkMacro
from veilgate.repositories.models import TokenRecordCreate
from veilgate.repositories.vault_repo import VaultRepository
from veilgate.security.crypto import generate_crockford_token_id
from veilgate.services.models import SessionContext, ToolRef


class TokenizerService:
    """Mints session-scoped deterministic tokens, attaches capability macros, and stores in vault."""

    def __init__(self, vault_repo: VaultRepository) -> None:
        self.vault_repo: VaultRepository = vault_repo

    async def tokenize(
        self,
        raw_value: str | int | float,
        token_type: str,
        origin_ref: ToolRef,
        origin_path: str,
        session: SessionContext,
        event_id: str,
        allowed_sinks: list[str] | SinkMacro = SinkMacro.TRUSTED_READ,
        allow_external_egress: bool = False,
        format_preserving: bool = False,
        sensitivity: SensitivityClass = SensitivityClass.PII_HIGH,
        ttl_seconds: int = 86_400,
    ) -> str:
        """Tokenize sensitive scalar into format-preserving or standard token frame.

        Returns:
            Rendered token string (e.g., '<vg:BANK_ROUTING:7K3QF2>').
        """
        token_id = generate_crockford_token_id()
        raw_str = str(raw_value)
        value_kind = "string"
        if isinstance(raw_value, int) and not isinstance(raw_value, bool):
            value_kind = "integer"
        elif isinstance(raw_value, float):
            value_kind = "number"

        # Determine rendered format
        if format_preserving and token_type.upper() == "EMAIL":
            rendered = f"vg-{token_id.lower()}@{EMAIL_TOKEN_DOMAIN}"
        elif format_preserving and token_type.upper() in ("URL", "URI"):
            rendered = f"{URL_TOKEN_PREFIX}{token_id.lower()}"
        elif format_preserving and value_kind == "integer":
            offset = int(hashlib.sha256(token_id.encode()).hexdigest()[:7], 16) % 99_999_999 + 1
            rendered = str(SYNTHETIC_INT_BASE + offset)
        else:
            rendered = f"{TOKEN_PREFIX}{token_type.upper()}:{token_id}{TOKEN_SUFFIX}"

        spec = TokenRecordCreate(
            token_id=token_id,
            session_id=session.session_id,
            rendered=rendered,
            token_type=token_type.upper(),
            sensitivity=sensitivity.value,
            value_kind=value_kind,
            raw_value=raw_str,
            origin_ref=origin_ref.qualified,
            origin_path=origin_path,
            origin_event_id=event_id,
            allowed_sinks=allowed_sinks if isinstance(allowed_sinks, list) else allowed_sinks.value,
            allow_external_egress=allow_external_egress,
            ttl_seconds=ttl_seconds,
        )

        record = await self.vault_repo.get_or_create(spec)
        return record.rendered
