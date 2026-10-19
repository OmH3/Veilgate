"""Minimizer service for egress response tokenization, bloat stripping, and compaction."""

import copy
import fnmatch
import json
import re
from typing import Any

from veilgate.config.policy_models import (
    FieldAction,
    SensitivityClass,
    SinkMacro,
    VeilgatePolicy,
)
from veilgate.engines.operators import evaluate_operator
from veilgate.repositories.stash_repo import StashRepository
from veilgate.security.crypto import generate_crockford_token_id
from veilgate.services.models import (
    MinimizedResult,
    SessionContext,
    ToolRef,
    TransformRecord,
)
from veilgate.services.tokenizer_service import TokenizerService
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.services.minimizer_service")

# Common sensitive key stems loaded for rapid matching
DEFAULT_SENSITIVE_KEY_STEMS: list[tuple[list[str], str, SensitivityClass, SinkMacro, bool]] = [
    (["ssn", "social_security"], "SSN", SensitivityClass.PII_HIGH, SinkMacro.NONE, False),
    (["routing_number", "bank_routing", "routing"], "BANK_ROUTING", SensitivityClass.PII_HIGH, SinkMacro.TRUSTED_READ, False),
    (["account_number", "bank_account", "iban"], "BANK_ACCOUNT", SensitivityClass.PII_HIGH, SinkMacro.TRUSTED_READ, False),
    (["api_key", "apikey", "secret_key", "password", "auth_token", "access_token"], "API_KEY", SensitivityClass.SECRET, SinkMacro.NONE, False),
    (["email", "contact_email"], "EMAIL", SensitivityClass.PII_MEDIUM, SinkMacro.TRUSTED_READ, True),
]

# Standard HTTP bloat keys to drop
DEFAULT_BLOAT_KEYS: set[str] = {
    "connection", "keep-alive", "server", "date", "etag", "via", "vary",
    "content-security-policy", "strict-transport-security", "x-request-id",
    "x-correlation-id", "x-envoy-upstream-service-time", "x-powered-by",
    "cf-ray", "cf-cache-status", "set-cookie", "cookie", "authorization",
    "_links", "_metadata", "__v",
}


class MinimizerService:
    """Classifies egress payload fields, tokenizes sensitive data, strips bloat, and compacts results."""

    def __init__(
        self,
        tokenizer: TokenizerService,
        stash_repo: StashRepository,
        policy: VeilgatePolicy,
    ) -> None:
        self.tokenizer: TokenizerService = tokenizer
        self.stash_repo: StashRepository = stash_repo
        self.policy: VeilgatePolicy = policy

    async def minimize(
        self,
        raw_payload: Any,
        ref: ToolRef,
        session: SessionContext,
        event_id: str,
    ) -> MinimizedResult:
        """Transform raw response payload into minimized, tokenized output."""
        tokens_before = len(json.dumps(raw_payload)) // 4

        # Deep clone to avoid mutating upstream references
        processed = copy.deepcopy(raw_payload)
        transforms: list[TransformRecord] = []
        dropped_stash: dict[str, Any] = {}

        if isinstance(processed, dict):
            await self._process_dict(
                processed,
                path="$",
                ref=ref,
                session=session,
                event_id=event_id,
                transforms=transforms,
                stash=dropped_stash,
            )
        elif isinstance(processed, list):
            await self._process_list(
                processed,
                path="$",
                ref=ref,
                session=session,
                event_id=event_id,
                transforms=transforms,
                stash=dropped_stash,
            )

        # Stash dropped fields if any were collected
        stash_id: str | None = None
        if dropped_stash and self.policy.compaction.stash_dropped_fields:
            stash_id = f"stash_{generate_crockford_token_id()}"
            await self.stash_repo.stash_result(
                stash_id=stash_id,
                session_id=session.session_id,
                qualified_ref=ref.qualified,
                payload_json=json.dumps(dropped_stash),
            )

        # Render content block
        tokens_after = len(json.dumps(processed)) // 4
        content_text = json.dumps(processed, indent=2)

        return MinimizedResult(
            content=[{"type": "text", "text": content_text}],
            structured_content=processed if isinstance(processed, (dict, list)) else None,
            is_error=False,
            transforms=transforms,
            stash_id=stash_id,
            tokens_before=tokens_before,
            tokens_after=tokens_after,
            integrity_lowered=False,
        )

    async def _process_dict(
        self,
        node: dict[str, Any],
        path: str,
        ref: ToolRef,
        session: SessionContext,
        event_id: str,
        transforms: list[TransformRecord],
        stash: dict[str, Any],
    ) -> None:
        """Process dictionary keys and values recursively."""
        keys = list(node.keys())
        tool_policy = next((t for t in self.policy.tools if fnmatch.fnmatch(ref.qualified.lower(), t.match.lower())), None)

        for key in keys:
            current_path = f"{path}.{key}"
            val = node[key]

            # 1. Bloat dropping check & user flat drop keywords
            key_lower = key.lower()
            if key_lower in [k.lower() for k in self.policy.drop] or (
                self.policy.compaction.drop_bloat and (key_lower in DEFAULT_BLOAT_KEYS or key_lower.startswith("x-"))
            ):
                stash[current_path] = node.pop(key)
                transforms.append(TransformRecord(json_path=current_path, action=FieldAction.DROP, reason="bloat_drop"))
                continue

            # User flat protect keywords
            if key_lower in [k.lower() for k in self.policy.protect] and isinstance(val, (str, int, float)) and not isinstance(val, bool):
                token_str = await self.tokenizer.tokenize(
                    raw_value=val,
                    token_type=key.upper(),
                    origin_ref=ref,
                    origin_path=current_path,
                    session=session,
                    event_id=event_id,
                    allowed_sinks=SinkMacro.TRUSTED_READ,
                )
                node[key] = token_str
                transforms.append(TransformRecord(json_path=current_path, action=FieldAction.TOKENIZE, token_type=key.upper(), reason="policy_protect_keyword"))
                continue

            # 2. Check explicit tool field rules
            matched_rule = None
            if tool_policy:
                for rule in tool_policy.field_rules:
                    if fnmatch.fnmatch(current_path.lower(), rule.path.lower()):
                        matched_rule = rule
                        break

            if matched_rule:
                if matched_rule.action == FieldAction.DROP:
                    stash[current_path] = node.pop(key)
                    transforms.append(TransformRecord(json_path=current_path, action=FieldAction.DROP, reason="policy_rule_drop"))
                    continue
                elif matched_rule.action == FieldAction.TOKENIZE and isinstance(val, (str, int, float)) and not isinstance(val, bool):
                    spec = matched_rule.tokenize
                    t_type = spec.token_type if spec else "GENERIC"
                    sinks = spec.allowed_sinks if spec else SinkMacro.TRUSTED_READ
                    egress = spec.allow_external_egress if spec else False
                    token_str = await self.tokenizer.tokenize(
                        raw_value=val,
                        token_type=t_type,
                        origin_ref=ref,
                        origin_path=current_path,
                        session=session,
                        event_id=event_id,
                        allowed_sinks=sinks,
                        allow_external_egress=egress,
                    )
                    node[key] = token_str
                    transforms.append(TransformRecord(json_path=current_path, action=FieldAction.TOKENIZE, token_type=t_type, reason="policy_rule_tokenize"))
                    continue

            # 3. Sensitive key stem matching
            stem_matched = False
            for stems, t_type, sens, sinks, format_pres in DEFAULT_SENSITIVE_KEY_STEMS:
                if evaluate_operator("key_stem", key, {"stems": stems}) and isinstance(val, (str, int, float)) and not isinstance(val, bool):
                    token_str = await self.tokenizer.tokenize(
                        raw_value=val,
                        token_type=t_type,
                        origin_ref=ref,
                        origin_path=current_path,
                        session=session,
                        event_id=event_id,
                        allowed_sinks=sinks,
                        allow_external_egress=format_pres,
                        format_preserving=format_pres,
                        sensitivity=sens,
                    )
                    node[key] = token_str
                    transforms.append(TransformRecord(json_path=current_path, action=FieldAction.TOKENIZE, token_type=t_type, reason="key_stem_match"))
                    stem_matched = True
                    break

            if stem_matched:
                continue

            # 4. Pattern check for scalars (SSN, credit card)
            if isinstance(val, str):
                if re.match(r"^\d{3}-\d{2}-\d{4}$", val.strip()):
                    token_str = await self.tokenizer.tokenize(
                        raw_value=val,
                        token_type="SSN",
                        origin_ref=ref,
                        origin_path=current_path,
                        session=session,
                        event_id=event_id,
                        allowed_sinks=SinkMacro.NONE,
                    )
                    node[key] = token_str
                    transforms.append(TransformRecord(json_path=current_path, action=FieldAction.TOKENIZE, token_type="SSN", reason="regex_ssn"))
                    continue

            # Recursive descent
            if isinstance(val, dict):
                await self._process_dict(val, current_path, ref, session, event_id, transforms, stash)
            elif isinstance(val, list):
                await self._process_list(val, current_path, ref, session, event_id, transforms, stash)

    async def _process_list(
        self,
        node: list[Any],
        path: str,
        ref: ToolRef,
        session: SessionContext,
        event_id: str,
        transforms: list[TransformRecord],
        stash: dict[str, Any],
    ) -> None:
        """Process list items recursively."""
        for idx, item in enumerate(node):
            item_path = f"{path}[{idx}]"
            if isinstance(item, dict):
                await self._process_dict(item, item_path, ref, session, event_id, transforms, stash)
            elif isinstance(item, list):
                await self._process_list(item, item_path, ref, session, event_id, transforms, stash)
