"""Minimizer service for egress response tokenization, bloat stripping, and compaction."""

import copy
import fnmatch
import json
import re
from typing import Any

from veilgate.config.constants import (
    EMAIL_TOKEN_DOMAIN,
    TOKEN_PREFIX,
    TOKEN_SUFFIX,
    URL_TOKEN_PREFIX,
)
from veilgate.config.policy_models import (
    FieldAction,
    SensitivityClass,
    SinkMacro,
    VeilgatePolicy,
)
from veilgate.engines.operators import evaluate_operator
from veilgate.repositories.stash_repo import StashRepository
from veilgate.security.crypto import generate_crockford_token_id
from veilgate.services.compaction_service import CompactionService
from veilgate.services.injection_service import InjectionService
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


# Pre-compiled fast gate for inline PII candidate strings (must contain >=2 digits, '@', or secret prefixes)
_INLINE_PII_FAST_GATE = re.compile(r"(?:\d.*?\d|@|sk-|gh[pousr]_|AKIA|ASIA)")
_INLINE_FALLBACK_PATTERNS: list[tuple[re.Pattern[str], str, SensitivityClass, SinkMacro, bool]] = [
    (
        re.compile(r"(?<!\w)[A-Za-z0-9._%+-]+@(?!vault\.veilgate\.invalid\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?!\w)"),
        "EMAIL",
        SensitivityClass.PII_MEDIUM,
        SinkMacro.TRUSTED_READ,
        True,
    ),
    (
        re.compile(r"(?<!\w)\d{3}-\d{2}-\d{4}(?!\w)"),
        "SSN",
        SensitivityClass.PII_HIGH,
        SinkMacro.NONE,
        False,
    ),
    (
        re.compile(r"(?<!\w)(?:AKIA|ASIA)[0-9A-Z]{16}(?!\w)"),
        "AWS_KEY",
        SensitivityClass.SECRET,
        SinkMacro.NONE,
        False,
    ),
    (
        re.compile(r"(?<!\w)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}(?!\w)"),
        "GITHUB_TOKEN",
        SensitivityClass.SECRET,
        SinkMacro.NONE,
        False,
    ),
]


class MinimizerService:
    """Classifies egress payload fields, tokenizes sensitive data, strips bloat, and compacts results."""

    def __init__(
        self,
        tokenizer: TokenizerService,
        stash_repo: StashRepository,
        policy: VeilgatePolicy,
        compaction_service: CompactionService | None = None,
        injection_service: InjectionService | None = None,
    ) -> None:
        self.tokenizer: TokenizerService = tokenizer
        self.stash_repo: StashRepository = stash_repo
        self.policy: VeilgatePolicy = policy
        self.compactor: CompactionService = compaction_service or CompactionService(policy.compaction)
        self.injection: InjectionService = injection_service or InjectionService()
        self._compiled_detectors: list[tuple[re.Pattern[str], re.Pattern[str], Any]] = [
            (
                re.compile(d.pattern),
                re.compile(rf"(?<!\w)(?:{d.pattern.lstrip('^').rstrip('$')})(?!\w)"),
                d,
            )
            for d in self.policy.loaded_detectors
        ]

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
        pre_stash_id = f"stash_{generate_crockford_token_id()}"

        if isinstance(processed, dict):
            await self._process_dict(
                processed,
                path="$",
                ref=ref,
                session=session,
                event_id=event_id,
                transforms=transforms,
                stash=dropped_stash,
                stash_id_hint=pre_stash_id,
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
                stash_id_hint=pre_stash_id,
            )
            if len(processed) > self.policy.compaction.max_array_items:
                dropped_stash["$"] = list(processed)
                processed, _ = self.compactor.compact_array_payload(processed, stash_id=pre_stash_id)

        # Stash dropped fields if any were collected
        stash_id: str | None = None
        if dropped_stash and self.policy.compaction.stash_dropped_fields:
            stash_rec = await self.stash_repo.stash_result(
                stash_id=pre_stash_id,
                session_id=session.session_id,
                qualified_ref=ref.qualified,
                payload_json=json.dumps(dropped_stash),
            )
            stash_id = stash_rec.stash_id

        # Render content block (unwrap MCP TextContent list, or use Markdown table when homogeneous dict list meets table_threshold)
        is_mcp_text_content_list = (
            isinstance(processed, list)
            and len(processed) > 0
            and all(
                isinstance(item, dict)
                and item.get("type") == "text"
                and set(item.keys()) <= {"type", "text"}
                for item in processed
            )
        )
        if is_mcp_text_content_list:
            content_text = "\n".join(str(item.get("text", "")) for item in processed)
        elif (
            isinstance(processed, list)
            and len(processed) >= self.policy.compaction.table_threshold
            and all(isinstance(item, dict) for item in processed)
        ):
            content_text = self.compactor.render_markdown_table(processed)
        else:
            content_text = json.dumps(processed, indent=2)

        tokens_after = len(content_text) // 4

        return MinimizedResult(
            content=[{"type": "text", "text": content_text}],
            structured_content=None if is_mcp_text_content_list else (processed if isinstance(processed, (dict, list)) else None),
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
        stash_id_hint: str = "",
    ) -> None:
        """Process dictionary keys and values recursively."""
        # Tabular SQL result set normalization (e.g. DuckDB/MotherDuck {"columns": [...], "rows": [[...]]})
        if (
            "columns" in node
            and "rows" in node
            and isinstance(node["columns"], list)
            and isinstance(node["rows"], list)
            and all(isinstance(c, str) for c in node["columns"])
        ):
            cols: list[str] = list(node["columns"])
            new_rows: list[Any] = []
            kept_cols: list[str] | None = None
            for r_idx, row in enumerate(node["rows"]):
                if isinstance(row, list) and len(row) == len(cols):
                    row_dict = dict(zip(cols, row, strict=False))
                    await self._process_dict(
                        row_dict,
                        f"{path}.rows[{r_idx}]",
                        ref,
                        session,
                        event_id,
                        transforms,
                        stash,
                        stash_id_hint,
                    )
                    if kept_cols is None:
                        kept_cols = [c for c in cols if c in row_dict]
                    new_rows.append([row_dict.get(c) for c in kept_cols])
                else:
                    new_rows.append(row)
            if kept_cols is not None:
                node["columns"] = kept_cols
            node["rows"] = new_rows

        keys = [k for k in node if k not in ("columns", "rows") or not isinstance(node.get("rows"), list)]
        tool_policy = next((t for t in self.policy.tools if fnmatch.fnmatch(ref.qualified.lower(), t.match.lower())), None)

        for key in keys:
            current_path = f"{path}.{key}"
            val = node[key]

            # Idempotency guard: never re-tokenize an already minted Veilgate token
            if isinstance(val, str) and (
                (val.startswith(TOKEN_PREFIX) and val.endswith(TOKEN_SUFFIX))
                or val.endswith(f"@{EMAIL_TOKEN_DOMAIN}")
                or val.startswith(URL_TOKEN_PREFIX)
            ):
                continue

            # 1. Bloat dropping check & user flat drop keywords
            key_lower = key.lower()
            bloat_keys = self.policy.loaded_bloat_keys or DEFAULT_BLOAT_KEYS
            if key_lower in [k.lower() for k in self.policy.drop] or (
                self.policy.compaction.drop_bloat and (key_lower in bloat_keys or key_lower.startswith("x-"))
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

            # 3. Sensitive key stem matching from sensitive-keys pack
            stem_matched = False
            if self.policy.loaded_sensitive_keys:
                for rule in self.policy.loaded_sensitive_keys:
                    if evaluate_operator("key_stem", key, {"stems": rule.stems}) and isinstance(val, (str, int, float)) and not isinstance(val, bool):
                        token_str = await self.tokenizer.tokenize(
                            raw_value=val,
                            token_type=rule.token_type,
                            origin_ref=ref,
                            origin_path=current_path,
                            session=session,
                            event_id=event_id,
                            allowed_sinks=SinkMacro(rule.allowed_sinks) if hasattr(SinkMacro, rule.allowed_sinks.upper()) else SinkMacro.TRUSTED_READ,
                            allow_external_egress=rule.allow_external_egress,
                            format_preserving=rule.format_preserving,
                            sensitivity=rule.sensitivity,
                        )
                        node[key] = token_str
                        transforms.append(TransformRecord(json_path=current_path, action=FieldAction.TOKENIZE, token_type=rule.token_type, reason="key_stem_match"))
                        stem_matched = True
                        break
            else:
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

            # 4. Pattern check for scalars against loaded PII detectors (pii-global, pii-india)
            if isinstance(val, str) and val.strip():
                stripped_val = val.strip()
                detector_matched = False
                for full_re, _inline_re, detector in self._compiled_detectors:
                    if full_re.search(stripped_val):
                        if detector.validator and not evaluate_operator(detector.validator, stripped_val):
                            continue
                        token_str = await self.tokenizer.tokenize(
                            raw_value=val,
                            token_type=detector.token_type,
                            origin_ref=ref,
                            origin_path=current_path,
                            session=session,
                            event_id=event_id,
                            allowed_sinks=SinkMacro(detector.allowed_sinks) if hasattr(SinkMacro, detector.allowed_sinks.upper()) else SinkMacro.NONE,
                            allow_external_egress=detector.allow_external_egress,
                            format_preserving=detector.format_preserving,
                            sensitivity=detector.sensitivity,
                        )
                        node[key] = token_str
                        transforms.append(TransformRecord(json_path=current_path, action=FieldAction.TOKENIZE, token_type=detector.token_type, reason=f"detector_{detector.id}"))
                        detector_matched = True
                        break

                if detector_matched:
                    continue

                # Fallback SSN pattern check if detectors not populated
                if not self.policy.loaded_detectors and re.match(r"^\d{3}-\d{2}-\d{4}$", stripped_val):
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

                # 5. If scalar string is itself a JSON-encoded dict/list (e.g. filesystem MCP returning {"content": "{...}"}),
                # recursively minimize the embedded JSON structure before falling back to inline free-text redaction
                if (stripped_val.startswith("{") and stripped_val.endswith("}")) or (
                    stripped_val.startswith("[") and stripped_val.endswith("]")
                ):
                    try:
                        embedded_json = json.loads(stripped_val)
                        if isinstance(embedded_json, dict):
                            await self._process_dict(
                                embedded_json,
                                current_path,
                                ref,
                                session,
                                event_id,
                                transforms,
                                stash,
                                stash_id_hint,
                            )
                            node[key] = json.dumps(embedded_json)
                            continue
                        elif isinstance(embedded_json, list):
                            await self._process_list(
                                embedded_json,
                                current_path,
                                ref,
                                session,
                                event_id,
                                transforms,
                                stash,
                                stash_id_hint,
                            )
                            node[key] = json.dumps(embedded_json)
                            continue
                    except json.JSONDecodeError:
                        pass

                # 6. Inline free-text PII redaction in unstructured multi-word text (Attack A16 defense)
                redacted_val = await self._redact_inline_free_text(
                    text=val,
                    current_path=current_path,
                    ref=ref,
                    session=session,
                    event_id=event_id,
                    transforms=transforms,
                )
                if len(redacted_val) > self.policy.compaction.max_string_chars:
                    stash[current_path] = redacted_val
                    redacted_val, _ = self.compactor.compact_string(redacted_val, stash_id=stash_id_hint)
                node[key] = redacted_val
                continue

            # Recursive descent
            if isinstance(val, dict):
                await self._process_dict(val, current_path, ref, session, event_id, transforms, stash, stash_id_hint)
            elif isinstance(val, list):
                await self._process_list(val, current_path, ref, session, event_id, transforms, stash, stash_id_hint)
                if len(val) > self.policy.compaction.max_array_items:
                    stash[current_path] = list(val)
                    node[key], _ = self.compactor.compact_array_payload(val, stash_id=stash_id_hint)

    async def _redact_inline_free_text(
        self,
        text: str,
        current_path: str,
        ref: ToolRef,
        session: SessionContext,
        event_id: str,
        transforms: list[TransformRecord],
    ) -> str:
        """Scan unstructured free-text fields and replace embedded PII substrings inline with tokens."""
        updated = text
        # Strip covert Unicode tag characters or injection tags if present in untrusted text output
        if not updated.isascii() or "<" in updated or "[" in updated:
            is_inj, _ = self.injection.scan_untrusted_output(updated)
            if is_inj:
                updated = self.injection.sanitize_description(updated)

        if " " not in updated and "\n" not in updated and ":" not in updated and "=" not in updated:
            return updated

        # Fast rejection gate: free text without >=2 digits, '@', or secret prefixes cannot match inline PII
        if not _INLINE_PII_FAST_GATE.search(updated):
            return updated

        # 1. Run pre-compiled loaded detectors stripped of full-string ^...$ anchors
        for _full_re, inline_re, detector in self._compiled_detectors:
            matches = list(inline_re.finditer(updated))
            for m in matches:
                candidate = m.group(0)
                if (
                    candidate.startswith(TOKEN_PREFIX)
                    or candidate.endswith(f"@{EMAIL_TOKEN_DOMAIN}")
                    or candidate.startswith(URL_TOKEN_PREFIX)
                ):
                    continue
                if detector.validator and not evaluate_operator(detector.validator, candidate):
                    continue
                token_str = await self.tokenizer.tokenize(
                    raw_value=candidate,
                    token_type=detector.token_type,
                    origin_ref=ref,
                    origin_path=current_path,
                    session=session,
                    event_id=event_id,
                    allowed_sinks=SinkMacro(detector.allowed_sinks) if hasattr(SinkMacro, detector.allowed_sinks.upper()) else SinkMacro.NONE,
                    allow_external_egress=detector.allow_external_egress,
                    format_preserving=detector.format_preserving,
                    sensitivity=detector.sensitivity,
                )
                updated = updated.replace(candidate, token_str, 1)
                transforms.append(
                    TransformRecord(
                        json_path=current_path,
                        action=FieldAction.TOKENIZE,
                        token_type=detector.token_type,
                        reason=f"inline_detector_{detector.id}",
                    )
                )

        # 2. Inline email & SSN fallback detectors for unstructured notes
        for pat_re, t_type, sens, sinks, fmt_pres in _INLINE_FALLBACK_PATTERNS:
            for m in list(pat_re.finditer(updated)):
                candidate = m.group(0)
                if candidate.startswith(TOKEN_PREFIX) or candidate.endswith(f"@{EMAIL_TOKEN_DOMAIN}"):
                    continue
                token_str = await self.tokenizer.tokenize(
                    raw_value=candidate,
                    token_type=t_type,
                    origin_ref=ref,
                    origin_path=current_path,
                    session=session,
                    event_id=event_id,
                    allowed_sinks=sinks,
                    allow_external_egress=False,
                    format_preserving=fmt_pres,
                    sensitivity=sens,
                )
                updated = updated.replace(candidate, token_str, 1)
                transforms.append(
                    TransformRecord(
                        json_path=current_path,
                        action=FieldAction.TOKENIZE,
                        token_type=t_type,
                        reason=f"inline_regex_{t_type.lower()}",
                    )
                )

        return updated

    async def _process_list(
        self,
        node: list[Any],
        path: str,
        ref: ToolRef,
        session: SessionContext,
        event_id: str,
        transforms: list[TransformRecord],
        stash: dict[str, Any],
        stash_id_hint: str = "",
    ) -> None:
        """Process list items recursively."""
        for idx, item in enumerate(node):
            item_path = f"{path}[{idx}]"
            if isinstance(item, dict):
                await self._process_dict(item, item_path, ref, session, event_id, transforms, stash, stash_id_hint)
            elif isinstance(item, list):
                await self._process_list(item, item_path, ref, session, event_id, transforms, stash, stash_id_hint)
            elif isinstance(item, str) and item.strip():
                stripped = item.strip()
                matched = False
                for full_re, _inline_re, detector in self._compiled_detectors:
                    if full_re.search(stripped):
                        if detector.validator and not evaluate_operator(detector.validator, stripped):
                            continue
                        node[idx] = await self.tokenizer.tokenize(
                            raw_value=item,
                            token_type=detector.token_type,
                            origin_ref=ref,
                            origin_path=item_path,
                            session=session,
                            event_id=event_id,
                            allowed_sinks=SinkMacro(detector.allowed_sinks) if hasattr(SinkMacro, detector.allowed_sinks.upper()) else SinkMacro.NONE,
                            allow_external_egress=detector.allow_external_egress,
                            format_preserving=detector.format_preserving,
                            sensitivity=detector.sensitivity,
                        )
                        transforms.append(
                            TransformRecord(
                                json_path=item_path,
                                action=FieldAction.TOKENIZE,
                                token_type=detector.token_type,
                                reason=f"detector_{detector.id}",
                            )
                        )
                        matched = True
                        break
                if not matched:
                    node[idx] = await self._redact_inline_free_text(
                        text=item,
                        current_path=item_path,
                        ref=ref,
                        session=session,
                        event_id=event_id,
                        transforms=transforms,
                    )
