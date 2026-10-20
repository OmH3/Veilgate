"""Taint tracking service enforcing sink policies, arg guards, and argument rehydration."""

import fnmatch
import json
import re
from collections.abc import Mapping
from typing import Any

from veilgate.config.constants import (
    SYNTHETIC_INT_BASE,
    ReasonCode,
)
from veilgate.config.policy_models import (
    Capability,
    PolicyLayer,
    SinkMacro,
    UnlistedSinkPolicy,
    VeilgatePolicy,
)
from veilgate.engines.operators import evaluate_operator
from veilgate.repositories.models import CatalogEntryRecord, TokenRecord
from veilgate.repositories.vault_repo import VaultRepository
from veilgate.services.models import (
    SessionContext,
    TaintPlan,
    TaintVerdict,
    TokenFinding,
    ToolRef,
)
from veilgate.utils.logging_utils import setup_logger
from veilgate.utils.text_scan import detect_smuggled_tokens

logger = setup_logger("veilgate.services.taint_service")


_RAW_EGRESS_GUARD_TYPES: set[str] = {
    "SSN",
    "CREDIT_CARD",
    "PAN",
    "AADHAAR",
    "AWS_KEY",
    "GITHUB_TOKEN",
    "API_KEY",
}


class TaintService:
    """Scans tool arguments for tokens, enforces sink policies, and rehydrates plaintext."""

    def __init__(self, vault_repo: VaultRepository, policy: VeilgatePolicy) -> None:
        self.vault_repo: VaultRepository = vault_repo
        self.policy: VeilgatePolicy = policy
        self._raw_egress_detectors: list[tuple[re.Pattern[str], Any]] = [
            (
                re.compile(rf"(?<!\w)(?:{d.pattern.lstrip('^').rstrip('$')})(?!\w)"),
                d,
            )
            for d in self.policy.loaded_detectors
            if d.token_type.upper() in _RAW_EGRESS_GUARD_TYPES and not d.allow_external_egress
        ]

    def scan_args_for_tokens(
        self, args: Mapping[str, Any], path_prefix: str = "$"
    ) -> list[TokenFinding]:
        """Recursively scan arguments dictionary for token placeholders."""
        findings: list[TokenFinding] = []

        for key, value in args.items():
            current_path = f"{path_prefix}.{key}"
            if isinstance(value, dict):
                findings.extend(self.scan_args_for_tokens(value, current_path))
            elif isinstance(value, list):
                for idx, item in enumerate(value):
                    item_path = f"{current_path}[{idx}]"
                    if isinstance(item, dict):
                        findings.extend(self.scan_args_for_tokens(item, item_path))
                    elif isinstance(item, str):
                        findings.extend(self._scan_string(item, item_path))
                    elif isinstance(item, int) and not isinstance(item, bool):
                        if SYNTHETIC_INT_BASE <= item < SYNTHETIC_INT_BASE + 100_000_000:
                            findings.append(
                                TokenFinding(
                                    rendered=str(item),
                                    token_id=str(item),
                                    token_type="INTEGER",
                                    arg_path=item_path,
                                    is_standalone_scalar=True,
                                )
                            )
            elif isinstance(value, str):
                findings.extend(self._scan_string(value, current_path))
            elif isinstance(value, int) and not isinstance(value, bool):
                if SYNTHETIC_INT_BASE <= value < SYNTHETIC_INT_BASE + 100_000_000:
                    findings.append(
                        TokenFinding(
                            rendered=str(value),
                            token_id=str(value),
                            token_type="INTEGER",
                            arg_path=current_path,
                            is_standalone_scalar=True,
                        )
                    )

        return findings

    def _scan_string(self, text: str, arg_path: str) -> list[TokenFinding]:
        """Extract token frames from a string value with multi-layer smuggling detection."""
        findings: list[TokenFinding] = []
        raw_findings, is_smuggled = detect_smuggled_tokens(text)

        for rendered, token_id, token_type, is_standalone in raw_findings:
            findings.append(
                TokenFinding(
                    rendered=rendered,
                    token_id=token_id,
                    token_type=token_type,
                    arg_path=arg_path,
                    is_standalone_scalar=is_standalone,
                    is_smuggled=is_smuggled,
                )
            )

        return findings

    def _scan_args_for_raw_pii(
        self, args: Mapping[str, Any], path_prefix: str = "$"
    ) -> list[TokenFinding]:
        """Scan arguments for raw un-tokenized PII/secrets before external egress."""
        raw_findings: list[TokenFinding] = []
        for key, value in args.items():
            current_path = f"{path_prefix}.{key}"
            if isinstance(value, dict):
                raw_findings.extend(self._scan_args_for_raw_pii(value, current_path))
            elif isinstance(value, list):
                for idx, item in enumerate(value):
                    item_path = f"{current_path}[{idx}]"
                    if isinstance(item, dict):
                        raw_findings.extend(self._scan_args_for_raw_pii(item, item_path))
                    elif isinstance(item, str):
                        raw_findings.extend(self._scan_raw_string(item, item_path))
            elif isinstance(value, str):
                raw_findings.extend(self._scan_raw_string(value, current_path))
        return raw_findings

    def _scan_raw_string(self, text: str, arg_path: str) -> list[TokenFinding]:
        """Check string for raw un-tokenized high-sensitivity secrets/PII."""
        results: list[TokenFinding] = []
        for inline_re, detector in self._raw_egress_detectors:
            for m in inline_re.finditer(text):
                candidate = m.group(0)
                if detector.validator and not evaluate_operator(detector.validator, candidate):
                    continue
                results.append(
                    TokenFinding(
                        rendered="[REDACTED_RAW_PII]",
                        token_id=f"RAW_{detector.token_type.upper()}",
                        token_type=detector.token_type.upper(),
                        arg_path=arg_path,
                        is_standalone_scalar=(candidate == text.strip()),
                    )
                )
        return results

    async def inspect(
        self,
        ref: ToolRef,
        args: Mapping[str, Any],
        session: SessionContext,
        catalog_entry: CatalogEntryRecord | None = None,
    ) -> TaintPlan:
        """Inspect arguments against policy and return taint plan."""
        tool_policy = next((t for t in self.policy.tools if fnmatch.fnmatch(ref.qualified.lower(), t.match.lower())), None)
        is_external_or_untrusted = bool(
            (catalog_entry and (Capability.EXTERNAL_EGRESS.value in catalog_entry.capabilities or catalog_entry.untrusted_tool))
            or (tool_policy and tool_policy.capabilities and Capability.EXTERNAL_EGRESS in tool_policy.capabilities)
        )

        verdicts: list[TaintVerdict] = []
        if is_external_or_untrusted and self._raw_egress_detectors:
            for raw_finding in self._scan_args_for_raw_pii(args):
                verdicts.append(
                    TaintVerdict(
                        finding=raw_finding,
                        decision="BLOCK",
                        reason=ReasonCode.TAINT_EGRESS_FORBIDDEN,
                        matched_layer=PolicyLayer.PACK,
                    )
                )

        findings = self.scan_args_for_tokens(args)
        if not findings:
            return TaintPlan(verdicts=verdicts)

        for finding in findings:
            # Resolve token from vault for this session
            record = await self.vault_repo.get_by_token(finding.token_id, session.session_id)
            if record is None:
                # Check by rendered representation
                record = await self.vault_repo.get_by_rendered(finding.rendered, session.session_id)

            if record is None:
                verdicts.append(
                    TaintVerdict(
                        finding=finding,
                        decision="BLOCK",
                        reason=ReasonCode.TOKEN_UNKNOWN,
                        matched_layer=PolicyLayer.USER,
                    )
                )
                continue

            # 0. Check encoded smuggling (Attack A6 defense)
            if finding.is_smuggled:
                verdicts.append(
                    TaintVerdict(
                        finding=finding,
                        decision="BLOCK",
                        reason=ReasonCode.TOKEN_ENCODED_SMUGGLING,
                        matched_layer=PolicyLayer.PACK,
                    )
                )
                continue

            finding.record = record

            # 1. Blocked token types check
            if tool_policy and record.token_type in tool_policy.blocked_token_types:
                verdicts.append(
                    TaintVerdict(
                        finding=finding,
                        decision="BLOCK",
                        reason=ReasonCode.TOKEN_TYPE_BLOCKED,
                        matched_layer=PolicyLayer.USER,
                    )
                )
                continue

            # 2. Arg guards check: prevent embedding sensitive tokens into templates or open parameters
            arg_name = finding.arg_path.split(".")[-1].split("[")[0].lower()
            if tool_policy and arg_name in [g.lower() for g in tool_policy.arg_guards]:
                if not finding.is_standalone_scalar:
                    verdicts.append(
                        TaintVerdict(
                            finding=finding,
                            decision="BLOCK",
                            reason=ReasonCode.TAINT_ARG_GUARD_BLOCKED,
                            matched_layer=PolicyLayer.USER,
                        )
                    )
                    continue

            # Check declarative arg-guards pack
            arg_guard_blocked = False
            for ag in self.policy.loaded_arg_guards:
                if arg_name in [n.lower() for n in ag.arg_names]:
                    if ag.disallow_embedded_tokens and not finding.is_standalone_scalar:
                        verdicts.append(
                            TaintVerdict(
                                finding=finding,
                                decision="BLOCK",
                                reason=ReasonCode.TAINT_ARG_GUARD_BLOCKED,
                                matched_layer=PolicyLayer.PACK,
                            )
                        )
                        arg_guard_blocked = True
                        break
                    if ag.allowed_token_types and finding.token_type not in ag.allowed_token_types:
                        verdicts.append(
                            TaintVerdict(
                                finding=finding,
                                decision="BLOCK",
                                reason=ReasonCode.TAINT_ARG_GUARD_BLOCKED,
                                matched_layer=PolicyLayer.PACK,
                            )
                        )
                        arg_guard_blocked = True
                        break

            if arg_guard_blocked:
                continue

            # 3. Egress boundary check (Confused Deputy defense)
            is_external_egress = False
            if catalog_entry and Capability.EXTERNAL_EGRESS.value in catalog_entry.capabilities or tool_policy and tool_policy.capabilities and Capability.EXTERNAL_EGRESS in tool_policy.capabilities:
                is_external_egress = True

            if is_external_egress and not record.allow_external_egress:
                verdicts.append(
                    TaintVerdict(
                        finding=finding,
                        decision="BLOCK",
                        reason=ReasonCode.TAINT_EGRESS_FORBIDDEN,
                        matched_layer=PolicyLayer.PACK,
                    )
                )
                continue

            # 4. Sink macro & pattern authorization check
            is_sink_allowed = self._check_sink_allowed(ref, record, catalog_entry, finding.arg_path)
            if is_sink_allowed:
                verdicts.append(
                    TaintVerdict(
                        finding=finding,
                        decision="REHYDRATE",
                        reason=ReasonCode.OK_SINK_ALLOWED,
                        matched_layer=PolicyLayer.USER,
                    )
                )
            else:
                # Fallback based on unlisted_sink_policy
                if self.policy.unlisted_sink_policy == UnlistedSinkPolicy.FORWARD_OPAQUE:
                    verdicts.append(
                        TaintVerdict(
                            finding=finding,
                            decision="FORWARD_OPAQUE",
                            reason=ReasonCode.OK_FORWARD_OPAQUE,
                            matched_layer=PolicyLayer.USER,
                        )
                    )
                else:
                    verdicts.append(
                        TaintVerdict(
                            finding=finding,
                            decision="BLOCK",
                            reason=ReasonCode.TAINT_SINK_NOT_ALLOWED,
                            matched_layer=PolicyLayer.USER,
                        )
                    )

        return TaintPlan(verdicts=verdicts)

    def _check_sink_allowed(
        self,
        target_ref: ToolRef,
        record: TokenRecord,
        catalog_entry: CatalogEntryRecord | None,
        arg_path: str = "",
    ) -> bool:
        """Evaluate if target tool matches token allowed_sinks patterns or capability macros."""
        sinks = record.allowed_sinks_json
        target_qualified = target_ref.qualified
        target_arg = arg_path.split(".")[-1].split("[")[0].lower() if arg_path else ""

        # Handle SinkMacro
        if sinks == SinkMacro.NONE.value:
            return False

        if sinks == SinkMacro.TRUSTED_READ.value:
            # Same server read or trusted read (excluding open-world tools)
            if catalog_entry:
                is_read = Capability.READ.value in catalog_entry.capabilities
                return is_read and not catalog_entry.is_open_world
            return True

        if sinks == SinkMacro.SAME_SERVER_READ.value:
            origin_server = record.origin_ref.split(".")[0]
            if target_ref.server == origin_server and catalog_entry:
                return Capability.READ.value in catalog_entry.capabilities
            return target_ref.server == origin_server

        def matches_pattern_and_slot(pattern_spec: str) -> bool:
            if ":" in pattern_spec:
                base_pat, required_slot = pattern_spec.split(":", 1)
                if not fnmatch.fnmatch(target_qualified.lower(), base_pat.lower()):
                    return False
                if target_arg and target_arg != required_slot.lower():
                    return False
                return True
            return fnmatch.fnmatch(target_qualified.lower(), pattern_spec.lower())

        # Handle list of patterns or single glob pattern
        if sinks.startswith("["):
            try:
                allowed_list: list[str] = json.loads(sinks)
                for pattern in allowed_list:
                    if matches_pattern_and_slot(pattern):
                        return True
            except json.JSONDecodeError as e:
                logger.exception(f"ERROR | {type(e).__name__}: {e}")
        else:
            if matches_pattern_and_slot(sinks):
                return True

        return False

    async def rehydrate(
        self, args: dict[str, Any], plan: TaintPlan
    ) -> dict[str, Any]:
        """Rehydrate approved tokens with decrypted plaintext values for upstream forwarding."""
        rehydrated = dict(args)

        for verdict in plan.verdicts:
            if verdict.decision != "REHYDRATE" or not verdict.finding.record:
                continue

            plaintext = await self.vault_repo.reveal(verdict.finding.record)
            self._replace_in_dict(rehydrated, verdict.finding.arg_path, verdict.finding.rendered, plaintext)

        return rehydrated

    def _replace_in_dict(
        self, root: dict[str, Any], path: str, target: str, replacement: str
    ) -> None:
        """Replace target token string at path with replacement plaintext."""
        # path format: $.arg_name or $.nested.arg
        parts = path.lstrip("$.").split(".")
        current: Any = root
        for p in parts[:-1]:
            if isinstance(current, dict) and p in current:
                current = current[p]
            else:
                return

        last_key = parts[-1]
        if isinstance(current, dict) and last_key in current:
            val = current[last_key]
            if isinstance(val, str):
                if val == target:
                    current[last_key] = replacement
                else:
                    current[last_key] = val.replace(target, replacement)
