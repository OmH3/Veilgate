"""Taint tracking service enforcing sink policies, arg guards, and argument rehydration."""

import fnmatch
import re
from typing import Any, Mapping

from veilgate.config.constants import (
    EMAIL_TOKEN_REGEX,
    ReasonCode,
    TOKEN_REGEX,
    URL_TOKEN_REGEX,
)
from veilgate.config.policy_models import (
    Capability,
    PolicyLayer,
    SinkMacro,
    UnlistedSinkPolicy,
    VeilgatePolicy,
)
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

logger = setup_logger("veilgate.services.taint_service")


class TaintService:
    """Scans tool arguments for tokens, enforces sink policies, and rehydrates plaintext."""

    def __init__(self, vault_repo: VaultRepository, policy: VeilgatePolicy) -> None:
        self.vault_repo: VaultRepository = vault_repo
        self.policy: VeilgatePolicy = policy

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
            elif isinstance(value, str):
                findings.extend(self._scan_string(value, current_path))

        return findings

    def _scan_string(self, text: str, arg_path: str) -> list[TokenFinding]:
        """Extract token frames from a string value."""
        findings: list[TokenFinding] = []

        # 1. Standard token pattern <vg:TYPE:TOKEN_ID>
        for match in TOKEN_REGEX.finditer(text):
            rendered = match.group(0)
            token_type = match.group(1)
            token_id = match.group(2)
            is_standalone = (text.strip() == rendered)
            findings.append(
                TokenFinding(
                    rendered=rendered,
                    token_id=token_id,
                    token_type=token_type,
                    arg_path=arg_path,
                    is_standalone_scalar=is_standalone,
                )
            )

        # 2. Email token pattern vg-[base32]@vault.veilgate.invalid
        for match in EMAIL_TOKEN_REGEX.finditer(text):
            rendered = match.group(0)
            token_id = match.group(1).upper()
            is_standalone = (text.strip().lower() == rendered.lower())
            findings.append(
                TokenFinding(
                    rendered=rendered,
                    token_id=token_id,
                    token_type="EMAIL",
                    arg_path=arg_path,
                    is_standalone_scalar=is_standalone,
                )
            )

        # 3. URL token pattern https://vault.veilgate.invalid/t/[base32]
        for match in URL_TOKEN_REGEX.finditer(text):
            rendered = match.group(0)
            token_id = match.group(1).upper()
            is_standalone = (text.strip().lower() == rendered.lower())
            findings.append(
                TokenFinding(
                    rendered=rendered,
                    token_id=token_id,
                    token_type="URL",
                    arg_path=arg_path,
                    is_standalone_scalar=is_standalone,
                )
            )

        return findings

    async def inspect(
        self,
        ref: ToolRef,
        args: Mapping[str, Any],
        session: SessionContext,
        catalog_entry: CatalogEntryRecord | None = None,
    ) -> TaintPlan:
        """Inspect arguments against policy and return taint plan."""
        findings = self.scan_args_for_tokens(args)
        if not findings:
            return TaintPlan(verdicts=[])

        verdicts: list[TaintVerdict] = []
        tool_policy = next((t for t in self.policy.tools if fnmatch.fnmatch(ref.qualified.lower(), t.match.lower())), None)

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
            arg_name = finding.arg_path.split(".")[-1].split("[")[0]
            if tool_policy and arg_name in tool_policy.arg_guards:
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

            # 3. Egress boundary check (Confused Deputy defense)
            is_external_egress = False
            if catalog_entry and Capability.EXTERNAL_EGRESS.value in catalog_entry.capabilities:
                is_external_egress = True
            elif tool_policy and tool_policy.capabilities and Capability.EXTERNAL_EGRESS in tool_policy.capabilities:
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
            is_sink_allowed = self._check_sink_allowed(ref, record, catalog_entry)
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
    ) -> bool:
        """Evaluate if target tool matches token allowed_sinks patterns or capability macros."""
        sinks = record.allowed_sinks_json
        target_qualified = target_ref.qualified

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

        # Handle list of patterns or single glob pattern
        if sinks.startswith("["):
            import json
            try:
                allowed_list: list[str] = json.loads(sinks)
                for pattern in allowed_list:
                    # Strip slot specifier (e.g., 'invoicedb.compare_*:account' -> 'invoicedb.compare_*')
                    base_pattern = pattern.split(":")[0]
                    if fnmatch.fnmatch(target_qualified.lower(), base_pattern.lower()):
                        return True
            except Exception:
                pass
        else:
            base_pattern = sinks.split(":")[0]
            if fnmatch.fnmatch(target_qualified.lower(), base_pattern.lower()):
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
