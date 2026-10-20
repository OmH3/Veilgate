"""Central FirewallPipeline orchestrating discovery, access control, taint, and egress minimization."""

import json
import time
from collections.abc import Mapping
from typing import Any

from ulid import ULID

from veilgate.config.constants import ReasonCode
from veilgate.exceptions.types import (
    ApprovalDeniedError,
    ApprovalTimeoutError,
    TaintViolationError,
    ToolNotAllowedError,
    ToolQuarantinedError,
)
from veilgate.repositories.catalog_repo import CatalogRepository
from veilgate.repositories.session_repo import SessionRepository
from veilgate.repositories.stash_repo import StashRepository
from veilgate.repositories.vault_repo import VaultRepository
from veilgate.services.acl_service import AclService
from veilgate.services.approval_service import ApprovalService
from veilgate.services.audit_service import AuditService
from veilgate.services.catalog_service import CatalogService
from veilgate.services.diet_service import DietService
from veilgate.services.minimizer_service import MinimizerService
from veilgate.services.models import (
    MinimizedResult,
    SessionContext,
    ToolRef,
)
from veilgate.services.taint_service import TaintService
from veilgate.services.tokenizer_service import TokenizerService
from veilgate.services.upstream_registry import UpstreamRegistry
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.pipeline")


class FirewallPipeline:
    """Zero-trust privacy firewall pipeline intercepting MCP discovery and invocations."""

    def __init__(
        self,
        session_repo: SessionRepository,
        catalog_repo: CatalogRepository,
        stash_repo: StashRepository,
        acl_service: AclService,
        catalog_service: CatalogService,
        taint_service: TaintService,
        minimizer_service: MinimizerService,
        diet_service: DietService,
        approval_service: ApprovalService,
        audit_service: AuditService,
        upstream_registry: UpstreamRegistry,
    ) -> None:
        self.sessions: SessionRepository = session_repo
        self.catalog_repo: CatalogRepository = catalog_repo
        self.stash_repo: StashRepository = stash_repo
        self.acl: AclService = acl_service
        self.catalog_svc: CatalogService = catalog_service
        self.taint: TaintService = taint_service
        self.minimizer: MinimizerService = minimizer_service
        self.diet: DietService = diet_service
        self.approvals: ApprovalService = approval_service
        self.audit: AuditService = audit_service
        self.upstreams: UpstreamRegistry = upstream_registry
        self.vault: VaultRepository = taint_service.vault_repo
        self.tokenizer: TokenizerService = minimizer_service.tokenizer
        self._known_sessions: set[str] = set()
        self._last_list_audit_state: dict[str, tuple[int, bool]] = {}

    async def on_list_tools(
        self, session: SessionContext
    ) -> list[dict[str, Any]]:
        """Orchestrate tool discovery: ingest upstreams, enforce ACL, and compact catalog."""
        # Ensure session record exists
        if session.session_id not in self._known_sessions:
            await self.sessions.create_or_touch(session.session_id, transport=session.transport.value)
            self._known_sessions.add(session.session_id)

        # 1. Ingest tools from configured upstreams
        for upstream in self.upstreams.policy.upstreams:
            raw_tools = await self.upstreams.list_tools_from_upstream(upstream)
            for tool_data in raw_tools:
                await self.catalog_svc.ingest_tool(
                    server_id=upstream.id,
                    tool_name=tool_data["name"],
                    description=tool_data.get("description", ""),
                    input_schema=tool_data.get("inputSchema"),
                    output_schema=tool_data.get("outputSchema"),
                )

        # 2. Retrieve catalog and filter via ACL
        all_catalog = await self.catalog_repo.list_tools()
        allowed_tools = self.acl.filter_catalog(all_catalog, session)

        # 3. Apply Context Diet selection
        selected_tools, is_search_active = self.diet.select(allowed_tools, session)

        # 4. Compact schemas
        compacted: list[dict[str, Any]] = [
            self.diet.compact_tool_schema(t.raw_json)
            for t in selected_tools
        ]

        # 5. Inject meta-tools if search mode active
        if is_search_active:
            compacted.append({
                "name": "veilgate_search_tools",
                "description": "Search the full upstream tool catalog using keywords or intent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"query": {"type": "string", "description": "Search query"}},
                    "required": ["query"],
                },
            })
            compacted.append({
                "name": "veilgate_expand",
                "description": "Expand dropped non-sensitive fields from a previous result stash.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "stash_id": {"type": "string", "description": "Stash ID from previous result"},
                        "paths": {"type": "array", "items": {"type": "string"}, "description": "JSON paths to retrieve"},
                    },
                    "required": ["stash_id"],
                },
            })

        # 6. Audit discovery (deduplicate identical back-to-back LIST state per session)
        list_state = (len(compacted), is_search_active)
        if self._last_list_audit_state.get(session.session_id) != list_state:
            self._last_list_audit_state[session.session_id] = list_state
            await self.audit.record(
                kind="LIST",
                session=session,
                reason=ReasonCode.OK,
                details={"tools_count": len(compacted), "search_active": is_search_active},
            )

        return compacted

    async def on_call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        session: SessionContext,
    ) -> MinimizedResult:
        """Intercept, sanitize, authorize, and rehydrate an incoming tool call."""
        start_time = time.perf_counter()
        call_event_id = str(ULID())
        args_dict = dict(arguments)
        logger.info(f"STARTED | step=on_call_tool | session={session.session_id} | tool={tool_name}")
        logger.info(
            f"INPUT | step=on_call_tool | {json.dumps({'tool': tool_name, 'args': args_dict}, default=str, ensure_ascii=False)}"
        )

        # Ensure session record exists
        if session.session_id not in self._known_sessions:
            await self.sessions.create_or_touch(session.session_id, transport=session.transport.value)
            self._known_sessions.add(session.session_id)

        # Handle Gateway Meta-Tools
        if tool_name == "veilgate_search_tools":
            return await self._handle_meta_search(args_dict, session)
        if tool_name == "veilgate_expand":
            return await self._handle_meta_expand(args_dict, session)

        ref = ToolRef.parse(tool_name)
        catalog_entry = await self.catalog_repo.get_tool(ref.qualified)

        # 1. ACL Check
        acl_decision = self.acl.decide(ref, session, catalog_entry)
        if acl_decision.decision == "DENY":
            await self.audit.record(
                kind="BLOCK",
                session=session,
                qualified_ref=ref.qualified,
                reason=acl_decision.reason,
                details={"step": "acl", "rule": acl_decision.matched_rule},
            )
            if acl_decision.reason == ReasonCode.TOOL_QUARANTINED:
                raise ToolQuarantinedError(
                    tool_name=ref.qualified,
                    expected_fingerprint=catalog_entry.pinned_fp or "unknown",
                    observed_fingerprint=catalog_entry.fingerprint if catalog_entry else "unknown",
                )
            raise ToolNotAllowedError(tool_name=ref.qualified)

        if acl_decision.decision == "REQUIRE_APPROVAL":
            approval = await self.approvals.request_approval(
                ref=ref,
                args=args_dict,
                session=session,
                reason=acl_decision.reason.value,
            )
            if approval.status not in ("APPROVED", "APPROVED_AND_SAVED"):
                await self.audit.record(
                    kind="APPROVAL",
                    session=session,
                    qualified_ref=ref.qualified,
                    reason=ReasonCode.APPROVAL_DENIED if approval.status == "DENIED" else ReasonCode.APPROVAL_TIMEOUT,
                    details={"status": approval.status, "decided_by": approval.decided_by},
                )
                if approval.status == "EXPIRED":
                    raise ApprovalTimeoutError(tool_name=ref.qualified, timeout_seconds=self.approvals.timeout_seconds)
                raise ApprovalDeniedError(tool_name=ref.qualified)

        # 2. Taint Inspection
        taint_plan = await self.taint.inspect(ref, args_dict, session, catalog_entry)
        if taint_plan.blocked:
            blocking = taint_plan.blocking_verdict
            reason = blocking.reason if blocking else ReasonCode.TAINT_EGRESS_FORBIDDEN
            details: dict[str, Any] = {"step": "taint"}
            if blocking and blocking.finding.record:
                details["token_id"] = blocking.finding.token_id
                details["token_type"] = blocking.finding.record.token_type

            await self.audit.record(
                kind="SECURITY",
                session=session,
                qualified_ref=ref.qualified,
                reason=reason,
                details=details,
            )
            raise TaintViolationError(
                safe_message=f"Transmission blocked by taint policy ({reason.value}).",
                reason=reason,
                token_id=blocking.finding.token_id if blocking else None,
                arg_path=blocking.finding.arg_path if blocking else None,
                tool_name=ref.qualified,
            )

        # 3. Rehydrate approved tokens for upstream execution
        forwarding_args = await self.taint.rehydrate(args_dict, taint_plan)

        # 4. Upstream Execution
        raw_result = await self.upstreams.call_upstream_tool(
            server_id=ref.server,
            tool_name=ref.tool,
            arguments=forwarding_args,
        )

        # 5. Egress Minimization & Tokenization
        raw_payload = raw_result.get("structured_content") or raw_result.get("content") or {}
        minimized = await self.minimizer.minimize(
            raw_payload=raw_payload,
            ref=ref,
            session=session,
            event_id=call_event_id,
        )

        # 6. Session Integrity Lowering: untrusted tool invocation lowers session integrity to LOW
        if catalog_entry and catalog_entry.untrusted_tool:
            if session.integrity != "LOW":
                session.integrity = "LOW"
                minimized.integrity_lowered = True
                await self.sessions.update_integrity(session.session_id, "LOW")
                logger.warning(f"INTEGRITY_LOWERED | Session {session.session_id} integrity -> LOW (called untrusted tool {ref.qualified})")

        # 7. Audit Call & Transformations
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        await self.audit.record(
            kind="CALL",
            session=session,
            qualified_ref=ref.qualified,
            reason=ReasonCode.OK,
            details={
                "latency_ms": round(latency_ms, 2),
                "tokens_before": minimized.tokens_before,
                "tokens_after": minimized.tokens_after,
                "transforms_count": len(minimized.transforms),
            },
        )
        logger.info(
            f"OUTPUT | step=on_call_tool | {json.dumps({'tool': ref.qualified, 'tokens_before': minimized.tokens_before, 'tokens_after': minimized.tokens_after, 'transforms': len(minimized.transforms)}, ensure_ascii=False)}"
        )
        logger.info(f"SUCCESS | step=on_call_tool | session={session.session_id} | tool={ref.qualified}")

        return minimized

    async def _handle_meta_search(
        self, args: dict[str, Any], session: SessionContext
    ) -> MinimizedResult:
        """Execute veilgate_search_tools meta-tool and promote matches."""
        query = args.get("query", "")
        all_catalog = await self.catalog_repo.list_tools()
        allowed = self.acl.filter_catalog(all_catalog, session)
        ranked = self.diet.search_tools(query, allowed)

        # Promote ranked tools in session
        for tool in ranked:
            session.promoted_tools.add(tool.qualified_ref)

        results = [
            {"name": t.qualified_ref, "capabilities": t.capabilities, "risk": t.risk_level}
            for t in ranked
        ]
        return MinimizedResult(
            content=[{"type": "text", "text": f"Found and unlocked {len(results)} matching tools:\n{results}"}],
            structured_content={"matches": results},
            tokens_before=0,
            tokens_after=10,
        )

    async def _handle_meta_expand(
        self, args: dict[str, Any], session: SessionContext
    ) -> MinimizedResult:
        """Execute veilgate_expand to retrieve previously dropped non-sensitive fields."""
        stash_id = args.get("stash_id", "")
        record = await self.stash_repo.get_stash(stash_id, session.session_id)
        if not record:
            return MinimizedResult(
                content=[{"type": "text", "text": f"Stash '{stash_id}' not found or expired."}],
                is_error=True,
            )

        return MinimizedResult(
            content=[{"type": "text", "text": record.payload_json}],
            structured_content={"stash_id": stash_id, "payload": record.payload_json},
        )
