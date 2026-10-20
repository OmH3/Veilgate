"""Human-in-the-loop (HITL) approval broker service."""

import asyncio
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from veilgate.config.policy_loader import PolicyLoader
from veilgate.config.policy_models import LearnedGrant
from veilgate.repositories.approval_repo import ApprovalRepository
from veilgate.repositories.models import ApprovalRecord
from veilgate.security.crypto import generate_crockford_token_id
from veilgate.services.models import ApprovalDecision, SessionContext, ToolRef
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.services.approval_service")


def compute_args_hash(args: Mapping[str, Any]) -> str:
    """Compute canonical SHA-256 hash of tool invocation arguments to prevent TOCTOU tampering."""
    canonical = json.dumps(dict(args), sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalService:
    """Brokers human approval requests across MCP elicitation, dashboard polling, and dev learning."""

    def __init__(
        self,
        approval_repo: ApprovalRepository,
        policy_loader: PolicyLoader,
        timeout_seconds: int = 120,
        dev_mode: bool = False,
    ) -> None:
        self.approval_repo: ApprovalRepository = approval_repo
        self.policy_loader: PolicyLoader = policy_loader
        self.timeout_seconds: int = timeout_seconds
        self.dev_mode: bool = dev_mode

    def verify_args_hash(self, record: ApprovalRecord, current_args: Mapping[str, Any]) -> bool:
        """Verify that current invocation arguments match the SHA-256 hash bound at request time."""
        try:
            summary_data = json.loads(record.summary_json)
            recorded_hash = summary_data.get("args_hash")
            if not recorded_hash:
                return False
            return recorded_hash == compute_args_hash(current_args)
        except json.JSONDecodeError as e:
            logger.exception(f"ERROR | {type(e).__name__}: {e}")
            return False

    async def request_approval(
        self,
        ref: ToolRef,
        args: dict[str, Any],
        session: SessionContext,
        reason: str,
    ) -> ApprovalDecision:
        """Create approval request bound to canonical args_hash and await reviewer decision."""
        approval_id = f"appr_{generate_crockford_token_id()}"
        args_hash = compute_args_hash(args)
        summary_json = json.dumps({
            "tool": ref.qualified,
            "args_hash": args_hash,
            "args_sample": {k: str(v)[:60] for k, v in args.items()},
        })

        await self.approval_repo.create_request(
            approval_id=approval_id,
            session_id=session.session_id,
            qualified_ref=ref.qualified,
            summary_json=summary_json,
            reason=reason,
        )

        logger.info(
            f"APPROVAL_REQUIRED | id={approval_id} tool={ref.qualified} reason={reason} "
            f"args_hash={args_hash[:12]} dev_mode={self.dev_mode} -> awaiting decision (timeout={self.timeout_seconds}s)"
        )

        # In non-interactive test or CLI headless environments without dashboard, auto-deny on timeout
        start = asyncio.get_event_loop().time()
        poll_interval = 0.05 if self.timeout_seconds <= 2 else 0.25

        while (asyncio.get_event_loop().time() - start) < self.timeout_seconds:
            record = await self.approval_repo.get(approval_id)
            if record and record.status != "PENDING":
                if record.status in ("APPROVED", "APPROVED_AND_SAVED"):
                    # TOCTOU verification (Attack A9 defense): verify args were not mutated after approval request
                    if not self.verify_args_hash(record, args):
                        logger.warning(
                            f"TOCTOU_DETECTED | Approval {approval_id} args_hash mismatch for {ref.qualified} -> DENIED"
                        )
                        await self.approval_repo.decide(
                            approval_id, status="DENIED", decided_by="toctou_args_hash_mismatch"
                        )
                        return ApprovalDecision(
                            approval_id=approval_id,
                            status="DENIED",
                            decided_by="toctou_args_hash_mismatch",
                        )

                # Handle "APPROVED_AND_SAVED" in dev mode
                if record.status == "APPROVED_AND_SAVED" and record.learned_grant:
                    grant = LearnedGrant(
                        grant_id=f"grnt_{generate_crockford_token_id()}",
                        pattern=ref.qualified,
                        token_type="APPROVED_GRANT",
                        created_at=datetime.now(UTC).isoformat(),
                    )
                    self.policy_loader.append_learned_grant(grant)

                return ApprovalDecision(
                    approval_id=approval_id,
                    status=record.status,
                    decided_by=record.decided_by or "unknown",
                    learned_grant=record.learned_grant,
                )

            await asyncio.sleep(poll_interval)

        # Mark expired on timeout
        await self.approval_repo.decide(approval_id, status="EXPIRED", decided_by="gateway_timeout")
        return ApprovalDecision(
            approval_id=approval_id,
            status="EXPIRED",
            decided_by="gateway_timeout",
        )
