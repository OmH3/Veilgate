"""Human-in-the-loop (HITL) approval broker service."""

import asyncio
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
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


def _ask_gui_or_terminal_choice(
    ref: ToolRef,
    args: Mapping[str, Any],
    reason: str,
    timeout_seconds: int = 120,
) -> str | None:
    """Prompt the developer via cross-platform native tkinter modal (Windows, macOS, Linux).

    Returns '1' (Allow once), '2' (Allow always), '3' (Deny), or None if no display is available.
    """
    # Skip launching GUI windows during short-timeout unit tests
    if timeout_seconds <= 5 or os.environ.get("PYTEST_CURRENT_TEST"):
        return None

    # On Linux/Unix without DISPLAY or WAYLAND_DISPLAY, fall back to dashboard/CLI
    if sys.platform != "win32" and sys.platform != "darwin":
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            return None

    try:
        args_json = json.dumps(dict(args), default=str, ensure_ascii=False)
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "veilgate.gui_prompt",
                ref.qualified,
                ref.server,
                reason,
                args_json,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        choice = (proc.stdout or "").strip()
        if choice in ("1", "2", "3"):
            return choice
        return None
    except Exception as e:
        logger.debug(f"Cross-platform GUI prompt unavailable: {e}")
        return None


class ApprovalService:
    """Brokers human approval requests across cross-platform GUI modals, terminal prompts, and dashboard."""

    def __init__(
        self,
        approval_repo: ApprovalRepository,
        policy_loader: PolicyLoader,
        timeout_seconds: int = 120,
    ) -> None:
        self.approval_repo: ApprovalRepository = approval_repo
        self.policy_loader: PolicyLoader = policy_loader
        self.timeout_seconds: int = timeout_seconds

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

    async def decide_request(
        self,
        target: str,
        choice: str,
        decided_by: str = "developer_gui",
    ) -> ApprovalRecord | None:
        """Apply a user authorization choice ('1'=Allow once, '2'=Allow always, '3'=Deny) to an approval ID or tool name."""
        record = await self.approval_repo.get(target)
        qualified_ref = record.qualified_ref if record else ToolRef.parse(target).qualified

        normalized = choice.strip().lower()
        if normalized in ("1", "once", "allow once", "allow_once", "allow-once"):
            status = "APPROVED"
            learned_grant = None
        elif normalized in ("2", "always", "allow always", "allow_always", "allow-always"):
            status = "APPROVED_AND_SAVED"
            learned_grant = qualified_ref
            grant = LearnedGrant(
                grant_id=f"grnt_{generate_crockford_token_id()}",
                pattern=learned_grant,
                token_type="APPROVED_GRANT",
                created_at=datetime.now(UTC).isoformat(),
            )
            self.policy_loader.append_learned_grant(grant)
            self.policy_loader.promote_learned_grants()
        else:
            status = "DENIED"
            learned_grant = None

        if record:
            await self.approval_repo.decide(
                record.approval_id,
                status=status,
                decided_by=decided_by,
                learned_grant=learned_grant,
            )
            return await self.approval_repo.get(record.approval_id)

        return ApprovalRecord(
            approval_id=target,
            session_id="gui_session",
            qualified_ref=qualified_ref,
            summary_json="{}",
            reason="GUI_APPROVAL",
            status=status,
            requested_at=datetime.now(UTC).isoformat(),
            decided_at=datetime.now(UTC).isoformat(),
            decided_by=decided_by,
            learned_grant=learned_grant,
        )

    async def _handle_gui_prompt(
        self,
        approval_id: str,
        ref: ToolRef,
        args: dict[str, Any],
        reason: str,
    ) -> None:
        """Run cross-platform GUI popup in background thread and persist decision to repository."""
        try:
            choice = await asyncio.to_thread(
                _ask_gui_or_terminal_choice,
                ref,
                args,
                reason,
                self.timeout_seconds,
            )
            if choice is None:
                return

            existing = await self.approval_repo.get(approval_id)
            if not existing or existing.status != "PENDING":
                return

            await self.decide_request(approval_id, choice, decided_by="developer_gui_modal")
        except Exception as e:
            logger.exception(f"Error handling GUI approval prompt for {approval_id}: {e}")

    async def request_approval(
        self,
        ref: ToolRef,
        args: dict[str, Any],
        session: SessionContext,
        reason: str,
    ) -> ApprovalDecision:
        """Create approval request bound to canonical args_hash and await reviewer decision via GUI modal or Dashboard."""
        args_hash = compute_args_hash(args)
        approval_id = f"appr_{generate_crockford_token_id()}"
        summary_json = json.dumps({
            "tool": ref.qualified,
            "args_hash": args_hash,
            "args": dict(args),
            "expires_at": (datetime.now(UTC) + timedelta(seconds=self.timeout_seconds)).isoformat(),
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
            f"args_hash={args_hash[:12]} -> launching native approval modal (timeout={self.timeout_seconds}s)"
        )

        prompt_task = asyncio.create_task(
            self._handle_gui_prompt(approval_id, ref, args, reason)
        )

        start = asyncio.get_event_loop().time()
        poll_interval = 0.05 if self.timeout_seconds <= 2 else 0.15

        try:
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

                    # Persist learned grant if "APPROVED_AND_SAVED" was chosen via Dashboard
                    if record.status == "APPROVED_AND_SAVED" and record.decided_by != "developer_gui_modal":
                        pattern = record.learned_grant or ref.qualified
                        grant = LearnedGrant(
                            grant_id=f"grnt_{generate_crockford_token_id()}",
                            pattern=pattern,
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
        finally:
            if not prompt_task.done():
                prompt_task.cancel()
