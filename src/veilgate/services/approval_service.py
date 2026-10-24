"""Human-in-the-loop (HITL) approval broker service."""

import asyncio
import hashlib
import json
import sys
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


def _ask_terminal_choice(ref: ToolRef, args: Mapping[str, Any], reason: str) -> str | None:
    """Prompt the developer directly on the controlling terminal (CONIN$/CONOUT$ on Windows, /dev/tty on Unix).

    Returns '1' (Allow once), '2' (Allow always), '3' (Deny), or None if terminal is unavailable.
    """
    tty_in = None
    tty_out = None
    try:
        # If not attached to an interactive console session, defer purely to dashboard
        if not sys.stdin.isatty() and not sys.stdout.isatty():
            return None

        if sys.platform == "win32":
            tty_in = open("CONIN$", "r", encoding="utf-8")
            tty_out = open("CONOUT$", "w", encoding="utf-8")
        else:
            tty_in = open("/dev/tty", "r", encoding="utf-8")
            tty_out = open("/dev/tty", "w", encoding="utf-8")

        prompt_text = (
            f"\n"
            f"╔══════════════════════════════════════════════════════════════╗\n"
            f"║          [VEILGATE] EGRESS TOOL AUTHORIZATION REQUIRED       ║\n"
            f"╚══════════════════════════════════════════════════════════════╝\n"
            f"Tool:      {ref.qualified} (Server: {ref.server})\n"
            f"Reason:    {reason}\n"
            f"Arguments: {json.dumps(dict(args), default=str)[:200]}\n"
            f"──────────────────────────────────────────────────────────────\n"
            f"Select authorization option:\n"
            f"  [1] Allow once         (authorize this call only)\n"
            f"  [2] Allow always       (save grant to policy.learned.yaml)\n"
            f"  [3] Deny               (block invocation immediately)\n"
            f"Enter choice [1/2/3] (default: 3): "
        )
        tty_out.write(prompt_text)
        tty_out.flush()

        line = tty_in.readline()
        if not line:
            return None
        choice = line.strip().lower()
        return choice if choice else "3"
    except Exception as e:
        logger.debug(f"Direct terminal prompt unavailable: {e}")
        return None
    finally:
        if tty_in:
            try:
                tty_in.close()
            except Exception:
                pass
        if tty_out:
            try:
                tty_out.close()
            except Exception:
                pass


class ApprovalService:
    """Brokers human approval requests across MCP elicitation, terminal prompts, and dashboard."""

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

    async def _handle_terminal_prompt(
        self,
        approval_id: str,
        ref: ToolRef,
        args: dict[str, Any],
        reason: str,
    ) -> None:
        """Run terminal prompt in background thread and persist decision to repository."""
        try:
            choice = await asyncio.to_thread(_ask_terminal_choice, ref, args, reason)
            if choice is None:
                # Terminal prompt not available or running headless/IDE; leave in PENDING for Dashboard review!
                return

            existing = await self.approval_repo.get(approval_id)
            if not existing or existing.status != "PENDING":
                return

            if choice in ("1", "once", "allow once"):
                await self.approval_repo.decide(
                    approval_id,
                    status="APPROVED",
                    decided_by="developer_terminal",
                )
            elif choice in ("2", "always", "allow always"):
                await self.approval_repo.decide(
                    approval_id,
                    status="APPROVED_AND_SAVED",
                    decided_by="developer_terminal",
                    learned_grant=ref.qualified,
                )
            elif choice in ("3", "deny", "block"):
                await self.approval_repo.decide(
                    approval_id,
                    status="DENIED",
                    decided_by="developer_terminal",
                )
        except Exception as e:
            logger.exception(f"Error handling terminal prompt for {approval_id}: {e}")

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
            f"args_hash={args_hash[:12]} -> awaiting decision (timeout={self.timeout_seconds}s)"
        )

        prompt_task = asyncio.create_task(
            self._handle_terminal_prompt(approval_id, ref, args, reason)
        )

        start = asyncio.get_event_loop().time()
        poll_interval = 0.05 if self.timeout_seconds <= 2 else 0.25

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

                    # Persist learned grant if "APPROVED_AND_SAVED" was chosen
                    if record.status == "APPROVED_AND_SAVED":
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

