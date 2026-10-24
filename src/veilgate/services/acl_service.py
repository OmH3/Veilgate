"""Access control list (ACL) service evaluating tool authorization and risk levels."""

import fnmatch
from collections.abc import Sequence

from veilgate.config.constants import ReasonCode
from veilgate.config.policy_models import Capability, PolicyLayer, ToolPolicySpec, VeilgatePolicy
from veilgate.repositories.models import CatalogEntryRecord
from veilgate.services.models import AclDecision, SessionContext, ToolRef
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.services.acl_service")

HIGH_RISK_CAPABILITIES: set[str] = {
    Capability.WRITE.value,
    Capability.DELETE.value,
    Capability.EXEC.value,
    Capability.EXTERNAL_EGRESS.value,
}


class AclService:
    """Evaluates ACL rules, session integrity constraints, and human review requirements."""

    def __init__(self, policy: VeilgatePolicy) -> None:
        self.policy: VeilgatePolicy = policy

    def _is_egress_tool(
        self,
        ref: ToolRef,
        catalog_entry: CatalogEntryRecord | None = None,
        tool_rule: ToolPolicySpec | None = None,
    ) -> bool:
        """Determine if a tool possesses external egress or network transmission capabilities."""
        if tool_rule and any(c.lower() in ("external_egress", "egress") for c in (tool_rule.capabilities or [])):
            return True
        if catalog_entry:
            if Capability.EXTERNAL_EGRESS.value in catalog_entry.capabilities or catalog_entry.untrusted_tool:
                return True
        name_lower = ref.qualified.lower()
        egress_patterns = ("*mail*", "*email*", "*send*", "*post*", "*http*", "*curl*", "*webhook*", "*upload*")
        return any(fnmatch.fnmatch(name_lower, pat) for pat in egress_patterns)

    def decide(
        self,
        ref: ToolRef,
        session: SessionContext,
        catalog_entry: CatalogEntryRecord | None = None,
    ) -> AclDecision:
        """Evaluate authorization decision for a tool invocation."""
        qualified = ref.qualified

        # 1. Quarantined tool protection
        if catalog_entry and catalog_entry.status == "quarantined":
            return AclDecision(
                decision="DENY",
                reason=ReasonCode.TOOL_QUARANTINED,
                matched_rule=qualified,
                matched_layer=PolicyLayer.USER,
            )

        # 2. Check interactive / learned policy grants
        for grant in self.policy.learned_grants:
            if fnmatch.fnmatch(qualified.lower(), grant.pattern.lower()):
                logger.info(f"ACL_ALLOW_LEARNED | tool={qualified} matched learned_grant={grant.pattern}")
                return AclDecision(
                    decision="ALLOW",
                    reason=ReasonCode.APPROVAL_APPROVED_AND_SAVED,
                    matched_rule=grant.pattern,
                    matched_layer=PolicyLayer.LEARNED,
                )

        # 3. Session integrity guard (LOW integrity forces approval for state-modifying tools)
        if session.integrity == "LOW" and catalog_entry:
            tool_caps = set(catalog_entry.capabilities)
            if tool_caps.intersection(HIGH_RISK_CAPABILITIES):
                return AclDecision(
                    decision="REQUIRE_APPROVAL",
                    reason=ReasonCode.LOW_INTEGRITY_APPROVAL_REQUIRED,
                    matched_rule="low_integrity_guard",
                    matched_layer=PolicyLayer.PACK,
                )

        # 4. Match against user policy tool rules (in order of definition)
        for tool_rule in self.policy.tools:
            if fnmatch.fnmatch(qualified.lower(), tool_rule.match.lower()):
                if not tool_rule.allow:
                    # If tool is egress, ask developer for approval rather than silent deny
                    if self._is_egress_tool(ref, catalog_entry, tool_rule=tool_rule):
                        return AclDecision(
                            decision="REQUIRE_APPROVAL",
                            reason=ReasonCode.EGRESS_APPROVAL_REQUIRED,
                            matched_rule=tool_rule.match,
                            matched_layer=PolicyLayer.USER,
                        )
                    return AclDecision(
                        decision="DENY",
                        reason=ReasonCode.TOOL_NOT_ALLOWED,
                        matched_rule=tool_rule.match,
                        matched_layer=PolicyLayer.USER,
                    )
                if tool_rule.require_approval:
                    return AclDecision(
                        decision="REQUIRE_APPROVAL",
                        reason=ReasonCode.APPROVAL_DENIED,
                        matched_rule=tool_rule.match,
                        matched_layer=PolicyLayer.USER,
                    )
                return AclDecision(
                    decision="ALLOW",
                    reason=ReasonCode.OK,
                    matched_rule=tool_rule.match,
                    matched_layer=PolicyLayer.USER,
                )

        # 5. Fallback to default_tool_allow or default deny
        if self.policy.default_tool_allow:
            return AclDecision(
                decision="ALLOW",
                reason=ReasonCode.OK,
                matched_rule="default_tool_allow",
                matched_layer=PolicyLayer.USER,
            )

        if self._is_egress_tool(ref, catalog_entry):
            return AclDecision(
                decision="REQUIRE_APPROVAL",
                reason=ReasonCode.EGRESS_APPROVAL_REQUIRED,
                matched_rule="default_deny",
                matched_layer=PolicyLayer.USER,
            )

        return AclDecision(
            decision="DENY",
            reason=ReasonCode.TOOL_NOT_ALLOWED,
            matched_rule="default_deny",
            matched_layer=PolicyLayer.USER,
        )

    def filter_catalog(
        self,
        tools: Sequence[CatalogEntryRecord],
        session: SessionContext,
    ) -> list[CatalogEntryRecord]:
        """Filter tool catalog for tools/list discovery, dropping denied or quarantined tools."""
        allowed: list[CatalogEntryRecord] = []
        for entry in tools:
            ref = ToolRef.parse(entry.qualified_ref)
            decision = self.decide(ref, session, catalog_entry=entry)
            if decision.decision in ("ALLOW", "REQUIRE_APPROVAL"):
                allowed.append(entry)
        return allowed
