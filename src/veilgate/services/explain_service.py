"""Offline <50ms zero-LLM policy explanation and debugger service."""

from typing import Any
from pydantic import BaseModel

from veilgate.config.policy_models import VeilgatePolicy
from veilgate.engines.operators import evaluate_operator
from veilgate.services.acl_service import AclService
from veilgate.services.catalog_service import CatalogService
from veilgate.services.minimizer_service import DEFAULT_BLOAT_KEYS, DEFAULT_SENSITIVE_KEY_STEMS
from veilgate.services.models import SessionContext, ToolRef


class ToolExplanation(BaseModel):
    """Detailed explanation report for a tool."""

    tool: str
    decision: str
    reason: str
    matched_rule: str | None
    capabilities: list[str]
    risk_level: str


class FieldExplanation(BaseModel):
    """Explanation report for an individual field."""

    path: str
    action: str
    reason: str
    token_type: str | None = None


class ExplainService:
    """Provides instant policy inspection and matching diagnostics."""

    def __init__(
        self,
        policy: VeilgatePolicy,
        acl_service: AclService,
        catalog_service: CatalogService,
    ) -> None:
        self.policy: VeilgatePolicy = policy
        self.acl: AclService = acl_service
        self.catalog: CatalogService = catalog_service

    def explain_tool(self, tool_name: str) -> ToolExplanation:
        """Explain how ACL and capability rules evaluate a given tool."""
        ref = ToolRef.parse(tool_name)
        caps, risk = self.catalog.derive_capabilities(ref.tool)
        dummy_session = SessionContext(
            session_id="explain_session",
            correlation_id="explain_cor",
        )
        decision = self.acl.decide(ref, dummy_session)

        return ToolExplanation(
            tool=ref.qualified,
            decision=decision.decision,
            reason=decision.reason.value,
            matched_rule=decision.matched_rule,
            capabilities=caps,
            risk_level=risk,
        )

    def explain_payload(self, payload: dict[str, Any], path_prefix: str = "$") -> list[FieldExplanation]:
        """Explain how minimizer and classification rules evaluate a JSON payload."""
        explanations: list[FieldExplanation] = []

        for key, val in payload.items():
            current_path = f"{path_prefix}.{key}"
            key_lower = key.lower()

            if key_lower in DEFAULT_BLOAT_KEYS or key_lower.startswith("x-"):
                explanations.append(
                    FieldExplanation(
                        path=current_path,
                        action="DROP",
                        reason="Matched HTTP bloat rule in bloat-http pack",
                    )
                )
                continue

            # Key stem matching
            matched_stem = False
            for stems, t_type, sens, sinks, format_pres in DEFAULT_SENSITIVE_KEY_STEMS:
                if evaluate_operator("key_stem", key, {"stems": stems}):
                    explanations.append(
                        FieldExplanation(
                            path=current_path,
                            action="TOKENIZE",
                            reason=f"Matched sensitive key stem {stems} in sensitive-keys pack",
                            token_type=t_type,
                        )
                    )
                    matched_stem = True
                    break

            if matched_stem:
                continue

            if isinstance(val, dict):
                explanations.extend(self.explain_payload(val, current_path))
            else:
                explanations.append(
                    FieldExplanation(
                        path=current_path,
                        action="ALLOW",
                        reason="No sensitive pattern matched; passes unchanged",
                    )
                )

        return explanations
