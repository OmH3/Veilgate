"""Catalog service for tool ingestion, fingerprint verification, and capability inference."""

import hashlib
import json
import re
from typing import Any

from veilgate.config.policy_models import Capability, RiskLevel, TrustLevel, VeilgatePolicy
from veilgate.repositories.catalog_repo import CatalogRepository
from veilgate.repositories.models import CatalogEntryRecord
from veilgate.services.models import ToolRef
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.services.catalog_service")

# Default verb patterns for fallback capability derivation
VERB_PATTERNS: list[tuple[str, Capability, RiskLevel]] = [
    (r"^(get|list|read|fetch|search|find|describe|view|query|inspect|show|load|scan|peek)", Capability.READ, RiskLevel.LOW),
    (r"^(create|add|insert|update|set|modify|edit|patch|write|append|save|put)", Capability.WRITE, RiskLevel.MEDIUM),
    (r"^(delete|remove|drop|purge|clear|truncate|destroy|erase|unlink)", Capability.DELETE, RiskLevel.HIGH),
    (r"^(send|post|publish|broadcast|dispatch|notify|emit|upload|forward)", Capability.EXTERNAL_EGRESS, RiskLevel.HIGH),
    (r"^(exec|run|eval|execute|shell|cmd|bash|script|invoke)", Capability.EXEC, RiskLevel.CRITICAL),
]


def compute_tool_fingerprint(name: str, input_schema: dict[str, Any] | None) -> str:
    """Compute deterministic SHA-256 fingerprint for a tool schema."""
    canonical_schema = json.dumps(input_schema or {}, sort_keys=True)
    payload = f"{name}:{canonical_schema}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CatalogService:
    """Ingests raw tool catalogs, detects rug-pulls, and derives capabilities."""

    def __init__(self, catalog_repo: CatalogRepository, policy: VeilgatePolicy) -> None:
        self.catalog_repo: CatalogRepository = catalog_repo
        self.policy: VeilgatePolicy = policy

    def derive_capabilities(self, tool_name: str) -> tuple[list[str], str]:
        """Infer capabilities and baseline risk level from tool name verb stems."""
        name_lower = tool_name.lower()
        capabilities: list[str] = []
        highest_risk = RiskLevel.LOW

        for pattern, cap, risk in VERB_PATTERNS:
            if re.search(pattern, name_lower):
                capabilities.append(cap.value)
                if risk == RiskLevel.CRITICAL:
                    highest_risk = RiskLevel.CRITICAL
                elif risk == RiskLevel.HIGH and highest_risk != RiskLevel.CRITICAL:
                    highest_risk = RiskLevel.HIGH
                elif risk == RiskLevel.MEDIUM and highest_risk in (RiskLevel.LOW,):
                    highest_risk = RiskLevel.MEDIUM

        if not capabilities:
            capabilities = [Capability.READ.value]

        return capabilities, highest_risk.value

    async def ingest_tool(
        self,
        server_id: str,
        tool_name: str,
        description: str,
        input_schema: dict[str, Any] | None,
        output_schema: dict[str, Any] | None = None,
    ) -> CatalogEntryRecord:
        """Process, fingerprint, verify against rug-pulls, and persist an upstream tool."""
        ref = ToolRef(server=server_id, tool=tool_name)
        fingerprint = compute_tool_fingerprint(tool_name, input_schema)

        # Check pinned fingerprint in policy or previous repository record
        pinned_fp: str | None = None
        upstream_spec = next((u for u in self.policy.upstreams if u.id == server_id), None)
        if upstream_spec and tool_name in upstream_spec.pinned_fingerprints:
            pinned_fp = upstream_spec.pinned_fingerprints[tool_name]

        existing = await self.catalog_repo.get_tool(ref.qualified)
        if existing and existing.pinned_fp:
            pinned_fp = existing.pinned_fp

        # Rug-pull detection: if pinned fingerprint exists and mismatches, quarantine tool
        status = "active"
        if pinned_fp and pinned_fp != fingerprint:
            status = "quarantined"
            logger.warning(
                f"RUG_PULL_DETECTED | Tool {ref.qualified} schema changed unexpectedly! "
                f"expected={pinned_fp[:12]} observed={fingerprint[:12]} -> QUARANTINED"
            )

        capabilities, risk_level = self.derive_capabilities(tool_name)

        # Determine server trust
        server_untrusted = False
        if upstream_spec and upstream_spec.trust == TrustLevel.UNTRUSTED:
            server_untrusted = True

        # Check open-world argument stems (urls, web search, open prompts)
        is_open_world = False
        if input_schema and "properties" in input_schema:
            props = input_schema["properties"]
            for prop_name in props:
                if any(kw in prop_name.lower() for kw in ("url", "href", "query", "search", "uri")):
                    is_open_world = True
                    break

        untrusted_tool = server_untrusted or (is_open_world and Capability.READ.value in capabilities)

        raw_json = json.dumps({
            "name": ref.exposed,
            "description": description,
            "inputSchema": input_schema or {},
            "outputSchema": output_schema,
        })

        entry = CatalogEntryRecord(
            qualified_ref=ref.qualified,
            server_id=server_id,
            fingerprint=fingerprint,
            pinned_fp=pinned_fp,
            status=status,
            capabilities=capabilities,
            is_open_world=is_open_world,
            untrusted_tool=untrusted_tool,
            risk_level=risk_level,
            schema_tokens=max(1, len(description) // 4 + 20),
            raw_json=raw_json,
            first_seen_at="",
            updated_at="",
        )

        await self.catalog_repo.upsert_tool(entry)
        return entry
