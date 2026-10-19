"""Diet service for tool catalog pruning, schema compaction, and meta-tool search."""

import copy
import json
import re
from typing import Any

from rank_bm25 import BM25Okapi

from veilgate.config.policy_models import DietMode, DietSpec
from veilgate.repositories.models import CatalogEntryRecord
from veilgate.services.models import SessionContext
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.services.diet_service")


class DietService:
    """Manages schema compaction, dynamic search ranking, and catalog minimization."""

    def __init__(self, spec: DietSpec) -> None:
        self.spec: DietSpec = spec

    def select(
        self,
        tools: list[CatalogEntryRecord],
        session: SessionContext,
    ) -> tuple[list[CatalogEntryRecord], bool]:
        """Select tools according to diet mode.

        Returns:
            Tuple of (selected_tools: list[CatalogEntryRecord], is_search_mode_active: bool).
        """
        # Full mode or auto below threshold: include all allowed tools
        if self.spec.mode == DietMode.FULL:
            return tools, False
        if self.spec.mode == DietMode.AUTO and len(tools) <= self.spec.search_threshold:
            return tools, False

        # Search mode: return pinned tools + 1 read tool per server + promoted tools
        selected: list[CatalogEntryRecord] = []
        servers_seen: set[str] = set()

        for tool in tools:
            # 1. Pinned tools
            if any(p in tool.qualified_ref for p in self.spec.pinned_tools):
                selected.append(tool)
                servers_seen.add(tool.server_id)
                continue

            # 2. Promoted tools unlocked by search in this session
            if tool.qualified_ref in session.promoted_tools:
                selected.append(tool)
                servers_seen.add(tool.server_id)
                continue

            # 3. 1 primary read tool per server for exploratory discovery
            if tool.server_id not in servers_seen and "read" in tool.capabilities:
                selected.append(tool)
                servers_seen.add(tool.server_id)

        return selected, True

    def search_tools(
        self,
        query: str,
        tools: list[CatalogEntryRecord],
        top_k: int | None = None,
    ) -> list[CatalogEntryRecord]:
        """Rank tools using BM25 over tool names and descriptions."""
        k = top_k or self.spec.top_k
        if not tools:
            return []

        corpus = [
            f"{t.qualified_ref} {t.raw_json}".lower().split()
            for t in tools
        ]
        bm25 = BM25Okapi(corpus)
        query_tokens = query.lower().split()
        scores = bm25.get_scores(query_tokens)

        scored_tools = sorted(zip(scores, tools), key=lambda x: x[0], reverse=True)
        return [tool for score, tool in scored_tools[:k] if score > 0]

    def compact_tool_schema(
        self,
        raw_tool_json: str,
    ) -> dict[str, Any]:
        """Compact description and strip noisy schema artifacts ($comment, examples)."""
        data = json.loads(raw_tool_json)
        desc = data.get("description", "")
        if len(desc) > self.spec.max_description_chars:
            data["description"] = desc[: self.spec.max_description_chars - 3] + "..."

        input_schema = data.get("inputSchema", {})
        self._prune_schema(input_schema)
        data["inputSchema"] = input_schema

        return data

    def _prune_schema(self, schema: dict[str, Any]) -> None:
        """Strip non-essential validation documentation keys recursively."""
        if not isinstance(schema, dict):
            return

        schema.pop("$comment", None)
        schema.pop("examples", None)

        if "properties" in schema and isinstance(schema["properties"], dict):
            for prop in schema["properties"].values():
                if isinstance(prop, dict):
                    self._prune_schema(prop)
