"""Tool catalog and schema shape cache repository."""

import json
from datetime import UTC, datetime

from veilgate.config.constants import TABLE_SCHEMA_CACHE, TABLE_TOOL_CATALOG
from veilgate.repositories.db import DatabaseManager
from veilgate.repositories.models import CatalogEntryRecord


class CatalogRepository:
    """Manages tool metadata persistence, pinned fingerprints, and schema classification cache."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db: DatabaseManager = db_manager
        self._list_cache: dict[str | None, list[CatalogEntryRecord]] = {}

    async def upsert_tool(self, entry: CatalogEntryRecord) -> None:
        """Insert or update tool catalog entry."""
        self._list_cache.clear()
        capabilities_json = json.dumps(entry.capabilities)
        now = datetime.now(UTC).isoformat()

        async with self.db.connection() as conn:
            await conn.execute(
                f"""
                INSERT INTO {TABLE_TOOL_CATALOG} (
                    qualified_ref, server_id, fingerprint, pinned_fp, status,
                    capabilities, is_open_world, untrusted_tool, risk_level,
                    schema_tokens, raw_json, first_seen_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(qualified_ref) DO UPDATE SET
                    server_id = excluded.server_id,
                    fingerprint = excluded.fingerprint,
                    pinned_fp = COALESCE(excluded.pinned_fp, tool_catalog.pinned_fp),
                    status = excluded.status,
                    capabilities = excluded.capabilities,
                    is_open_world = excluded.is_open_world,
                    untrusted_tool = excluded.untrusted_tool,
                    risk_level = excluded.risk_level,
                    schema_tokens = excluded.schema_tokens,
                    raw_json = excluded.raw_json,
                    updated_at = excluded.updated_at;
                """,
                (
                    entry.qualified_ref,
                    entry.server_id,
                    entry.fingerprint,
                    entry.pinned_fp,
                    entry.status,
                    capabilities_json,
                    1 if entry.is_open_world else 0,
                    1 if entry.untrusted_tool else 0,
                    entry.risk_level,
                    entry.schema_tokens,
                    entry.raw_json,
                    entry.first_seen_at or now,
                    now,
                ),
            )
            await conn.commit()

    async def get_tool(self, qualified_ref: str) -> CatalogEntryRecord | None:
        """Fetch tool catalog entry by qualified reference ('server.tool')."""
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"SELECT * FROM {TABLE_TOOL_CATALOG} WHERE qualified_ref = ?;",
                (qualified_ref,),
            )
            row = await cursor.fetchone()
            if row is None:
                return None

            data = dict(row)
            data["capabilities"] = json.loads(data["capabilities"])
            data["is_open_world"] = bool(data["is_open_world"])
            data["untrusted_tool"] = bool(data["untrusted_tool"])
            return CatalogEntryRecord.model_validate(data)

    async def list_tools(self, server_id: str | None = None) -> list[CatalogEntryRecord]:
        """List catalog entries, optionally filtered by upstream server ID."""
        if server_id in self._list_cache:
            return self._list_cache[server_id]

        async with self.db.connection() as conn:
            if server_id:
                cursor = await conn.execute(
                    f"SELECT * FROM {TABLE_TOOL_CATALOG} WHERE server_id = ? ORDER BY qualified_ref;",
                    (server_id,),
                )
            else:
                cursor = await conn.execute(
                    f"SELECT * FROM {TABLE_TOOL_CATALOG} ORDER BY qualified_ref;"
                )
            rows = await cursor.fetchall()
            results: list[CatalogEntryRecord] = []
            for row in rows:
                data = dict(row)
                data["capabilities"] = json.loads(data["capabilities"])
                data["is_open_world"] = bool(data["is_open_world"])
                data["untrusted_tool"] = bool(data["untrusted_tool"])
                results.append(CatalogEntryRecord.model_validate(data))
            self._list_cache[server_id] = results
            return results

    async def pin_fingerprint(self, qualified_ref: str, fingerprint: str) -> None:
        """Pin approved tool fingerprint to protect against upstream rug pulls."""
        self._list_cache.clear()
        now = datetime.now(UTC).isoformat()
        async with self.db.connection() as conn:
            await conn.execute(
                f"""
                UPDATE {TABLE_TOOL_CATALOG}
                SET pinned_fp = ?, status = 'active', updated_at = ?
                WHERE qualified_ref = ?;
                """,
                (fingerprint, now, qualified_ref),
            )
            await conn.commit()

    async def set_status(self, qualified_ref: str, status: str) -> None:
        """Update tool status ('active', 'quarantined', 'denied')."""
        self._list_cache.clear()
        now = datetime.now(UTC).isoformat()
        async with self.db.connection() as conn:
            await conn.execute(
                f"""
                UPDATE {TABLE_TOOL_CATALOG}
                SET status = ?, updated_at = ?
                WHERE qualified_ref = ?;
                """,
                (status, now, qualified_ref),
            )
            await conn.commit()

    async def get_schema_classifications(
        self, qualified_ref: str, shape_fingerprint: str
    ) -> str | None:
        """Retrieve cached field classifications JSON for an observed response shape."""
        async with self.db.connection() as conn:
            cursor = await conn.execute(
                f"""
                SELECT classifications FROM {TABLE_SCHEMA_CACHE}
                WHERE qualified_ref = ? AND shape_fingerprint = ?;
                """,
                (qualified_ref, shape_fingerprint),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return row["classifications"]

    async def set_schema_classifications(
        self,
        qualified_ref: str,
        shape_fingerprint: str,
        classifications_json: str,
        source: str = "deterministic",
    ) -> None:
        """Cache field classifications for an observed response shape."""
        now = datetime.now(UTC).isoformat()
        async with self.db.connection() as conn:
            await conn.execute(
                f"""
                INSERT INTO {TABLE_SCHEMA_CACHE} (
                    qualified_ref, shape_fingerprint, classifications, source, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(qualified_ref, shape_fingerprint) DO UPDATE SET
                    classifications = excluded.classifications,
                    source = excluded.source;
                """,
                (qualified_ref, shape_fingerprint, classifications_json, source, now),
            )
            await conn.commit()
