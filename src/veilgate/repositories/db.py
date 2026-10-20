"""Asynchronous SQLite connection and migration manager for Veilgate."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.repositories.db")

MIGRATIONS_DIR: Path = Path(__file__).parent / "migrations"


class DatabaseManager:
    """Manages asynchronous SQLite connections, PRAGMAs, and schema migrations."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path: Path = Path(db_path)
        self._initialized: bool = False

    async def initialize(self) -> None:
        """Ensure parent directory exists and execute migration scripts."""
        if self._initialized:
            return

        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        async with self.connection() as db:
            await db.execute("PRAGMA journal_mode = WAL;")
            await db.execute("PRAGMA synchronous = NORMAL;")
            await db.execute("PRAGMA foreign_keys = ON;")
            await db.execute("PRAGMA busy_timeout = 5000;")

            # Run migration 0001_init.sql
            init_migration = MIGRATIONS_DIR / "0001_init.sql"
            if init_migration.exists():
                sql_script = init_migration.read_text(encoding="utf-8")
                await db.executescript(sql_script)
                await db.commit()

        self._initialized = True
        logger.info(f"SUCCESS | SQLite database initialized at {self.db_path}")

    @asynccontextmanager
    async def connection(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        """Provide an active aiosqlite connection with foreign keys enabled."""
        conn = await aiosqlite.connect(self.db_path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
        finally:
            await conn.close()
