"""Test per la creazione dello schema e i vincoli FK."""

from __future__ import annotations

import uuid

import aiosqlite
import pytest

from graph_engine.storage.schema import DDL


class TestSchemaCreation:
    async def test_tables_created(self, tmp_path):
        """Tutte le tabelle vengono create senza errori."""
        db = tmp_path / "test.db"
        async with aiosqlite.connect(str(db)) as conn:
            await conn.execute("PRAGMA foreign_keys = ON")
            await conn.executescript(DDL)

            # Enumera tutte le tabelle
            async with conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ) as cur:
                tables = [row[0] async for row in cur]

        assert "analysis_target" in tables
        assert "state" in tables
        assert "transition" in tables
        assert "evidence" in tables
        assert "verdict" in tables

    async def test_foreign_key_enforcement(self, tmp_path):
        """Inserimento con target_id inesistente → violazione FK."""
        db = tmp_path / "test.db"
        async with aiosqlite.connect(str(db)) as conn:
            await conn.execute("PRAGMA foreign_keys = ON")
            await conn.executescript(DDL)

            with pytest.raises(aiosqlite.IntegrityError):
                await conn.execute(
                    """INSERT INTO state (id, target_id, url, dom_hash, depth)
                       VALUES (?, ?, ?, ?, ?)""",
                    (str(uuid.uuid4()), str(uuid.uuid4()), "http://x.com", "abc123", 0),
                )
