"""Test idempotenza — chiamare save_target due volte con lo stesso target.id
non duplica le righe."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from graph_engine.models import (
    AnalysisTarget,
    State,
    TargetStatus,
)
from graph_engine.storage.repository import save_target


async def _count(conn, table: str) -> int:
    async with conn.execute(f"SELECT COUNT(*) FROM {table}") as cur:
        row = await cur.fetchone()
        return row[0]


class TestIdempotentSave:
    async def test_double_save_no_duplicates(self, tmp_path):
        """Due chiamate con lo stesso target.id → stesse righe."""
        import aiosqlite

        db = str(tmp_path / "test.db")
        tid = uuid.uuid4()
        target = AnalysisTarget(
            id=tid,
            input_url="https://example.com",
            url_hash="hash123",
            status=TargetStatus.done,
            created_at=datetime(2026, 8, 12, tzinfo=timezone.utc),
        )

        s = State(
            id=uuid.uuid4(),
            target_id=tid,
            url="https://example.com",
            dom_hash="domhash",
            depth=0,
        )

        # Primo salvataggio
        await save_target(target, [s], [], [], None, db_path=db)

        async with aiosqlite.connect(db) as conn:
            targets_1 = await _count(conn, "analysis_target")
            states_1 = await _count(conn, "state")

        assert targets_1 == 1
        assert states_1 == 1

        # Secondo salvataggio — stesso target.id
        await save_target(target, [s], [], [], None, db_path=db)

        async with aiosqlite.connect(db) as conn:
            targets_2 = await _count(conn, "analysis_target")
            states_2 = await _count(conn, "state")

        # Nessuna riga duplicata
        assert targets_2 == 1, f"analysis_target: {targets_1} → {targets_2}"
        assert states_2 == 1, f"state: {states_1} → {states_2}"
