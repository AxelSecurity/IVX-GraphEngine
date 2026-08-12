"""Test eliminazione a cascata — ON DELETE CASCADE."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import aiosqlite

from graph_engine.models import (
    AnalysisTarget,
    Evidence,
    EvidenceScope,
    State,
    TargetStatus,
    Transition,
    TransitionKind,
    Verdict,
    Classification,
)
from graph_engine.storage.repository import save_target


class TestCascadeDelete:
    async def test_delete_target_cleans_up_orphans(self, tmp_path):
        """Cancellare un target elimina stati/transizioni/evidence/verdict."""
        db = str(tmp_path / "test.db")
        tid = uuid.uuid4()

        target = AnalysisTarget(
            id=tid,
            input_url="https://example.com",
            url_hash="hash",
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

        t = Transition(
            id=uuid.uuid4(),
            target_id=tid,
            from_state=s.id,
            to_state=s.id,
            kind=TransitionKind.http_3xx,
        )

        e = Evidence(
            id=uuid.uuid4(),
            target_id=tid,
            scope=EvidenceScope.target,
            scope_id=tid,
            layer="L1",
            key="test_key",
            value="test_value",
            produced_by="test",
        )

        v = Verdict(
            target_id=tid,
            classification=Classification.benign,
            confidence=1.0,
        )

        await save_target(target, [s], [t], [e], v, db_path=db)

        # Verifica che tutto sia stato salvato
        async with aiosqlite.connect(db) as conn:
            await conn.execute("PRAGMA foreign_keys = ON")

            async with conn.execute(
                "SELECT COUNT(*) FROM state WHERE target_id = ?", (str(tid),)
            ) as cur:
                assert (await cur.fetchone())[0] == 1

            async with conn.execute(
                "SELECT COUNT(*) FROM transition WHERE target_id = ?", (str(tid),)
            ) as cur:
                assert (await cur.fetchone())[0] == 1

            async with conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE target_id = ?", (str(tid),)
            ) as cur:
                assert (await cur.fetchone())[0] == 1

            async with conn.execute(
                "SELECT COUNT(*) FROM verdict WHERE target_id = ?", (str(tid),)
            ) as cur:
                assert (await cur.fetchone())[0] == 1

            # ── Elimina il target ──────────────────────────────────────
            await conn.execute(
                "DELETE FROM analysis_target WHERE id = ?", (str(tid),)
            )

            # ── Verifica cascade ────────────────────────────────────────
            async with conn.execute(
                "SELECT COUNT(*) FROM state WHERE target_id = ?", (str(tid),)
            ) as cur:
                assert (await cur.fetchone())[0] == 0

            async with conn.execute(
                "SELECT COUNT(*) FROM transition WHERE target_id = ?", (str(tid),)
            ) as cur:
                assert (await cur.fetchone())[0] == 0

            async with conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE target_id = ?", (str(tid),)
            ) as cur:
                assert (await cur.fetchone())[0] == 0

            async with conn.execute(
                "SELECT COUNT(*) FROM verdict WHERE target_id = ?", (str(tid),)
            ) as cur:
                assert (await cur.fetchone())[0] == 0
