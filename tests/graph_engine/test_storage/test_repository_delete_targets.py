"""Test per delete_targets — eliminazione (multipla) con cascata SQLite.

La cascata su state/transition/evidence/verdict è verificata con query
dirette sulle tabelle, non solo sul conteggio del target.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import aiosqlite

from graph_engine.models import (
    AnalysisTarget,
    Classification,
    Evidence,
    EvidenceScope,
    State,
    TargetStatus,
    Transition,
    TransitionKind,
    Verdict,
)
from graph_engine.storage.repository import delete_targets, save_target


async def _save_full_target(tid, db: str) -> None:
    """Salva un target con 1 stato, 1 transizione, 1 evidenza, 1 verdict."""
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
        confidence=0.9,
    )
    await save_target(target, [s], [t], [e], v, db_path=db)


async def _count(db: str, query: str, params=()) -> int:
    """Esegue una query COUNT con PRAGMA foreign_keys attivo."""
    async with aiosqlite.connect(db) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        async with conn.execute(query, params) as cur:
            row = await cur.fetchone()
    return row[0] if row else 0


class TestDeleteTargets:
    async def test_delete_single_target_cascades(self, tmp_path):
        """Un solo ID → riga sparita e cascata su tutte le tabelle figlie."""
        db = str(tmp_path / "test.db")
        tid = uuid.uuid4()
        await _save_full_target(tid, db)

        result = await delete_targets([str(tid)], db_path=db)

        assert result == {"deleted_count": 1, "not_found": []}
        # Query dirette per tabella: non deve restare NULLA del target
        for table in ("analysis_target", "state", "transition", "evidence", "verdict"):
            n = await _count(db, f"SELECT COUNT(*) FROM {table}")
            assert n == 0, f"righe residue in {table}"

    async def test_delete_multiple_targets_leaves_others_untouched(self, tmp_path):
        """Più target in una chiamata spariscono; il target NON in lista sopravvive."""
        db = str(tmp_path / "test.db")
        t1 = uuid.uuid4()
        t2 = uuid.uuid4()
        keep = uuid.uuid4()
        for t in (t1, t2, keep):
            await _save_full_target(t, db)

        result = await delete_targets([str(t1), str(t2)], db_path=db)

        assert result == {"deleted_count": 2, "not_found": []}
        # Il target sopravvissuto è intatto, con tutti i suoi figli
        assert await _count(db, "SELECT COUNT(*) FROM analysis_target") == 1
        for table in ("state", "transition", "evidence", "verdict"):
            n = await _count(
                db, f"SELECT COUNT(*) FROM {table} WHERE target_id = ?", (str(keep),)
            )
            assert n == 1, f"{table} del target sopravvissuto è stata toccata"

    async def test_missing_id_not_found_others_deleted(self, tmp_path):
        """ID inesistente → non solleva, compare in not_found; i validi vengono eliminati."""
        db = str(tmp_path / "test.db")
        t1 = uuid.uuid4()
        await _save_full_target(t1, db)
        ghost = uuid.uuid4()  # mai salvato

        result = await delete_targets([str(ghost), str(t1)], db_path=db)

        assert result["deleted_count"] == 1
        assert result["not_found"] == [str(ghost)]
        assert await _count(db, "SELECT COUNT(*) FROM analysis_target") == 0

    async def test_all_missing_ids(self, tmp_path):
        """Tutti ID inesistenti → deleted_count 0, tutti in not_found, nessun errore."""
        db = str(tmp_path / "test.db")
        g1 = uuid.uuid4()
        g2 = uuid.uuid4()

        result = await delete_targets([str(g1), str(g2)], db_path=db)

        assert result["deleted_count"] == 0
        assert sorted(result["not_found"]) == sorted([str(g1), str(g2)])

    async def test_empty_list_is_explicit_noop(self, tmp_path):
        """Lista vuota → {'deleted_count': 0, 'not_found': []}, il DB non viene toccato."""
        db = str(tmp_path / "test.db")
        tid = uuid.uuid4()
        await _save_full_target(tid, db)

        result = await delete_targets([], db_path=db)

        assert result == {"deleted_count": 0, "not_found": []}
        assert await _count(db, "SELECT COUNT(*) FROM analysis_target") == 1

    async def test_duplicate_ids_deleted_once(self, tmp_path):
        """ID duplicati nella richiesta → eliminati una sola volta, conteggio onesto."""
        db = str(tmp_path / "test.db")
        tid = uuid.uuid4()
        await _save_full_target(tid, db)

        result = await delete_targets([str(tid), str(tid)], db_path=db)

        assert result == {"deleted_count": 1, "not_found": []}
        assert await _count(db, "SELECT COUNT(*) FROM analysis_target") == 0
