"""Connessioni del repository: WAL, schema una volta, upsert del target."""

from __future__ import annotations

import sqlite3

from graph_engine.models import (
    AnalysisTarget,
    Classification,
    State,
    TargetStatus,
    Verdict,
)
from graph_engine.storage import repository
from graph_engine.storage.repository import (
    count_running,
    get_target_by_id,
    save_target,
)


async def test_database_uses_wal(tmp_path):
    db = str(tmp_path / "wal.db")
    await save_target(AnalysisTarget(input_url="https://a.example"), [], [], [], None, db_path=db)
    mode = sqlite3.connect(db).execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"


async def test_schema_executed_once_per_file(tmp_path, monkeypatch):
    db = str(tmp_path / "once.db")
    calls = []
    real_connect = repository.aiosqlite.connect

    def _tracking_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        real_script = conn.executescript

        async def _script(sql):
            calls.append(sql)
            return await real_script(sql)

        conn.executescript = _script
        return conn

    monkeypatch.setattr(repository.aiosqlite, "connect", _tracking_connect)
    target = AnalysisTarget(input_url="https://a.example")
    for _ in range(3):
        await save_target(target, [], [], [], None, db_path=db)
    await get_target_by_id(str(target.id), db_path=db)
    assert len(calls) == 1


async def test_status_resave_keeps_graph_consistent(tmp_path):
    """Risalvare il target (es. queued → running → done) aggiorna la riga
    senza duplicati e il grafo salvato è quello dell'ultimo save."""
    db = str(tmp_path / "upsert.db")
    target = AnalysisTarget(input_url="https://a.example")
    await save_target(target, [], [], [], None, db_path=db)

    target.status = TargetStatus.running
    await save_target(target, [], [], [], None, db_path=db)
    assert await count_running(db_path=db) == 1

    state = State(target_id=target.id, url="https://a.example", dom_hash="h")
    verdict = Verdict(
        target_id=target.id, classification=Classification.benign,
        confidence=0.9, produced_by="foundry",
    )
    target.status = TargetStatus.done
    await save_target(target, [state], [], [], verdict, db_path=db)

    data = await get_target_by_id(str(target.id), db_path=db)
    assert data["target"].status == TargetStatus.done
    assert len(data["states"]) == 1
    assert data["verdict"].classification == Classification.benign
    assert await count_running(db_path=db) == 0

    rows = sqlite3.connect(db).execute(
        "SELECT COUNT(*) FROM analysis_target WHERE id = ?", (str(target.id),)
    ).fetchone()[0]
    assert rows == 1
