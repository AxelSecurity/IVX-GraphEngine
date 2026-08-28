"""Test per list_targets()/count_targets() — listing paginato per la dashboard."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from graph_engine.models import (
    AnalysisTarget,
    Classification,
    TargetStatus,
    Verdict,
)
from graph_engine.storage.repository import count_targets, list_targets, save_target


async def _seed(db: str) -> None:
    """3 target indipendenti: benign/done, suspicious/done, error/nessun verdetto."""
    t1 = AnalysisTarget(
        id=uuid.uuid4(),
        input_url="https://benign.example.com",
        status=TargetStatus.done,
        created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    v1 = Verdict(target_id=t1.id, classification=Classification.benign, confidence=0.9)

    t2 = AnalysisTarget(
        id=uuid.uuid4(),
        input_url="https://phishy-login.example.net",
        status=TargetStatus.done,
        created_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
    )
    v2 = Verdict(target_id=t2.id, classification=Classification.suspicious, confidence=0.4)

    t3 = AnalysisTarget(
        id=uuid.uuid4(),
        input_url="https://broken.example.org",
        status=TargetStatus.error,
        created_at=datetime(2026, 8, 10, tzinfo=timezone.utc),
    )

    await save_target(t1, [], [], [], v1, db_path=db)
    await save_target(t2, [], [], [], v2, db_path=db)
    await save_target(t3, [], [], [], None, db_path=db)


class TestListTargets:
    async def test_lists_newest_first(self, tmp_path):
        db = str(tmp_path / "test.db")
        await _seed(db)

        rows = await list_targets(db_path=db)
        assert [r["status"] for r in rows] == ["error", "done", "done"]
        assert await count_targets(db_path=db) == 3

    async def test_filter_by_status(self, tmp_path):
        db = str(tmp_path / "test.db")
        await _seed(db)

        rows = await list_targets(status="error", db_path=db)
        assert len(rows) == 1
        assert rows[0]["input_url"] == "https://broken.example.org"
        assert await count_targets(status="error", db_path=db) == 1

    async def test_filter_by_classification(self, tmp_path):
        db = str(tmp_path / "test.db")
        await _seed(db)

        rows = await list_targets(classification="benign", db_path=db)
        assert len(rows) == 1
        assert rows[0]["classification"] == "benign"

    async def test_filter_by_search_substring(self, tmp_path):
        db = str(tmp_path / "test.db")
        await _seed(db)

        rows = await list_targets(search="phishy", db_path=db)
        assert len(rows) == 1
        assert "phishy-login" in rows[0]["input_url"]

        assert await count_targets(search="nonexistent-substring", db_path=db) == 0

    async def test_pagination(self, tmp_path):
        db = str(tmp_path / "test.db")
        await _seed(db)

        page1 = await list_targets(limit=2, offset=0, db_path=db)
        page2 = await list_targets(limit=2, offset=2, db_path=db)
        assert len(page1) == 2
        assert len(page2) == 1
        # Nessuna riga duplicata tra le pagine
        assert {r["input_url"] for r in page1}.isdisjoint({r["input_url"] for r in page2})

    async def test_empty_db(self, tmp_path):
        db = str(tmp_path / "empty.db")
        assert await list_targets(db_path=db) == []
        assert await count_targets(db_path=db) == 0
