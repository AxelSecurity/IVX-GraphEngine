"""Test storico — più analisi dello stesso URL con id diversi."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from graph_engine.models import (
    AnalysisTarget,
    Classification,
    State,
    TargetStatus,
    Verdict,
)
from graph_engine.storage.repository import (
    get_history_for_url_hash,
    get_latest_for_url_hash,
    save_target,
)


class TestHistory:
    async def test_multiple_analyses_same_url_hash(self, tmp_path):
        """3 analisi dello stesso url_hash → ordine cronologico inverso."""
        db = str(tmp_path / "test.db")
        url_hash = "same-url-hash-abc"

        tid1 = uuid.uuid4()
        tid2 = uuid.uuid4()
        tid3 = uuid.uuid4()

        # Analisi 1 — più vecchia
        t1 = AnalysisTarget(
            id=tid1,
            input_url="https://example.com",
            url_hash=url_hash,
            status=TargetStatus.done,
            created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
        v1 = Verdict(
            target_id=tid1,
            classification=Classification.benign,
            confidence=0.95,
        )

        # Analisi 2 — intermedia
        t2 = AnalysisTarget(
            id=tid2,
            input_url="https://example.com",
            url_hash=url_hash,
            status=TargetStatus.done,
            created_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
        )
        v2 = Verdict(
            target_id=tid2,
            classification=Classification.suspicious,
            confidence=0.40,
        )

        # Analisi 3 — più recente
        t3 = AnalysisTarget(
            id=tid3,
            input_url="https://example.com",
            url_hash=url_hash,
            status=TargetStatus.done,
            created_at=datetime(2026, 8, 10, tzinfo=timezone.utc),
        )
        v3 = Verdict(
            target_id=tid3,
            classification=Classification.phishing,
            confidence=0.88,
        )

        s1 = State(
            id=uuid.uuid4(),
            target_id=tid1,
            url="https://example.com",
            dom_hash="dh",
            depth=0,
        )
        s2 = State(
            id=uuid.uuid4(),
            target_id=tid2,
            url="https://example.com",
            dom_hash="dh",
            depth=0,
        )
        s3 = State(
            id=uuid.uuid4(),
            target_id=tid3,
            url="https://example.com",
            dom_hash="dh",
            depth=0,
        )

        # Salva le 3 analisi indipendenti
        await save_target(t1, [s1], [], [], v1, db_path=db)
        await save_target(t2, [s2], [], [], v2, db_path=db)
        await save_target(t3, [s3], [], [], v3, db_path=db)

        # ── get_history_for_url_hash ────────────────────────────────────
        history = await get_history_for_url_hash(url_hash, db_path=db)
        assert len(history) == 3

        # Ordine: più recente primo
        assert history[0]["id"] == str(tid3)
        assert history[0]["classification"] == "phishing"

        assert history[1]["id"] == str(tid2)
        assert history[1]["classification"] == "suspicious"

        assert history[2]["id"] == str(tid1)
        assert history[2]["classification"] == "benign"

        # ── get_latest_for_url_hash ─────────────────────────────────────
        latest = await get_latest_for_url_hash(url_hash, db_path=db)
        assert latest is not None
        assert latest["target"].id == tid3
        assert latest["verdict"].classification == Classification.phishing

    async def test_no_history_for_unknown_hash(self, tmp_path):
        """Hash mai visto → lista vuota / None."""
        db = str(tmp_path / "test.db")

        history = await get_history_for_url_hash("never-seen-hash", db_path=db)
        assert history == []

        latest = await get_latest_for_url_hash("never-seen-hash", db_path=db)
        assert latest is None
