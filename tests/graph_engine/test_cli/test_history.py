"""Test end-to-end per il flag --history.

Verifica che la logica di _print_history() produca lo STESSO url_hash
della pipeline ingest() usata durante l'analisi normale — non una
canonicalizzazione separata che divergerebbe silenziosamente.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

import pytest

from graph_engine.models import (
    AnalysisTarget,
    Classification,
    State,
    TargetStatus,
    Verdict,
)
from graph_engine.storage.repository import (
    get_history_for_url_hash,
    save_target,
)


# ---------------------------------------------------------------------------
# Helper — replica la logica di hash detection di _print_history
# ---------------------------------------------------------------------------


def _compute_url_hash(history_input: str) -> str:
    """Stessa logica di _print_history: SHA-256 → as-is, URL → ingest()."""
    from graph_engine.ingestion.pipeline import ingest

    if re.fullmatch(r"^[0-9a-f]{64}$", history_input, re.IGNORECASE):
        return history_input.lower()
    ingested = ingest(history_input)
    return ingested["url_hash"]


# ---------------------------------------------------------------------------
# Test: hash identico tra ingest() e --history
# ---------------------------------------------------------------------------


class TestHistoryHashIdentity:
    """L'hash calcolato dal path --history deve essere IDENTICO a quello
    salvato durante l'ingest originale."""

    async def test_same_url_produces_same_hash(self, tmp_path):
        """ingest() + save_target() → --history sullo stesso URL → stesso hash."""
        db = str(tmp_path / "test.db")
        raw_url = "https://evil.example.com/login?next=/dashboard"

        # ── Simula il path di analisi normale ───────────────────────────
        from graph_engine.ingestion.pipeline import ingest

        ingested = ingest(raw_url)
        url_hash_from_ingest = ingested["url_hash"]

        assert len(url_hash_from_ingest) == 64
        assert re.fullmatch(r"^[0-9a-f]{64}$", url_hash_from_ingest)

        tid = uuid.uuid4()
        target = AnalysisTarget(
            id=tid,
            input_url=ingested["input_url"],
            canonical_url=ingested["canonical_url"],
            url_hash=url_hash_from_ingest,
            final_url=ingested["canonical_url"],
            status=TargetStatus.done,
            created_at=datetime(2026, 8, 12, tzinfo=timezone.utc),
        )

        s = State(
            id=uuid.uuid4(),
            target_id=tid,
            url=ingested["canonical_url"],
            dom_hash="domhash",
            depth=0,
        )

        verdict = Verdict(
            target_id=tid,
            classification=Classification.suspicious,
            confidence=0.5,
        )

        await save_target(target, [s], [], [], verdict, db_path=db)

        # ── Simula il path --history (stessa logica di _print_history) ──
        url_hash_from_history = _compute_url_hash(raw_url)

        # ── GLI HASH DEVONO ESSERE IDENTICI ─────────────────────────────
        assert url_hash_from_history == url_hash_from_ingest, (
            f"Hash mismatch!\n"
            f"  ingest:  {url_hash_from_ingest}\n"
            f"  history: {url_hash_from_history}"
        )

        # ── E devono trovare il record salvato ──────────────────────────
        rows = await get_history_for_url_hash(url_hash_from_history, db_path=db)
        assert len(rows) == 1
        assert rows[0]["id"] == str(tid)
        assert rows[0]["classification"] == "suspicious"

    async def test_url_with_unwrap_produces_same_hash(self, tmp_path):
        """URL wrappato (es. SafeBrowsing) → refang+unwrap → same hash."""
        db = str(tmp_path / "test.db")

        # URL con notazione antispam
        raw_url = "https://example[.]com/path"

        from graph_engine.ingestion.pipeline import ingest

        ingested = ingest(raw_url)
        url_hash_from_ingest = ingested["url_hash"]

        tid = uuid.uuid4()
        target = AnalysisTarget(
            id=tid,
            input_url=ingested["input_url"],
            canonical_url=ingested["canonical_url"],
            url_hash=url_hash_from_ingest,
            final_url=ingested["canonical_url"],
            status=TargetStatus.done,
            created_at=datetime(2026, 8, 12, tzinfo=timezone.utc),
        )

        s = State(
            id=uuid.uuid4(),
            target_id=tid,
            url=ingested["canonical_url"],
            dom_hash="dh",
            depth=0,
        )

        await save_target(target, [s], [], [], None, db_path=db)

        url_hash_from_history = _compute_url_hash(raw_url)

        assert url_hash_from_history == url_hash_from_ingest

        rows = await get_history_for_url_hash(url_hash_from_history, db_path=db)
        assert len(rows) == 1

    async def test_sha256_hash_passed_directly(self, tmp_path):
        """Se passo un hash SHA-256 già pronto, _compute_url_hash lo usa
        direttamente senza chiamare ingest()."""
        db = str(tmp_path / "test.db")

        from graph_engine.ingestion.pipeline import ingest

        raw_url = "https://example.com/page"
        ingested = ingest(raw_url)
        original_hash = ingested["url_hash"]

        tid = uuid.uuid4()
        target = AnalysisTarget(
            id=tid,
            input_url=raw_url,
            canonical_url=ingested["canonical_url"],
            url_hash=original_hash,
            status=TargetStatus.done,
            created_at=datetime(2026, 8, 12, tzinfo=timezone.utc),
        )

        s = State(
            id=uuid.uuid4(),
            target_id=tid,
            url=ingested["canonical_url"],
            dom_hash="dh",
            depth=0,
        )

        await save_target(target, [s], [], [], None, db_path=db)

        # Passa l'hash direttamente (non un URL)
        hash_from_direct = _compute_url_hash(original_hash)
        assert hash_from_direct == original_hash.lower()

        # Uppercase deve essere normalizzato a lowercase
        hash_from_upper = _compute_url_hash(original_hash.upper())
        assert hash_from_upper == original_hash.lower()

        rows = await get_history_for_url_hash(hash_from_direct, db_path=db)
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Test: --history con DB vuoto non crasha
# ---------------------------------------------------------------------------


class TestHistoryEmptyDb:
    """Verifica che --history su un DB vuoto restituisca JSON vuoto
    senza sollevare eccezioni."""

    async def test_empty_db_no_crash(self, tmp_path):
        """DB vuoto → {"history": [], "url_hash": "..."}, nessuna eccezione."""
        db = str(tmp_path / "test.db")

        from graph_engine.ingestion.pipeline import ingest

        raw_url = "https://never-analyzed.example.com"
        ingested = ingest(raw_url)
        url_hash = ingested["url_hash"]

        rows = await get_history_for_url_hash(url_hash, db_path=db)
        assert rows == []

        # Verifichiamo che anche il formato JSON sia corretto
        payload = {"history": rows, "url_hash": url_hash}
        dumped = json.dumps(payload, indent=2, default=str)
        parsed = json.loads(dumped)
        assert parsed["history"] == []
        assert parsed["url_hash"] == url_hash

    async def test_nonexistent_db_file_no_crash(self, tmp_path):
        """File DB che non esiste ancora → get_history ritorna []."""
        from graph_engine.storage.repository import get_history_for_url_hash

        db = str(tmp_path / "nonexistent_dir" / "test.db")
        rows = await get_history_for_url_hash(
            "a" * 64,  # hash sintetico, 64 caratteri
            db_path=db,
        )
        assert rows == []
