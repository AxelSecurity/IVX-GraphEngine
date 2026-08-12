"""Test per l'endpoint Trellix /trellix/analyze."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

from graph_engine.api.allowlist import add_entry
from graph_engine.models import (
    AnalysisTarget,
    Classification,
    TargetStatus,
    Verdict,
)
from graph_engine.storage.repository import save_target


class TestRoutesTrellix:
    """Test end-to-end per GET /trellix/analyze."""

    # ------------------------------------------------------------------
    # Allowlist hit → risposta immediata
    # ------------------------------------------------------------------

    async def test_whitelist_bypasses_analysis(self, app, client, tmp_path, monkeypatch):
        """Whitelist hit → safe immediato, run_full_analysis MAI chiamata."""
        db = str(tmp_path / "test.db")
        await add_entry("example.com", "whitelist", db_path=db)

        # Mock: se run_full_analysis viene chiamato, il test fallisce
        called = False

        async def _fake_pipeline(*args, **kwargs):
            nonlocal called
            called = True
            return "should-not-be-called"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        res = await client.get("/trellix/analyze?url=https://example.com/login")
        assert res.status_code == 200
        body = res.json()
        assert body["verdict"] == "safe"
        assert body["confidence"] == 1.0
        assert "Whitelist" in body["signature"]
        assert not called, "run_full_analysis was called despite whitelist hit"

    async def test_blacklist_bypasses_analysis(self, app, client, tmp_path, monkeypatch):
        """Blacklist hit → malicious immediato, run_full_analysis MAI chiamata."""
        db = str(tmp_path / "test.db")
        await add_entry("evil.com", "blacklist", db_path=db)

        called = False

        async def _fake_pipeline(*args, **kwargs):
            nonlocal called
            called = True
            return "should-not-be-called"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        res = await client.get("/trellix/analyze?url=https://evil.com/phish")
        assert res.status_code == 200
        body = res.json()
        assert body["verdict"] == "malicious"
        assert body["confidence"] == 1.0
        assert not called, "run_full_analysis was called despite blacklist hit"

    # ------------------------------------------------------------------
    # Cache hit (analisi recente) → risposta immediata
    # ------------------------------------------------------------------

    async def test_cache_hit_bypasses_analysis(self, app, client, tmp_path, monkeypatch):
        """Analisi recente (< 24h) presente → risposta da cache, no nuova analisi."""
        db = str(tmp_path / "test.db")

        from graph_engine.ingestion.pipeline import ingest

        ingested = ingest("https://fresh.example.com/page")
        url_hash = ingested["url_hash"]

        # Seed: target done con verdict, creato 1 ora fa
        target = AnalysisTarget(
            input_url="https://fresh.example.com/page",
            canonical_url="https://fresh.example.com/page",
            url_hash=url_hash,
            final_url="https://fresh.example.com/page",
            status=TargetStatus.done,
            created_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        verdict = Verdict(
            target_id=target.id,
            classification=Classification.phishing,
            confidence=0.95,
            produced_by="foundry",
            brand="PayPal",
            rationale="Pagina di login falsa con logo PayPal",
        )
        await save_target(target, [], [], [], verdict, db_path=db)

        called = False

        async def _fake_pipeline(*args, **kwargs):
            nonlocal called
            called = True
            return "should-not-be-called"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        res = await client.get(
            "/trellix/analyze?url=https://fresh.example.com/page"
        )
        assert res.status_code == 200
        body = res.json()
        # Cache hit → verdetto dal seed
        assert body["verdict"] == "malicious"
        assert body["confidence"] >= 0.8
        assert not called, "run_full_analysis was called despite cache hit"

    async def test_stale_cache_triggers_new_analysis(self, app, client, tmp_path, monkeypatch):
        """Cache > 24h → nuova analisi."""
        db = str(tmp_path / "test.db")

        from graph_engine.ingestion.pipeline import ingest

        ingested = ingest("https://old.example.com/page")
        url_hash = ingested["url_hash"]

        target = AnalysisTarget(
            input_url="https://old.example.com/page",
            canonical_url="https://old.example.com/page",
            url_hash=url_hash,
            status=TargetStatus.done,
            created_at=datetime.now(timezone.utc) - timedelta(hours=25),
        )
        verdict = Verdict(
            target_id=target.id,
            classification=Classification.benign,
            confidence=0.90,
            produced_by="foundry",
        )
        await save_target(target, [], [], [], verdict, db_path=db)

        called = False

        async def _fake_pipeline(*args, **kwargs):
            nonlocal called
            called = True
            # Simula nuova analisi: aggiorna il target a done con verdict
            t = kwargs.get("target") or args[2] if len(args) > 2 else None
            if t:
                t.status = TargetStatus.done
                await save_target(
                    t, [], [], [],
                    Verdict(
                        target_id=t.id,
                        classification=Classification.suspicious,
                        confidence=0.4,
                        produced_by="foundry",
                    ),
                    db_path=db,
                )
            return str(t.id) if t else "no-target"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        res = await client.get(
            "/trellix/analyze?url=https://old.example.com/page"
        )
        assert res.status_code == 200
        assert called, "run_full_analysis was NOT called despite stale cache"

    # ------------------------------------------------------------------
    # Fire-and-continue: timeout test
    # ------------------------------------------------------------------

    async def test_timeout_fire_and_continue(self, app, tmp_path, monkeypatch):
        """Timeout scade → risposta timed_out, MA il task continua in background."""
        from graph_engine.api.routes_trellix import build_trellix_router

        db = str(tmp_path / "test.db")
        wait_s = 0.5  # timeout ridotto per il test

        done_event = asyncio.Event()
        saved_event = asyncio.Event()

        async def _slow_pipeline(*args, **kwargs):
            """Pipeline lenta: dorme più del timeout ma POI completa."""
            await asyncio.sleep(1.5)  # più del timeout di 0.5s
            # Simula il salvataggio finale
            t = kwargs.get("target")
            if t:
                t.status = TargetStatus.done
                await save_target(
                    t, [], [], [],
                    Verdict(
                        target_id=t.id,
                        classification=Classification.benign,
                        confidence=0.9,
                        produced_by="foundry",
                    ),
                    db_path=db,
                )
                saved_event.set()
            done_event.set()
            return str(t.id) if t else "done"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _slow_pipeline,
        )

        # App minima con il solo router Trellix a timeout ridotto
        # (create_app usa il timeout di produzione, non iniettabile)
        trellix_router = build_trellix_router(db_path=db, wait_timeout_s=wait_s)

        from fastapi import FastAPI

        test_app = FastAPI()
        test_app.include_router(trellix_router)

        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as c:
            t0 = time.monotonic()
            res = await c.get(
                "/trellix/analyze?url=https://slow.example.com"
            )
            elapsed = time.monotonic() - t0

        # 1. La risposta deve arrivare entro ~2s (molto meno dei 3s del task)
        assert res.status_code == 200
        assert elapsed < 3.0, f"Response took {elapsed}s, expected < 3s"

        body = res.json()
        # 2. Deve essere timed_out → safe/allow/Analysis-Incomplete
        assert body["verdict"] == "safe"
        assert "Analysis-Incomplete" in body["signature"]

        # 3. Il task DEVE continuare in background (NON cancellato)
        #    Aspettiamo che completi
        await asyncio.wait_for(done_event.wait(), timeout=10)
        await asyncio.wait_for(saved_event.wait(), timeout=5)

        # 4. Dopo il completamento, il risultato DEVE essere su SQLite
        from graph_engine.storage.repository import get_latest_for_url_hash
        from graph_engine.ingestion.pipeline import ingest

        url_hash = ingest("https://slow.example.com")["url_hash"]
        data = await get_latest_for_url_hash(url_hash, db_path=db)
        assert data is not None
        assert data["target"].status == TargetStatus.done
        assert data["verdict"] is not None
        assert data["verdict"].classification == Classification.benign

    # ------------------------------------------------------------------
    # URL doppio-encodato
    # ------------------------------------------------------------------

    async def test_double_encoded_url(self, app, client, tmp_path, monkeypatch):
        """URL doppio-encodato (pattern Trellix) → decodificato correttamente."""
        db = str(tmp_path / "test.db")

        received_url = None

        async def _fake_pipeline(raw_url, **kwargs):
            nonlocal received_url
            received_url = raw_url
            # Salva qualcosa per non rompere la route
            t = kwargs.get("target")
            if t:
                t.status = TargetStatus.done
                await save_target(t, [], [], [], None, db_path=db)
            return str(t.id) if t else "done"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        # URL con encoding %253A%252F%252F → dopo un unquote diventa https://...
        res = await client.get(
            "/trellix/analyze?url=https%253A%252F%252Fexample.com%252Flogin"
        )
        assert res.status_code == 200
        assert received_url == "https://example.com/login", (
            f"Expected 'https://example.com/login', got '{received_url}'"
        )
