"""Test per l'endpoint Trellix /trellix/analyze."""

from __future__ import annotations

import asyncio
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
    # Analisi sincrona: la route attende il completamento reale
    # ------------------------------------------------------------------

    async def test_waits_for_completion_no_deadline(self, app, tmp_path, monkeypatch):
        """La route attende il completamento REALE della pipeline anche
        quando è lenta: risponde col verdetto finale persistito — mai
        una risposta "incompleta" autoimposta.  La finestra di tempo è
        gestita a monte (Front Door / Trellix), non dal modulo."""
        from graph_engine.api.routes_trellix import build_trellix_router

        db = str(tmp_path / "test.db")

        async def _slow_pipeline(*args, **kwargs):
            """Pipeline lenta che però completa e persiste il verdetto."""
            await asyncio.sleep(0.5)
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
            return str(t.id) if t else "done"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _slow_pipeline,
        )

        trellix_router = build_trellix_router(db_path=db)

        from fastapi import FastAPI

        test_app = FastAPI()
        test_app.include_router(trellix_router)

        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as c:
            res = await c.get("/trellix/analyze?url=https://slow.example.com")

        # La risposta porta il verdetto finale della pipeline lenta —
        # nessuna deadline, nessuna Analysis-Incomplete autoimposta
        assert res.status_code == 200
        body = res.json()
        assert body["verdict"] == "safe"
        assert "Analysis-Incomplete" not in body["signature"]
        assert body["confidence"] == 0.9

        # Il risultato è persistito su SQLite
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

    # ------------------------------------------------------------------
    # URL in chiaro nella query string (il formato reale di Trellix)
    # ------------------------------------------------------------------

    async def test_plain_url_passed_unchanged(self, app, client, tmp_path, monkeypatch):
        """URL in chiaro senza caratteri speciali → arriva identico alla
        pipeline (formato Trellix: ?url=http://example.org)."""
        db = str(tmp_path / "test.db")

        received_url = None

        async def _fake_pipeline(raw_url, **kwargs):
            nonlocal received_url
            received_url = raw_url
            t = kwargs.get("target")
            if t:
                t.status = TargetStatus.done
                await save_target(t, [], [], [], None, db_path=db)
            return str(t.id) if t else "done"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        res = await client.get("/trellix/analyze?url=http://example.org")
        assert res.status_code == 200
        assert received_url == "http://example.org", (
            f"Expected 'http://example.org', got '{received_url}'"
        )

    async def test_plain_url_with_embedded_query_not_truncated(
        self, app, client, tmp_path, monkeypatch,
    ):
        """Regressione: URL in chiaro con & e = propri (es. link di
        sicurezza email) NON deve essere troncato al primo &.  Il parsing
        standard di FastAPI lo troncherebbe — la route usa la query
        string grezza."""
        db = str(tmp_path / "test.db")

        received_url = None

        async def _fake_pipeline(raw_url, **kwargs):
            nonlocal received_url
            received_url = raw_url
            t = kwargs.get("target")
            if t:
                t.status = TargetStatus.done
                await save_target(t, [], [], [], None, db_path=db)
            return str(t.id) if t else "done"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        target = "https://evil.example/redirect?a=1&b=2"
        res = await client.get(
            "/trellix/analyze?url=" + target,
        )
        assert res.status_code == 200
        assert received_url == target, (
            f"URL troncato: expected '{target}', got '{received_url}'"
        )

    async def test_missing_url_param_returns_422(self, app, client):
        """GET senza il parametro url → 422."""
        res = await client.get("/trellix/analyze")
        assert res.status_code == 422

    async def test_pipeline_runs_with_full_defaults(
        self, app, client, tmp_path, monkeypatch,
    ):
        """La route Trellix non comprime più la pipeline: nessun budget
        fast, nessun timeout di pagina/settle/captcha ridotto — l'analisi
        gira con i default PIENI del runner.  Regressione sulla vecchia
        finestra dei 60s (il fast path è stato rimosso: la deadline è
        gestita a monte da Front Door / Trellix)."""
        db = str(tmp_path / "test.db")

        captured = {}

        async def _fake_pipeline(*args, **kwargs):
            captured.update(kwargs)
            t = kwargs.get("target")
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
            return str(t.id) if t else "done"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        res = await client.get(
            "/trellix/analyze?url=https://full.example.com/login"
        )
        assert res.status_code == 200
        # La risposta porta il verdetto persistito dal mock
        body = res.json()
        assert body["verdict"] == "safe"
        assert body["confidence"] == 0.4

        # Nessuna compressione fast: i parametri della vecchia finestra
        # NON vengono passati — il runner usa i propri default pieni
        # (artefatti inclusi: Vision + bundle continuano a vedere la
        # pagina)
        for key in (
            "budget",
            "top_n_actions",
            "captcha_wait_s",
            "l2_timeout_s",
            "l3_timeout_s",
            "settle_max_wait_s",
            "page_timeout_ms",
            "capture_artifacts",
        ):
            assert captured.get(key) is None, (
                f"Parametro fast '{key}' ancora passato alla pipeline: "
                "la route deve usare i default pieni del runner"
            )
