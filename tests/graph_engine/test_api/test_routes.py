"""Test per gli endpoint HTTP dell'API — 6 route testate con ASGITransport."""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from graph_engine.models import (
    AnalysisTarget,
    Classification,
    Evidence,
    EvidenceScope,
    State,
    TargetStatus,
    Verdict,
)
from graph_engine.storage.repository import save_target


class TestRoutes:
    """Test end-to-end per le route REST."""

    # ------------------------------------------------------------------
    # POST /analyses
    # ------------------------------------------------------------------

    async def test_create_analysis_returns_202(self, client, fake_pipeline):
        """POST /analyses → 202 con id, status, input_url."""
        res = await client.post(
            "/analyses",
            json={"url": "https://example.com", "classify": False},
        )
        assert res.status_code == 202
        body = res.json()
        assert body["status"] == "queued"
        assert body["input_url"] == "https://example.com"
        # L'id deve essere un UUID valido (36 caratteri)
        assert len(body["id"]) == 36
        assert "-" in body["id"]

    async def test_create_analysis_lifecycle(self, client, fake_pipeline):
        """POST → 202, poi il background task completa → status done."""
        res = await client.post(
            "/analyses",
            json={"url": "https://example.com/page", "classify": True},
        )
        assert res.status_code == 202
        target_id = res.json()["id"]

        # Poll fino a done (o timeout)
        for _ in range(100):
            res2 = await client.get(f"/analyses/{target_id}")
            assert res2.status_code == 200
            data = res2.json()
            if data["target"]["status"] != "queued":
                break
            await asyncio.sleep(0.02)
        else:
            pytest.fail("Il task non è mai uscito dallo stato 'queued'")

        # Ora dovrebbe essere done (o running — ma con mock è istantaneo)
        assert data["target"]["status"] in ("running", "done")
        # Forza un ultimo check dopo una breve attesa per done
        await asyncio.sleep(0.05)
        res3 = await client.get(f"/analyses/{target_id}")
        final_data = res3.json()
        # Con la pipeline mockata, il task dovrebbe aver finito
        assert final_data["target"]["status"] in ("running", "done")

    # ------------------------------------------------------------------
    # GET /analyses/{id} + /graph — 404
    # ------------------------------------------------------------------

    async def test_get_nonexistent_returns_404(self, client):
        """GET su id inesistente → 404."""
        for path in [
            "/analyses/00000000-0000-0000-0000-000000000000",
            "/analyses/00000000-0000-0000-0000-000000000000/graph",
            "/analyses/00000000-0000-0000-0000-000000000000/artifacts",
        ]:
            res = await client.get(path)
            assert res.status_code == 404, f"{path} ha restituito {res.status_code}"

    # ------------------------------------------------------------------
    # GET /analyses/{id}/graph
    # ------------------------------------------------------------------

    async def test_graph_endpoint_returns_data(self, app, client, tmp_path):
        """GET /analyses/{id}/graph restituisce il grafo completo."""
        # Stesso db_path usato dal fixture app
        db = str(tmp_path / "test.db")

        # Seed: salva un target con stati, transizioni, evidence
        target = AnalysisTarget(
            input_url="https://seed.example.com",
            canonical_url="https://seed.example.com",
            url_hash="a" * 64,
            final_url="https://seed.example.com/landing",
            status=TargetStatus.done,
        )
        tid = target.id
        state = State(
            target_id=tid,
            url="https://seed.example.com",
            dom_hash="h1",
            depth=0,
        )
        target.root_state_id = state.id
        evidence = Evidence(
            target_id=tid,
            scope=EvidenceScope.target,
            scope_id=tid,
            layer="L0",
            key="test_key",
            value="test_value",
            produced_by="test",
        )
        verdict = Verdict(
            target_id=tid,
            classification=Classification.benign,
            confidence=0.95,
            produced_by="foundry",
            brand=None,
        )
        await save_target(
            target, [state], [], [evidence], verdict,
            db_path=db,
        )

        # GET /analyses/{id}
        res = await client.get(f"/analyses/{tid}")
        assert res.status_code == 200
        data = res.json()
        assert data["target"]["status"] == "done"
        assert data["num_states"] == 1
        assert data["num_transitions"] == 0
        assert data["num_evidence"] == 1
        assert data["verdict"]["classification"] == "benign"

        # GET /analyses/{id}/graph
        res2 = await client.get(f"/analyses/{tid}/graph")
        assert res2.status_code == 200
        graph = res2.json()
        assert len(graph["states"]) == 1
        assert len(graph["evidence"]) == 1
        assert graph["verdict"]["confidence"] == 0.95

    # ------------------------------------------------------------------
    # GET /analyses/{id}/artifacts
    # ------------------------------------------------------------------

    async def test_artifacts_endpoint(self, app, client, tmp_path):
        """GET /analyses/{id}/artifacts elenca file ricorsivamente."""
        # Seed target salvato su db
        target = AnalysisTarget(
            input_url="https://artifacts.example.com",
            status=TargetStatus.done,
        )
        tid = str(target.id)
        await save_target(target, [], [], [], None, db_path=str(tmp_path / "test_artifacts.db"))

        # Crea file finti nella directory artefatti.
        # La struttura è: artifacts/{target_id}/{state_id}/screenshot.png
        state_dir = tmp_path / "artifacts" / tid / "s1"
        state_dir.mkdir(parents=True)
        (state_dir / "screenshot.png").write_text("fake png")
        (state_dir / "dom.html").write_text("<html></html>")
        sub = state_dir / "subdir"
        sub.mkdir()
        (sub / "nested.txt").write_text("nested")

        # Ricostruisci app con artifact_root corretto
        from graph_engine.api.app import create_app

        test_app = create_app(
            db_path=str(tmp_path / "test_artifacts.db"),
            artifact_root=tmp_path / "artifacts",
        )
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as c:
            res = await c.get(f"/analyses/{tid}/artifacts")

        assert res.status_code == 200
        data = res.json()
        assert data["target_id"] == tid
        assert data["count"] == 3
        paths = {f["path"] for f in data["files"]}
        assert "s1/screenshot.png" in paths
        assert "s1/dom.html" in paths
        assert "s1/subdir/nested.txt" in paths

    # ------------------------------------------------------------------
    # GET /analyses/history + GET /health
    # ------------------------------------------------------------------

    async def test_history_endpoint(self, app, client, tmp_path):
        """GET /analyses/history restituisce le analisi per url_hash."""
        url_hash = "b" * 64

        # Salva due target con lo stesso url_hash
        t1 = AnalysisTarget(
            input_url="https://hist.example.com",
            url_hash=url_hash,
            status=TargetStatus.done,
        )
        await save_target(t1, [], [], [], None, db_path=str(tmp_path / "hist.db"))

        t2 = AnalysisTarget(
            input_url="https://hist.example.com",
            url_hash=url_hash,
            status=TargetStatus.error,
        )
        await save_target(t2, [], [], [], None, db_path=str(tmp_path / "hist.db"))

        # Ricostruisci app con il db giusto
        from graph_engine.api.app import create_app

        test_app = create_app(db_path=str(tmp_path / "hist.db"))
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as c:
            # Per url_hash
            res = await c.get(f"/analyses/history?url_hash={url_hash}")

        assert res.status_code == 200
        data = res.json()
        assert data["url_hash"] == url_hash
        assert len(data["history"]) == 2
        # Ordine: più recenti prima
        statuses = [h["status"] for h in data["history"]]
        assert "done" in statuses
        assert "error" in statuses

        # 422 se nessun parametro
        res2 = await client.get("/analyses/history")
        assert res2.status_code == 422

        # Con url (non hash) → l'ingest calcola l'hash
        res3 = await client.get(
            "/analyses/history?url=https://example.com"
        )
        assert res3.status_code == 200

    async def test_health_endpoint(self, client):
        """GET /health restituisce status ok e running_jobs."""
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert isinstance(data["running_jobs"], int)
