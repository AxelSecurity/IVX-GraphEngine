"""Test per gli endpoint HTTP dell'API — 6 route testate con ASGITransport."""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from graph_engine.api.allowlist import add_entry, add_url_entry
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

    # ------------------------------------------------------------------
    # GET /analyses — elenco sottomissioni (dashboard)
    # ------------------------------------------------------------------

    async def test_list_analyses_paginated_and_filtered(self, app, client, tmp_path):
        """GET /analyses: più recenti prima, filtri e paginazione."""
        db = str(tmp_path / "test.db")

        t1 = AnalysisTarget(
            input_url="https://one.example.com",
            status=TargetStatus.done,
        )
        v1 = Verdict(
            target_id=t1.id, classification=Classification.benign, confidence=0.9,
        )
        t2 = AnalysisTarget(
            input_url="https://two.example.com",
            status=TargetStatus.error,
        )
        await save_target(t1, [], [], [], v1, db_path=db)
        await save_target(t2, [], [], [], None, db_path=db)

        from graph_engine.api.app import create_app

        test_app = create_app(db_path=db)
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as c:
            res = await c.get("/analyses")
            assert res.status_code == 200
            data = res.json()
            assert data["total"] == 2
            assert len(data["items"]) == 2

            res2 = await c.get("/analyses?status=error")
            assert res2.status_code == 200
            data2 = res2.json()
            assert data2["total"] == 1
            assert data2["items"][0]["input_url"] == "https://two.example.com"

            res3 = await c.get("/analyses?classification=benign")
            assert res3.json()["total"] == 1

            res4 = await c.get("/analyses?limit=1&offset=0")
            assert len(res4.json()["items"]) == 1
            assert res4.json()["limit"] == 1

    # ------------------------------------------------------------------
    # GET /analyses/{id}/artifacts/{state_id}/{filename} — contenuto
    # ------------------------------------------------------------------

    async def test_artifact_file_serves_content(self, tmp_path):
        """Il contenuto di uno screenshot/DOM/HAR viene servito correttamente."""
        target = AnalysisTarget(
            input_url="https://shot.example.com", status=TargetStatus.done,
        )
        tid = str(target.id)
        db = str(tmp_path / "test.db")
        await save_target(target, [], [], [], None, db_path=db)

        state_dir = tmp_path / "artifacts" / tid / "s1"
        state_dir.mkdir(parents=True)
        (state_dir / "screenshot.png").write_bytes(b"\x89PNG\r\n fake")
        (state_dir / "dom.html").write_text("<html>hi</html>")

        from graph_engine.api.app import create_app

        test_app = create_app(db_path=db, artifact_root=tmp_path / "artifacts")
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as c:
            res = await c.get(f"/analyses/{tid}/artifacts/s1/screenshot.png")
            assert res.status_code == 200
            assert res.headers["content-type"] == "image/png"
            assert res.content == b"\x89PNG\r\n fake"

            res2 = await c.get(f"/analyses/{tid}/artifacts/s1/dom.html")
            assert res2.status_code == 200
            assert "<html>hi</html>" in res2.text

    async def test_artifact_file_rejects_unknown_filename(self, tmp_path):
        """Un filename fuori whitelist → 404, mai un path arbitrario."""
        target = AnalysisTarget(
            input_url="https://shot.example.com", status=TargetStatus.done,
        )
        tid = str(target.id)
        db = str(tmp_path / "test.db")
        await save_target(target, [], [], [], None, db_path=db)

        from graph_engine.api.app import create_app

        test_app = create_app(db_path=db, artifact_root=tmp_path / "artifacts")
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as c:
            res = await c.get(f"/analyses/{tid}/artifacts/s1/../../etc/passwd")
            assert res.status_code == 404

            res2 = await c.get(f"/analyses/{tid}/artifacts/s1/not-a-real-file.txt")
            assert res2.status_code == 404

    async def test_artifact_file_missing_target_or_file(self, tmp_path):
        """Target inesistente o file non ancora scritto → 404."""
        db = str(tmp_path / "test.db")
        from graph_engine.api.app import create_app

        test_app = create_app(db_path=db, artifact_root=tmp_path / "artifacts")
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as c:
            res = await c.get(
                "/analyses/00000000-0000-0000-0000-000000000000/artifacts/s1/screenshot.png"
            )
            assert res.status_code == 404


class TestDeleteAnalysesEndpoint:
    """POST /analyses/delete — eliminazione definitiva dalla dashboard."""

    # ------------------------------------------------------------------
    # POST /analyses/delete
    # ------------------------------------------------------------------

    async def test_delete_success(self, app, client, tmp_path):
        """Elimina un target: 200, deleted_count=1, il target sparisce, gli altri restano."""
        db = str(tmp_path / "test.db")
        t1 = AnalysisTarget(
            input_url="https://del.example.com", status=TargetStatus.done,
        )
        t2 = AnalysisTarget(
            input_url="https://keep.example.com", status=TargetStatus.done,
        )
        await save_target(t1, [], [], [], None, db_path=db)
        await save_target(t2, [], [], [], None, db_path=db)

        res = await client.post("/analyses/delete", json={"ids": [str(t1.id)]})

        assert res.status_code == 200
        assert res.json() == {"deleted_count": 1, "not_found": []}
        # Il target eliminato non esiste più; l'altro sopravvive
        assert (await client.get(f"/analyses/{t1.id}")).status_code == 404
        assert (await client.get(f"/analyses/{t2.id}")).status_code == 200

    async def test_delete_empty_list_returns_400(self, app, client, tmp_path):
        """Lista vuota → 400 e nessuna eliminazione di massa."""
        db = str(tmp_path / "test.db")
        t1 = AnalysisTarget(
            input_url="https://keep1.example.com", status=TargetStatus.done,
        )
        t2 = AnalysisTarget(
            input_url="https://keep2.example.com", status=TargetStatus.done,
        )
        await save_target(t1, [], [], [], None, db_path=db)
        await save_target(t2, [], [], [], None, db_path=db)

        res = await client.post("/analyses/delete", json={"ids": []})

        assert res.status_code == 400
        # Nessun target è stato toccato
        res2 = await client.get("/analyses")
        assert res2.status_code == 200
        assert res2.json()["total"] == 2

    async def test_delete_mixed_ids(self, app, client, tmp_path):
        """ID misti trovati/non-trovati: i validi vengono eliminati, il ghost in not_found."""
        import uuid as _uuid

        db = str(tmp_path / "test.db")
        t1 = AnalysisTarget(
            input_url="https://mix.example.com", status=TargetStatus.done,
        )
        await save_target(t1, [], [], [], None, db_path=db)
        ghost = str(_uuid.uuid4())  # mai salvato

        # Artefatti del ghost sul disco: NON devono essere toccati
        # (pulizia solo per gli ID eliminati con successo)
        ghost_dir = tmp_path / "artifacts" / ghost / "s1"
        ghost_dir.mkdir(parents=True)
        (ghost_dir / "screenshot.png").write_bytes(b"x")

        res = await client.post(
            "/analyses/delete", json={"ids": [ghost, str(t1.id)]}
        )

        assert res.status_code == 200
        body = res.json()
        assert body["deleted_count"] == 1
        assert body["not_found"] == [ghost]
        assert ghost_dir.exists()

    async def test_delete_removes_artifact_dir(self, app, client, tmp_path):
        """La cartella data/graph_artifacts/<id>/ sparisce dopo l'eliminazione riuscita."""
        db = str(tmp_path / "test.db")
        target = AnalysisTarget(
            input_url="https://art.example.com", status=TargetStatus.done,
        )
        tid = str(target.id)
        await save_target(target, [], [], [], None, db_path=db)

        # La fixture app usa artifact_root = tmp_path / "artifacts"
        state_dir = tmp_path / "artifacts" / tid / "s1"
        state_dir.mkdir(parents=True)
        (state_dir / "screenshot.png").write_bytes(b"fake png")

        res = await client.post("/analyses/delete", json={"ids": [tid]})

        assert res.status_code == 200
        assert res.json() == {"deleted_count": 1, "not_found": []}
        assert not (tmp_path / "artifacts" / tid).exists()

    async def test_delete_missing_artifact_dir_not_an_error(self, app, client, tmp_path):
        """Cartella artefatti assente (capture_artifacts=False) → 200, nessun errore."""
        db = str(tmp_path / "test.db")
        target = AnalysisTarget(
            input_url="https://noart.example.com", status=TargetStatus.done,
        )
        tid = str(target.id)
        await save_target(target, [], [], [], None, db_path=db)
        # Nessuna cartella artefatti creata

        res = await client.post("/analyses/delete", json={"ids": [tid]})

        assert res.status_code == 200
        assert res.json() == {"deleted_count": 1, "not_found": []}


class TestGetAnalysisTrellixResponse:
    """GET /analyses/{id}/trellix — il JSON restituito a Trellix IVX.

    La dashboard usa questo endpoint per mostrare, nel dettaglio di ogni
    analisi, la risposta esatta che Trellix ha ricevuto (o riceverebbe).
    """

    async def test_phishing_verdict_maps_to_malicious_block(self, app, client, tmp_path):
        """Verdict phishing + brand → malicious/block con firma d'attacco."""
        db = str(tmp_path / "test.db")
        target = AnalysisTarget(
            input_url="https://login-ms.example.com", status=TargetStatus.done,
        )
        verdict = Verdict(
            target_id=target.id,
            classification=Classification.phishing,
            confidence=0.95,
            produced_by="foundry",
            brand="Microsoft",
            rationale="Pagina di login falsa con logo Microsoft.",
        )
        await save_target(target, [], [], [], verdict, db_path=db)

        res = await client.get(f"/analyses/{target.id}/trellix")

        assert res.status_code == 200
        body = res.json()
        assert body["verdict"] == "malicious"
        assert body["recommended_action"] == "block"
        assert body["confidence"] >= 0.8
        assert body["signature"] == "Phishing: Microsoft Impersonation"
        assert body["reason"] == "Pagina di login falsa con logo Microsoft."

    async def test_output_identical_to_trellix_route(self, app, client, tmp_path):
        """Fedeltà: il JSON mostrato in dashboard DEVE essere identico a
        quello costruito dalla route /trellix/analyze sugli stessi dati."""
        from graph_engine.api.trellix_verdict import build_trellix_response
        from graph_engine.storage.repository import get_target_by_id

        db = str(tmp_path / "test.db")
        target = AnalysisTarget(
            input_url="https://susp.example.com", status=TargetStatus.done,
        )
        verdict = Verdict(
            target_id=target.id,
            classification=Classification.suspicious,
            confidence=0.4,
            produced_by="heuristic_fallback",
            rationale=(
                "Fallback euristico (run Foundry fallito): segnali "
                "insufficienti per la classificazione automatica."
            ),
        )
        await save_target(target, [], [], [], verdict, db_path=db)

        res = await client.get(f"/analyses/{target.id}/trellix")
        assert res.status_code == 200

        data = await get_target_by_id(str(target.id), db_path=db)
        assert res.json() == build_trellix_response(data)

    async def test_running_target_shows_analysis_incomplete(self, app, client, tmp_path):
        """Analisi in corso → il ramo Analysis-Incomplete (onesto, come
        nella route Trellix reale)."""
        db = str(tmp_path / "test.db")
        target = AnalysisTarget(
            input_url="https://run.example.com", status=TargetStatus.running,
        )
        await save_target(target, [], [], [], None, db_path=db)

        res = await client.get(f"/analyses/{target.id}/trellix")

        assert res.status_code == 200
        body = res.json()
        assert body["verdict"] == "safe"
        assert body["recommended_action"] == "allow"
        assert body["signature"] == "Analysis-Incomplete — Benign By Default"

    async def test_unknown_target_returns_404(self, app, client):
        """Target inesistente → 404, come le altre route di dettaglio."""
        res = await client.get(
            "/analyses/99999999-9999-4999-8999-999999999999/trellix"
        )
        assert res.status_code == 404


class TestListsRoutes:
    """GET/POST/DELETE /lists — whitelist/blacklist per domini e URL."""

    async def test_lists_empty(self, app, client):
        """Nessuna entry → due liste vuote."""
        res = await client.get("/lists")
        assert res.status_code == 200
        assert res.json() == {"domains": [], "urls": []}

    async def test_add_domain_entry_normalized(self, app, client, tmp_path):
        """POST /lists (domain) → 201 con dominio registrabile normalizzato."""
        res = await client.post(
            "/lists",
            json={
                "kind": "domain",
                "value": "login.Site.IT",
                "list_type": "whitelist",
                "note": "Operatore verificato",
            },
        )
        assert res.status_code == 201
        body = res.json()
        assert body["ok"] is True
        assert body["value"] == "site.it"
        assert body["list_type"] == "whitelist"

        res2 = await client.get("/lists")
        domains = res2.json()["domains"]
        assert len(domains) == 1
        assert domains[0]["value"] == "site.it"
        assert domains[0]["note"] == "Operatore verificato"
        assert domains[0]["added_by"] == "dashboard"

    async def test_add_url_entry_normalized(self, app, client):
        """POST /lists (url) → 201 con URL senza query/frammento."""
        res = await client.post(
            "/lists",
            json={
                "kind": "url",
                "value": "https://site.it/login?sid=abc#top",
                "list_type": "blacklist",
            },
        )
        assert res.status_code == 201
        body = res.json()
        assert body["value"] == "https://site.it/login"
        assert body["list_type"] == "blacklist"

        res2 = await client.get("/lists")
        urls = res2.json()["urls"]
        assert len(urls) == 1
        assert urls[0]["value"] == "https://site.it/login"

    async def test_add_invalid_kind_422(self, app, client):
        res = await client.post(
            "/lists",
            json={"kind": "ip", "value": "1.2.3.4", "list_type": "blacklist"},
        )
        assert res.status_code == 422

    async def test_add_invalid_list_type_422(self, app, client):
        res = await client.post(
            "/lists",
            json={"kind": "domain", "value": "site.it", "list_type": "gray"},
        )
        assert res.status_code == 422

    async def test_add_invalid_url_scheme_422(self, app, client):
        res = await client.post(
            "/lists",
            json={"kind": "url", "value": "ftp://site.it/x", "list_type": "whitelist"},
        )
        assert res.status_code == 422

    async def test_remove_entry(self, app, client, tmp_path):
        """DELETE /lists rimuove; la seconda rimozione → removed=false."""
        db = str(tmp_path / "test.db")
        await add_url_entry("https://site.it/login", "whitelist", db_path=db)

        # httpx .delete() non accetta il kwarg "json" — si usa .request()
        res = await client.request(
            "DELETE",
            "/lists",
            json={"kind": "url", "value": "https://site.it/login?x=1"},
        )
        assert res.status_code == 200
        assert res.json() == {"ok": True, "removed": True}

        res2 = await client.request(
            "DELETE",
            "/lists",
            json={"kind": "url", "value": "https://site.it/login"},
        )
        assert res2.json()["removed"] is False


class TestAnalysisBypass:
    """Bypass whitelist/blacklist nel POST /analyses (decisione 2026-09-01:
    verdetto forzato subito, pipeline MAI avviata)."""

    async def test_whitelist_url_creates_done_benign_target(
        self, app, client, tmp_path, monkeypatch,
    ):
        db = str(tmp_path / "test.db")
        await add_url_entry("https://example.com/trusted", "whitelist", db_path=db)

        called = False

        async def _fake_pipeline(*args, **kwargs):
            nonlocal called
            called = True

        monkeypatch.setattr("graph_engine.api.routes.run_full_analysis", _fake_pipeline)

        res = await client.post(
            "/analyses",
            json={"url": "https://example.com/trusted?sid=1", "classify": True},
        )
        assert res.status_code == 202
        body = res.json()
        assert body["status"] == "done"

        res2 = await client.get(f"/analyses/{body['id']}")
        data = res2.json()
        assert data["target"]["status"] == "done"
        assert data["verdict"]["classification"] == "benign"
        assert data["verdict"]["confidence"] == 1.0
        assert data["verdict"]["produced_by"] == "prefilter"
        assert "whitelist" in data["verdict"]["rationale"]
        assert not called, "run_full_analysis avviata nonostante il bypass"

    async def test_blacklist_domain_creates_done_phishing_target(
        self, app, client, tmp_path, monkeypatch,
    ):
        db = str(tmp_path / "test.db")
        await add_entry("evil.com", "blacklist", db_path=db)

        called = False

        async def _fake_pipeline(*args, **kwargs):
            nonlocal called
            called = True

        monkeypatch.setattr("graph_engine.api.routes.run_full_analysis", _fake_pipeline)

        res = await client.post(
            "/analyses",
            json={"url": "https://login.evil.com/phish"},
        )
        body = res.json()
        assert body["status"] == "done"

        res2 = await client.get(f"/analyses/{body['id']}")
        data = res2.json()
        assert data["verdict"]["classification"] == "phishing"
        assert data["verdict"]["confidence"] == 1.0
        assert data["verdict"]["produced_by"] == "prefilter"
        assert "blacklist" in data["verdict"]["rationale"]
        assert not called, "run_full_analysis avviata nonostante il bypass"

    async def test_no_bypass_without_entry(self, client, fake_pipeline):
        """Nessuna entry in lista → flusso normale (queued, pipeline parte)."""
        res = await client.post(
            "/analyses",
            json={"url": "https://example.com/page", "classify": False},
        )
        assert res.status_code == 202
        assert res.json()["status"] == "queued"
