"""Test dell'autenticazione API key dell'API esterna.

La route ``/api/v1/analyze`` NON deve mai restare aperta: senza
``API_KEY`` risponde **503** (configurazione mancante); con una chiave
configurata, una richiesta senza chiave o con chiave errata riceve
**401**.  ``API_KEY`` accetta più chiavi separate da virgola.

La stessa chiave vale, in alternativa al cookie di sessione, sulle
route del ciclo di vita delle analisi (``POST /analyses``, ``GET
/analyses[/...]``) — mai su cancellazioni, liste forzate o utenti.

Il conftest imposta ``api_key="test-key"`` e il client la invia
nell'header ``X-API-Key``: i test qui sotto la sovrascrivono via
monkeypatch per esercitare i casi limite.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from graph_engine.config import settings

_ANALYZE = "/api/v1/analyze?url=https://example.com"


async def _fake_pipeline(*args, **kwargs):
    return "test-id"


def _client(app, **headers) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=headers,
    )


class TestApiKey:
    async def test_no_key_configured_returns_503(self, app, monkeypatch):
        """Nessuna chiave configurata → 503, mai route aperta.

        Anche con un header X-API-Key presente, senza chiave lato server
        la risposta è 503: l'operatore deve configurare API_KEY."""
        monkeypatch.setattr(settings, "api_key", None)

        async with _client(app, **{"X-API-Key": "test-key"}) as c:
            res = await c.get(_ANALYZE)

        assert res.status_code == 503
        assert "API_KEY" in res.json()["detail"]

    async def test_missing_header_returns_401(self, app):
        """Chiave configurata ma header assente → 401."""
        async with _client(app) as c:
            res = await c.get(_ANALYZE)
        assert res.status_code == 401

    async def test_wrong_key_returns_401(self, app):
        async with _client(app, **{"X-API-Key": "chiave-sbagliata"}) as c:
            res = await c.get(_ANALYZE)
        assert res.status_code == 401

    async def test_bearer_not_accepted(self, app):
        """Il vecchio Bearer legacy non è più un metodo di auth."""
        async with _client(app, Authorization="Bearer test-key") as c:
            res = await c.get(_ANALYZE)
        assert res.status_code == 401

    async def test_correct_key_passes(self, client, monkeypatch):
        """Chiave corretta (header del client di default) → l'analisi parte."""
        monkeypatch.setattr(
            "graph_engine.api.jobs.run_full_analysis", _fake_pipeline,
        )
        res = await client.get(_ANALYZE)
        assert res.status_code == 200

    async def test_multiple_keys_each_valid(self, app, monkeypatch):
        """Con più chiavi configurate ognuna autentica il proprio client,
        una chiave fuori lista resta 401."""
        monkeypatch.setattr(settings, "api_key", "client-a, client-b")
        monkeypatch.setattr(
            "graph_engine.api.jobs.run_full_analysis", _fake_pipeline,
        )
        for key, expected in (
            ("client-a", 200), ("client-b", 200), ("client-c", 401),
        ):
            async with _client(app, **{"X-API-Key": key}) as c:
                res = await c.get(_ANALYZE)
            assert res.status_code == expected, key


class TestApiKeyOnAnalysesRoutes:
    """La API key vale come alternativa al cookie SOLO sul ciclo di vita
    delle analisi (sottomissione + polling)."""

    async def test_submit_and_poll_with_api_key(self, client, monkeypatch):
        monkeypatch.setattr(
            "graph_engine.api.jobs.run_full_analysis", _fake_pipeline,
        )
        res = await client.post("/analyses", json={"url": "https://example.com"})
        assert res.status_code == 202
        target_id = res.json()["id"]

        for path in (
            f"/analyses/{target_id}",
            f"/analyses/{target_id}/graph",
            f"/analyses/{target_id}/verdict",
            "/analyses",
        ):
            res = await client.get(path)
            assert res.status_code == 200, path

    async def test_wrong_key_on_analyses_returns_401(self, app):
        async with _client(app, **{"X-API-Key": "chiave-sbagliata"}) as c:
            res = await c.get("/analyses")
        assert res.status_code == 401

    async def test_api_key_not_valid_for_admin_routes(self, client):
        """Cancellazioni, liste forzate e utenti restano riservati alla
        sessione della dashboard."""
        res = await client.post("/analyses/delete", json={"ids": ["x"]})
        assert res.status_code == 401
        res = await client.get("/lists")
        assert res.status_code == 401
        res = await client.get("/auth/users")
        assert res.status_code == 401
