"""Test dell'autenticazione API key della route Trellix.

Decisione utente 2026-09-01: la route NON deve mai restare aperta.
Senza ``TRELLIX_API_KEY`` (né il Bearer legacy ``TRELLIX_API_TOKEN``)
risponde **503** (configurazione mancante); con una credenziale
configurata, una richiesta senza/ con credenziale errata riceve **401**.

Il conftest imposta ``trellix_api_key="test-key"`` e il client la invia
nell'header ``X-API-Key``: i test qui sotto la sovrascrivono via
monkeypatch per esercitare i casi limite.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from graph_engine.config import settings


class TestApiKey:
    async def test_no_key_configured_returns_503(self, app, monkeypatch):
        """Nessuna credenziale configurata → 503, mai route aperta.

        Anche con un header X-API-Key presente (il client di test lo
        invia sempre), senza chiave lato server la risposta è 503:
        l'operatore deve configurare TRELLIX_API_KEY."""
        monkeypatch.setattr(settings, "trellix_api_key", None)
        monkeypatch.setattr(settings, "trellix_api_token", None)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"X-API-Key": "test-key"},
        ) as c:
            res = await c.get("/trellix/analyze?url=https://example.com")

        assert res.status_code == 503
        assert "TRELLIX_API_KEY" in res.json()["detail"]

    async def test_missing_header_returns_401(self, app):
        """Chiave configurata ma header assente → 401."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            res = await c.get("/trellix/analyze?url=https://example.com")
        assert res.status_code == 401

    async def test_wrong_key_returns_401(self, app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"X-API-Key": "chiave-sbagliata"},
        ) as c:
            res = await c.get("/trellix/analyze?url=https://example.com")
        assert res.status_code == 401

    async def test_correct_key_passes(self, client, monkeypatch):
        """Chiave corretta (header del client di default) → l'analisi parte."""
        async def _fake_pipeline(*args, **kwargs):
            return "test-id"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        res = await client.get("/trellix/analyze?url=https://example.com")
        assert res.status_code == 200


class TestLegacyBearer:
    async def test_legacy_token_still_accepted(self, app, monkeypatch):
        """TRELLIX_API_TOKEN (Bearer) resta valido per retrocompatibilità."""
        monkeypatch.setattr(settings, "trellix_api_key", None)
        monkeypatch.setattr(settings, "trellix_api_token", "secret-token")

        async def _fake_pipeline(*args, **kwargs):
            return "test-id"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": "Bearer secret-token"},
        ) as c:
            res = await c.get("/trellix/analyze?url=https://example.com")
        assert res.status_code == 200

    async def test_wrong_bearer_returns_401(self, app, monkeypatch):
        monkeypatch.setattr(settings, "trellix_api_key", None)
        monkeypatch.setattr(settings, "trellix_api_token", "secret-token")

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": "Bearer wrong-token"},
        ) as c:
            res = await c.get("/trellix/analyze?url=https://example.com")
        assert res.status_code == 401

    async def test_malformed_auth_header_returns_401(self, app, monkeypatch):
        """Header Authorization non-Bearer (es. Basic) → 401."""
        monkeypatch.setattr(settings, "trellix_api_key", None)
        monkeypatch.setattr(settings, "trellix_api_token", "secret-token")

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": "Basic secret-token"},
        ) as c:
            res = await c.get("/trellix/analyze?url=https://example.com")
        assert res.status_code == 401
