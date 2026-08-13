"""Test per l'autenticazione Bearer dell'endpoint Trellix."""

from __future__ import annotations

from graph_engine.config import settings


class TestAuth:
    """Test del meccanismo di auth opzionale TRELLIX_API_TOKEN."""

    async def test_no_token_configured_allows_all(self, client, monkeypatch):
        """Senza TRELLIX_API_TOKEN → nessuna auth richiesta."""
        monkeypatch.setattr(settings, "trellix_api_token", None)

        # Mock della pipeline per evitare che l'analisi parta davvero
        async def _fake_pipeline(*args, **kwargs):
            return "test-id"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        res = await client.get(
            "/trellix/analyze?url=https://example.com",
            # Nessun header Authorization
        )
        # Non 401 — auth disabilitata
        assert res.status_code == 200

    async def test_token_required_when_configured(self, client, monkeypatch):
        """TRELLIX_API_TOKEN impostato, nessuna auth → 401."""
        monkeypatch.setattr(settings, "trellix_api_token", "secret-token")

        res = await client.get(
            "/trellix/analyze?url=https://example.com",
            # Nessun header Authorization
        )
        assert res.status_code == 401

    async def test_wrong_token_returns_401(self, client, monkeypatch):
        """Token sbagliato → 401."""
        monkeypatch.setattr(settings, "trellix_api_token", "secret-token")

        res = await client.get(
            "/trellix/analyze?url=https://example.com",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert res.status_code == 401

    async def test_correct_token_passes(self, client, monkeypatch):
        """Token corretto → 200, analisi procede."""
        monkeypatch.setattr(settings, "trellix_api_token", "secret-token")

        async def _fake_pipeline(*args, **kwargs):
            return "test-id"

        monkeypatch.setattr(
            "graph_engine.api.routes_trellix.run_full_analysis",
            _fake_pipeline,
        )

        res = await client.get(
            "/trellix/analyze?url=https://example.com",
            headers={"Authorization": "Bearer secret-token"},
        )
        assert res.status_code == 200

    async def test_malformed_auth_header_returns_401(self, client, monkeypatch):
        """Header Authorization malformato (non inizia con 'Bearer ') → 401."""
        monkeypatch.setattr(settings, "trellix_api_token", "secret-token")

        res = await client.get(
            "/trellix/analyze?url=https://example.com",
            headers={"Authorization": "Basic secret-token"},
        )
        assert res.status_code == 401
