"""Tests for URLhaus reputation provider.

URLhaus richiede ora una Auth-Key gratuita (header ``Auth-Key``):
senza ``URLHAUS_API_KEY`` il provider è disabilitato (skip pulito,
zero chiamate HTTP), come MISP/OpenCTI.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx

from graph_engine.config import settings
from graph_engine.osint.reputation.urlhaus import UrlhausProvider

_TEST_API_KEY = "test-urlhaus-api-key"


def _configure_urlhaus(monkeypatch, key: str = _TEST_API_KEY):
    """Configura la Auth-Key URLhaus sul singleton per il singolo test."""
    monkeypatch.setattr(settings, "urlhaus_api_key", key)


class TestUrlhausProviderMocked:
    async def test_url_listed(self, monkeypatch):
        """URL presente in URLhaus → listed=True."""
        _configure_urlhaus(monkeypatch)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "url": "http://evil.example/phish",
            "threat": "malware_download",
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        provider = UrlhausProvider()
        result = await provider.check("http://evil.example/phish", mock_client)

        assert result["provider"] == "urlhaus"
        assert result["listed"] is True
        assert "threat" in result["details"]

    async def test_url_not_listed(self, monkeypatch):
        """URL non presente in URLhaus → listed=False, no errore."""
        _configure_urlhaus(monkeypatch)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "no_results",
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        provider = UrlhausProvider()
        result = await provider.check("http://benign.example", mock_client)

        assert result["provider"] == "urlhaus"
        assert result["listed"] is False
        assert result["details"]["query_status"] == "no_results"

    async def test_timeout(self, monkeypatch):
        """Timeout URLhaus → listed=False con dettagli errore."""
        _configure_urlhaus(monkeypatch)

        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.TimeoutException("timed out")
        )

        provider = UrlhausProvider()
        result = await provider.check("http://example.com", mock_client)

        assert result["listed"] is False
        assert "error" in result["details"]

    async def test_http_error(self, monkeypatch):
        """Errore HTTP URLhaus → listed=False, mai eccezione."""
        _configure_urlhaus(monkeypatch)

        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.HTTPError("500 Server Error")
        )

        provider = UrlhausProvider()
        result = await provider.check("http://example.com", mock_client)

        assert result["listed"] is False
        assert "error" in result["details"]

    async def test_cache_hit_skips_http(self, monkeypatch):
        """Risultato in cache → nessuna chiamata HTTP."""
        _configure_urlhaus(monkeypatch)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "no_results",
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        provider = UrlhausProvider()
        result1 = await provider.check("http://example.com", mock_client)
        mock_client.post.reset_mock()
        result2 = await provider.check("http://example.com", mock_client)

        assert result1 == result2
        mock_client.post.assert_not_called()

    async def test_auth_key_header_sent(self, monkeypatch):
        """Con chiave configurata, la richiesta porta l'header Auth-Key."""
        _configure_urlhaus(monkeypatch)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "no_results",
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        provider = UrlhausProvider()
        await provider.check("http://benign.example", mock_client)

        # Il confine httpx deve ricevere l'header Auth-Key
        _, kwargs = mock_client.post.call_args
        assert kwargs["headers"] == {"Auth-Key": _TEST_API_KEY}

    async def test_unauthorized_401_returns_clean_error(self, monkeypatch):
        """Chiave configurata ma 401 (invalida/scaduta) → errore pulito,
        mai eccezione che risale."""
        _configure_urlhaus(monkeypatch)

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "401 Unauthorized", request=MagicMock(), response=mock_response
            )
        )

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        provider = UrlhausProvider()
        result = await provider.check("http://example.com", mock_client)

        assert result["provider"] == "urlhaus"
        assert result["listed"] is False
        assert "auth failed" in result["details"]["error"]
        assert "401" in result["details"]["error"]


class TestUrlhausNotConfigured:
    """Senza URLHAUS_API_KEY → skipped, zero chiamate HTTP."""

    async def test_not_configured_skips(self, monkeypatch):
        """Senza chiave → skipped immediato, nessuna chiamata HTTP."""
        monkeypatch.setattr(settings, "urlhaus_api_key", None)

        mock_client = MagicMock()
        mock_client.post = AsyncMock()

        provider = UrlhausProvider()
        result = await provider.check("http://evil.example", mock_client)

        assert result["provider"] == "urlhaus"
        assert result["listed"] is False
        assert result["details"]["skipped"] == "not configured"
        mock_client.post.assert_not_called()

    async def test_not_configured_no_http_even_on_error(self, monkeypatch):
        """Anche con client non funzionante, se disabilitato nessuna
        chiamata."""
        monkeypatch.setattr(settings, "urlhaus_api_key", None)

        mock_client = MagicMock()

        provider = UrlhausProvider()
        result = await provider.check(
            "http://evil.example",
            mock_client,
        )

        assert result["listed"] is False
        mock_client.post.assert_not_called()

    async def test_no_network_when_disabled(self, monkeypatch):
        """Blocco rete esplicito: se il provider tentasse comunque una
        richiesta httpx, il mock solleverebbe e il test fallirebbe
        (stesso pattern di test_reputation_misp_opencti_disabled.py)."""
        monkeypatch.setattr(settings, "urlhaus_api_key", None)

        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            side_effect=RuntimeError(
                "RETE BLOCCATA: URLhaus ha tentato una richiesta HTTP!"
            )
        )

        provider = UrlhausProvider()
        result = await provider.check("http://evil.example", mock_client)

        assert result["listed"] is False
        assert result["details"]["skipped"] == "not configured"
        # Verifica ATTIVA: il client httpx non deve mai essere invocato
        mock_client.post.assert_not_called()
