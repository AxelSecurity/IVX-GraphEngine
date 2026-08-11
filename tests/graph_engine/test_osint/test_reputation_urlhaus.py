"""Tests for URLhaus reputation provider."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx

from graph_engine.osint.reputation.urlhaus import UrlhausProvider


class TestUrlhausProviderMocked:
    async def test_url_listed(self):
        """URL presente in URLhaus → listed=True."""
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

    async def test_url_not_listed(self):
        """URL non presente in URLhaus → listed=False, no errore."""
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

    async def test_timeout(self):
        """Timeout URLhaus → listed=False con dettagli errore."""
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.TimeoutException("timed out")
        )

        provider = UrlhausProvider()
        result = await provider.check("http://example.com", mock_client)

        assert result["listed"] is False
        assert "error" in result["details"]

    async def test_http_error(self):
        """Errore HTTP URLhaus → listed=False, mai eccezione."""
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.HTTPError("500 Server Error")
        )

        provider = UrlhausProvider()
        result = await provider.check("http://example.com", mock_client)

        assert result["listed"] is False
        assert "error" in result["details"]

    async def test_cache_hit_skips_http(self):
        """Risultato in cache → nessuna chiamata HTTP."""
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
