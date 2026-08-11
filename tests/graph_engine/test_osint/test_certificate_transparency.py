"""Tests for the crt.sh Certificate Transparency query."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from graph_engine.osint.certificate_transparency import (
    _extract_certificate_info,
    query_crtsh,
)


# ---------------------------------------------------------------------------
# Fixture: risposta crt.sh mockata con 3 certificati, 2 domini ciascuno
# ---------------------------------------------------------------------------

def _make_crtsh_response() -> list[dict]:
    """Costruisce una risposta crt.sh realistica con 3 certificati."""
    return [
        {
            "id": 1,
            "name_value": "evil.example.com\nsibling1.example.com",
            "not_before": "2024-01-15T00:00:00",
            "entry_timestamp": "2024-01-15T00:00:00",
        },
        {
            "id": 2,
            "name_value": "evil.example.com\nsibling2.example.com\nsibling1.example.com",
            "not_before": "2024-06-01T00:00:00",
            "entry_timestamp": "2024-06-01T00:00:00",
        },
        {
            "id": 3,
            "name_value": "evil.example.com\nsibling3.example.com",
            "not_before": "2023-01-01T00:00:00",
            "entry_timestamp": "2023-01-01T00:00:00",
        },
    ]


# ---------------------------------------------------------------------------
# Test _extract_certificate_info (logica pura, senza HTTP)
# ---------------------------------------------------------------------------


class TestExtractCertificateInfo:
    def test_san_list_deduplicated_and_query_excluded(self):
        """SAN list aggregata, deduplicata, dominio interrogato escluso."""
        certs = _make_crtsh_response()
        result = _extract_certificate_info(certs, "evil.example.com")

        assert "evil.example.com" not in result["sibling_domains"]
        assert set(result["sibling_domains"]) == {
            "sibling1.example.com",
            "sibling2.example.com",
            "sibling3.example.com",
        }
        assert result["truncated"] is False
        assert result["total_siblings"] == 3
        assert result["total_certs"] == 3

    def test_cert_ages_correct(self):
        """newest/oldest in giorni calcolati correttamente."""
        certs = _make_crtsh_response()
        result = _extract_certificate_info(certs, "evil.example.com")

        assert result["newest_cert_days"] is not None
        assert result["oldest_cert_days"] is not None
        # Il più nuovo dovrebbe essere più giovane del più vecchio
        assert result["newest_cert_days"] < result["oldest_cert_days"]

    def test_empty_response(self):
        """Lista certificati vuota → risultato vuoto, nessun errore."""
        result = _extract_certificate_info([], "example.com")
        assert result["sibling_domains"] == []
        assert result["total_siblings"] == 0
        assert result["total_certs"] == 0
        assert result["newest_cert_days"] is None

    def test_truncation_with_flag(self):
        """Quando i domini fratelli superano MAX_SIBLING_DOMAINS."""
        # Crea tanti domini quanti ne servono per triggerare il troncamento
        certs = [{
            "id": 1,
            "name_value": "\n".join(f"sibling{j}.example.com" for j in range(60)),
            "not_before": "2024-01-01T00:00:00",
        }]

        from graph_engine.osint.certificate_transparency import MAX_SIBLING_DOMAINS
        result = _extract_certificate_info(certs, "evil.example.com")

        assert result["truncated"] is True
        assert len(result["sibling_domains"]) == MAX_SIBLING_DOMAINS
        assert result["total_siblings"] > MAX_SIBLING_DOMAINS

    def test_query_domain_not_in_sans(self):
        """Se il dominio interrogato non è nella SAN, non succede nulla."""
        certs = [{
            "id": 1,
            "name_value": "other1.example.com\nother2.example.com",
            "not_before": "2024-01-01T00:00:00",
        }]
        result = _extract_certificate_info(certs, "evil.example.com")
        assert set(result["sibling_domains"]) == {
            "other1.example.com", "other2.example.com"
        }


# ---------------------------------------------------------------------------
# Test query_crtsh con mock httpx (nostro codice esegue per davvero)
# ---------------------------------------------------------------------------


class TestQueryCrtshMocked:
    async def test_successful_query(self):
        """Query crt.sh → SAN list e metadati estratti correttamente."""
        mock_response = MagicMock()
        mock_response.json.return_value = _make_crtsh_response()
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await query_crtsh("evil.example.com", mock_client)

        assert "error" not in result
        assert result["total_certs"] == 3
        assert "sibling1.example.com" in result["sibling_domains"]
        assert "evil.example.com" not in result["sibling_domains"]

    async def test_empty_response(self):
        """crt.sh restituisce [] → risultato vuoto strutturato."""
        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await query_crtsh("example.com", mock_client)

        assert "error" not in result
        assert result["sibling_domains"] == []
        assert result["total_certs"] == 0

    @patch("graph_engine.osint.certificate_transparency.cache_get",
           return_value=None)
    async def test_timeout(self, mock_cache):
        """Timeout crt.sh → error nel risultato, mai eccezione."""
        from graph_engine.osint.certificate_transparency import CRTSH_TIMEOUT

        mock_client = MagicMock()
        mock_client.get = AsyncMock(
            side_effect=httpx.TimeoutException("timed out")
        )

        result = await query_crtsh("timeout-test.example.com", mock_client)

        assert "error" in result
        assert "timeout" in result["error"].lower()

    @patch("graph_engine.osint.certificate_transparency.cache_get",
           return_value=None)
    async def test_invalid_json(self, mock_cache):
        """crt.sh restituisce JSON malformato → error, mai eccezione."""
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("invalid JSON")
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await query_crtsh("invalid-json.example.com", mock_client)

        assert "error" in result
        assert "invalid json" in result["error"].lower()

    @patch("graph_engine.osint.certificate_transparency.cache_get",
           return_value=None)
    async def test_http_error(self, mock_cache):
        """Errore HTTP crt.sh → error, mai eccezione."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock(
            side_effect=httpx.HTTPError("500 Server Error")
        )

        result = await query_crtsh("http-error.example.com", mock_client)

        assert "error" in result
        assert "http error" in result["error"].lower()

    async def test_cache_hit_skips_http(self):
        """Se il risultato è in cache, nessuna chiamata HTTP."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock()

        # Prima chiamata: popola la cache
        mock_response = MagicMock()
        mock_response.json.return_value = _make_crtsh_response()
        mock_response.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.get.side_effect = None

        # Resetta mock per verificare
        mock_client.get = AsyncMock(return_value=mock_response)

        result1 = await query_crtsh("evil.example.com", mock_client)
        # La seconda chiamata dovrebbe usare la cache
        mock_client.get.reset_mock()
        result2 = await query_crtsh("evil.example.com", mock_client)

        # Entrambi i risultati devono essere uguali
        assert result1 == result2
        # La seconda chiamata NON deve aver fatto HTTP
        mock_client.get.assert_not_called()
