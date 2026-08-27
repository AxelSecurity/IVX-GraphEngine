"""Tests for the ctlogs.dev fallback (Certificate Transparency).

Formato delle risposte conforme al contratto documentato su
https://api.ctlogs.dev: la ricerca ``/v1/domain/{host}`` restituisce
righe SENZA SAN list (solo ``san_count``), il dettaglio ``/v1/cert/{id}``
restituisce ``san_dns`` (array completo dei dNSName).  Senza chiave il
fallback usa l'endpoint pubblico ``https://ctlogs.dev/search`` (stessa
forma ``rows``/``has_next``/``next_cursor``, senza dettagli SAN).

Nessuna rete reale: client httpx mockato.  La chiave si forza sul
singleton ``graph_engine.config.settings`` (come per MISP/OpenCTI).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from graph_engine.config import settings
from graph_engine.osint.certificate_transparency import query_ctlogs


# ---------------------------------------------------------------------------
# Fixture: risposte ctlogs.dev mockate (forma del contratto documentato)
# ---------------------------------------------------------------------------

def _make_search_response(rows, has_next=False):
    return {
        "rows": rows,
        "has_next": has_next,
        "next_cursor": "cursor-123" if has_next else "",
        "duration_ms": 42,
    }


_ROWS = [
    {
        "id": "id-newest",
        "match": "evil.example.com",
        "not_before": "2026-08-20T00:00:00Z",
        "not_after": "2026-11-18T00:00:00Z",
        "serial_hex": "abc123",
        "issuer": "Let's Encrypt",
        "key_algo": "ECDSA P-256",
        "san_count": 2,
    },
    {
        "id": "id-older",
        "match": "evil.example.com",
        "not_before": "2025-01-10T00:00:00Z",
        "not_after": "2025-04-10T00:00:00Z",
        "serial_hex": "def456",
        "issuer": "Let's Encrypt",
        "key_algo": "RSA 2048",
        "san_count": 3,
    },
]

_DETAILS = {
    "id-newest": {
        "san_dns": ["evil.example.com", "sibling1.example.com"],
        "not_before": "2026-08-20T00:00:00Z",
    },
    "id-older": {
        "san_dns": [
            "evil.example.com",
            "sibling2.example.com",
            "sibling1.example.com",
        ],
        "not_before": "2025-01-10T00:00:00Z",
    },
}


def _make_mock_client(
    rows=None,
    details=None,
    search_error=None,
    has_next=False,
):
    """Client mockato: risposte distinte per /v1/domain/ e /v1/cert/."""
    rows = _ROWS if rows is None else rows
    details = _DETAILS if details is None else details

    def _respond(url, **kwargs):
        if search_error is not None:
            raise search_error
        if "/v1/cert/" in url:
            cert_id = url.rsplit("/", 1)[-1]
            if cert_id in details:
                resp = MagicMock()
                resp.json.return_value = details[cert_id]
                resp.raise_for_status = MagicMock()
                return resp
            # Dettaglio non recuperabile: errore HTTP
            raise httpx.HTTPError(f"detail fetch failed for {cert_id}")
        resp = MagicMock()
        resp.json.return_value = _make_search_response(rows, has_next=has_next)
        resp.raise_for_status = MagicMock()
        return resp

    client = MagicMock()
    client.get = AsyncMock(side_effect=_respond)
    return client


def _enable_ctlogs(monkeypatch, key="test-key"):
    monkeypatch.setattr(settings, "ctlogs_api_key", key)


class TestQueryCtlogsMocked:
    async def test_successful_query_builds_siblings_from_details(
        self, monkeypatch
    ):
        """Ricerca + dettagli → SAN aggregati, dominio escluso, date note."""
        _enable_ctlogs(monkeypatch)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs(
                "evil.example.com", _make_mock_client()
            )

        assert "error" not in result
        assert "sibling1.example.com" in result["sibling_domains"]
        assert "sibling2.example.com" in result["sibling_domains"]
        assert "evil.example.com" not in result["sibling_domains"]
        assert result["total_certs"] == 2
        assert result["newest_cert_days"] is not None
        assert result["oldest_cert_days"] is not None
        assert result["source"] == "ctlogs.dev"
        assert result["mode"] == "api"

    async def test_anonymous_mode_uses_public_endpoint(self, monkeypatch):
        """Senza CTLOGS_API_KEY → endpoint pubblico /search?output=json:
        date note dalla ricerca, sibling vuoti (nessuna SAN list),
        nessun header Bearer, nessuna richiesta ai dettagli."""
        monkeypatch.setattr(settings, "ctlogs_api_key", None)
        client = _make_mock_client()
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs("evil.example.com", client)

        assert "error" not in result
        assert result["mode"] == "anonymous"
        assert result["sibling_domains"] == []
        assert result["total_siblings"] == 0
        assert result["newest_cert_days"] is not None
        assert result["oldest_cert_days"] is not None
        assert result["total_certs"] == 2
        assert result["source"] == "ctlogs.dev"

        # Una sola richiesta: la ricerca pubblica, senza header Bearer
        assert len(client.get.call_args_list) == 1
        called = client.get.call_args_list[0]
        assert called.args[0] == (
            "https://ctlogs.dev/search?q=evil.example.com&output=json"
        )
        assert called.kwargs["headers"] is None

    async def test_anonymous_paginated_marks_oldest_and_total_unknown(
        self, monkeypatch
    ):
        """Anche l'endpoint pubblico pagina (has_next): oldest e total
        None, mai inventati; newest resta noto (prima riga)."""
        monkeypatch.setattr(settings, "ctlogs_api_key", None)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs(
                "evil.example.com", _make_mock_client(has_next=True)
            )

        assert "error" not in result
        assert result["mode"] == "anonymous"
        assert result["newest_cert_days"] is not None
        assert result["oldest_cert_days"] is None
        assert result["total_certs"] is None

    async def test_anonymous_empty_rows(self, monkeypatch):
        """Nessun certificato sull'endpoint pubblico → risultato vuoto
        strutturato, mai error (verificato live sul formato)."""
        monkeypatch.setattr(settings, "ctlogs_api_key", None)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs(
                "empty.example.com", _make_mock_client(rows=[])
            )

        assert "error" not in result
        assert result["mode"] == "anonymous"
        assert result["sibling_domains"] == []
        assert result["total_certs"] == 0
        assert result["source"] == "ctlogs.dev"

    async def test_auth_header_sent(self, monkeypatch):
        """L'API key viaggia nell'header Authorization: Bearer."""
        _enable_ctlogs(monkeypatch, key="secret-key")
        client = _make_mock_client()
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            await query_ctlogs("evil.example.com", client)

        # Ogni chiamata (ricerca + dettagli) porta l'header Bearer
        for call in client.get.call_args_list:
            assert call.kwargs["headers"] == {
                "Authorization": "Bearer secret-key"
            }

    async def test_paginated_response_marks_oldest_and_total_unknown(
        self, monkeypatch
    ):
        """has_next → oldest_cert_days e total_certs None (mai inventati),
        newest resta noto (prima riga)."""
        _enable_ctlogs(monkeypatch)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs(
                "evil.example.com", _make_mock_client(has_next=True)
            )

        assert "error" not in result
        assert result["newest_cert_days"] is not None
        assert result["oldest_cert_days"] is None
        assert result["total_certs"] is None

    async def test_no_rows_empty_result(self, monkeypatch):
        """Nessun certificato → risultato vuoto strutturato, mai error."""
        _enable_ctlogs(monkeypatch)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs(
                "empty.example.com", _make_mock_client(rows=[])
            )

        assert "error" not in result
        assert result["sibling_domains"] == []
        assert result["total_certs"] == 0
        assert result["source"] == "ctlogs.dev"

    async def test_detail_failure_is_best_effort(self, monkeypatch):
        """Un dettaglio non recuperabile non fa fallire l'aggregazione."""
        _enable_ctlogs(monkeypatch)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs(
                "evil.example.com",
                _make_mock_client(details={"id-newest": _DETAILS["id-newest"]}),
            )

        assert "error" not in result
        assert "sibling1.example.com" in result["sibling_domains"]
        assert "sibling2.example.com" not in result["sibling_domains"]

    async def test_401_auth_error(self, monkeypatch):
        """401 → error esplicito sulla chiave, mai eccezione."""
        _enable_ctlogs(monkeypatch)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs(
                "auth-error.example.com",
                _make_mock_client(
                    search_error=_http_status_error(401)
                ),
            )

        assert "error" in result
        assert "auth" in result["error"].lower()

    async def test_429_quota_error(self, monkeypatch):
        """429 → error esplicito su quota/rate limit, mai eccezione."""
        _enable_ctlogs(monkeypatch)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs(
                "quota.example.com",
                _make_mock_client(search_error=_http_status_error(429)),
            )

        assert "error" in result
        assert "429" in result["error"]

    async def test_timeout(self, monkeypatch):
        """Timeout → error nel risultato, mai eccezione."""
        _enable_ctlogs(monkeypatch)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs(
                "timeout.example.com",
                _make_mock_client(
                    search_error=httpx.TimeoutException("timed out")
                ),
            )

        assert "error" in result
        assert "timeout" in result["error"].lower()

    async def test_invalid_json(self, monkeypatch):
        """JSON malformato → error, mai eccezione."""
        _enable_ctlogs(monkeypatch)

        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("invalid JSON")
        mock_response.raise_for_status = MagicMock()
        client = MagicMock()
        client.get = AsyncMock(return_value=mock_response)

        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result = await query_ctlogs("invalid.example.com", client)

        assert "error" in result
        assert "invalid json" in result["error"].lower()

    async def test_cache_hit_skips_http(self, monkeypatch):
        """Seconda chiamata sullo stesso dominio → cache, zero HTTP.

        Prima chiamata con cache bypassata (patch cache_get → None) per
        forzare l'HTTP; la seconda usa la cache reale scritta dalla
        prima (stesso pattern del test crt.sh esistente).
        """
        _enable_ctlogs(monkeypatch)
        client = _make_mock_client()
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            result1 = await query_ctlogs("evil.example.com", client)
        client.get.reset_mock()
        result2 = await query_ctlogs("evil.example.com", client)

        assert result1 == result2
        client.get.assert_not_called()

    async def test_cache_separated_by_mode(self, monkeypatch):
        """La cache anonima non viene riusata dalla modalità API: quando
        la chiave arriva il fallback rifà le richieste e vede i sibling
        che la modalità anonima non può vedere."""
        client = _make_mock_client()

        # Modalità anonima: prima chiamata forza HTTP (cache bypassata),
        # la seconda conferma la cache anonima reale.
        monkeypatch.setattr(settings, "ctlogs_api_key", None)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            anon = await query_ctlogs("evil.example.com", client)
        client.get.reset_mock()
        anon_cached = await query_ctlogs("evil.example.com", client)
        assert anon_cached == anon
        client.get.assert_not_called()

        # Arriva la chiave: cache API separata → HTTP di nuovo, sibling visti.
        _enable_ctlogs(monkeypatch)
        with patch(
            "graph_engine.osint.certificate_transparency.cache_get",
            return_value=None,
        ):
            api = await query_ctlogs("evil.example.com", client)

        assert api["mode"] == "api"
        assert "sibling1.example.com" in api["sibling_domains"]
        assert api != anon


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _http_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.ctlogs.dev/v1/domain/x")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError(
        f"{status_code}", request=request, response=response
    )
