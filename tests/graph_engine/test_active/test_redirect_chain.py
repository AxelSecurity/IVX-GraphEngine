"""Test per graph_engine.active.redirect_chain — catena di redirect."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from graph_engine.active.redirect_chain import trace_redirect_chain


# ---------------------------------------------------------------------------
# Helper: costruisce un mock di risposta httpx con headers mockati
# ---------------------------------------------------------------------------


def _mock_response(
    status_code: int,
    headers: dict | None = None,
    set_cookie_values: list[str] | None = None,
):
    """Costruisce un MagicMock che simula una risposta httpx.

    Gli headers sono mockati in modo che ``.get()`` e ``.get_list()``
    funzionino come i metodi reali di ``httpx.Headers``.
    """
    resp = MagicMock()
    resp.status_code = status_code

    headers_mock = MagicMock()
    if headers:
        def _get(key, default=None):
            return headers.get(key, default)
        headers_mock.get.side_effect = _get
    else:
        headers_mock.get.return_value = None

    if set_cookie_values is not None:
        headers_mock.get_list.return_value = set_cookie_values
    else:
        headers_mock.get_list.return_value = []

    resp.headers = headers_mock
    return resp


class TestRedirectChain:
    """Verifica il tracciamento manuale dei redirect HTTP."""

    async def test_follows_chain_of_three_redirects(self):
        """Catena di 3 redirect seguita correttamente."""
        client = AsyncMock(spec=httpx.AsyncClient)

        # Mock: 4 risposte in sequenza: 302 → 301 → 307 → 200
        resp1 = _mock_response(302, {"location": "/page2", "server": "nginx"})
        resp2 = _mock_response(301, {"location": "/page3"},
                               set_cookie_values=["session=abc123; Path=/"])
        resp3 = _mock_response(307, {"location": "/final"})
        resp4 = _mock_response(200, {"server": "Apache"})

        client.get = AsyncMock(side_effect=[resp1, resp2, resp3, resp4])

        result = await trace_redirect_chain("https://evil.example.com/start", client)

        assert result["hop_count"] == 4
        assert result["redirect_count"] == 3
        assert result["truncated"] is False
        assert result["final_url"] == "https://evil.example.com/final"

        hops = result["hops"]
        assert hops[0]["status_code"] == 302
        assert hops[0]["location"] == "/page2"
        assert hops[0]["server"] == "nginx"

        assert hops[1]["status_code"] == 301
        assert hops[1]["cookies"] == ["session"]  # solo nome, non valore

        assert hops[3]["status_code"] == 200
        assert "location" not in hops[3]  # non-redirect, nessuna location

    async def test_max_hops_truncates(self):
        """Loop infinito bloccato da max_hops."""
        client = AsyncMock(spec=httpx.AsyncClient)

        resp = _mock_response(302, {"location": "/same"})
        client.get = AsyncMock(return_value=resp)

        result = await trace_redirect_chain(
            "https://evil.example.com/loop", client, max_hops=5
        )

        assert result["truncated"] is True
        assert result["hop_count"] == 5
        assert result["redirect_count"] == 5

    async def test_network_error_does_not_block_previous_hops(self):
        """Errore di rete su un hop non blocca la registrazione degli hop precedenti."""
        client = AsyncMock(spec=httpx.AsyncClient)

        # Primo hop: 302 OK
        resp1 = _mock_response(302, {"location": "/next"})
        # Secondo hop: errore di rete
        client.get = AsyncMock(side_effect=[
            resp1,
            httpx.ConnectError("Connection refused"),
        ])

        result = await trace_redirect_chain("https://evil.example.com/start", client)

        assert result["hop_count"] == 2
        assert result["redirect_count"] == 1
        assert result["hops"][0]["status_code"] == 302
        assert "error" in result["hops"][1]
        assert "Connection refused" in result["hops"][1]["error"]

    async def test_non_redirect_stops_immediately(self):
        """Risposta 200 al primo hop → catena di 1 hop."""
        client = AsyncMock(spec=httpx.AsyncClient)

        resp = _mock_response(200)
        client.get = AsyncMock(return_value=resp)

        result = await trace_redirect_chain("https://benign.example.com", client)

        assert result["hop_count"] == 1
        assert result["redirect_count"] == 0
        assert result["truncated"] is False

    async def test_exception_wrapped_as_error_hop(self):
        """Qualunque eccezione → hop con error, mai propagata."""
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get = AsyncMock(side_effect=RuntimeError("unexpected boom"))

        # Non deve sollevare eccezione
        result = await trace_redirect_chain("https://evil.example.com", client)

        assert result["hop_count"] == 1
        assert result["redirect_count"] == 0
        assert "error" in result["hops"][0]
