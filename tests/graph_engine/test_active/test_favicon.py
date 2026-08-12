"""Test per graph_engine.active.favicon — hash favicon stile Shodan/Censys."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock

import httpx
import mmh3
import pytest

from graph_engine.active.favicon import fetch_favicon_hash


# ---------------------------------------------------------------------------
# Fixture: byte noti per verifica algoritmo esatto
# ---------------------------------------------------------------------------

# Un piccolo PNG valido (1x1 pixel rosso) per test deterministici
_KNOWN_FAVICON_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f"
    b"\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)


class TestFaviconHash:
    """Verifica l'algoritmo esatto di hashing favicon."""

    async def test_algorithm_produces_hash(self):
        """Fetch di un favicon valido produce favicon_hash e favicon_size_bytes."""
        client = AsyncMock(spec=httpx.AsyncClient)

        resp = MagicMock()
        resp.status_code = 200
        resp.content = _KNOWN_FAVICON_BYTES
        client.get = AsyncMock(return_value=resp)

        result = await fetch_favicon_hash("https://example.com", client)

        assert result is not None
        assert "favicon_hash" in result
        assert "favicon_size_bytes" in result
        assert result["favicon_size_bytes"] == len(_KNOWN_FAVICON_BYTES)
        assert isinstance(result["favicon_hash"], int)

    async def test_base64_encodebytes_vs_b64encode_produce_different_hashes(self):
        """DIMOSTRA che base64.encodebytes (MIME) e base64.b64encode (plain)
        producono hash mmh3 DIVERSI sullo stesso input.

        Questo test esiste per provare che la scelta della funzione conta
        davvero e non è intercambiabile — se qualcuno in futuro cambiasse
        ``base64.encodebytes`` con ``base64.b64encode``, il test fallisce.
        """
        raw_bytes = _KNOWN_FAVICON_BYTES

        # Metodo MIME-style (quello giusto, stile Shodan)
        encoded_mime = base64.encodebytes(raw_bytes)
        hash_mime = mmh3.hash(encoded_mime)

        # Metodo plain (SENZA a-capo)
        encoded_plain = base64.b64encode(raw_bytes)
        hash_plain = mmh3.hash(encoded_plain)

        # DEVONO essere diversi — se sono uguali, qualcuno ha cambiato
        # la funzione e il test deve fallire
        assert hash_mime != hash_plain, (
            f"base64.encodebytes e base64.b64encode producono lo stesso hash "
            f"({hash_mime}) — la scelta della funzione NON è intercambiabile!"
        )

        # Verifica anche che encodebytes contenga a-capo
        assert b"\n" in encoded_mime, (
            "base64.encodebytes deve contenere a-capo (MIME-style)"
        )
        assert b"\n" not in encoded_plain, (
            "base64.b64encode NON deve contenere a-capo (plain)"
        )

    async def test_404_returns_none(self):
        """Favicon non trovato → None."""
        client = AsyncMock(spec=httpx.AsyncClient)

        resp = MagicMock()
        resp.status_code = 404
        resp.content = b""
        client.get = AsyncMock(return_value=resp)

        result = await fetch_favicon_hash("https://example.com", client)

        assert result is None

    async def test_empty_body_returns_none(self):
        """Body vuoto → None."""
        client = AsyncMock(spec=httpx.AsyncClient)

        resp = MagicMock()
        resp.status_code = 200
        resp.content = b""
        client.get = AsyncMock(return_value=resp)

        result = await fetch_favicon_hash("https://example.com", client)

        assert result is None

    async def test_network_error_returns_none(self):
        """Errore di rete → None, mai eccezione."""
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))

        result = await fetch_favicon_hash("https://example.com", client)

        assert result is None

    async def test_uses_root_favicon_ico(self):
        """Verifica che venga interrogato /favicon.ico sulla root del dominio."""
        client = AsyncMock(spec=httpx.AsyncClient)

        resp = MagicMock()
        resp.status_code = 200
        resp.content = _KNOWN_FAVICON_BYTES
        client.get = AsyncMock(return_value=resp)

        await fetch_favicon_hash("https://sub.example.com/path/page.html", client)

        # Deve aver chiamato /favicon.ico sulla root del dominio
        call_url = client.get.call_args[0][0]
        assert call_url == "https://sub.example.com/favicon.ico"
