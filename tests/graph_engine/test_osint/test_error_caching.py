"""Gli esiti di errore OSINT non restano in cache come dati validi.

Prima: un timeout ctlogs restava in cache 6h, un "tutti i server RDAP
falliti" 24h, un DNS senza risposta 1h — ogni analisi successiva dello
stesso dominio ereditava l'errore.  Ora gli errori hanno ``TTL_ERROR``
(5 minuti) e il resto mantiene il TTL del provider.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from graph_engine.osint import cache
from graph_engine.osint.cache import TTL_ERROR, cache_get, cache_set


class TestCacheTtlOverride:
    def test_stored_ttl_shortens_lookup_ttl(self, monkeypatch):
        cache_set("p", "k", {"error": "timeout"}, ttl_seconds=TTL_ERROR)
        assert cache_get("p", "k", 3600) == {"error": "timeout"}

        real_time = time.time()
        monkeypatch.setattr(cache.time, "time", lambda: real_time + TTL_ERROR + 1)
        assert cache_get("p", "k", 3600) is None

    def test_value_without_override_keeps_provider_ttl(self, monkeypatch):
        cache_set("p", "k2", {"ok": True})
        real_time = time.time()
        monkeypatch.setattr(cache.time, "time", lambda: real_time + TTL_ERROR + 1)
        assert cache_get("p", "k2", 3600) == {"ok": True}

    def test_stored_ttl_never_extends(self, monkeypatch):
        """Un TTL salvato più lungo NON allunga quello del chiamante."""
        cache_set("p", "k3", {"ok": True}, ttl_seconds=10_000)
        real_time = time.time()
        monkeypatch.setattr(cache.time, "time", lambda: real_time + 61)
        assert cache_get("p", "k3", 60) is None


class TestProvidersMarkErrors:
    async def test_ctlogs_error_cached_with_short_ttl(self):
        from graph_engine.osint import certificate_transparency as ct

        with patch.object(
            ct, "_fetch_and_parse_ctlogs",
            new=AsyncMock(return_value={"error": "ctlogs.dev timeout after 15s"}),
        ), patch.object(ct, "cache_set") as mock_set:
            await ct.query_ctlogs("evil.example.com", MagicMock())
        assert mock_set.call_args.kwargs["ttl_seconds"] == TTL_ERROR

    async def test_ctlogs_success_cached_with_provider_ttl(self):
        from graph_engine.osint import certificate_transparency as ct

        with patch.object(
            ct, "_fetch_and_parse_ctlogs",
            new=AsyncMock(return_value={"sibling_domains": []}),
        ), patch.object(ct, "cache_set") as mock_set:
            await ct.query_ctlogs("ok.example.com", MagicMock())
        assert mock_set.call_args.kwargs["ttl_seconds"] is None

    async def test_rdap_error_cached_with_short_ttl(self):
        from graph_engine.osint import rdap

        with patch.object(
            rdap, "_fetch_rdap",
            new=AsyncMock(return_value={"error": "All 2 RDAP server(s) failed"}),
        ), patch.object(rdap, "cache_set") as mock_set:
            await rdap.query_rdap("evil.example.com", MagicMock())
        assert mock_set.call_args.kwargs["ttl_seconds"] == TTL_ERROR

    async def test_dns_no_records_cached_with_short_ttl(self):
        from graph_engine.osint import dns_resolve

        loop = asyncio.get_running_loop()
        with patch.object(
            loop, "getaddrinfo", new=AsyncMock(side_effect=OSError("nx")),
        ), patch.object(dns_resolve, "cache_set") as mock_set:
            result = await dns_resolve.resolve_dns("nx.example.com")
        assert result["error"]
        assert mock_set.call_args.kwargs["ttl_seconds"] == TTL_ERROR


class TestRdapTotalDeadline:
    async def test_server_timeouts_share_one_deadline(self, monkeypatch):
        """Il timeout RDAP vale per l'intera query: ogni tentativo riceve
        solo il tempo RESIDUO, e oltre la deadline i server restanti
        vengono saltati invece di aspettare N × timeout."""
        from graph_engine.osint import rdap

        monkeypatch.setattr(
            rdap, "_get_iana_bootstrap",
            AsyncMock(return_value={"com": [
                "https://a.example/", "https://b.example/", "https://c.example/",
            ]}),
        )
        timeouts: list[float] = []

        async def _slow_get(url, timeout):
            timeouts.append(timeout)
            await asyncio.sleep(0.15)
            raise httpx.TimeoutException("timed out")

        client = MagicMock()
        client.get = _slow_get

        result = await rdap._fetch_rdap("example.com", client, timeout=0.2)

        assert "error" in result
        assert len(timeouts) == 2, "il terzo server andava saltato (deadline)"
        assert timeouts[1] < timeouts[0] <= 0.2
        assert "deadline" in result["error"]
