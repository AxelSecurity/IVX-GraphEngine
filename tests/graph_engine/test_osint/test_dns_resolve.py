"""Test per graph_engine.osint.dns_resolve — risoluzione DNS A/AAAA."""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, patch

import pytest

from graph_engine.osint.cache import TTL_DNS, cache_set
from graph_engine.osint.dns_resolve import resolve_dns


# ---------------------------------------------------------------------------
# Helper: costruisce un fake addrinfo come restituito da loop.getaddrinfo
# ---------------------------------------------------------------------------


def _fake_addrinfo(*addresses):
    """Costruisce una lista finta nel formato di ``loop.getaddrinfo``."""
    result = []
    for addr in addresses:
        result.append((socket.AF_INET, 0, 0, "", (addr, 0)))
    return result


class TestDnsResolve:
    """Test unitari con mock di loop.getaddrinfo."""

    async def test_a_records_only(self):
        """Hostname con solo IPv4 → a_records popolato, aaaa_records vuoto."""
        fake_a = _fake_addrinfo("93.184.216.34")

        async def mock_getaddrinfo(host, port, **kwargs):
            if kwargs.get("family") == socket.AF_INET:
                return fake_a
            raise socket.gaierror("No AAAA records")

        with patch.object(
            asyncio.get_running_loop(), "getaddrinfo", side_effect=mock_getaddrinfo
        ):
            result = await resolve_dns("example.com")

        assert result["a_records"] == ["93.184.216.34"]
        assert result["aaaa_records"] == []
        assert result["error"] is None

    async def test_a_and_aaaa_records(self):
        """Hostname con IPv4 + IPv6 → entrambi popolati."""
        fake_a = _fake_addrinfo("93.184.216.34")
        fake_aaaa = _fake_addrinfo("2606:2800:220:1:248:1893:25c8:1946")

        async def mock_getaddrinfo(host, port, **kwargs):
            if kwargs.get("family") == socket.AF_INET:
                return fake_a
            return fake_aaaa

        with patch.object(
            asyncio.get_running_loop(), "getaddrinfo", side_effect=mock_getaddrinfo
        ):
            result = await resolve_dns("dualstack.example.com")

        assert "93.184.216.34" in result["a_records"]
        assert "2606:2800:220:1:248:1893:25c8:1946" in result["aaaa_records"]
        assert result["error"] is None

    async def test_multiple_a_records(self):
        """Hostname con più record A → tutti restituiti."""
        fake_a = _fake_addrinfo("1.2.3.4", "5.6.7.8")

        async def mock_getaddrinfo(host, port, **kwargs):
            if kwargs.get("family") == socket.AF_INET:
                return fake_a
            raise socket.gaierror("No AAAA")

        with patch.object(
            asyncio.get_running_loop(), "getaddrinfo", side_effect=mock_getaddrinfo
        ):
            result = await resolve_dns("multi-a.example.com")

        assert len(result["a_records"]) == 2
        assert "1.2.3.4" in result["a_records"]
        assert "5.6.7.8" in result["a_records"]

    async def test_nxdomain_returns_error(self):
        """NXDOMAIN → error popolato, liste vuote, nessuna eccezione."""

        async def mock_getaddrinfo(host, port, **kwargs):
            raise socket.gaierror("Name or service not known")

        with patch.object(
            asyncio.get_running_loop(), "getaddrinfo", side_effect=mock_getaddrinfo
        ):
            result = await resolve_dns("nonexistent.invalid")

        assert result["a_records"] == []
        assert result["aaaa_records"] == []
        assert result["error"] is not None
        assert "No DNS records found" in result["error"]

    async def test_timeout_returns_error(self):
        """Timeout → error popolato, mai eccezione."""

        async def mock_getaddrinfo(host, port, **kwargs):
            await asyncio.sleep(10)  # non arriverà mai a completare

        with patch.object(
            asyncio.get_running_loop(), "getaddrinfo", side_effect=mock_getaddrinfo
        ), patch("graph_engine.osint.dns_resolve._DNS_TIMEOUT", 0.05):
            result = await resolve_dns("slow-dns.example.com")

        assert result["a_records"] == []
        assert result["aaaa_records"] == []
        assert result["error"] is not None

    async def test_duplicate_addresses_removed(self):
        """Indirizzi duplicati → deduplicati."""
        # getaddrinfo può restituire lo stesso IP più volte per famiglie
        # di socket diverse (STREAM/DGRAM). Li deduplichiamo.
        fake_a = _fake_addrinfo("10.0.0.1", "10.0.0.1", "10.0.0.2")

        async def mock_getaddrinfo(host, port, **kwargs):
            if kwargs.get("family") == socket.AF_INET:
                return fake_a
            raise socket.gaierror("No AAAA")

        with patch.object(
            asyncio.get_running_loop(), "getaddrinfo", side_effect=mock_getaddrinfo
        ):
            result = await resolve_dns("dup.example.com")

        assert result["a_records"] == ["10.0.0.1", "10.0.0.2"]


class TestDnsCache:
    """Verifica che la cache venga usata correttamente."""

    async def test_second_call_uses_cache(self, tmp_path, monkeypatch):
        """Seconda chiamata sullo stesso hostname entro il TTL → non
        richiede una nuova risoluzione."""
        monkeypatch.setattr(
            "graph_engine.osint.cache._CACHE_ROOT", tmp_path / "osint_cache"
        )

        call_count = 0

        async def mock_getaddrinfo(host, port, **kwargs):
            nonlocal call_count
            call_count += 1
            if kwargs.get("family") == socket.AF_INET:
                return _fake_addrinfo("1.1.1.1")
            raise socket.gaierror("No AAAA")

        with patch.object(
            asyncio.get_running_loop(), "getaddrinfo", side_effect=mock_getaddrinfo
        ):
            result1 = await resolve_dns("cached.example.com")
            result2 = await resolve_dns("cached.example.com")

        # Entrambe le chiamate devono restituire lo stesso risultato
        assert result1["a_records"] == result2["a_records"]
        # getaddrinfo viene chiamato 2 volte per risoluzione (A + AAAA in
        # asyncio.gather). Dopo la prima risoluzione il risultato è in cache:
        # la seconda chiamata a resolve_dns NON deve chiamare getaddrinfo.
        assert call_count == 2, (
            f"getaddrinfo chiamato {call_count} volte — "
            f"la cache non ha funzionato (attese 2: A+AAAA per la prima "
            f"risoluzione, 0 per la seconda da cache)"
        )

    async def test_different_hostnames_not_cached_together(self, tmp_path, monkeypatch):
        """Hostname diversi → risoluzioni separate."""
        monkeypatch.setattr(
            "graph_engine.osint.cache._CACHE_ROOT", tmp_path / "osint_cache"
        )

        call_count = 0

        async def mock_getaddrinfo(host, port, **kwargs):
            nonlocal call_count
            call_count += 1
            if host == "host-a.example.com" and kwargs.get("family") == socket.AF_INET:
                return _fake_addrinfo("10.0.0.1")
            if host == "host-b.example.com" and kwargs.get("family") == socket.AF_INET:
                return _fake_addrinfo("10.0.0.2")
            raise socket.gaierror("No AAAA")

        with patch.object(
            asyncio.get_running_loop(), "getaddrinfo", side_effect=mock_getaddrinfo
        ):
            result_a = await resolve_dns("host-a.example.com")
            result_b = await resolve_dns("host-b.example.com")

        assert result_a["a_records"] == ["10.0.0.1"]
        assert result_b["a_records"] == ["10.0.0.2"]
        # Due risoluzioni distinte → ciascuna chiama getaddrinfo 2 volte
        # (A + AAAA in asyncio.gather), totale 4
        assert call_count == 4, (
            f"getaddrinfo chiamato {call_count} volte — "
            f"attese 4 (2 per hostname: A+AAAA ciascuno)"
        )
