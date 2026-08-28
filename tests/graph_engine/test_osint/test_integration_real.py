"""Test d'integrazione reale — API pubbliche su dominio noto stabile.

Questi test richiedono RETE e sono marcati ``@pytest.mark.integration``.
NON vengono eseguiti dalla suite predefinita (``pytest.ini: addopts = -m "not integration"``).
Servono a beccare cambi di formato delle API reali nel tempo.

Esegui con::

    pytest -m integration tests/graph_engine/test_osint/test_integration_real.py
"""

from __future__ import annotations

import pytest


@pytest.mark.integration
class TestRealCtlogs:
    """ctlogs.dev su un dominio noto con molti certificati (google.com).

    Senza ``CTLOGS_API_KEY`` gira in modalità anonima (niente SAN list);
    con la chiave in modalità API (sibling dai dettagli).  Il test è
    valido per entrambe.
    """

    async def test_ctlogs_real_returns_certificates(self):
        """ctlogs.dev su google.com deve restituire la cronologia certificati
        (e sibling se in modalità API) o errore trasparente."""
        import httpx
        from graph_engine.osint.certificate_transparency import query_ctlogs

        async with httpx.AsyncClient() as client:
            result = await query_ctlogs("google.com", client)

        # Accetta sia successo che errori transitori (rate limit, quota)
        # — il formato della risposta è ciò che ci interessa
        if "error" in result:
            pytest.skip(f"ctlogs.dev temporaneamente non disponibile: {result['error']}")
            return

        assert result["source"] == "ctlogs.dev"
        assert result["mode"] in ("api", "anonymous")
        assert isinstance(result["sibling_domains"], list)
        # google.com è paginato (has_next): oldest e total restano None
        assert result["newest_cert_days"] is not None
        if result["mode"] == "api":
            assert result["total_siblings"] > 0
            assert "google.com" not in result["sibling_domains"]
        else:
            # Modalità anonima: niente SAN list → sibling vuoti
            assert result["sibling_domains"] == []


@pytest.mark.integration
class TestRealRdap:
    """RDAP su un dominio noto, stabile e longevo (google.com)."""

    async def test_rdap_real_returns_data(self):
        """RDAP su google.com deve restituire età, registrar."""
        import httpx
        from graph_engine.osint.rdap import query_rdap

        async with httpx.AsyncClient() as client:
            result = await query_rdap("google.com", client)

        if "error" in result:
            pytest.skip(f"RDAP temporaneamente non disponibile: {result['error']}")
            return

        # google.com esiste da decenni
        assert result["domain_age_days"] is not None
        assert result["domain_age_days"] > 365  # più di un anno
        assert len(result["nameservers"]) > 0


@pytest.mark.integration
class TestRealUrlhaus:
    """URLhaus su URL nota — verifichiamo solo che l'API risponda.

    Nota (2026-08): l'API URLhaus ora restituisce 401 Unauthorized —
    potrebbe richiedere autenticazione. Il nostro provider gestisce
    correttamente questa risposta come errore, senza crash.
    """

    async def test_urlhaus_real_no_results_for_google(self):
        """google.com non dovrebbe essere nel feed URLhaus."""
        import httpx
        from graph_engine.osint.reputation.urlhaus import UrlhausProvider

        async with httpx.AsyncClient() as client:
            provider = UrlhausProvider()
            result = await provider.check("https://www.google.com", client)

        assert result["provider"] == "urlhaus"
        # Accetta sia no_results (API funzionante) che error (es. 401 auth)
        # — il provider non deve mai crashare
        if "error" in result.get("details", {}):
            pytest.skip(
                f"URLhaus API non disponibile (possibile cambiamento auth): "
                f"{result['details']['error'][:100]}"
            )
            return

        assert result["listed"] is False
        assert result["details"].get("query_status") == "no_results"


@pytest.mark.integration
class TestRealDns:
    """Risoluzione DNS reale su hostname stabili."""

    async def test_dns_real_google_has_a_records(self):
        """google.com deve risolvere con almeno un record A (formato IPv4)."""
        from graph_engine.osint.dns_resolve import resolve_dns

        result = await resolve_dns("google.com")

        if result.get("error"):
            pytest.skip(f"DNS temporaneamente non disponibile: {result['error']}")
            return

        assert len(result["a_records"]) > 0, (
            "google.com deve avere almeno un record A"
        )
        # Verifica formato IPv4 su ogni record
        import ipaddress
        for addr in result["a_records"]:
            ip = ipaddress.ip_address(addr)
            assert ip.version == 4, f"Atteso IPv4, ottenuto {addr}"
